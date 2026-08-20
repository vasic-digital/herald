//go:build !windows

package lifecycle

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// §11.4.263 regression guard — process-group signal safety for this
// package's harness teardowns.
//
// BOB-126 forensic anchor: signalling a process GROUP whose pgid is <= 1 is
// the host-destroying syscall. After the negation that targets a group,
//
//	pid  1 -> kill(-1, sig)  = signal EVERY process this UID may signal
//	pid  0 -> kill( 0, sig)  = signal the CALLER'S OWN process group (self-kill)
//	pid -1 -> kill( 1, sig)  = signal init directly
//
// so the check must happen on the RAW pid, BEFORE the negation. Note that a
// naive `pid != 1` check MISSES the pid == 0 self-kill; only `pid > 1` closes
// the whole class.
//
// These tests NEVER signal anything: killFn is swapped for a recorder, which
// is the §11.4.263(C) requirement to "patch the killpg call itself AND assert
// killpg was called with pgid > 1". Running the unguarded behaviour for real
// would take the host down, so the seam IS the only safe oracle.
//
// §11.4.115 RED: the RED artifact is this file's subject with ONLY the
// `if pid <= 1 { ... }` block removed from killProcessGroup in
// procgroup_unix.go — which is simultaneously the canonical §1.1 mutation.
// That mutation still COMPILES, so every failure below is BEHAVIOURAL: the
// recorder observes the kill(-1, sig) that would have fired.
//
// NOTE: killFn is package-global, so these tests deliberately do not call
// t.Parallel().

// ---------------------------------------------------------------------------
// kill recorder
// ---------------------------------------------------------------------------

type killRecord struct {
	pid int
	sig syscall.Signal
}

// recordKills swaps killFn for a recorder for the duration of the test and
// restores it afterwards. The returned pointer accumulates every call.
func recordKills(t *testing.T, ret error) *[]killRecord {
	t.Helper()
	calls := make([]killRecord, 0, 2)
	prev := killFn
	killFn = func(pid int, sig syscall.Signal) error {
		calls = append(calls, killRecord{pid: pid, sig: sig})
		return ret
	}
	t.Cleanup(func() { killFn = prev })
	return &calls
}

// unsafePGIDs is the closed set of raw pids that MUST never reach kill().
// Each is degenerate only AFTER the negation, which is why the guard
// validates the raw value.
var unsafePGIDs = []int{-1, 0, 1}

// ---------------------------------------------------------------------------
// core behavioural assertions
// ---------------------------------------------------------------------------

// TestKillProcessGroup_RefusesUnsafePGID is the §11.4.263 core assertion:
// every pid <= 1 is REFUSED, for every signal this package delivers, and no
// signal reaches the syscall layer.
func TestKillProcessGroup_RefusesUnsafePGID(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		for _, pid := range unsafePGIDs {
			t.Run(fmt.Sprintf("pid=%d/%v", pid, sig), func(t *testing.T) {
				calls := recordKills(t, nil)
				err := killProcessGroup(pid, sig)
				// PRIMARY invariant first: no signal may reach the
				// kernel. Checking this before the error contract is
				// what makes the RED log name the exact call that
				// would have fired.
				if len(*calls) != 0 {
					got := (*calls)[0]
					t.Fatalf("pid=%d sig=%v: guard did NOT fire — kill(%d, %v) reached the syscall layer; "+
						"this is the BOB-126 host-destroying call", pid, sig, got.pid, got.sig)
				}
				if err == nil {
					t.Fatalf("pid=%d sig=%v: expected refusal error, got nil", pid, sig)
				}
				if !errors.Is(err, errUnsafeProcessGroup) {
					t.Fatalf("pid=%d sig=%v: error %v does not wrap errUnsafeProcessGroup", pid, sig, err)
				}
			})
		}
	}
}

// TestKillProcessGroup_SignalsRealGroup is the §11.4.201(1) false-positive
// guard: a legitimate pid > 1 MUST still be signalled, with the negation
// applied exactly once. A guard that refuses everything is a FAIL-bluff.
func TestKillProcessGroup_SignalsRealGroup(t *testing.T) {
	for _, pid := range []int{2, 4242, 999999} {
		t.Run(fmt.Sprintf("pid=%d", pid), func(t *testing.T) {
			calls := recordKills(t, nil)
			if err := killProcessGroup(pid, syscall.SIGKILL); err != nil {
				t.Fatalf("legitimate pid %d was refused: %v", pid, err)
			}
			if len(*calls) != 1 {
				t.Fatalf("expected exactly 1 kill call, got %d: %+v", len(*calls), *calls)
			}
			got := (*calls)[0]
			if got.pid != -pid || got.sig != syscall.SIGKILL {
				t.Fatalf("expected kill(%d, SIGKILL), got kill(%d, %v)", -pid, got.pid, got.sig)
			}
			if got.pid >= -1 {
				t.Fatalf("pgid argument %d is not a real process group", got.pid)
			}
		})
	}
}

// TestKillProcessGroup_PropagatesRealError preserves the pre-existing
// best-effort contract: a real kill error (e.g. ESRCH when the group is
// already gone) still propagates and is NOT mistaken for a guard refusal.
func TestKillProcessGroup_PropagatesRealError(t *testing.T) {
	calls := recordKills(t, syscall.ESRCH)
	err := killProcessGroup(4242, syscall.SIGTERM)
	if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("expected ESRCH to propagate, got %v", err)
	}
	if errors.Is(err, errUnsafeProcessGroup) {
		t.Fatalf("a real kill error was misreported as a guard refusal: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 kill call, got %d", len(*calls))
	}
}

// ---------------------------------------------------------------------------
// AST scanner — structure matching, not substring (§11.4.201(7)(a))
// ---------------------------------------------------------------------------

// procGroupSite is one process-group signal call discovered in package source.
type procGroupSite struct {
	file    string
	line    int
	sigName string // e.g. "SIGTERM"
	guarded bool   // true => routed through killProcessGroup
}

// sigByName maps the signal identifiers this package actually delivers onto
// their values, so a per-site test can exercise the site's REAL signal.
var sigByName = map[string]syscall.Signal{
	"SIGTERM": syscall.SIGTERM,
	"SIGKILL": syscall.SIGKILL,
}

// scanProcGroupSites parses Go source and returns every process-group signal
// call it contains.
//
// It matches STRUCTURE, not substring: an unguarded site is a CallExpr on
// syscall.Kill whose FIRST ARGUMENT is a unary minus (the negation that makes
// it target a group). A guarded site is a CallExpr on killProcessGroup. A
// comment or string literal that merely MENTIONS either form is a CARRIER and
// is correctly ignored, because neither is a CallExpr — this is precisely the
// false-match a grep would produce (§11.4.201(7)(a)).
//
// src may be nil, in which case filename is read from disk.
func scanProcGroupSites(fset *token.FileSet, filename string, src any) ([]procGroupSite, error) {
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var sites []procGroupSite
	base := filepath.Base(filename)

	// sigNameOf extracts "SIGTERM"/"SIGKILL" from a syscall.SIGx argument.
	sigNameOf := func(args []ast.Expr, idx int) string {
		if len(args) <= idx {
			return ""
		}
		sel, ok := args[idx].(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		return sel.Sel.Name
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr: // syscall.Kill(...)
			pkg, ok := fun.X.(*ast.Ident)
			if !ok || pkg.Name != "syscall" || fun.Sel.Name != "Kill" {
				return true
			}
			// Only a NEGATED first argument targets a process group.
			// syscall.Kill(pid, sig) signals a single process and is not
			// in scope for §11.4.263 — refusing it would be a
			// §11.4.201(1) false positive.
			un, ok := call.Args[0].(*ast.UnaryExpr)
			if !ok || un.Op != token.SUB {
				return true
			}
			sites = append(sites, procGroupSite{
				file:    base,
				line:    fset.Position(call.Pos()).Line,
				sigName: sigNameOf(call.Args, 1),
				guarded: false,
			})
		case *ast.Ident: // killProcessGroup(...)
			if fun.Name != "killProcessGroup" {
				return true
			}
			sites = append(sites, procGroupSite{
				file:    base,
				line:    fset.Position(call.Pos()).Line,
				sigName: sigNameOf(call.Args, 1),
				guarded: true,
			})
		}
		return true
	})
	return sites, nil
}

// scanPackageProcGroupSites scans every .go file in the package directory,
// regardless of build tags — the parser does not evaluate them, which is what
// lets this cover the integration-tagged harnesses that do not compile in the
// default configuration.
func scanPackageProcGroupSites(t *testing.T) []procGroupSite {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var all []procGroupSite
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		sites, err := scanProcGroupSites(fset, e.Name(), nil)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		all = append(all, sites...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].file != all[j].file {
			return all[i].file < all[j].file
		}
		return all[i].line < all[j].line
	})
	return all
}

// TestScanProcGroupSites_SelfValidates is the §11.4.107(10) analyzer
// self-validation: the scanner is proven able to SEE the defect it looks for
// (golden-bad) and proven NOT to fire on the shapes that are legitimate
// (golden-good + negative controls). An unvalidated scanner is a bluff.
func TestScanProcGroupSites_SelfValidates(t *testing.T) {
	cases := []struct {
		name          string
		src           string
		wantUnguarded int
		wantGuarded   int
	}{
		{
			name:          "golden-bad/unguarded process-group kill is DETECTED",
			src:           "package p\nfunc f() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }\n",
			wantUnguarded: 1,
		},
		{
			name:        "golden-good/guarded call is recognised as guarded",
			src:         "package p\nfunc f() { _ = killProcessGroup(cmd.Process.Pid, syscall.SIGTERM) }\n",
			wantGuarded: 1,
		},
		{
			// §11.4.201(1) false-positive guard: signalling a SINGLE
			// process is not a process-group signal and must not fire.
			name: "negative-control/single-process kill is NOT flagged",
			src:  "package p\nfunc f() { _ = syscall.Kill(pid, syscall.SIGTERM) }\n",
		},
		{
			// §11.4.201(7)(a) carrier guard: prose that MENTIONS the
			// forbidden shape is not the forbidden shape. A grep fails
			// this case; structure matching passes it.
			name: "carrier/comment and string mentioning the shape is NOT flagged",
			src: "package p\n" +
				"// Never write syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) here.\n" +
				"const doc = \"syscall.Kill(-1, syscall.SIGKILL)\"\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			sites, err := scanProcGroupSites(fset, "fixture.go", tc.src)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			var gotUnguarded, gotGuarded int
			for _, s := range sites {
				if s.guarded {
					gotGuarded++
				} else {
					gotUnguarded++
				}
			}
			if gotUnguarded != tc.wantUnguarded || gotGuarded != tc.wantGuarded {
				t.Fatalf("scanner mis-classified: got unguarded=%d guarded=%d, want unguarded=%d guarded=%d",
					gotUnguarded, gotGuarded, tc.wantUnguarded, tc.wantGuarded)
			}
		})
	}
}

// guardOwnFiles are the guard's own implementation and its tests. Their
// killProcessGroup calls are the guard being EXERCISED, not harness
// teardowns, so they are excluded from the teardown-site census.
//
// This exclusion is deliberately narrow and one-directional: it applies ONLY
// to the guarded-site census. UNGUARDED sites are still scanned in every
// file, including these — an exclusion that could hide a raw
// syscall.Kill(-pid, ...) would be a blind spot, not a filter
// (§11.4.201(6)).
var guardOwnFiles = map[string]bool{
	"procgroup_unix.go":      true,
	"procgroup_unix_test.go": true,
}

// isTeardownSite reports whether a guarded site is a real harness teardown
// rather than the guard exercising itself.
func isTeardownSite(s procGroupSite) bool {
	return s.guarded && !guardOwnFiles[s.file]
}

// knownTeardownFiles are the harnesses that spawn a subject with
// Setpgid and tear it down by signalling the whole group. Each contributes
// two sites (SIGTERM, then SIGKILL after the grace window).
var knownTeardownFiles = []string{
	"mtproto_atmosphere_test.go",
	"mtproto_wave65_lifecycle_test.go",
	"mtproto_wave6_loop_test.go",
	"slack_roundtrip_test.go",
}

// minGuardedSites is a deliberate coverage ratchet (§11.4.135): the census at
// the time this guard landed was 8 (4 harnesses x SIGTERM+SIGKILL). Adding a
// harness raises it; retiring one is a deliberate, visible edit here rather
// than a silent loss of coverage.
const minGuardedSites = 8

// TestProcGroupSites_AllRouteThroughGuard is the wiring assertion.
//
// Evidence class (§11.4.226): this is a SOURCE-layer claim — "does every
// call site route through the guard?" — checked with a SOURCE-layer oracle.
// That is class-matched, not an echo. It does NOT claim to observe the guard
// firing; the behavioural tests above do that.
func TestProcGroupSites_AllRouteThroughGuard(t *testing.T) {
	sites := scanPackageProcGroupSites(t)

	var unguarded, guarded []procGroupSite
	for _, s := range sites {
		switch {
		case !s.guarded:
			// Scanned in EVERY file, with no exclusions.
			unguarded = append(unguarded, s)
		case isTeardownSite(s):
			guarded = append(guarded, s)
		}
	}

	for _, s := range unguarded {
		t.Errorf("%s:%d delivers an UNGUARDED process-group signal (syscall.Kill with a negated pid) — "+
			"route it through killProcessGroup (§11.4.263)", s.file, s.line)
	}

	// Vacuity guard: a suite that finds nothing to protect is not green,
	// it is blind (§11.4.201(6)).
	if len(guarded) < minGuardedSites {
		t.Errorf("guarded process-group sites dropped to %d, below the %d ratchet — "+
			"if a harness was deliberately retired, lower minGuardedSites in the same change",
			len(guarded), minGuardedSites)
	}

	byFile := map[string]int{}
	for _, s := range guarded {
		byFile[s.file]++
	}
	for _, f := range knownTeardownFiles {
		if byFile[f] < 2 {
			t.Errorf("%s has %d guarded teardown site(s), expected >= 2 (SIGTERM + SIGKILL)", f, byFile[f])
		}
	}

	for _, s := range guarded {
		t.Logf("guarded site: %s:%d (%s)", s.file, s.line, s.sigName)
	}
}

// TestProcGroupTeardownSites_GuardFires is the per-site behavioural proof.
//
// The site table is DERIVED FROM REAL SOURCE by the AST scan, not hand-copied,
// so a newly added teardown automatically gets a subtest and a reverted one
// disappears from the table (and trips the wiring test above).
//
// Each subtest drives the guard with the exact signal that site delivers and
// asserts that a degenerate pgid is refused with NO syscall reaching the
// kernel. With the `if pid <= 1` block removed from killProcessGroup, every
// subtest fails here having observed kill(-1, <that site's signal>) — the
// §11.4.115 behavioural RED.
func TestProcGroupTeardownSites_GuardFires(t *testing.T) {
	sites := scanPackageProcGroupSites(t)

	var checked int
	for _, s := range sites {
		if !s.guarded {
			continue // reported by TestProcGroupSites_AllRouteThroughGuard
		}
		if !isTeardownSite(s) {
			continue // the guard exercising itself, not a harness teardown
		}
		sig, ok := sigByName[s.sigName]
		if !ok {
			t.Errorf("%s:%d delivers unrecognised signal %q — extend sigByName so this site is covered",
				s.file, s.line, s.sigName)
			continue
		}
		for _, pid := range unsafePGIDs {
			name := fmt.Sprintf("%s:%d/%s/pid=%d", s.file, s.line, s.sigName, pid)
			t.Run(name, func(t *testing.T) {
				calls := recordKills(t, nil)
				err := killProcessGroup(pid, sig)
				if len(*calls) != 0 {
					got := (*calls)[0]
					t.Fatalf("guard did NOT fire for this site — kill(%d, %v) reached the syscall layer; "+
						"this is the BOB-126 host-destroying call", got.pid, got.sig)
				}
				if !errors.Is(err, errUnsafeProcessGroup) {
					t.Fatalf("guard did not refuse pid=%d: err=%v", pid, err)
				}
			})
		}
		checked++
	}

	if checked < minGuardedSites {
		t.Fatalf("only %d site(s) exercised, below the %d ratchet — the per-site suite is under-covering",
			checked, minGuardedSites)
	}
}
