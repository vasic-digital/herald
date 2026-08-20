//go:build !windows

package lifecycle

import (
	"errors"
	"fmt"
	"syscall"
)

// Process-group signal safety for this package's harness teardowns
// (§11.4.263).
//
// Every live harness in this package spawns its subject (`pherald listen`,
// `pherald watch`) with SysProcAttr{Setpgid: true} and tears it down by
// signalling the WHOLE process group — SIGTERM, a grace window, then
// SIGKILL. That teardown is what this file guards.
//
// The helper lives in a non-test file on purpose: it is a package-level
// safety primitive, and any future non-test code in this package that
// needs to signal a process group MUST route through it rather than
// re-deriving the negation.

// killFn is the process-group signal primitive, indirected so tests can
// observe the exact (pid, signal) pair a teardown would deliver without
// signalling a real process group. §11.4.263(C) requires the killpg call
// itself to be patchable so a test can assert it was called with pgid > 1.
var killFn = syscall.Kill

// errUnsafeProcessGroup is returned instead of delivering a signal whose
// target is not a real process group (§11.4.263).
var errUnsafeProcessGroup = errors.New("refusing process-group signal: pgid is not a real process group")

// killProcessGroup delivers sig to the process group led by pid, refusing
// any pid that is not a real process-group leader (§11.4.263(A)/(B)).
//
// The negation that turns a pid into a process-group target makes the
// degenerate values indistinguishable from a legitimate call once applied:
//
//	pid  1 -> kill(-1, sig) == signal EVERY process this UID may signal
//	pid  0 -> kill( 0, sig) == signal the CALLER'S OWN process group
//	                           (-0 == 0 in two's complement — self-kill)
//	pid -1 -> kill( 1, sig) == signal init directly
//
// so the validation happens on the RAW pid, BEFORE the negation. A caller
// that reaches this with pid <= 1 has a defect upstream; the refusal is
// returned rather than swallowed (§11.4.1 — no silent failure, §11.4.252 —
// fail closed) and names the offending value (§11.4.6).
//
// Honest scope note (§11.4.6): in Go, cmd.Process.Pid after a successful
// cmd.Start() is a real forked pid, and every caller in this package
// registers its teardown only after Start returned nil. This guard is
// therefore DEFENSE IN DEPTH — it closes the pgid <= 1 class by
// construction; it is not the remediation of a demonstrated live incident
// in this package.
// The error constructor is a separate function on purpose. The canonical
// §1.1 mutation for this guard is "delete the three-line `if pid <= 1`
// block below" — and that mutation MUST leave code that still COMPILES, so
// the resulting test failures are BEHAVIOURAL (§11.4.115) rather than a
// build break. Keeping fmt's only use out here is what guarantees that:
// delete the block and fmt is still imported-and-used, the function merely
// stops refusing.
func unsafeProcessGroupError(pid int, sig syscall.Signal) error {
	return fmt.Errorf("%w (pid=%d, signal=%v)", errUnsafeProcessGroup, pid, sig)
}

func killProcessGroup(pid int, sig syscall.Signal) error {
	if pid <= 1 { // ─┐ §1.1 mutation / §11.4.115 RED:
		return unsafeProcessGroupError(pid, sig) //  │ delete these
	} // ─┘ three lines
	return killFn(-pid, sig)
}
