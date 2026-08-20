//go:build integration_mtproto

package lifecycle

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	workable "github.com/vasic-digital/herald/commons_workable"
	"github.com/vasic-digital/herald/qaherald/internal/mtproto"
)

// TestMTProto_ATMOSphere_SSoTChangeNotifiesGroup is HRD-156 test T-A: the
// §11.4.98-compliant, anti-bluff end-to-end proof of the ATMOSphere↔Herald
// OUTBOUND flow against REAL Telegram, observed via a REAL MTProto user
// account. NO mocks at any layer:
//
//	1. A unique workable-item is created in a REAL workable-items SQLite SSoT.
//	2. The REAL `pherald watch` binary (spawned as a subprocess, cmd.Dir =
//	   repoRoot) detects the DB mutation, diffs it, and renders the
//	   "🆕 <atm_id> created" message via the production workflow.Notifier.
//	3. pherald fans the rendered message out through the REAL tgram channel
//	   (HERALD_CHANNELS=tgram + HERALD_TGRAM_BOT_TOKEN + HERALD_TGRAM_CHAT_ID)
//	   so a REAL Telegram message reaches the configured chat.
//	4. The MTProto user account OBSERVES that bot message arriving in the
//	   chat (WaitForReply matcher keyed on the unique atm_id nonce).
//
// The asserted positive evidence is the bot's "🆕 <nonce> created" message
// actually landing in the group as SEEN by the MTProto user — not a journal
// entry, not an "absence of error", not a metadata check. If the message is
// not observed, a real user-visible feature is broken and the test FAILs loudly.
//
// Honest-SKIP per §11.4.3 when credentials absent OR the MTProto session file
// is missing. NEVER falls back to a manual-dep path.
//
// Build tag: integration_mtproto — exercised by the e2e gate, not default go test.
func TestMTProto_ATMOSphere_SSoTChangeNotifiesGroup(t *testing.T) {
	appIDStr := os.Getenv("HERALD_MTPROTO_APP_ID")
	appHash := os.Getenv("HERALD_MTPROTO_APP_HASH")
	phone := os.Getenv("HERALD_MTPROTO_PHONE")
	password := os.Getenv("HERALD_MTPROTO_PASSWORD")
	botToken := os.Getenv("HERALD_TGRAM_BOT_TOKEN")
	chatIDStr := os.Getenv("HERALD_TGRAM_CHAT_ID")

	if appIDStr == "" || appHash == "" || phone == "" || botToken == "" || chatIDStr == "" {
		t.Skipf("skip: MTProto+Tgram credentials missing per §11.4.3 (HERALD_MTPROTO_APP_ID/APP_HASH/PHONE + HERALD_TGRAM_BOT_TOKEN + HERALD_TGRAM_CHAT_ID required)")
	}

	appID, err := strconv.Atoi(appIDStr)
	if err != nil {
		t.Skipf("skip: HERALD_MTPROTO_APP_ID not an integer")
	}
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		t.Skipf("skip: HERALD_TGRAM_CHAT_ID not an integer")
	}

	cfg := mtproto.Config{AppID: appID, AppHash: appHash, Phone: phone, Password: password}
	exists, err := cfg.SessionExists()
	if err != nil {
		t.Fatalf("SessionExists: %v", err)
	}
	if !exists {
		t.Skipf("skip: MTProto session file missing — run `qaherald mtproto login` first")
	}

	// Resolve observation timeout from env (default 45s — watcher poll +
	// diff + Telegram fan-out + MTProto propagation).
	timeoutSec := 45
	if v := os.Getenv("HERALD_MTPROTO_ATMOSPHERE_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeoutSec = n
		}
	}

	// Walk up to the repo root (the directory holding go.work). pherald
	// watch resolves docs/* paths relative to its CWD, and `go build` for
	// ./pherald/cmd/pherald must run from the workspace root.
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.work")); err == nil {
			break
		}
		repoRoot = filepath.Dir(repoRoot)
	}

	// Build pherald into a temp dir.
	tmpDir := t.TempDir()
	pheraldBin := filepath.Join(tmpDir, "pherald")
	buildCmd := exec.Command("go", "build", "-o", pheraldBin, "./pherald/cmd/pherald")
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build pherald: %v\n%s", err, string(out))
	}
	t.Logf("pherald built at %s", pheraldBin)

	// Create a temp workable-items SSoT (real SQLite, real schema). Seed one
	// baseline item so the DB + schema exist and the watcher's initial
	// snapshot is non-trivial; the ASSERTED item is added AFTER watch starts.
	dbPath := filepath.Join(tmpDir, "workable_items.db")
	store, err := workable.Open(dbPath)
	if err != nil {
		t.Fatalf("workable.Open: %v", err)
	}
	repo := workable.NewRepo(store)

	seedCtx, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := repo.Create(seedCtx, workable.Item{
		AtmID:           "ATM-QALIVE-BASELINE",
		Type:            "Task",
		Status:          "Queued",
		Title:           "QA-LIVE baseline (pre-watch seed)",
		CurrentLocation: "Issues",
	}); err != nil {
		seedCancel()
		_ = store.Close()
		t.Fatalf("seed baseline item: %v", err)
	}
	seedCancel()

	// Generate a UNIQUE atm_id nonce. It appears verbatim in the rendered
	// "🆕 <atm_id> created" message (workflow.RenderChange / KindCreated), so
	// the MTProto matcher keys on it to prove THIS run's message arrived.
	nonceID := fmt.Sprintf("ATM-QALIVE-%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:8])
	t.Logf("unique atm_id nonce for this run: %s", nonceID)

	// Spawn `pherald watch` against the temp DB. Channel + recipient config
	// come from the inherited env (HERALD_TGRAM_BOT_TOKEN + HERALD_TGRAM_CHAT_ID);
	// we only force HERALD_CHANNELS=tgram so the fan-out targets Telegram.
	watchCtx, watchCancel := context.WithCancel(context.Background())
	watchCmd := exec.CommandContext(watchCtx, pheraldBin,
		"watch", "--db", dbPath, "--poll", "1s")
	watchCmd.Env = append(os.Environ(), "HERALD_CHANNELS=tgram")
	watchCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	watchCmd.Dir = repoRoot

	logPath := filepath.Join(tmpDir, "pherald-watch.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		watchCancel()
		_ = store.Close()
		t.Fatalf("create watch log: %v", err)
	}
	watchCmd.Stdout = logFile
	watchCmd.Stderr = logFile

	if err := watchCmd.Start(); err != nil {
		watchCancel()
		_ = logFile.Close()
		_ = store.Close()
		t.Fatalf("start pherald watch: %v", err)
	}
	t.Logf("pherald watch PID=%d (db=%s, channels=tgram, log=%s)", watchCmd.Process.Pid, dbPath, logPath)

	// Cleanup (t.Cleanup → LIFO): kill the watch process group, close the
	// store + log file. The t.TempDir handles file removal.
	t.Cleanup(func() {
		_ = killProcessGroup(watchCmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- watchCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = killProcessGroup(watchCmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		watchCancel()
		_ = logFile.Close()
		_ = store.Close()
	})

	// Bounded startup wait: poll the log for the watcher's readiness line
	// ("pherald watch: watching ..."), else fall back to a fixed budget that
	// comfortably exceeds the boot + first poll interval.
	if !waitForWatchReady(logPath, 10*time.Second) {
		// Not fatal on its own — the safety-net reconcile + WAL-poll still
		// observe a later mutation — but log it for diagnosis.
		t.Logf("note: watcher readiness line not seen within 10s; proceeding (poll fallback covers the mutation)")
	} else {
		t.Logf("✓ pherald watch is ready (readiness line observed)")
	}
	// Small extra grace so the watcher's baseline snapshot + first poll tick
	// definitely precede the asserted mutation.
	time.Sleep(2 * time.Second)

	// Build + connect the MTProto observer (mirror HRD-140/141).
	client, err := mtproto.New(cfg)
	if err != nil {
		t.Fatalf("mtproto.New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+60)*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	myID, myUsername, err := client.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	t.Logf("MTProto user active: @%s (user_id=%d)", myUsername, myID)

	// Mutate the SSoT AFTER watch is up + the observer is connected. This
	// item.created is what `pherald watch` must detect → render → notify.
	mutCtx, mutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := repo.Create(mutCtx, workable.Item{
		AtmID:           nonceID,
		Type:            "Task",
		Status:          "Queued",
		Title:           "QA-LIVE ATMOSphere↔Herald outbound notify proof",
		CurrentLocation: "Issues",
	}); err != nil {
		mutCancel()
		t.Fatalf("create asserted item %s: %v", nonceID, err)
	}
	mutCancel()
	t.Logf("SSoT mutated: created %s in Issues — awaiting bot notification in chat %d", nonceID, chatID)

	// Observe the REAL bot message landing in the chat. The matcher requires
	// a bot-authored message whose text carries our unique nonce atm_id (the
	// "🆕 <nonce> created" render). FromUserID != myID guards against matching
	// our own MTProto traffic.
	observeCtx, observeCancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer observeCancel()

	reply, err := client.WaitForReply(observeCtx, chatID, func(m mtproto.Message) bool {
		return m.FromUserID != myID && strings.Contains(m.Text, nonceID)
	})
	if err != nil {
		tail, _ := exec.Command("tail", "-40", logPath).CombinedOutput()
		t.Fatalf("ATMOSphere↔Herald outbound FAILED: bot's \"🆕 %s created\" notification NOT observed in chat %d within %ds (%v) — a real user-visible feature is broken.\npherald watch log tail:\n%s",
			nonceID, chatID, timeoutSec, err, string(tail))
	}

	// Positive runtime evidence (§107): the exact bot message text the
	// MTProto user actually saw.
	t.Logf("PASS: ATMOSphere↔Herald outbound proven END-TO-END — bot message_id=%d from user_id=%d text=%q",
		reply.ID, reply.FromUserID, strings.TrimSpace(reply.Text))
}

// waitForWatchReady polls logPath for the `pherald watch: watching` readiness
// line emitted by newWatchCmd's RunE just before runWatch begins. Returns true
// as soon as the line appears, false if it never appears within timeout.
func waitForWatchReady(logPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(logPath); err == nil {
			if strings.Contains(string(data), "pherald watch: watching") {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}
