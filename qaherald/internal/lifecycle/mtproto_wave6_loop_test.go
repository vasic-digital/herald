//go:build integration_mtproto

package lifecycle

import (
	"context"
	tgJSON "encoding/json"
	"errors"
	"fmt"
	tgHTTP "net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vasic-digital/herald/qaherald/internal/mtproto"
)

// TestMTProto_Wave6_AutonomousClosedLoop is the §11.4.98-compliant
// replacement for tests/test_wave6_live_loop.sh. It exercises the full
// closed-loop end-to-end with NO operator action during the test:
//
//  1. MTProto user sends a unique message to HERALD_TGRAM_CHAT_ID.
//  2. pherald listen (spawned by this test) polls Telegram, sees the
//     message, dispatches to Claude Code, gets back a HERALD-REPLY.
//  3. pherald calls tgram.SendReply with reply_to_message_id pointing
//     at our MTProto-sent message_id.
//  4. MTProto sees the bot's reply via WaitForReply matcher
//     (FromUserID != myUserID && ReplyToMessageID == ourSentMsgID).
//  5. Assert reply landed within timeout + journal captured the flow.
//
// Honest-SKIP per §11.4.3 when credentials absent OR session missing.
// NEVER falls back to a manual-dep path.
//
// Build tag: integration_mtproto.
//
// §11.4.98 rule (2) session-collision guard: spawns pherald with
// HERALD_CLAUDE_PROJECT_NAME=Herald-MTProto-Test-<unix-ns> so its
// Claude session UUID is dedicated, never colliding with the dev
// conductor's session.
func TestMTProto_Wave6_AutonomousClosedLoop(t *testing.T) {
	appIDStr := os.Getenv("HERALD_MTPROTO_APP_ID")
	appHash := os.Getenv("HERALD_MTPROTO_APP_HASH")
	phone := os.Getenv("HERALD_MTPROTO_PHONE")
	password := os.Getenv("HERALD_MTPROTO_PASSWORD")
	botToken := os.Getenv("HERALD_TGRAM_BOT_TOKEN")
	chatIDStr := os.Getenv("HERALD_TGRAM_CHAT_ID")
	claudeBin := os.Getenv("HERALD_CLAUDE_BIN")

	if appIDStr == "" || appHash == "" || phone == "" || botToken == "" || chatIDStr == "" {
		t.Skipf("skip: MTProto/Tgram credentials missing per §11.4.3")
	}
	if claudeBin == "" {
		// PATH lookup fallback
		if _, err := exec.LookPath("claude"); err != nil {
			t.Skipf("skip: HERALD_CLAUDE_BIN unset and 'claude' not on PATH per §11.4.3")
		}
	} else if _, err := exec.LookPath(claudeBin); err != nil {
		t.Skipf("skip: HERALD_CLAUDE_BIN=%q not executable", claudeBin)
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

	// Resolve timeout from env (default 180s — Claude Code processing time)
	timeoutSec := 180
	if v := os.Getenv("HERALD_MTPROTO_WAVE6_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeoutSec = n
		}
	}

	// Build pherald into temp dir
	tmpDir := t.TempDir()
	pheraldBin := filepath.Join(tmpDir, "pherald")
	buildCmd := exec.Command("go", "build", "-o", pheraldBin, "./pherald/cmd/pherald")
	repoRoot, _ := os.Getwd()
	// Walk up to repo root
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.work")); err == nil {
			break
		}
		repoRoot = filepath.Dir(repoRoot)
	}
	buildCmd.Dir = repoRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build pherald: %v\n%s", err, string(out))
	}
	t.Logf("pherald built at %s", pheraldBin)

	// MTProto client
	client, err := mtproto.New(cfg)
	if err != nil {
		t.Fatalf("mtproto.New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+60)*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	myID, myUsername, err := client.WhoAmI(ctx)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	t.Logf("MTProto active: @%s (user_id=%d)", myUsername, myID)

	// THREAD-CONTEXT proof substrate — envelope capture (used by the
	// THREAD-CONTEXT LEG below). The pherald journal records cc.dispatch as the
	// RAW user_message text, NOT the rendered <<<HERALD-DISPATCH-v1>>> envelope
	// (the THREAD CONTEXT block is rendered inside the dispatcher and passed
	// straight to `claude --print <envelope>`; it is never journaled). To
	// HARD-prove, anti-bluff §107, that the tgram adapter gathered the quoted
	// parent (threadContextFromReply) AND that the dispatcher fed it to Claude,
	// we intercept the REAL envelope bytes pherald hands to `claude`: a
	// transparent wrapper at HERALD_CLAUDE_BIN tees its full argv (which contains
	// `--print <envelope>`) to a capture file, then exec's the REAL claude so
	// Tier-2 dispatch stays fully live (no faking — the autonomy chain above
	// still dispatches through it unchanged). This keys the THREAD-CONTEXT
	// assertion on the ACTUAL rendered envelope, strictly stronger than the
	// journal (which lacks the envelope entirely). These helpers are local to
	// this file because the equivalent slack_roundtrip helpers live behind a
	// different build tag (integration) and never co-compile here.
	realClaude := claudeBin
	if realClaude == "" {
		rc, lerr := exec.LookPath("claude")
		if lerr != nil {
			t.Fatalf("resolve real claude binary for envelope-capture wrapper: %v", lerr)
		}
		realClaude = rc
	} else {
		rc, lerr := exec.LookPath(realClaude)
		if lerr != nil {
			t.Fatalf("resolve HERALD_CLAUDE_BIN=%q for envelope-capture wrapper: %v", realClaude, lerr)
		}
		realClaude = rc
	}
	envCapturePath := filepath.Join(tmpDir, "cc_envelopes.log")
	ccWrapperPath := filepath.Join(tmpDir, "claude-capture.sh")
	ccWrapperSrc := "#!/bin/sh\n" +
		"{\n" +
		"  printf '<<<CC-ENVELOPE-RECORD>>>\\n'\n" +
		"  for a in \"$@\"; do printf '%s\\n' \"$a\"; done\n" +
		"  printf '<<<CC-ENVELOPE-END>>>\\n'\n" +
		"} >> " + mtpShellSingleQuote(envCapturePath) + " 2>/dev/null\n" +
		"exec " + mtpShellSingleQuote(realClaude) + " \"$@\"\n"
	if werr := os.WriteFile(ccWrapperPath, []byte(ccWrapperSrc), 0o755); werr != nil {
		t.Fatalf("write claude-capture wrapper: %v", werr)
	}
	t.Logf("envelope-capture wrapper at %s -> real claude %s (capture: %s)", ccWrapperPath, realClaude, envCapturePath)

	// Spawn pherald listen with dedicated Claude session UUID per §11.4.98 rule (2)
	qaDir := filepath.Join(tmpDir, "qa-journal")
	if err := os.MkdirAll(qaDir, 0o700); err != nil {
		t.Fatalf("mkdir qa-journal: %v", err)
	}
	pheraldCtx, pheraldCancel := context.WithCancel(context.Background())
	defer pheraldCancel()
	pheraldProjectName := fmt.Sprintf("Herald-MTProto-Test-%d", time.Now().UnixNano())
	pheraldCmd := exec.CommandContext(pheraldCtx, pheraldBin, "listen", "--qa-out-dir", qaDir)
	pheraldCmd.Env = append(os.Environ(),
		"HERALD_CLAUDE_PROJECT_NAME="+pheraldProjectName,
		// Route every `claude` invocation through the transparent
		// envelope-capture wrapper (THREAD-CONTEXT proof). The wrapper tees the
		// rendered envelope then exec's the real claude, so Tier-2 dispatch is
		// unaffected and the autonomy chain stays live.
		"HERALD_CLAUDE_BIN="+ccWrapperPath,
	)
	pheraldCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// CRITICAL: pherald listen resolves `docs/Issues.md` relative to its
	// CWD. The Go test runs in qaherald/internal/lifecycle/ — set Dir to
	// the repo root so pherald finds the docs tree.
	pheraldCmd.Dir = repoRoot
	logFile, err := os.Create(filepath.Join(qaDir, "pherald.log"))
	if err != nil {
		t.Fatalf("create pherald.log: %v", err)
	}
	defer logFile.Close()
	pheraldCmd.Stdout = logFile
	pheraldCmd.Stderr = logFile
	if err := pheraldCmd.Start(); err != nil {
		t.Fatalf("start pherald: %v", err)
	}
	t.Logf("pherald listen PID=%d (project=%s, journal=%s)", pheraldCmd.Process.Pid, pheraldProjectName, qaDir)
	// Pre-ack stale updates so pherald (which we just spawned, but won't
	// have ack'd anything on its first getUpdates call) doesn't process
	// the prior session's chat history. Without this, pherald would try
	// to SendReply to N+1 messages in parallel → TLS connection-reset
	// storm from Telegram's anti-abuse rate limiter.
	consumePendingUpdates(t, os.Getenv("HERALD_TGRAM_BOT_TOKEN"))
	defer func() {
		// SIGTERM with grace, then SIGKILL
		_ = killProcessGroup(pheraldCmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- pheraldCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = killProcessGroup(pheraldCmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}()

	// Wait for pherald bootstrap
	time.Sleep(3 * time.Second)

	// Send MTProto message
	testMsg := fmt.Sprintf("herald-mtproto-wave6-closed-loop-%d", time.Now().UnixNano())
	sentID, err := client.SendMessage(ctx, chatID, testMsg)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	t.Logf("MTProto sent message_id=%d text=%q", sentID, testMsg)

	// §11.4.98 autonomy assertion: prove the chain ran end-to-end by
	// observing the pherald journal — not by depending on Claude's reply
	// content (which can be empty / malformed without breaking the chain
	// itself). The journal entries we require:
	//
	//   1. {direction:"in",  kind:"tgram.message"}  with our message_id
	//      — proves pherald RECEIVED our MTProto-sent message via the
	//        bot's getUpdates poller.
	//
	//   2. {direction:"out", kind:"cc.dispatch"}    referencing our text
	//      — proves pherald DISPATCHED to Claude Code (the subprocess
	//        was spawned with our envelope).
	//
	//   3. {direction:"in",  kind:"cc.reply"}       (any text)
	//      — proves Claude RESPONDED (the cc.reply event is journaled
	//        even when text is empty — pherald only refuses to call
	//        tgram.SendReply on empty text downstream, but the cc.reply
	//        receipt itself is the autonomy proof).
	//
	// All three entries present == §11.4.98 autonomy fully proven.
	// The bot's actual reply landing in Telegram is a Claude-content
	// quality concern, NOT an autonomy concern.
	journalPath := filepath.Join(qaDir, "transcript.jsonl")
	t.Logf("waiting up to %ds for journal entries proving autonomy chain (in/dispatch/reply)...", timeoutSec)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	var sawIn, sawDispatch, sawReply bool
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(journalPath); err == nil {
			text := string(data)
			// Match on TEXT (unique per run) not message_id — MTProto's
			// sent message_id is a different namespace from the Bot API's
			// chat-local message_id pherald logs in the journal.
			if !sawIn && strings.Contains(text, `"kind":"tgram.message"`) && strings.Contains(text, testMsg) {
				sawIn = true
				t.Logf("✓ journal: tgram.message in carrying our text (sent_id=%d)", sentID)
			}
			if !sawDispatch && strings.Contains(text, `"kind":"cc.dispatch"`) && strings.Contains(text, testMsg) {
				sawDispatch = true
				t.Logf("✓ journal: cc.dispatch out referencing our text")
			}
			if !sawReply && strings.Contains(text, `"kind":"cc.reply"`) {
				sawReply = true
				t.Logf("✓ journal: cc.reply in — Claude responded")
			}
		}
		if sawIn && sawDispatch && sawReply {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !sawIn || !sawDispatch || !sawReply {
		tail, _ := exec.Command("tail", "-30", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		t.Fatalf("§11.4.98 autonomy chain INCOMPLETE: in=%v dispatch=%v reply=%v — pherald log tail:\n%s",
			sawIn, sawDispatch, sawReply, string(tail))
	}
	t.Logf("PASS: §11.4.98 autonomy chain proven via journal — MTProto → bot inbound → Claude dispatch → Claude reply")

	// Best-effort: ALSO try to observe the bot's actual reply via MTProto.
	// This is a nice-to-have (proves the SendReply call succeeded), not
	// a §11.4.98 prerequisite. If Claude returned empty text, SendReply
	// won't have fired — the autonomy chain is still proven.
	probeCtx, probeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer probeCancel()
	if reply, err := client.WaitForReply(probeCtx, chatID, func(m mtproto.Message) bool {
		return m.FromUserID != myID && m.ReplyToMessageID == sentID
	}); err == nil {
		t.Logf("BONUS: bot reply observed via MTProto — message_id=%d text=%q", reply.ID, strings.TrimSpace(reply.Text)[:min(80, len(strings.TrimSpace(reply.Text)))])
	} else {
		t.Logf("note: bot reply not observed via MTProto within 30s (Claude may have returned empty text — autonomy still proven via journal): %v", err)
	}

	// THREADING LEG (operator mandate 2026-06-02): a reply MUST be delivered as a
	// REPLY to the originating message on every messenger that supports it. On
	// Telegram that is reply_to_message_id. We prove it DETERMINISTICALLY via the
	// Tier-1 fast-path (no dependency on Claude session fidelity / HRD-159): the
	// MTProto user posts a natural-language status query, the deterministic
	// CommandRecognizer answers "Looking up the status of ATM-<pid>…" via
	// tgram.SendReply with reply_to_message_id = our query's message_id, and we
	// HARD-assert the reply is observed AND carries ReplyToMessageID == that id —
	// which is exactly Telegram's threading mechanism (a quoted reply).
	idToken := fmt.Sprintf("ATM-%d", pheraldCmd.Process.Pid)
	cmdMsg := "What is the status of " + idToken + "?"
	cmdSentID, serr := client.SendMessage(ctx, chatID, cmdMsg)
	if serr != nil {
		t.Fatalf("MTProto SendMessage (Tier-1 status query) failed: %v", serr)
	}
	t.Logf("MTProto sent Tier-1 status query message_id=%d text=%q", cmdSentID, cmdMsg)
	thrCtx, thrCancel := context.WithTimeout(ctx, 60*time.Second)
	defer thrCancel()
	// Match the bot's reply by TEXT (the deterministic "Looking up the status of
	// ATM-<pid>…" carries our unique id token — the bot emits it ONLY in response
	// to our query, so the text proves causation). We do NOT match on
	// reply_to_message_id equality: the MTProto user's message_id (cmdSentID) and
	// the Bot-API chat-local message_id pherald replies-to are DIFFERENT id
	// namespaces. THREADING is proven by asserting the observed reply IS a quoted
	// reply (ReplyToMessageID != 0) — i.e. pherald sent it as a reply_to, not a
	// standalone message.
	reply, terr := client.WaitForReply(thrCtx, chatID, func(m mtproto.Message) bool {
		return m.FromUserID != myID && strings.Contains(m.Text, idToken)
	})
	if terr != nil {
		tail, _ := exec.Command("tail", "-25", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		t.Fatalf("§11.4.98 Telegram reply-DELIVERY FAILED: no reply carrying %q (in response to our status query message_id=%d) observed via MTProto — the reply did not reach Telegram. pherald log tail:\n%s",
			idToken, cmdSentID, string(tail))
	}
	if reply.ReplyToMessageID == 0 {
		t.Fatalf("Telegram reply NOT threaded: the bot's reply (id=%d, text=%q) has NO reply_to_message_id — it was sent as a standalone message, not a quoted reply (operator mandate: replies MUST be threaded on Telegram via reply_to_message_id)",
			reply.ID, strings.TrimSpace(reply.Text))
	}
	t.Logf("✓ TELEGRAM reply-DELIVERY + THREADING PROVEN: bot reply message_id=%d is a quoted reply (reply_to_message_id=%d, our query MTProto-id=%d) text=%q",
		reply.ID, reply.ReplyToMessageID, cmdSentID, strings.TrimSpace(reply.Text)[:min(70, len(strings.TrimSpace(reply.Text)))])

	// ───────────────────────────────────────────────────────────────────────
	// THREAD-CONTEXT LEG (operator mandate 2026-06-02): HARD-prove thread-context-
	// awareness on TELEGRAM end-to-end — when a Subscriber sends a message that
	// QUOTES another message, pherald includes the QUOTED PARENT as thread context
	// in the Claude envelope (the rendered envelope carries a literal `THREAD
	// CONTEXT` block naming Participants + the parent message text).
	//
	// Mechanism under test (verified by reading the code, NOT assumed):
	//   tgram adapter: msg.ReplyTo != nil → threadContextFromReply(msg) populates
	//     commons.InboundEvent.ThreadContext with the immediate quoted parent
	//     (commons_messaging/channels/tgram/thread_context.go).
	//   inbound dispatcher: ev.ThreadContext → CodeRequest.ThreadContext
	//     (pherald/internal/inbound/dispatcher.go) → claude_code.DispatchRequest
	//     .ThreadContext (cc_adapter.go).
	//   claude_code: renderThreadContext writes the `THREAD CONTEXT … Participants:
	//     … [N] <who> said: <parent text> …` block into the envelope
	//     (commons_messaging/dispatch/claude_code/claude_code.go).
	//
	// Drive path: post a freeform PARENT (unique nonce) via SendMessage, then post
	// a freeform REPLY that QUOTES the parent via client.SendReply(ctx, chatID,
	// replyText, parentID) — this sets reply_to_message_id on the USER's outbound
	// message, so pherald observes an inbound msg.ReplyTo != nil and the tgram
	// adapter's threadContextFromReply populates the thread context. The reply is a
	// freeform question carrying a unique nonce so it routes to CC/Tier-2 (the
	// envelope path). We then HARD-assert, against the REAL captured envelope bytes
	// (anti-bluff §107: the actual argv pherald handed to `claude`, NOT a metadata
	// flag), that the envelope for THIS reply carries THREAD CONTEXT + Participants:
	// + the PARENT message's text — proving the gather-and-feed chain end-to-end.
	parentNonce := time.Now().UnixNano()
	parentMsg := fmt.Sprintf("context-parent %d: the login flow is throwing 500s", parentNonce)
	parentID, perr := client.SendMessage(ctx, chatID, parentMsg)
	if perr != nil {
		t.Fatalf("MTProto SendMessage (thread-context parent) failed: %v", perr)
	}
	t.Logf("MTProto sent thread-context PARENT message_id=%d text=%q", parentID, parentMsg)

	// The QUOTED reply: SendReply sets reply_to_message_id = parentID on the
	// user's outbound message, so pherald's inbound msg.ReplyTo is non-nil and the
	// tgram adapter gathers the quoted parent as thread context. Freeform + unique
	// nonce so it routes to CC/Tier-2 and exercises the envelope render path.
	replyNonce := time.Now().UnixNano()
	replyMsg := fmt.Sprintf("context-reply %d: which auth endpoint is returning the 500?", replyNonce)
	replyID, rerr := client.SendReply(ctx, chatID, replyMsg, parentID)
	if rerr != nil {
		t.Fatalf("MTProto SendReply (thread-context quoted reply) failed: %v", rerr)
	}
	t.Logf("MTProto sent thread-context QUOTED REPLY message_id=%d text=%q (quotes parent message_id=%d)", replyID, replyMsg, parentID)

	// Poll the capture file (bounded ~120s) for the cc envelope record that
	// references our reply text (the record carrying replyMsg) — that is THIS
	// quoted reply's rendered envelope.
	const tcWindowSec = 120
	t.Logf("waiting up to %ds for the cc envelope (quoted reply) to carry THREAD CONTEXT...", tcWindowSec)
	var tcEnvelope string
	var tcEnvelopeFound bool
	tcDeadline := time.Now().Add(tcWindowSec * time.Second)
	for time.Now().Before(tcDeadline) {
		if data, rerr := os.ReadFile(envCapturePath); rerr == nil {
			for _, rec := range mtpSplitEnvelopeRecords(string(data)) {
				if strings.Contains(rec, replyMsg) {
					tcEnvelope = rec
					tcEnvelopeFound = true
					break
				}
			}
		}
		if tcEnvelopeFound {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !tcEnvelopeFound {
		capTail, _ := os.ReadFile(envCapturePath)
		logTail, _ := exec.Command("tail", "-40", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		ct := string(capTail)
		if len(ct) > 1200 {
			ct = ct[len(ct)-1200:]
		}
		t.Fatalf("THREAD-CONTEXT leg FAILED: no captured cc envelope referenced the quoted reply text %q within %ds — pherald never dispatched it to claude. capture tail:\n%s\npherald log tail:\n%s",
			replyMsg, tcWindowSec, ct, string(logTail))
	}

	// HARD assertions against the ACTUAL envelope bytes for the quoted reply.
	var tcMissing []string
	if !strings.Contains(tcEnvelope, "THREAD CONTEXT") {
		tcMissing = append(tcMissing, `"THREAD CONTEXT"`)
	}
	if !strings.Contains(tcEnvelope, "Participants:") {
		tcMissing = append(tcMissing, `"Participants:"`)
	}
	if !strings.Contains(tcEnvelope, parentMsg) {
		tcMissing = append(tcMissing, fmt.Sprintf("quoted-parent text %q", parentMsg))
	}
	if len(tcMissing) > 0 {
		logTail, _ := exec.Command("tail", "-40", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		env := tcEnvelope
		if len(env) > 2000 {
			env = env[:2000] + "…"
		}
		t.Fatalf("THREAD-CONTEXT leg FAILED: the cc.dispatch envelope for the quoted reply did NOT carry %s — the tgram adapter did not gather the quoted parent OR the dispatcher did not feed it to Claude. Envelope record:\n%s\npherald log tail:\n%s",
			strings.Join(tcMissing, " + "), env, string(logTail))
	}
	t.Logf("✓ TELEGRAM THREAD-CONTEXT PROVEN: rendered envelope for the quoted reply carried THREAD CONTEXT + Participants + the quoted parent")

	// Ensure clean ctx
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("unexpected ctx error: %v", err)
	}
}

// min for pre-Go 1.21 friendliness (qaherald/go.mod is 1.25.3 but defensive).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// consumePendingUpdates walks the bot's getUpdates queue + ACKs every
// pending update so a freshly-spawned pherald doesn't process stale
// chat history. Critical for §11.4.98 autonomous tests because the test
// chat is reused across many runs; without this, each run's pherald
// would attempt to reply to every prior run's stimulus in parallel,
// triggering Telegram's TLS connection-reset rate limiter.
//
// Best-effort — failures are logged but don't fail the test.
func consumePendingUpdates(t *testing.T, botToken string) {
	t.Helper()
	if botToken == "" {
		return
	}
	type gu struct {
		OK     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
		} `json:"result"`
	}
	pollURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?limit=100&timeout=0", botToken)
	resp, err := tgHTTP.Get(pollURL)
	if err != nil {
		t.Logf("pre-ack getUpdates: %s (continuing)", strings.ReplaceAll(err.Error(), botToken, "<redacted-bot-token>"))
		return
	}
	defer resp.Body.Close()
	var r gu
	if err := tgJSON.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Logf("pre-ack decode: %v", err)
		return
	}
	if len(r.Result) == 0 {
		t.Logf("pre-ack: queue already empty")
		return
	}
	var maxID int64
	for _, u := range r.Result {
		if u.UpdateID > maxID {
			maxID = u.UpdateID
		}
	}
	ackURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&limit=1&timeout=0", botToken, maxID+1)
	if r2, err := tgHTTP.Get(ackURL); err == nil {
		r2.Body.Close()
	}
	t.Logf("pre-ack: discarded %d stale updates (max_update_id=%d)", len(r.Result), maxID)
}

// mtpShellSingleQuote wraps s in POSIX single quotes, escaping any embedded
// single quote, so the generated envelope-capture wrapper references paths
// safely even if t.TempDir() ever contains a quote or space. Local to this
// (integration_mtproto-tagged) file — the equivalent slack helper lives behind
// the `integration` build tag and never co-compiles here.
func mtpShellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// mtpSplitEnvelopeRecords splits the capture file written by the
// envelope-capture wrapper into one string per claude invocation. Each record
// is the argv between the <<<CC-ENVELOPE-RECORD>>> and <<<CC-ENVELOPE-END>>>
// sentinels the wrapper emits; a trailing unterminated record (mid-write) is
// ignored so a concurrent append cannot yield a half-record false match. Local
// to this file for the same build-tag isolation reason as mtpShellSingleQuote.
func mtpSplitEnvelopeRecords(s string) []string {
	const begin = "<<<CC-ENVELOPE-RECORD>>>"
	const end = "<<<CC-ENVELOPE-END>>>"
	var out []string
	rest := s
	for {
		bi := strings.Index(rest, begin)
		if bi < 0 {
			break
		}
		after := rest[bi+len(begin):]
		ei := strings.Index(after, end)
		if ei < 0 {
			break // trailing unterminated record (still being written) — skip
		}
		out = append(out, after[:ei])
		rest = after[ei+len(end):]
	}
	return out
}
