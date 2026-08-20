//go:build integration

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vasic-digital/herald/qaherald/internal/messenger"
)

// TestSlack_LiveRoundTrip is the §11.4.98-compliant, fully-automated Slack
// inbound round-trip harness — the Slack analog of
// mtproto_wave6_loop_test.go's TestMTProto_Wave6_AutonomousClosedLoop. It
// closes HRD-115 (Slack send-side is already live-proven by
// TestSlack_Live_Send / E127; only the inbound ROUND-TRIP remains).
//
// The closed loop, with ZERO human action during execution:
//
//  1. A QA *user* identity (HERALD_SLACK_QA_USER_TOKEN, an xoxp-… user OAuth
//     token) posts a deterministic, nonce-bearing probe message into the
//     channel via chat.postMessage — posting AS THE USER, not as the bot.
//     This is the §32.9 echo-wall solution: a Slack bot never receives its
//     OWN messages over Socket Mode, so the bot side could never observe a
//     bot-authored probe. A SEPARATE user identity is mandatory.
//
//  2. The pherald Slack bot (spawned by this test as a `pherald listen
//     --channels slack` subprocess, wired to HERALD_SLACK_BOT_TOKEN +
//     HERALD_SLACK_APP_TOKEN) receives the user message over Socket Mode,
//     dispatches it to Claude Code, parses <<<HERALD-REPLY>>>, and replies.
//
//  3. This test asserts the full round-trip via two legs:
//     LEG 1 — autonomy chain (Tier-2, Claude Code), proven via the pherald
//     --qa-out-dir JSONL journal: the inbound message line (kind is
//     channel-agnostic in journal.go; the payload carries "channel":"slack")
//     carrying our probe text proves pherald RECEIVED our user-posted
//     message; `cc.dispatch` proves it DISPATCHED; `cc.reply` proves Claude
//     RESPONDED. The CC reply-DELIVERY to Slack is only a soft note here — a
//     fresh, context-less bootstrap session returns empty reply text, so
//     nothing is posted back (HRD-159, a pre-existing CROSS-CHANNEL gap; the
//     Telegram round-trip masks the same gap with a soft BONUS).
//     LEG 2 — reply-DELIVERY (HARD-asserted), proven DETERMINISTICALLY via the
//     Tier-1 fast-path: the QA user posts a natural-language status query
//     ("what is the status of ATM-<pid>?") which the deterministic
//     CommandRecognizer answers WITHOUT a Claude round-trip
//     ("Looking up the status of ATM-<pid>…") via slack.SendReply; the QA user
//     reads that reply back from Slack (ts>probe, unique id echoed), proving
//     the reply-back-to-Slack leg really lands — independent of CC session
//     fidelity.
//
//  4. Teardown SIGTERMs the listen subprocess and asserts a clean exit.
//
//  5. A redacted transcript (tokens + wss:// scrubbed) is written under
//     docs/qa/HRD-115-LIVE-roundtrip-<TS>/ as the §107.x evidence artefact.
//
// Honest-SKIP per §11.4.3 when ANY required credential is absent — NEVER a
// fake pass, NEVER a manual-action fallback. The new credential this harness
// introduces is HERALD_SLACK_QA_USER_TOKEN (the user side); the bot side
// reuses the already-present HERALD_SLACK_BOT_TOKEN / _APP_TOKEN /
// _CHANNEL_ID.
//
// Build tag: integration (matches slack_live_integration_test.go).
//
// §11.4.98 rule (2) session-collision guard: spawns pherald with
// HERALD_CLAUDE_PROJECT_NAME=Herald-Slack-Test-<unix-ns> so its Claude
// session UUID is dedicated, never colliding with the dev conductor's session.
func TestSlack_LiveRoundTrip(t *testing.T) {
	botToken := os.Getenv("HERALD_SLACK_BOT_TOKEN")
	appToken := os.Getenv("HERALD_SLACK_APP_TOKEN")
	channelID := os.Getenv("HERALD_SLACK_CHANNEL_ID")
	qaUserToken := os.Getenv("HERALD_SLACK_QA_USER_TOKEN")
	claudeBin := os.Getenv("HERALD_CLAUDE_BIN")

	if botToken == "" || appToken == "" || channelID == "" || qaUserToken == "" {
		t.Skipf("skip: Slack round-trip credentials missing per §11.4.3 " +
			"(HERALD_SLACK_BOT_TOKEN + HERALD_SLACK_APP_TOKEN + HERALD_SLACK_CHANNEL_ID + HERALD_SLACK_QA_USER_TOKEN required; " +
			"the QA user token is the xoxp-… user OAuth token (chat:write + channels:history) that drives the user side)")
	}
	if claudeBin == "" {
		if _, err := exec.LookPath("claude"); err != nil {
			t.Skipf("skip: HERALD_CLAUDE_BIN unset and 'claude' not on PATH per §11.4.3")
		}
	} else if _, err := exec.LookPath(claudeBin); err != nil {
		t.Skipf("skip: HERALD_CLAUDE_BIN=%q not executable", claudeBin)
	}

	// Resolve timeout from env (default 180s — Claude Code processing time).
	timeoutSec := 180
	if v := os.Getenv("HERALD_SLACK_ROUNDTRIP_TIMEOUT_SEC"); v != "" {
		if n, perr := slackAtoiPositive(v); perr == nil {
			timeoutSec = n
		}
	}

	// Locate the repo root (the test runs in qaherald/internal/lifecycle/).
	repoRoot, err := slackFindRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	// Build pherald into a temp dir.
	tmpDir := t.TempDir()
	pheraldBin := filepath.Join(tmpDir, "pherald")
	buildCmd := exec.Command("go", "build", "-o", pheraldBin, "./pherald/cmd/pherald")
	buildCmd.Dir = repoRoot
	if out, berr := buildCmd.CombinedOutput(); berr != nil {
		t.Fatalf("build pherald: %v\n%s", berr, string(out))
	}
	t.Logf("pherald built at %s", pheraldBin)

	// LEG 4 substrate — envelope capture (THREAD-CONTEXT proof).
	//
	// The pherald journal records cc.dispatch as the RAW user_message text, NOT
	// the rendered <<<HERALD-DISPATCH-v1>>> envelope (the THREAD CONTEXT block is
	// rendered inside claude_code.Dispatcher.buildCmd → FormatEnvelopeWithPreText
	// and passed straight to `claude --print <envelope>`; it is never journaled —
	// see e2e_bluff_hunt E66's documented SKIP). To HARD-prove, anti-bluff, that
	// the slack adapter gathered the thread (fetchThreadContext) AND that the
	// dispatcher fed it to Claude, we intercept the REAL envelope bytes pherald
	// hands to `claude`: a transparent wrapper at HERALD_CLAUDE_BIN tees its full
	// argv (which contains `--print <envelope>`) to a capture file, then exec's
	// the REAL claude so Tier-2 dispatch stays fully live (no faking — LEG 1's
	// autonomy chain still dispatches through it unchanged). This keys the LEG-4
	// assertion on the ACTUAL rendered envelope, strictly stronger than the
	// journal (which lacks the envelope entirely).
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
	// The wrapper records each invocation's argv (one envelope per record,
	// delimited by a sentinel) then transparently delegates to the real claude.
	// `printf %s\n "$@"` writes each arg on its own line; the envelope is a
	// single `--print` arg, so the multi-line THREAD CONTEXT block lands intact.
	ccWrapperSrc := "#!/bin/sh\n" +
		"{\n" +
		"  printf '<<<CC-ENVELOPE-RECORD>>>\\n'\n" +
		"  for a in \"$@\"; do printf '%s\\n' \"$a\"; done\n" +
		"  printf '<<<CC-ENVELOPE-END>>>\\n'\n" +
		"} >> " + shellSingleQuote(envCapturePath) + " 2>/dev/null\n" +
		"exec " + shellSingleQuote(realClaude) + " \"$@\"\n"
	if werr := os.WriteFile(ccWrapperPath, []byte(ccWrapperSrc), 0o755); werr != nil {
		t.Fatalf("write claude-capture wrapper: %v", werr)
	}
	t.Logf("envelope-capture wrapper at %s -> real claude %s (capture: %s)", ccWrapperPath, realClaude, envCapturePath)

	// QA user-side Slack client (drives the USER side: chat.postMessage posts
	// AS the user via the xoxp- token; conversations.history reads the bot's
	// reply). The empty baseURL defaults to https://slack.com/api — real bytes.
	qaUser := messenger.NewSlackClient(qaUserToken, channelID, "")
	defer qaUser.Close()

	// Confirm the QA user identity up-front (fail loud if the token is a bot
	// token by mistake — a bot xoxb- token would still auth.test OK but the
	// echo-wall solution requires a USER identity distinct from the bot).
	identCtx, identCancel := context.WithTimeout(context.Background(), 30*time.Second)
	qaUsername, _, ierr := qaUser.Me(identCtx)
	identCancel()
	if ierr != nil {
		t.Fatalf("QA user auth.test failed (is HERALD_SLACK_QA_USER_TOKEN a valid xoxp- user token?): %v", ierr)
	}
	t.Logf("QA user identity: %s", qaUsername)

	// Spawn pherald listen --channels slack with a dedicated Claude session
	// UUID per §11.4.98 rule (2). Journal to <tmp>/qa-journal/transcript.jsonl.
	qaDir := filepath.Join(tmpDir, "qa-journal")
	if err := os.MkdirAll(qaDir, 0o700); err != nil {
		t.Fatalf("mkdir qa-journal: %v", err)
	}
	pheraldCtx, pheraldCancel := context.WithCancel(context.Background())
	defer pheraldCancel()
	pheraldProjectName := fmt.Sprintf("Herald-Slack-Test-%d", time.Now().UnixNano())
	pheraldCmd := exec.CommandContext(pheraldCtx, pheraldBin, "listen", "--channels", "slack", "--qa-out-dir", qaDir)
	pheraldCmd.Env = append(os.Environ(),
		"HERALD_CLAUDE_PROJECT_NAME="+pheraldProjectName,
		// Pin the channel set on the spawned process so it does not pick up a
		// stray HERALD_CHANNELS from the inherited env.
		"HERALD_CHANNELS=slack",
		// Route every `claude` invocation through the transparent
		// envelope-capture wrapper (LEG 4 THREAD-CONTEXT proof). The wrapper
		// tees the rendered envelope then exec's the real claude, so Tier-2
		// dispatch (LEG 1) is unaffected.
		"HERALD_CLAUDE_BIN="+ccWrapperPath,
	)
	pheraldCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// pherald listen resolves docs/Issues.md relative to its CWD; run it from
	// the repo root so it finds the docs tree (same as the MTProto harness).
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
	t.Logf("pherald listen --channels slack PID=%d (project=%s, journal=%s)", pheraldCmd.Process.Pid, pheraldProjectName, qaDir)

	// Teardown: SIGTERM with grace, then SIGKILL; assert clean exit.
	var pheraldExitErr error
	teardownDone := false
	teardown := func() {
		if teardownDone {
			return
		}
		teardownDone = true
		_ = killProcessGroup(pheraldCmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- pheraldCmd.Wait() }()
		select {
		case pheraldExitErr = <-done:
		case <-time.After(8 * time.Second):
			_ = killProcessGroup(pheraldCmd.Process.Pid, syscall.SIGKILL)
			pheraldExitErr = <-done
		}
	}
	defer teardown()

	// Wait for the Socket Mode connection to come up. The slack adapter logs
	// to pherald.log; poll for the listen startup line AND give the WebSocket
	// a moment to finish apps.connections.open. We gate on the startup line
	// (deterministic) then add a short settle so the first inbound is not
	// dropped before the socket is live.
	if err := slackWaitForListenReady(t, filepath.Join(qaDir, "pherald.log"), 30*time.Second); err != nil {
		tail, _ := exec.Command("tail", "-40", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		t.Fatalf("pherald listen did not signal Slack readiness within 30s: %v\nlog tail:\n%s", err, string(tail))
	}
	// Socket Mode settle: the startup line prints before RunContext finishes
	// the WebSocket handshake. A short fixed settle avoids a lost-first-message
	// race without depending on a log line the SDK does not emit deterministically.
	time.Sleep(4 * time.Second)

	// Post the deterministic, nonce-bearing probe AS THE QA USER.
	// Nonce derived from the probe content + project name (NOT random/time-only)
	// so it is unique-per-run yet reconstructable for the transcript.
	nonce := fmt.Sprintf("%s-%d", pheraldProjectName, pheraldCmd.Process.Pid)
	// A real instruction that elicits a deterministic NON-EMPTY reply containing
	// the nonce — so (a) Claude produces reply text (an empty reply is a no-op,
	// proving nothing about the reply-back-to-Slack leg) and (b) the reply we
	// observe in Slack is unambiguously THIS round-trip's reply, not a stale
	// message from an earlier run.
	probe := "Please reply with a brief acknowledgement that includes this exact token verbatim: " + nonce
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 30*time.Second)
	probeTS, serr := qaUser.Send(sendCtx, probe)
	sendCancel()
	if serr != nil {
		t.Fatalf("QA user Send (chat.postMessage) failed: %v", serr)
	}
	t.Logf("QA user posted probe ts=%s text=%q", probeTS, probe)

	// §11.4.98 autonomy assertion via the pherald journal (evidence channel a).
	journalPath := filepath.Join(qaDir, "transcript.jsonl")
	t.Logf("waiting up to %ds for journal entries proving autonomy chain (in/dispatch/reply)...", timeoutSec)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	var sawIn, sawDispatch, sawReply bool
	for time.Now().Before(deadline) {
		if data, rerr := os.ReadFile(journalPath); rerr == nil {
			text := string(data)
			if !sawIn && strings.Contains(text, `"kind":"tgram.message"`) && strings.Contains(text, probe) {
				sawIn = true
				t.Logf("✓ journal: inbound message carrying our probe text (channel:slack)")
			}
			if !sawDispatch && strings.Contains(text, `"kind":"cc.dispatch"`) && strings.Contains(text, probe) {
				sawDispatch = true
				t.Logf("✓ journal: cc.dispatch out referencing our probe text")
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
		tail, _ := exec.Command("tail", "-40", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		t.Fatalf("§11.4.98 autonomy chain INCOMPLETE: in=%v dispatch=%v reply=%v — pherald log tail:\n%s",
			sawIn, sawDispatch, sawReply, string(tail))
	}
	t.Logf("PASS: §11.4.98 autonomy chain proven via journal — Slack user → bot inbound (Socket Mode) → Claude dispatch → Claude reply")

	// SOFT note (Tier-2 / CC delivery): try to read the Claude reply back. In
	// this harness pherald bootstraps a FRESH, context-less Claude session which
	// returns EMPTY reply text (pherald.log "reply skipped — empty reply text"),
	// so the CC reply is typically NOT delivered. That specific gap is tracked by
	// HRD-159 (cross-channel — the Telegram round-trip has it too). We do NOT
	// hard-assert it here; reply-DELIVERY is instead PROVEN below via the
	// deterministic Tier-1 fast-path (which does not depend on CC session
	// fidelity). ts>probe freshness-gates against any stale earlier-run message.
	ccProbeCtx, ccProbeCancel := context.WithTimeout(context.Background(), 20*time.Second)
	if reply, werr := qaUser.WaitForReply(ccProbeCtx, probeTS, func(r messenger.Reply) bool {
		return r.SenderIsBot && slackTSAfter(string(r.MessageID), string(probeTS)) && r.Text != probe
	}, 18*time.Second); werr == nil {
		t.Logf("note: CC reply also delivered (bonus, ts=%s) text=%q nonce_echoed=%v",
			reply.MessageID, slackTrunc(reply.Text, 80), strings.Contains(reply.Text, nonce))
	} else {
		t.Logf("note: CC (Tier-2) reply not delivered — fresh bootstrap session returns empty text (HRD-159, cross-channel): %v", werr)
	}
	ccProbeCancel()

	// HARD assertion — reply-DELIVERY leg (§11.4.98), proven DETERMINISTICALLY
	// via the Tier-1 fast-path. A natural-language status query ("what is the
	// status of ATM-<pid>?") is recognized by the deterministic CommandRecognizer
	// (NO Claude round-trip — so it does not depend on CC session fidelity) and
	// pherald replies "Looking up the status of ATM-<pid>…" via slack.SendReply.
	// The QA user reading that reply back from Slack proves the FULL round-trip
	// reply-DELIVERY leg really lands. The id token (ATM-<pid>) is unique-per-run
	// and echoed in the deterministic reply, giving unambiguous provenance; the
	// ts>probe2 gate excludes any stale earlier message.
	idToken := fmt.Sprintf("ATM-%d", pheraldCmd.Process.Pid)
	cmdProbe := "What is the status of " + idToken + "?"
	send2Ctx, send2Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	probe2TS, serr2 := qaUser.Send(send2Ctx, cmdProbe)
	send2Cancel()
	if serr2 != nil {
		t.Fatalf("QA user Send (Tier-1 status-query probe) failed: %v", serr2)
	}
	t.Logf("QA user posted Tier-1 status-query probe ts=%s text=%q", probe2TS, cmdProbe)

	// Find the bot's reply IN THE THREAD via conversations.replies. A correctly
	// threaded reply (thread_ts set) does NOT appear in conversations.history's
	// top-level timeline, so we must look inside the thread rooted at the probe.
	// Finding the bot's reply HERE proves BOTH that it was delivered AND that it
	// is in-thread (operator mandate 2026-06-02: replies MUST be threaded on
	// every messenger that supports it).
	var sawCmdReply bool
	var deliveredReply messenger.Reply
	threadDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(threadDeadline) {
		thrCtx, thrCancel := context.WithTimeout(context.Background(), 15*time.Second)
		replies, rerr := qaUser.GetThreadReplies(thrCtx, string(probe2TS))
		thrCancel()
		if rerr != nil {
			t.Logf("conversations.replies poll error (will retry): %v", rerr)
		} else {
			for _, r := range replies {
				// The bot's reply is the thread message that is NOT the probe
				// (root) and carries the unique id token. We CANNOT key on
				// SenderIsBot: the QA user posts via an app-associated user token,
				// so its messages also carry the app's bot_id — only the user-id
				// (and the ts) distinguish them. Excluding the probe ts + matching
				// the id token unambiguously selects pherald's reply.
				if string(r.MessageID) != string(probe2TS) && strings.Contains(r.Text, idToken) {
					sawCmdReply = true
					deliveredReply = r
					break
				}
			}
		}
		if sawCmdReply {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !sawCmdReply {
		tail, _ := exec.Command("tail", "-25", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		t.Fatalf("§11.4.98 reply-DELIVERY leg FAILED: the deterministic Tier-1 reply (carrying %q) was not found IN THE THREAD rooted at the probe (ts=%s) — the round-trip reply did not reach Slack. pherald log tail:\n%s",
			idToken, probe2TS, string(tail))
	}
	t.Logf("✓ reply-DELIVERY PROVEN: Tier-1 reply found in the thread (reply ts=%s) text=%q",
		deliveredReply.MessageID, slackTrunc(deliveredReply.Text, 90))

	// HARD assertion — the reply MUST be IN-THREAD under the probe. Because we
	// fetched it via conversations.replies(ts=probe), it is in the thread by
	// construction; we additionally assert ReplyToMessageID == the probe ts
	// (the qaherald client sets it from thread_ts) as belt-and-braces.
	if string(deliveredReply.ReplyToMessageID) != string(probe2TS) {
		t.Fatalf("reply NOT in-thread: reply thread parent=%q, want probe ts=%q — the reply was posted top-level, not threaded (operator mandate: replies MUST be threaded on Slack via thread_ts)",
			deliveredReply.ReplyToMessageID, probe2TS)
	}
	t.Logf("✓ THREADING PROVEN: reply is in-thread under the probe (thread_ts=%s == probe ts=%s)", deliveredReply.ReplyToMessageID, probe2TS)

	// LEG 3 — INBOUND THREADED MESSAGE (operator mandate 2026-06-02): a Subscriber
	// must be processed when they reply WITHIN an existing thread, and pherald MUST
	// reply back into that SAME thread. The QA user now posts a SECOND status query
	// as a threaded reply (thread_ts == probe2TS) inside the thread LEG 2 created.
	// pherald receives an inbound message carrying thread_ts and — because
	// extractReplyToID PREFERS thread_ts — must reply into the same thread.
	idToken2 := fmt.Sprintf("ATM-%d", pheraldCmd.Process.Pid+1)
	inThreadQuery := "And the status of " + idToken2 + "?"
	sendT3Ctx, sendT3Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	inThreadQueryTS, serr3 := qaUser.SendInThread(sendT3Ctx, inThreadQuery, string(probe2TS))
	sendT3Cancel()
	if serr3 != nil {
		teardown()
		t.Fatalf("QA user SendInThread (reply within existing thread) failed: %v", serr3)
	}
	t.Logf("QA user posted an IN-THREAD reply ts=%s (thread_ts=%s) text=%q", inThreadQueryTS, probe2TS, inThreadQuery)

	var sawInThreadReply bool
	var inThreadReply messenger.Reply
	t3Deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(t3Deadline) {
		t3Ctx, t3Cancel := context.WithTimeout(context.Background(), 15*time.Second)
		replies, rerr := qaUser.GetThreadReplies(t3Ctx, string(probe2TS))
		t3Cancel()
		if rerr != nil {
			t.Logf("conversations.replies poll error (will retry): %v", rerr)
		} else {
			for _, r := range replies {
				// pherald's reply to the in-thread query: carries idToken2 and is
				// neither the in-thread query nor any earlier message.
				if string(r.MessageID) != string(inThreadQueryTS) && strings.Contains(r.Text, idToken2) {
					sawInThreadReply = true
					inThreadReply = r
					break
				}
			}
		}
		if sawInThreadReply {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !sawInThreadReply {
		tail, _ := exec.Command("tail", "-25", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		teardown()
		t.Fatalf("INBOUND-THREADED processing FAILED: pherald did not reply (carrying %q) to the Subscriber's in-thread message — a reply within an existing thread was not processed/answered in-thread. pherald log tail:\n%s",
			idToken2, string(tail))
	}
	if string(inThreadReply.ReplyToMessageID) != string(probe2TS) {
		teardown()
		t.Fatalf("INBOUND-THREADED reply landed in the WRONG thread: parent=%q want probe ts=%q — a reply to an in-thread message must stay in the SAME thread",
			inThreadReply.ReplyToMessageID, probe2TS)
	}
	t.Logf("✓ INBOUND-THREADED PROVEN: pherald processed the Subscriber's in-thread reply and answered IN THE SAME thread (reply ts=%s thread_ts=%s) text=%q",
		inThreadReply.MessageID, inThreadReply.ReplyToMessageID, slackTrunc(inThreadReply.Text, 70))

	// LEG 4 — THREAD-CONTEXT AWARENESS END-TO-END (operator mandate 2026-06-02).
	// The Subscriber posts a FREEFORM (NOT a Tier-1 status query) message INSIDE
	// the existing thread (thread_ts == probe2TS, the LEG-2 thread root). Because
	// it is freeform it routes to CC/Tier-2 — exercising the envelope path. The
	// slack adapter's fetchThreadContext (conversations.replies) gathers the
	// thread's PRIOR messages → commons.InboundEvent.ThreadContext → the
	// dispatcher renders a THREAD CONTEXT block (Participants + prior messages +
	// SUBJECT) into the `claude --print <envelope>` argv. We HARD-assert, against
	// the REAL captured envelope bytes (anti-bluff: actual argv pherald handed to
	// claude, NOT a metadata flag), that the envelope for THIS message carries the
	// THREAD CONTEXT marker + Participants: + the text of at least one PRIOR thread
	// message — proving the gather-and-feed chain end-to-end.
	tcNonce := fmt.Sprintf("ctxq-%d", pheraldCmd.Process.Pid)
	tcQuery := "Can you summarise what this thread is about? (" + tcNonce + ")"
	sendT4Ctx, sendT4Cancel := context.WithTimeout(context.Background(), 30*time.Second)
	tcQueryTS, serr4 := qaUser.SendInThread(sendT4Ctx, tcQuery, string(probe2TS))
	sendT4Cancel()
	if serr4 != nil {
		teardown()
		t.Fatalf("QA user SendInThread (freeform thread-context query) failed: %v", serr4)
	}
	t.Logf("QA user posted an IN-THREAD freeform query ts=%s (thread_ts=%s) text=%q", tcQueryTS, probe2TS, tcQuery)

	// A PRIOR in-thread message whose text MUST appear in the rendered THREAD
	// CONTEXT block. The LEG-2 status query (cmdProbe, carrying idToken) is the
	// thread root; idToken is unique-per-run, so finding it inside the envelope
	// for the freeform message is unambiguous proof the adapter gathered THIS
	// thread (not a stale/empty context).
	priorThreadMarker := idToken // "ATM-<pid>" — the LEG-2 root message's id token

	// Poll the capture file (bounded ~120s) for the cc.dispatch envelope that
	// references our freeform query AND carries THREAD CONTEXT + Participants: +
	// the prior message. The wrapper appends one record per claude invocation;
	// we scan for the record containing tcNonce (THIS message's envelope).
	t.Logf("waiting up to 120s for the cc envelope (freeform in-thread message) to carry THREAD CONTEXT...")
	var tcEnvelope string
	var tcEnvelopeFound bool
	tcDeadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(tcDeadline) {
		if data, rerr := os.ReadFile(envCapturePath); rerr == nil {
			for _, rec := range slackSplitEnvelopeRecords(string(data)) {
				if strings.Contains(rec, tcNonce) {
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
		tail, _ := exec.Command("tail", "-40", filepath.Join(qaDir, "pherald.log")).CombinedOutput()
		cap, _ := os.ReadFile(envCapturePath)
		teardown()
		t.Fatalf("THREAD-CONTEXT leg FAILED: no captured cc envelope referenced the freeform in-thread query nonce %q within 120s — pherald never dispatched it to claude. capture tail:\n%s\npherald log tail:\n%s",
			tcNonce, slackTrunc(string(cap), 1200), string(tail))
	}

	// HARD assertions against the ACTUAL envelope bytes.
	var tcMissing []string
	if !strings.Contains(tcEnvelope, "THREAD CONTEXT") {
		tcMissing = append(tcMissing, `"THREAD CONTEXT"`)
	}
	if !strings.Contains(tcEnvelope, "Participants:") {
		tcMissing = append(tcMissing, `"Participants:"`)
	}
	if !strings.Contains(tcEnvelope, priorThreadMarker) {
		tcMissing = append(tcMissing, fmt.Sprintf("prior-thread-message marker %q", priorThreadMarker))
	}
	if len(tcMissing) > 0 {
		teardown()
		t.Fatalf("THREAD-CONTEXT leg FAILED: the cc.dispatch envelope for the in-thread message did NOT carry %s — the adapter did not gather the thread OR the dispatcher did not feed it to Claude. Envelope record:\n%s",
			strings.Join(tcMissing, " + "), slackTrunc(tcEnvelope, 2000))
	}
	t.Logf("✓ THREAD-CONTEXT PROVEN: cc.dispatch envelope for the in-thread message carried THREAD CONTEXT + Participants + prior message")

	// Teardown now (before writing evidence) so we can record the exit status.
	teardown()
	if pheraldExitErr != nil {
		// SIGTERM-induced exit surfaces as *exec.ExitError; that is the
		// expected clean-shutdown signal, not a failure. Only an unexpected
		// non-signal error is a problem.
		var exitErr *exec.ExitError
		if !errors.As(pheraldExitErr, &exitErr) {
			t.Errorf("pherald listen did not exit cleanly on SIGTERM: %v", pheraldExitErr)
		} else {
			t.Logf("pherald listen exited on SIGTERM (expected): %v", pheraldExitErr)
		}
	} else {
		t.Logf("pherald listen exited cleanly (status 0)")
	}

	// §107.x evidence: write a redacted transcript under docs/qa/.
	evidenceDir := filepath.Join(repoRoot, "docs", "qa",
		fmt.Sprintf("HRD-115-LIVE-roundtrip-%s", time.Now().UTC().Format("2006-01-02T15-04-05Z")))
	if werr := slackWriteEvidence(evidenceDir, slackEvidence{
		Nonce:           nonce,
		Probe:           probe,
		ProbeTS:         string(probeTS),
		QAUsername:      qaUsername,
		CmdProbe:        cmdProbe,
		CmdProbeTS:      string(probe2TS),
		IDToken:         idToken,
		ReplyDelivered:  sawCmdReply,
		DeliveredReply:  deliveredReply,
		InThreadQuery:   inThreadQuery,
		InThreadQueryTS: string(inThreadQueryTS),
		InThreadIDToken: idToken2,
		InThreadHandled: sawInThreadReply,
		InThreadReply:   inThreadReply,
		TCQuery:         tcQuery,
		TCQueryTS:       string(tcQueryTS),
		TCPriorMarker:   priorThreadMarker,
		TCEnvelope:      tcEnvelope,
		TCProven:        tcEnvelopeFound,
		JournalPath:     journalPath,
		LogPath:         filepath.Join(qaDir, "pherald.log"),
	}); werr != nil {
		t.Errorf("write §107.x evidence: %v", werr)
	} else {
		t.Logf("§107.x evidence written under %s", evidenceDir)
	}
}

// slackEvidence is the redacted transcript payload written under docs/qa/.
type slackEvidence struct {
	Nonce          string
	Probe          string // the Tier-2 CC autonomy-chain probe
	ProbeTS        string
	QAUsername     string
	CmdProbe       string // the Tier-1 deterministic reply-delivery probe
	CmdProbeTS     string
	IDToken        string // unique id echoed in the Tier-1 reply
	ReplyDelivered bool   // Tier-1 reply observed back in Slack (HARD-proven)
	DeliveredReply messenger.Reply
	// Leg 3 — inbound threaded-message processing.
	InThreadQuery   string // the Subscriber's reply posted WITHIN the existing thread
	InThreadQueryTS string
	InThreadIDToken string
	InThreadHandled bool // pherald replied in-thread to the in-thread message (HARD-proven)
	InThreadReply   messenger.Reply
	// Leg 4 — thread-context awareness end-to-end.
	TCQuery       string // the freeform in-thread message that exercised the envelope
	TCQueryTS     string
	TCPriorMarker string // a prior thread message's unique marker that MUST appear in the envelope
	TCEnvelope    string // the REAL captured cc.dispatch envelope record for the freeform message
	TCProven      bool   // the envelope carried THREAD CONTEXT + Participants + prior message (HARD-proven)
	JournalPath   string
	LogPath       string
}

// slackWriteEvidence writes a human-readable, REDACTED transcript +
// a copy of the (already token-free) JSONL journal and pherald.log under
// evidenceDir. Tokens (xoxb-/xapp-/xoxp-) and wss:// URLs are scrubbed from
// every byte copied out, satisfying the §107.x in-repo-evidence mandate
// without leaking credentials.
func slackWriteEvidence(evidenceDir string, ev slackEvidence) error {
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return fmt.Errorf("mkdir evidence dir: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# HRD-115 — Slack inbound round-trip (§11.4.98 self-driving)\n\n")
	fmt.Fprintf(&b, "QA user identity : %s\n\n", ev.QAUsername)
	fmt.Fprintf(&b, "## Leg 1 — autonomy chain (Tier-2, Claude Code)\n")
	fmt.Fprintf(&b, "CC probe text    : %s\n", ev.Probe)
	fmt.Fprintf(&b, "CC probe ts      : %s\n", ev.ProbeTS)
	fmt.Fprintf(&b, "Proven (journal) : inbound(channel:slack) -> cc.dispatch -> cc.reply (see transcript.jsonl)\n")
	fmt.Fprintf(&b, "Note             : CC reply-delivery in a fresh bootstrap session returns empty text (HRD-159, cross-channel)\n\n")
	fmt.Fprintf(&b, "## Leg 2 — reply-DELIVERY (Tier-1 deterministic fast-path)\n")
	fmt.Fprintf(&b, "Status-query     : %s\n", ev.CmdProbe)
	fmt.Fprintf(&b, "Query ts         : %s\n", ev.CmdProbeTS)
	fmt.Fprintf(&b, "Unique id token  : %s\n", ev.IDToken)
	fmt.Fprintf(&b, "Reply DELIVERED  : %v\n", ev.ReplyDelivered)
	if ev.ReplyDelivered {
		fmt.Fprintf(&b, "Delivered reply ts   : %s\n", ev.DeliveredReply.MessageID)
		fmt.Fprintf(&b, "Delivered reply text : %s\n", ev.DeliveredReply.Text)
		fmt.Fprintf(&b, "In-thread under      : %s (thread_ts == the status-query ts ⇒ threaded reply)\n", ev.DeliveredReply.ReplyToMessageID)
	}
	fmt.Fprintf(&b, "\n## Leg 3 — INBOUND threaded message (Subscriber replies WITHIN an existing thread)\n")
	fmt.Fprintf(&b, "Subscriber in-thread msg : %s\n", ev.InThreadQuery)
	fmt.Fprintf(&b, "In-thread msg ts         : %s (thread_ts=%s)\n", ev.InThreadQueryTS, ev.CmdProbeTS)
	fmt.Fprintf(&b, "Unique id token          : %s\n", ev.InThreadIDToken)
	fmt.Fprintf(&b, "Processed + answered     : %v\n", ev.InThreadHandled)
	if ev.InThreadHandled {
		fmt.Fprintf(&b, "In-thread reply ts       : %s\n", ev.InThreadReply.MessageID)
		fmt.Fprintf(&b, "In-thread reply text     : %s\n", ev.InThreadReply.Text)
		fmt.Fprintf(&b, "Stayed in SAME thread    : %s (thread_ts == the original thread root)\n", ev.InThreadReply.ReplyToMessageID)
	}
	fmt.Fprintf(&b, "\n## Leg 4 — THREAD-CONTEXT awareness (Subscriber posts a FREEFORM message inside the thread)\n")
	fmt.Fprintf(&b, "Freeform in-thread msg : %s\n", ev.TCQuery)
	fmt.Fprintf(&b, "Freeform msg ts        : %s (thread_ts=%s)\n", ev.TCQueryTS, ev.CmdProbeTS)
	fmt.Fprintf(&b, "Prior-message marker   : %s (must appear inside the rendered THREAD CONTEXT block)\n", ev.TCPriorMarker)
	fmt.Fprintf(&b, "Envelope carried ctx   : %v (THREAD CONTEXT + Participants: + the prior thread message)\n", ev.TCProven)
	if ev.TCProven {
		// Record a REDACTED excerpt of the actual rendered envelope as the
		// positive runtime evidence that pherald gathered the thread and fed it
		// to Claude. slackRedact scrubs any xox-/wss:// before it touches disk.
		fmt.Fprintf(&b, "Envelope excerpt (REDACTED, captured from the real `claude --print` argv):\n")
		fmt.Fprintf(&b, "----- BEGIN THREAD CONTEXT EXCERPT -----\n%s\n----- END THREAD CONTEXT EXCERPT -----\n", slackThreadContextExcerpt(ev.TCEnvelope))
	}
	fmt.Fprintf(&b, "\nDirection legend: USER -> (Slack) -> pherald bot -> {Claude Code | Tier-1 recognizer} -> (Slack reply) -> USER\n")
	if err := os.WriteFile(filepath.Join(evidenceDir, "TRANSCRIPT.md"), []byte(slackRedact(b.String())), 0o644); err != nil {
		return err
	}
	// Copy the JSONL journal + pherald.log, redacted (defence-in-depth; the
	// journal does not record tokens, but redact anyway).
	if data, err := os.ReadFile(ev.JournalPath); err == nil {
		_ = os.WriteFile(filepath.Join(evidenceDir, "transcript.jsonl"), []byte(slackRedact(string(data))), 0o644)
	}
	if data, err := os.ReadFile(ev.LogPath); err == nil {
		_ = os.WriteFile(filepath.Join(evidenceDir, "pherald.log"), []byte(slackRedact(string(data))), 0o644)
	}
	return nil
}

// slackRedact scrubs Slack tokens (xoxb-/xapp-/xoxp-) and wss:// URLs from s,
// replacing each match with a sentinel. Whitespace-delimited token scrubbing
// is sufficient because Slack tokens carry no internal spaces.
func slackRedact(s string) string {
	out := make([]string, 0, 64)
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		// Preserve original spacing by replacing matched substrings in-place
		// rather than re-joining fields (which would collapse whitespace).
		redacted := line
		for _, f := range fields {
			trimmed := strings.Trim(f, `"',.;:()[]{}`)
			if slackIsSecret(trimmed) {
				redacted = strings.ReplaceAll(redacted, trimmed, "[REDACTED]")
			}
		}
		out = append(out, redacted)
	}
	return strings.Join(out, "\n")
}

// slackIsSecret reports whether tok looks like a Slack token or a WebSocket URL.
func slackIsSecret(tok string) bool {
	switch {
	case strings.HasPrefix(tok, "xoxb-"),
		strings.HasPrefix(tok, "xapp-"),
		strings.HasPrefix(tok, "xoxp-"),
		strings.HasPrefix(tok, "wss://"):
		return true
	}
	return false
}

// slackWaitForListenReady polls the pherald log file until the `pherald
// listen: starting inbound runtime` startup line appears (the deterministic
// boot marker) or the timeout expires.
func slackWaitForListenReady(t *testing.T, logPath string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(logPath); err == nil {
			if strings.Contains(string(data), "starting inbound runtime") {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("startup line 'starting inbound runtime' not observed")
}

// slackFindRepoRoot walks up from the test's CWD until it finds go.work.
func slackFindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("go.work not found walking up from CWD")
}

// slackAtoiPositive parses a positive integer or returns an error.
func slackAtoiPositive(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a positive integer: %q", s)
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return 0, fmt.Errorf("not a positive integer: %q", s)
	}
	return n, nil
}

// slackTrunc truncates s to at most n runes for log readability.
func slackTrunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// shellSingleQuote wraps s in POSIX single quotes, escaping any embedded
// single quote, so the generated wrapper script references paths safely even
// if t.TempDir() ever contains a quote or space. (TempDir paths are tame on
// the CI hosts, but the quoting keeps the generated /bin/sh well-formed.)
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// slackSplitEnvelopeRecords splits the capture file written by the
// envelope-capture wrapper into one string per claude invocation. Each record
// is the argv between the <<<CC-ENVELOPE-RECORD>>> and <<<CC-ENVELOPE-END>>>
// sentinels the wrapper emits; a trailing unterminated record (mid-write) is
// ignored so a concurrent append cannot yield a half-record false match.
func slackSplitEnvelopeRecords(s string) []string {
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

// slackThreadContextExcerpt extracts the THREAD CONTEXT block (from the marker
// up to the trailing blank line that precedes the user message) from a captured
// envelope, REDACTED, for a compact evidence excerpt. Falls back to a redacted
// truncation of the whole record if the marker boundaries cannot be located.
func slackThreadContextExcerpt(envelope string) string {
	start := strings.Index(envelope, "THREAD CONTEXT")
	if start < 0 {
		return slackRedact(slackTrunc(envelope, 1200))
	}
	block := envelope[start:]
	// The renderThreadContext block ends with a "\n\n" separator before the rest
	// of the envelope; cut there to keep the excerpt focused.
	if endIdx := strings.Index(block, "\n\n"); endIdx >= 0 {
		block = block[:endIdx]
	}
	return slackRedact(slackTrunc(block, 1600))
}

// slackTSAfter reports whether Slack message ts a is strictly after ts b.
// Slack timestamps are "<epoch>.<seq>" decimal strings; a float compare orders
// them correctly. A non-parseable ts is treated as NOT-after (conservative), so
// a malformed value can never let a stale message satisfy a freshness check.
func slackTSAfter(a, b string) bool {
	fa, ea := strconv.ParseFloat(a, 64)
	fb, eb := strconv.ParseFloat(b, 64)
	if ea != nil || eb != nil {
		return false
	}
	return fa > fb
}
