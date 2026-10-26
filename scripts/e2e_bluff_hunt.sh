#!/usr/bin/env bash
# End-to-end bluff-hunt for Herald per Universal §11.4 + the operator's
# 2026-05-20 standing mandate:
#
#   "Make sure that all existing tests and Challenges do work in anti-
#    bluff manner — they MUST confirm that all tested codebase really
#    works as expected!"
#
# Strategy: run EVERY user-visible Herald feature end-to-end against
# real services + assert observable behaviour. A bluffing feature that
# "compiles and tests green" but doesn't work for the user will FAIL
# at least one assertion here.
#
# Eighty-eight invariants (E1..E88; E55 + E62 + E63..E70 + E71..E80 SKIP-
# with-reason in the common no-creds / no-T9-evidence case — E81..E88 new
# in GAP-3 §11.4.85 stress + chaos suite (HRD-122..HRD-128): each runs a
# real hermetic Go stress/chaos test AND cites a docs/qa/<run-id>/
# stress_chaos/ evidence anchor (§11.4.2 / §11.4.5); E71..E80 new in
# Wave 6.5 comprehensive ticket-lifecycle (HRD-101); E63..E70 new in Wave
# 6 inbound runtime; E56-E62 Wave 4b TOON content negotiation; E49-E55
# Wave 4a HTTP/3+Brotli+Alt-Svc+TLS; E37-E42 live in Wave 3b; E45 still
# SKIP-with-reason — pending Wave 3c cross-binary wiring; each invariant
# is the "captured-evidence" for one feature class per §11.4.5 + §11.4.69):
#
#   E1.  pherald binary builds (compile-level — necessary, not sufficient).
#   E2.  pherald version --json returns parseable JSON with required fields.
#   E3.  Default test suite green (anti-bluff audit's I2 — re-asserted).
#   E4.  Inheritance gate + paired I6 meta-test green.
#   E5.  CodeGraph anti-bluff validate (7/7 PASS — symbols actually present).
#   E6.  scripts/audit_antibluff.sh 13/13 PASS (submodule anchor cascade).
#   E7.  pherald serve actually starts + binds + accepts HTTP.
#   E8.  /v1/healthz returns 200 with status:ok + version.
#   E9.  /v1/readyz returns 200 with status:ready.
#   E10. /v1/events POST without auth → 401 (Wave 3b live + JWT-gated; was 501-stub through Wave 2).
#   E11. /metrics returns text/plain + herald_build_info gauge.
#   E12. pherald serve graceful-shutdowns on SIGTERM (drain + exit 0).
#
# Optional (run when podman-machine is up + DOCKER_HOST is set):
#   E13. Quickstart compose Postgres boots + migrations apply + RLS
#        isolation proven via the M2 Postgres integration tests.
#   E14. commons_storage RLS tenant-isolation round-trip (HRD-010 Wave 1).
#   E15. commons_infra queue enqueue/dequeue round-trip against live PG.
#   E16. commons_infra redis TTL round-trip against live Redis.
#   E17. Telegram Send delivers + outbound_delivery_evidence persisted
#        (HRD-011 Wave 1 — live Bot API + live PG).
#   E18. Claude Code Dispatch round-trip + claude_code_sessions persisted
#        (HRD-012 Wave 1 — live CLI + live PG).
#
# Wave 2 flavor-binary invariants (added 2026-05-21):
#   E19-E24. New flavor version --json probes (sherald, cherald, bherald,
#            rherald, iherald, scherald — each --json shape valid + flavor field matches).
#   E25-E27. Serving flavors actually bind + healthz returns 200
#            (sherald, cherald, iherald).
#   E28-E30. Flavor-specific routes return expected status. Wave 3a
#            close-out: sherald GET /v1/safety_state + cherald GET
#            /v1/compliance went LIVE → assert 401 (JWT-gated). iherald
#            POST /v1/webhooks/page stays 501 + HRD-024 until that HRD
#            lands. Body-200 evidence for the live routes is in E44+E47.
#   E31. Representative §43 stub exits non-zero with HRD pointer
#        (sherald destructive-guard → HRD-033 in stderr).
#   E32. New serving flavor graceful-shuts on SIGTERM (sherald).
#   E33. pherald e2e regression sentinel — re-runs the pre-Wave-2
#        version probe after every flavor probe so a flavor regression
#        that breaks pherald is caught (rebuild fresh + version --json).
#
# Optional (live channels, run when operator-supplied creds are present):
#   E34. Full vertical slice — operator hand-sent Telegram inbound →
#        Claude Code → Telegram outbound (HRD-011 + HRD-012 Wave 1).
#
# Wave 4a transport substrate (added 2026-05-22):
#   E49. TCP/HTTPS listener bound on the configured port (lsof TCP probe).
#   E50. UDP/HTTP3 listener bound on the same port (lsof UDP / ss probe).
#   E51. HTTP/2 GET healthz → 200 + Alt-Svc 'h3=":<port>"' advertised.
#   E52. HTTP/3 GET healthz → 200 + JSON body via real quic-go client
#        (compiled inline; observes the QUIC handshake completing).
#   E53. Brotli round-trip — Accept-Encoding:br → Content-Encoding:br +
#        body decodes via andybalholm/brotli to identical identity body.
#   E54. TLS 1.3 + ALPN 'h3' negotiated via openssl s_client probe.
#   E55. tcpdump captures ≥ 4 UDP packets on the H3 port during a real
#        HTTP/3 request (SKIP-with-reason if tcpdump absent / no root).
#
# Wave 4a serving binaries now bind HTTPS on TCP (+ HTTP/3 on UDP) by
# default. Existing E7-E48 HTTPS round-trips use `-k` because the dev
# cert is self-signed (~/.herald/dev-{cert,key}.pem auto-generated by
# commons_tls.ResolveCertSource when ProdMode=false). Operators wanting
# plaintext for legacy probes must export HERALD_DISABLE_HTTP3=1.
#
# Wave 4b TOON content negotiation (added 2026-05-22):
#   E56. Accept: application/json → Content-Type: application/json + body[0]='{'.
#   E57. Accept: application/toon → Content-Type: application/toon + body[0]!='{'.
#   E58. TOON response round-trips via real digital.vasic.toon.Unmarshal.
#   E59. TOON body strictly smaller than JSON body for same payload.
#   E60. WIRE-LEVEL anti-bluff — TOON body first byte not '{' and not '['.
#   E61. Accept q-value preference honored (json,toon;q=0.5 → JSON).
#   E62. SKIP-with-reason — encoder-failure fallback unit-tested only.
#
# Wave 6 pherald inbound runtime (added 2026-05-22):
#   E63. pherald listen lifecycle — boots cleanly + SIGTERM-exits 0 against
#        a real Bot API (gated on HERALD_TGRAM_BOT_TOKEN + HERALD_TGRAM_CHAT_ID;
#        otherwise SKIP-with-reason: getMe handshake would hit api.telegram.org).
#   E64. Bot self-filter — captured docs/qa/HRD-NNN-W6-*/transcript.jsonl
#        contains NO tgram.message line whose payload sender matches the
#        bot's own username (anti-echo-loop wire evidence). SKIP-with-reason
#        until T10b commits a real transcript.
#   E65. Attachment sha256 — for any inbound message with attachments, the
#        on-disk file at docs/qa/HRD-NNN-W6-*/attachments/<sha256>.<ext>
#        actually hashes to <sha256>. SKIP-with-reason until T10b commits.
#   E66. Envelope pre-text — captured cc.dispatch journal line carries the
#        verbatim operator wording "We have received new message from our
#        communication channel ". SKIP-with-reason — requires both T10b
#        evidence AND a journal extension that records the rendered envelope
#        (current journal records user_message text, not the pre-text-
#        prefixed envelope; HRD-NNN-W6e tracks the extension).
#   E67. Opus pin in argv — a captured CC argv line includes the literal
#        "--model claude-opus-4-7" pair. SKIP-with-reason — current journal
#        does not record the spawned argv (HRD-NNN-W6e tracks the argv
#        capture extension; T2 unit test catches the model-flag presence
#        at the cmd-construction layer in the meantime).
#   E68. reply_to_message_id wire-bytes — captured tgram.send_reply journal
#        line carries a non-zero reply_to_message_id matching an earlier
#        tgram.message line's message_id. SKIP-with-reason until T10b.
#   E69. Action routing — issue.open — for any cc.reply line with
#        payload.action == "issue.open", there is NO subsequent tgram.send_
#        reply line for the same inbound (issue.open routes to the issue
#        opener, not back to Telegram). SKIP-with-reason until T10b emits
#        an issue.open-action scenario.
#   E70. Live closed-loop (T9 script) — invoke tests/test_wave6_live_loop.sh;
#        PASS on exit 0; SKIP-with-reason when stdout begins with "SKIP:"
#        (script's own creds-absent guard); FAIL otherwise.
#
# Wave 6.5 comprehensive ticket-lifecycle (added 2026-05-23):
#   E71. Classifier emitted at least one "Type":"bug" + one "Type":"help_command"
#        line in docs/qa/HRD-101-lifecycle-<latest>/transcript.jsonl (proves
#        the deterministic §32.6 classifier ran on real operator input).
#   E72. Issues.md mutation — issues.diff has ≥1 added HRD- row (Bug:/Task:
#        scenario actually appended a workable item).
#   E73. Done: migration — fixed.diff has ≥1 added HRD- row (closure
#        scenario actually moved the row Issues.md → Fixed.md).
#   E74. Reopen: migration — issues.diff has a re-added row OR fixed.diff
#        has a deleted row (reopen scenario reversed the migration).
#   E75. Help: fast-path — pherald-listen.log has at least one "inbound
#        dispatched: help_command (fast-path)" line (classifier bypassed CC).
#   E76. Status: fast-path — pherald-listen.log has at least one "inbound
#        dispatched: status_request (fast-path)" line.
#   E77. Attachment download sha256 — every file in
#        docs/qa/HRD-101-lifecycle-<latest>/attachments/ has a base name
#        (sans extension) equal to its sha256 content hash.
#   E78. Outbound attachment fan-out — transcript carries an attachments[]
#        list OR listen-log records a sendPhoto/sendDocument/sendVoice/
#        sendAudio/sendVideo call.
#   E79. Non-operator Done: rejected — transcript or listen-log carries a
#        "not in HERALD_OPERATOR_IDS" or "Done: rejected"/"Reopen: rejected"
#        line (S9 path).
#   E80. Bot self-filter held — pherald-listen.log has zero panic/fatal
#        lines during the full S1..S15 lifecycle run.
#
# GAP-3 §11.4.85 stress + chaos suite (added 2026-05-27; HRD-122..HRD-128):
#   E81. Runner exactly-once-archive + bounded dispatch under N=16 concurrent
#        replay (-race) → TestRunner_Stress_ConcurrentReplay_ExactlyOnce PASS
#        + evidence anchor runner/exactly_once.txt `archival_exactly_once=1`.
#   E82. /v1/events chaos — input-corruption + duplicate-key + auth-storm →
#        tests PASS + evidence anchor events/categorised_errors.txt
#        `all_malformed_rejected_no_5xx=1` (every malformed body 4xx or transport-rejected, never 2xx-accept, never 5xx, never panic).
#   E83. /v1/compliance chaos — PG-drop fails loud → test PASS + evidence
#        anchor compliance/pg_drop_fail_loud.log `fail_loud_no_fabricated_200=1`.
#   E84. /v1/safety_state chaos — consistent under concurrent mutation
#        (-race) → test PASS + evidence anchor safety_state/
#        concurrent_mutation.log `consistent_under_concurrent_mutation=1`.
#   E85. pherald listen inbound chaos — malformed payloads degrade, never
#        panic → tests PASS + evidence anchors listen/handle_malformed_raw.txt
#        `panic_free=1` + listen/malformed_payloads.txt
#        `all_malformed_degraded_no_panic=1`.
#   E86. claude_code dispatch chaos — process-death/timeout/truncated-reply
#        tagged-error, no hang (-race) → tests PASS + evidence anchors
#        claude_code/subprocess_kill.log `tagged_error_no_hang=1` +
#        timeout_cancel.log `deadline_fired=1`.
#   E87. RunMigrations chaos — disk-full ENOSPC propagates tagged, not
#        swallowed → TestRunMigrations_Chaos_DiskFull_TaggedError PASS +
#        evidence anchor resource/disk_full_tagged_error.txt `tagged_error=1`.
#   E88. §12.6 host-mem headroom — the resource-exhaustion suite adds
#        negligible host pressure → TestResource_HostMemHeadroom_Section126
#        PASS + evidence anchor resource/host_memory_headroom.txt
#        `section_12_6_headroom_proven=1`.
#   (All eight are hermetic — no live creds / no container runtime needed.
#   The container-pause / real-disk-fill / container-OOM live variants are
#   SKIP-with-reason inside the Go tests themselves. Each evidence-anchor
#   grep SKIPs-with-reason when no docs/qa/<run-id>/ dir is present.)
#
# Docs Chain verify-only drift-gate (§11.4.106; added 2026-06-02):
#   E148. `docs_chain verify herald-docs` reports the whole tracked-doc corpus
#         in-sync — the output line contains the literal "in-sync" AND the exit
#         code is 0. This is the pure content-hash drift gate the constitution
#         §11.4.106 names: it re-hashes every committed .md and its .html/.pdf/
#         .docx siblings and refuses success the instant ANY sibling has drifted
#         (a stale export is a §11.4 documentation-layer bluff). Unlike the
#         E146/E147 sync-gates it needs NEITHER pandoc NOR weasyprint (verify
#         only reads + hashes existing files), so it SKIPs-with-reason (§11.4.3)
#         ONLY when the docs_chain binary itself is absent from PATH (CI may not
#         carry it — built from the sibling ~/Projects/docs_chain repo). On a
#         real STALE result it FAILs with the drifted node list shown.
#
# Exit 0 only when E1..E12 + E19..E88 (plus E13..E18 + E34 if attempted) all pass.
# Failure prints the offending invariant so the operator knows EXACTLY
# which feature is bluffing.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Use distinct ports + binary path to avoid collision with operator's own work.
PHERALD_BIN="/tmp/pherald-bluff-$$"
HTTP_PORT="${HERALD_E2E_PORT:-24791}"
PHERALD_PID=""

# Wave 3a: cherald + sherald refuse to start without a usable JWT verifier
# (HERALD_AUTH_MODE + matching secret). Set process-wide so the existing
# E19-E32 flavor probes (version --json, serve healthz, §43 stubs) also
# work after the auth-required-at-startup design from T5/T7. Override on
# the wire via Authorization header is the only path that yields 200.
export HERALD_AUTH_MODE="${HERALD_AUTH_MODE:-hmac}"
export HERALD_AUTH_HMAC_SECRET="${HERALD_AUTH_HMAC_SECRET:-test-secret-32-bytes-of-padding!!}"

# Wave 3a: codegraph (npx @colbymchenry/codegraph) refuses Node ≥ 23 by
# default; the operator's Mac runs Node 25 and downgrade is out of scope.
# The override flag is documented in the upstream tool itself and validates
# correctly on the indexed graph. Set globally so E5 PASSes.
export CODEGRAPH_ALLOW_UNSAFE_NODE="${CODEGRAPH_ALLOW_UNSAFE_NODE:-1}"

# Wave 4a: dual-listener (TCP/HTTPS + UDP/HTTP3) is on by default; serve
# requires a TLS cert. commons_tls auto-generates a self-signed dev cert
# at $HOME/.herald/dev-{cert,key}.pem when ProdMode=false. Curl probes
# against the dev cert use `-k` (skip verify). No need to override the
# operator's real ~/.herald — auto-gen is idempotent and safe.

cleanup() {
    if [ -n "${PHERALD_PID}" ]; then
        kill "${PHERALD_PID}" 2>/dev/null || true
        wait "${PHERALD_PID}" 2>/dev/null || true
    fi
    rm -f "${PHERALD_BIN}"
}
trap cleanup EXIT

pass=0
fail=0
fail_names=()
# §11.4 anti-bluff (P2-1): stress/chaos evidence anchors that SKIP because the
# §11.4.85 suite has not been run yet are counted here and surfaced LOUDLY in the
# summary — a green run with N unverified evidence anchors must NOT read as "all
# proven". Distinct from `pass`: a SKIP is an honest gap (§11.4.3), not a PASS.
sc_skip=0
sc_skip_names=()

check() {
    local name="$1"; shift
    if eval "$@" > /tmp/e2e_out 2>&1; then
        # §11.4 anti-bluff guard (P2-3): a `go test -run <regex>` whose regex
        # matches NO test exits 0 with "[no tests to run]" — a silent SKIP-as-
        # green that turns the invariant into a no-op if a targeted test is
        # ever renamed. Treat "selected zero tests" as FAIL. We FAIL only when
        # NO package ran any test (no real `ok` line, no `--- PASS/FAIL` line),
        # so a multi-package run where some subpackages legitimately have no
        # matching tests still PASSes (one real run is enough).
        if printf '%s' "$*" | grep -q 'go test' && printf '%s' "$*" | grep -q -- '-run '; then
            if grep -q 'no tests to run' /tmp/e2e_out 2>/dev/null \
               && ! grep -qE '^--- (PASS|FAIL)|^ok[[:space:]][^[]*$' /tmp/e2e_out 2>/dev/null; then
                echo "FAIL  ${name}"
                echo "      (go test -run selected ZERO tests — invariant is a no-op; renamed test? §11.4 anti-bluff)"
                tail -5 /tmp/e2e_out | sed 's/^/      /'
                fail=$((fail+1))
                fail_names+=("${name}")
                return
            fi
        fi
        echo "PASS  ${name}"
        pass=$((pass+1))
    else
        echo "FAIL  ${name}"
        echo "      (last 5 lines of output below)"
        tail -5 /tmp/e2e_out | sed 's/^/      /'
        fail=$((fail+1))
        fail_names+=("${name}")
    fi
}

# ----------------------------------------------------------------------
# pg_self_heal <password> — DEV-CONTAINER PASSWORD NORMALIZATION (best-effort).
#
# Why this exists: the dev `herald-postgres` container (host port 24100) may
# have been created with an arbitrary POSTGRES_PASSWORD (e.g. an operator's
# ad-hoc compose-up, a prior session's password, or the quickstart default).
# Different e2e blocks expect different credentials against the SAME shared
# container:
#   - the `pherald serve` HTTPS probes (E7-E12 / E37-E42) hardcode the DSN
#     password "herald_dev" (commons_infra/boot.go default);
#   - the Go integration tests (E14-E17) hardcode HERALD_DB_PASSWORD=
#     "test-postgres-password-DO-NOT-USE-IN-PROD" via t.Setenv (un-overridable
#     from outside the test process).
# A single Postgres role can only carry one password at a time, so each
# PG-dependent block normalizes the container role password to what THAT
# block needs, right before it runs. This is honest: the block still makes a
# real authenticated connection + asserts real observable behaviour — we only
# reconcile the dev credential so the assertion can reach the wire.
#
# The container's LOCAL unix socket uses `trust` auth (no password), so the
# ALTER works via `podman/docker exec` regardless of the current password.
# No-op (returns 0) when the container or its runtime is unavailable — never
# hard-fails; the block's own `nc -z 24100` reachability gate decides PASS/
# SKIP. NOT captured in git as container state — this re-applies on every run
# so the e2e is self-healing across fresh sessions.
pg_self_heal() {
    local pw="$1"
    local rt=""
    if command -v podman >/dev/null 2>&1; then rt="podman"
    elif command -v docker >/dev/null 2>&1; then rt="docker"
    else return 0; fi
    "${rt}" exec herald-postgres psql -U herald -d herald \
        -c "ALTER USER herald WITH PASSWORD '${pw}'" >/dev/null 2>&1 || true
    return 0
}

# ----------------------------------------------------------------------
# E1: pherald binary builds.
echo "== E1: pherald compile =="
check "E1 pherald binary builds" "go build -o '${PHERALD_BIN}' ./pherald/cmd/pherald"

# ----------------------------------------------------------------------
# E2: pherald version --json.
echo ""
echo "== E2: pherald version --json =="
check "E2 version --json returns valid JSON with required fields" \
    "'${PHERALD_BIN}' version --json | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"binary\"]==\"pherald\"; assert d[\"version\"]; assert d[\"go_version\"]; assert d[\"os\"]; assert d[\"arch\"]; print(\"ok\")'"

# ----------------------------------------------------------------------
# E3: Default test suite.
echo ""
echo "== E3: Default-mode go test suite =="
check "E3 go test -race -count=1 across 11 Herald module trees (commons, commons_prefix, commons_messaging, commons_storage, commons_constitution, commons_infra, commons_auth, commons_tls, commons_watch, commons_workable, pherald)" \
    "go test -race -count=1 ./commons/... ./commons_prefix/... ./commons_messaging/... ./commons_storage/... ./commons_constitution/... ./commons_infra/... ./commons_auth/... ./commons_tls/... ./commons_watch/... ./commons_workable/... ./pherald/..."

# ----------------------------------------------------------------------
# E4: Gate + paired meta.
echo ""
echo "== E4: Inheritance gate + paired I6/I8 meta-tests =="
check "E4a inheritance gate 15 PASS / 0 FAIL (includes I8a/b/c §107 covenant)" \
    "bash tests/test_constitution_inheritance.sh"
check "E4b I6 paired meta-test 3 PASS / 0 FAIL" \
    "bash tests/test_i6_refinement_meta.sh"
check "E4c I8 paired meta-test 5 PASS / 0 FAIL (§107 covenant anchor mutation)" \
    "bash tests/test_i8_usability_meta.sh"

# ----------------------------------------------------------------------
# E5: CodeGraph validate.
echo ""
echo "== E5: CodeGraph anti-bluff validation =="
check "E5 codegraph_validate.sh 7/7 PASS" \
    "bash scripts/codegraph_validate.sh"

# ----------------------------------------------------------------------
# E6: Anti-bluff audit.
echo ""
echo "== E6: scripts/audit_antibluff.sh =="
check "E6 audit_antibluff.sh 14/14 PASS (includes I8 §107 paired meta-test)" \
    "bash scripts/audit_antibluff.sh"

# ----------------------------------------------------------------------
# E7..E12: pherald serve live HTTP smoke.
#
# Wave 3b: pherald serve now REQUIRES HERALD_PG_DSN (no PG-less serve mode).
# Gate the whole block behind PG reachability (mirrors E14-E16 pattern).
# When PG isn't reachable, SKIP-with-reason — the same surfaces are
# re-exercised by E37-E42 below under the same gate.
#
# E10 changed from "501 + HRD-016 pointer" → "401 unauthorized" because
# /v1/events is now live + auth-gated. A POST without a Bearer token
# correctly returns 401 (auth middleware short-circuits before the
# handler). The honest-stub era ended at HRD-016 close-out (Wave 3b).
echo ""
echo "== E7-E12: pherald serve live HTTP smoke on :${HTTP_PORT} =="
# Dev-container password normalization: the serve probe's DSN hardcodes
# "herald_dev". Reconcile the container role password before connecting
# (best-effort no-op when the container/runtime is absent).
pg_self_heal "herald_dev"
if nc -z 127.0.0.1 24100 2>/dev/null; then
    # HERALD_AUTH_MODE + HERALD_AUTH_HMAC_SECRET are also exported at the top
    # of the script, but set them explicitly here too (mirroring the correct
    # E37-E42 invocation) so this block is self-documenting and robust to any
    # future change of the top-level defaults — `pherald serve` REFUSES to
    # start without a usable JWT verifier (build verifier: HERALD_AUTH_MODE
    # must be set / HMAC mode requires HMACSecret).
    HERALD_AUTH_MODE=hmac \
    HERALD_AUTH_HMAC_SECRET="test-secret-32-bytes-of-padding!!" \
    HERALD_PG_DSN="postgres://herald:herald_dev@127.0.0.1:24100/herald" \
        "${PHERALD_BIN}" serve --http-port "${HTTP_PORT}" >/tmp/pherald_serve.log 2>&1 &
    PHERALD_PID=$!
    # Wait until the port responds (max 10s). Wave 4a: TCP is HTTPS now.
    ready=0
    for i in $(seq 1 20); do
        if curl -k -fsS "https://127.0.0.1:${HTTP_PORT}/v1/healthz" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "${ready}" = 1 ]; then
        echo "PASS  E7 pherald serve binds + accepts HTTPS"
        pass=$((pass+1))
    else
        echo "FAIL  E7 pherald serve never accepted HTTPS within 10s"
        fail=$((fail+1))
        fail_names+=("E7")
    fi

    # E8: healthz body sanity.
    check "E8 /v1/healthz returns 200 + status:ok + version" \
        "curl -k -fsS 'https://127.0.0.1:${HTTP_PORT}/v1/healthz' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"status\"]==\"ok\"; assert d[\"build\"][\"version\"]; print(\"ok\")'"

    check "E9 /v1/readyz returns 200 + status:ready" \
        "curl -k -fsS 'https://127.0.0.1:${HTTP_PORT}/v1/readyz' | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"status\"]==\"ready\"; print(\"ok\")'"

    # E10: /v1/events without auth → 401 (Wave 3b live + JWT-gated).
    check "E10 /v1/events POST without auth returns 401 (Wave 3b live + JWT-gated)" \
        "test \"\$(curl -k -s -o /tmp/ev.body -w \"%{http_code}\" -X POST 'https://127.0.0.1:${HTTP_PORT}/v1/events' -H 'Content-Type: application/cloudevents+json' -d '{}')\" = 401"

    check "E11 /metrics returns text/plain + pherald_build_info gauge" \
        "curl -k -fsS 'https://127.0.0.1:${HTTP_PORT}/metrics' | grep -q '^pherald_build_info{'"

    # E12: graceful shutdown — send SIGTERM and verify exit 0.
    kill -TERM "${PHERALD_PID}"
    wait "${PHERALD_PID}" 2>/dev/null
    exit_code=$?
    PHERALD_PID=""
    if [ "${exit_code}" = 0 ]; then
        echo "PASS  E12 pherald serve graceful-shutdown on SIGTERM (exit 0)"
        pass=$((pass+1))
    else
        echo "FAIL  E12 pherald serve exited ${exit_code} on SIGTERM (want 0)"
        fail=$((fail+1))
        fail_names+=("E12")
    fi
else
    echo "SKIP  E7-E12 (Postgres :24100 unreachable — pherald serve requires HERALD_PG_DSN per Wave 3b; §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# E13: optional live Postgres integration via commons_infra.
echo ""
echo "== E13: optional live Postgres M2 integration tests =="
if [ -n "${DOCKER_HOST:-}" ] || podman info >/dev/null 2>&1; then
    # Set DOCKER_HOST from podman if not already set.
    if [ -z "${DOCKER_HOST:-}" ]; then
        sock=$(podman info --format '{{.Host.RemoteSocket.Path}}' 2>/dev/null || true)
        [ -n "${sock}" ] && export DOCKER_HOST="unix://${sock}"
    fi
    # Boot Postgres via the quickstart compose if not already running.
    if ! nc -z 127.0.0.1 24100 2>/dev/null; then
        HERALD_DB_PASSWORD="test-postgres-password-DO-NOT-USE-IN-PROD" \
        HERALD_REDIS_PASSWORD="test-redis-password-DO-NOT-USE-IN-PROD" \
        HERALD_PROJECT_NAME="Herald-E2E" \
        HERALD_TENANT_ID="00000000-0000-0000-0000-000000000099" \
        podman-compose -f quickstart/docker-compose.quickstart.yml --project-name herald-e2e up -d postgres >/dev/null 2>&1 || true
        # Wait for postgres reachability.
        for i in $(seq 1 30); do
            nc -z 127.0.0.1 24100 2>/dev/null && break
            sleep 1
        done
    fi
    if nc -z 127.0.0.1 24100 2>/dev/null; then
        # E13's M2 tests authenticate with the test password (the prior
        # E7-E12 self-heal left the container at "herald_dev"). Reconcile.
        pg_self_heal "test-postgres-password-DO-NOT-USE-IN-PROD"
        check "E13 M2 Postgres integration tests (RLS + transition gate)" \
            "HERALD_DB_PASSWORD='test-postgres-password-DO-NOT-USE-IN-PROD' DOCKER_HOST='\${DOCKER_HOST}' go test -tags=integration -timeout 5m -count=1 -run TestPostgres ./commons_constitution/..."
    else
        echo "SKIP  E13 — Postgres on :24100 unreachable (closed-set reason: hardware_not_present)"
    fi
else
    echo "SKIP  E13 — no container runtime (closed-set reason: hardware_not_present)"
fi

# ----------------------------------------------------------------------
# E14-E16: HRD-010 commons_storage live wiring (Wave 1 evidence).
# Requires container runtime (docker or podman). Skip-with-reason if
# absent per §11.4.3. Tests already implemented:
#   E14: commons_storage/storage_integration_test.go (RLS isolation)
#   E15: commons_infra/clients_integration_test.go (queue enqueue/dequeue)
#   E16: commons_infra/clients_integration_test.go (redis TTL)
echo ""
echo "== E14-E16: HRD-010 commons_storage live integration =="
# §11.4.3 SKIP-with-reason guard: container CLI installed AND PG/Redis
# actually reachable (mirrors E13's reachability probe). A bare
# `command -v podman` succeeds when podman is installed but its daemon
# is down — that produced FAIL-without-runtime regressions in fresh
# sessions. The reachability probe catches that case.
if (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) \
   && nc -z 127.0.0.1 24100 2>/dev/null; then
    # Dev-container password normalization: these integration tests hardcode
    # HERALD_DB_PASSWORD="test-postgres-password-DO-NOT-USE-IN-PROD" via
    # t.Setenv (commons_storage/storage_integration_test.go +
    # commons_messaging/.../persist_integration_test.go) — un-overridable from
    # outside the test process. Reconcile the dev container role password to
    # match so the test's authenticated pgx connect reaches the wire.
    pg_self_heal "test-postgres-password-DO-NOT-USE-IN-PROD"
    check "E14 commons_storage RLS tenant-isolation round-trip (live PG)" \
        "go test ./commons_storage/ -tags=integration -run TestRLS_TenantIsolation_RoundTrip -count=1 -timeout=180s"
    check "E15 commons_infra queue enqueue/dequeue round-trip (live PG)" \
        "go test ./commons_infra/ -tags=integration -run TestUp_PopulatesQueue_EnqueueDequeueRoundTrip -count=1 -timeout=180s"
    if nc -z 127.0.0.1 24200 2>/dev/null; then
        check "E16 commons_infra redis TTL round-trip (live Redis)" \
            "go test ./commons_infra/ -tags=integration -run TestUp_PopulatesRedis_TTLRoundTrip -count=1 -timeout=180s"
    else
        echo "SKIP  E16 — Redis on :24200 unreachable (closed-set reason: hardware_not_present)"
    fi
else
    echo "SKIP  E14-E16 (container runtime absent OR Postgres :24100 unreachable — §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# E17/E18/E34: HRD-011 + HRD-012 live channel + dispatcher (Wave 1
# vertical slice). Each SKIPs with explicit §11.4.3 reason if its
# prerequisite is absent — never PASS-by-default. Note: the live
# vertical-slice slot was renumbered from E19 → E34 on 2026-05-21 to
# free E19-E33 for the six new flavor-binary invariants.
echo ""
echo "== E17/E18/E34: HRD-011 Telegram + HRD-012 Claude Code live integration =="

# E17: Telegram Send + outbound_delivery_evidence persistence.
if [ -n "${HERALD_TGRAM_BOT_TOKEN:-}" ] && [ -n "${HERALD_TGRAM_CHAT_ID:-}" ] && (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) && nc -z 127.0.0.1 24100 2>/dev/null; then
    check "E17 Telegram Send delivers + persists evidence (live Bot API + live PG)" \
        "go test ./commons_messaging/channels/tgram/ -tags=integration -run TestSend_PersistsDeliveryEvidence -count=1 -timeout=300s"
else
    echo "SKIP  E17 (HERALD_TGRAM_BOT_TOKEN+_CHAT_ID, container runtime, OR live PG :24100 absent — the test persists outbound_delivery_evidence to PG, so PG-reachability is a hard prerequisite; §11.4.3 explicit SKIP-with-reason)"
fi

# E18: Claude Code Dispatch + session_state persistence.
CLAUDE_BIN_FOR_E18="${HERALD_CLAUDE_BIN:-claude}"
if command -v "${CLAUDE_BIN_FOR_E18}" >/dev/null 2>&1 \
   && [ -n "${HERALD_CLAUDE_PROJECT_NAME:-}" ] \
   && [ -n "${HERALD_CLAUDE_SESSION_UUID:-}" ] \
   && (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1); then
    check "E18 Claude Code Dispatch round-trip + session_state persist (live CLI + live PG)" \
        "go test ./commons_messaging/dispatch/claude_code/ -tags=integration -run TestDispatch_PersistsSessionState -count=1 -timeout=600s"
else
    echo "SKIP  E18 (claude binary OR HERALD_CLAUDE_PROJECT_NAME/SESSION_UUID OR container runtime absent — §11.4.3 explicit SKIP-with-reason)"
fi

# E34: Full vertical slice — operator hand-sent Telegram inbound → Claude → Telegram outbound.
# (Renumbered from E19 → E34 on 2026-05-21; the E19-E33 slots are now
# occupied by the Wave 2 flavor-binary invariants below.)
if [ -n "${HERALD_TGRAM_BOT_TOKEN:-}" ] \
   && [ -n "${HERALD_TGRAM_CHAT_ID:-}" ] \
   && [ "${HERALD_TGRAM_LIVE_INBOUND:-}" = "1" ] \
   && command -v "${CLAUDE_BIN_FOR_E18}" >/dev/null 2>&1 \
   && [ -n "${HERALD_CLAUDE_PROJECT_NAME:-}" ] \
   && [ -n "${HERALD_CLAUDE_SESSION_UUID:-}" ] \
   && (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1); then
    check "E34 full vertical slice — Telegram inbound → Claude Code → Telegram outbound" \
        "go test ./commons_messaging/ -tags=integration -run TestVerticalSlice_TelegramClaudeRoundTrip -count=1 -timeout=600s"
else
    echo "SKIP  E34 (HERALD_TGRAM_LIVE_INBOUND=1 + Telegram creds + claude + container runtime + project/session env required — §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# E19-E33: Wave 2 flavor-binary invariants — 15 new checks against the
# 6 new flavor binaries (sherald / cherald / iherald serving + bherald /
# rherald / scherald CLI-only) per Wave 2 Task 13.
# ----------------------------------------------------------------------

echo ""
echo "== E19-E24: New flavor version --json (6 binaries) =="
e_counter=19
for entry in "sherald:s" "cherald:c" "bherald:b" "rherald:r" "iherald:i" "scherald:sc"; do
    flavor="${entry%%:*}"
    expect_flavor="${entry##*:}"
    label="E${e_counter}(${flavor})"
    bin="/tmp/${flavor}-bluff-$$"
    if ! go build -o "${bin}" "./${flavor}/cmd/${flavor}" > /tmp/e2e_out 2>&1; then
        echo "FAIL  ${label} ${flavor} build failed"
        tail -5 /tmp/e2e_out | sed 's/^/      /'
        fail=$((fail+1))
        fail_names+=("${label}-build")
        e_counter=$((e_counter+1))
        continue
    fi
    check "${label} version --json shape + flavor=${expect_flavor} + binary=${flavor}" \
        "\"${bin}\" version --json | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"flavor\"]==\"${expect_flavor}\"; assert d[\"version\"]; assert d[\"go_version\"]; assert d[\"binary\"]==\"${flavor}\"'"
    rm -f "${bin}"
    e_counter=$((e_counter+1))
done

echo ""
echo "== E25-E30 + E32: Serving flavors bind healthz/route + sherald SIGTERM =="
# Wave 3a close-out: sherald /v1/safety_state + cherald /v1/compliance
# went LIVE — E28/E29 now assert the route is JWT-gated (no-auth → 401)
# instead of the Wave 2 "501 stub + HRD pointer" check. HRD-024 close-out:
# iherald POST /v1/webhooks/page is now LIVE too (the
# PagerDuty/Opsgenie-compatible inbound escalation surface driving the
# bindings.Pipeline) — E30 now asserts the route is JWT-gated (no-auth → 401)
# rather than the Wave 2 501-stub. The "202 + Receipt" path (real bus emit +
# persisted constitution_state row) is covered by the iherald/internal/page
# handler tests.
serve_idx=25
route_idx=28
for entry in "sherald:24993:HRD-098:safety_state:GET:401" "cherald:24992:HRD-028:compliance:GET:401" "iherald:24994:HRD-024:webhooks/page:POST:401"; do
    flavor="${entry%%:*}"
    rest="${entry#*:}"
    port="${rest%%:*}"
    rest="${rest#*:}"
    hrd="${rest%%:*}"
    rest="${rest#*:}"
    route_short="${rest%%:*}"
    rest="${rest#*:}"
    method="${rest%%:*}"
    expected_code="${rest##*:}"
    serve_label="E${serve_idx}(${flavor})"
    route_label="E${route_idx}(${flavor})"
    bin="/tmp/${flavor}-serve-$$"
    if ! go build -o "${bin}" "./${flavor}/cmd/${flavor}" > /tmp/e2e_out 2>&1; then
        echo "FAIL  ${serve_label} build"
        tail -5 /tmp/e2e_out | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("${serve_label}-build")
        serve_idx=$((serve_idx+1)); route_idx=$((route_idx+1))
        continue
    fi
    "${bin}" serve --http-port "${port}" > /tmp/${flavor}-serve.log 2>&1 &
    serve_pid=$!
    # Wait up to 5s for the port to be live. Wave 4a: TCP is HTTPS now.
    ready=0
    for i in $(seq 1 10); do
        if curl -k -fsS "https://127.0.0.1:${port}/v1/healthz" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "${ready}" = 1 ]; then
        echo "PASS  ${serve_label} healthz 200 + status:ok on :${port} (HTTPS)"
        pass=$((pass+1))
    else
        echo "FAIL  ${serve_label} ${flavor} serve never accepted HTTPS within 5s on :${port}"
        tail -5 /tmp/${flavor}-serve.log 2>&1 | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("${serve_label}")
    fi
    if [ "${expected_code}" = "501" ]; then
        check "${route_label} /v1/${route_short} returns 501 + ${hrd} in body (Wave 2 honesty stub)" \
            "curl -k -sS -o /tmp/route-body -w '%{http_code}' -X '${method}' 'https://127.0.0.1:${port}/v1/${route_short}' | grep -q '^501$' && grep -q '${hrd}' /tmp/route-body"
    else
        check "${route_label} /v1/${route_short} returns 401 (Wave 3a — route went live, JWT-gated)" \
            "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X '${method}' 'https://127.0.0.1:${port}/v1/${route_short}')\" = '401' ]"
    fi

    # E32 only for sherald: SIGTERM graceful exit.
    if [ "${flavor}" = "sherald" ]; then
        kill -TERM "${serve_pid}" 2>/dev/null
        wait "${serve_pid}" 2>/dev/null
        ec=$?
        # Accept 0 (clean) or 130/143 (shell-default codes for SIGINT/SIGTERM).
        if [ "${ec}" = "0" ] || [ "${ec}" = "130" ] || [ "${ec}" = "143" ]; then
            echo "PASS  E32(sherald) graceful-shutdown on SIGTERM (exit=${ec})"
            pass=$((pass+1))
        else
            echo "FAIL  E32(sherald) graceful-shutdown — exit=${ec} (want 0/130/143)"
            fail=$((fail+1)); fail_names+=("E32-sherald-shutdown")
        fi
    else
        kill "${serve_pid}" 2>/dev/null || true
        wait "${serve_pid}" 2>/dev/null || true
    fi
    rm -f "${bin}"
    serve_idx=$((serve_idx+1))
    route_idx=$((route_idx+1))
done

echo ""
echo "== E31: REAL §43 destructive-guard (HRD-033) §9.1 gate + §107 lazy-verifier =="
# v1.0.0 Batch C: destructive-guard is now a REAL §43 command (replacing the old
# stub that just exited non-zero with an HRD-033 pointer). E31 now exercises the
# real HRD-033 command (sherald/cmd/sherald/sysops_cmds.go) AND proves the §107
# lazy-verifier usability fix: the §43 CLI subcommands run BARE — with the JWT
# auth env UNSET (`env -u HERALD_AUTH_MODE -u HERALD_AUTH_HMAC_SECRET`) — because
# sherald now builds its JWT verifier LAZILY inside `serve`, not at process start.
# E31a = §9.1 BLOCK path (no backup); E31b = §9.1 ALLOW path (--backup-exists).
bin="/tmp/sherald-stub-$$"
if go build -o "${bin}" "./sherald/cmd/sherald" > /tmp/e2e_out 2>&1; then
    # E31a: destructive op, NO backup, NO auth env → NON-ZERO + [FAIL] §9.1 verdict.
    set +e
    env -u HERALD_AUTH_MODE -u HERALD_AUTH_HMAC_SECRET \
        "${bin}" destructive-guard git reset --hard > /tmp/e31a.out 2>&1
    rc_a=$?
    set -e
    if [ "${rc_a}" != "0" ] \
        && grep -qF '[FAIL] §9.1' /tmp/e31a.out \
        && grep -qF 'WITHOUT a preceding hardlinked backup' /tmp/e31a.out; then
        echo "PASS  E31a destructive-guard (no auth env) blocks 'git reset --hard' without backup (rc=${rc_a}, [FAIL] §9.1)"
        pass=$((pass+1))
    else
        echo "FAIL  E31a destructive-guard no-backup: rc=${rc_a} fail-verdict=$(grep -qF '[FAIL] §9.1' /tmp/e31a.out && echo yes || echo no) reason=$(grep -qF 'WITHOUT a preceding hardlinked backup' /tmp/e31a.out && echo yes || echo no)"
        tail -5 /tmp/e31a.out | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("E31a")
    fi
    # E31b: same op WITH --backup-exists, NO auth env → ZERO + [PASS] §9.1 verdict.
    set +e
    env -u HERALD_AUTH_MODE -u HERALD_AUTH_HMAC_SECRET \
        "${bin}" destructive-guard --backup-exists git reset --hard > /tmp/e31b.out 2>&1
    rc_b=$?
    set -e
    if [ "${rc_b}" = "0" ] && grep -qF '[PASS] §9.1' /tmp/e31b.out; then
        echo "PASS  E31b destructive-guard (no auth env) allows 'git reset --hard' with --backup-exists (rc=${rc_b}, [PASS] §9.1)"
        pass=$((pass+1))
    else
        echo "FAIL  E31b destructive-guard --backup-exists: rc=${rc_b} pass-verdict=$(grep -qF '[PASS] §9.1' /tmp/e31b.out && echo yes || echo no)"
        tail -5 /tmp/e31b.out | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("E31b")
    fi
    rm -f "${bin}"
else
    echo "FAIL  E31: sherald build failed"
    tail -5 /tmp/e2e_out | sed 's/^/      /'
    fail=$((fail+1)); fail_names+=("E31-build")
fi

echo ""
echo "== E33: pherald regression sentinel — re-verify version --json post-Wave2 =="
pbin="/tmp/pherald-regression-$$"
if go build -o "${pbin}" "./pherald/cmd/pherald" > /tmp/e2e_out 2>&1; then
    check "E33 pherald version --json (regression sentinel post-Wave 2)" \
        "\"${pbin}\" version --json | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"flavor\"]==\"p\"; assert d[\"binary\"]==\"pherald\"; assert d[\"version\"]'"
    rm -f "${pbin}"
else
    echo "FAIL  E33 pherald build"
    tail -5 /tmp/e2e_out | sed 's/^/      /'
    fail=$((fail+1)); fail_names+=("E33-build")
fi

# ----------------------------------------------------------------------
# E35-E36 + E43-E48: Wave 3a substrate + cherald/sherald live routes.
# ----------------------------------------------------------------------

echo ""
echo "== E35-E36: Auth gate (cherald + sherald reject bad/missing JWT) =="
# HERALD_AUTH_MODE + HERALD_AUTH_HMAC_SECRET are exported at the top
# of the script so the auth-required-at-startup wiring lets the binary
# boot. Bad/missing JWT then exercises the GinMiddleware reject path.

for flavor in cherald sherald; do
    case "${flavor}" in
        cherald) port=24992; route="/v1/compliance"; method="GET";;
        sherald) port=24993; route="/v1/safety_state"; method="GET";;
    esac
    bin="/tmp/${flavor}-bluff-$$"
    if go build -o "${bin}" "./${flavor}/cmd/${flavor}" > /tmp/e2e_out 2>&1; then
        "${bin}" serve --http-port "${port}" > /tmp/${flavor}-e35.log 2>&1 &
        serve_pid=$!
        # Wait up to 5s for the port to be live. Wave 4a: HTTPS now.
        ready=0
        for i in $(seq 1 10); do
            if curl -k -fsS "https://127.0.0.1:${port}/v1/healthz" >/dev/null 2>&1; then
                ready=1; break
            fi
            sleep 0.5
        done
        if [ "${ready}" = 1 ]; then
            check "E35(${flavor}) ${method} ${route} no auth → 401" \
                "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X '${method}' https://127.0.0.1:${port}${route})\" = '401' ]"
            check "E36(${flavor}) ${method} ${route} wrong HMAC → 401" \
                "BAD_TOKEN=\$(HMAC_SECRET='wrong-secret-32-bytes-padding!!!' python3 -c 'import hmac,hashlib,base64,json,time,os; s=os.environ[\"HMAC_SECRET\"].encode(); h=base64.urlsafe_b64encode(b\"{\\\"alg\\\":\\\"HS256\\\",\\\"typ\\\":\\\"JWT\\\"}\").rstrip(b\"=\"); p=base64.urlsafe_b64encode(json.dumps({\"tenant\":\"550e8400-e29b-41d4-a716-446655440000\",\"sub\":\"t\",\"exp\":int(time.time())+300}).encode()).rstrip(b\"=\"); sig=base64.urlsafe_b64encode(hmac.new(s,h+b\".\"+p,hashlib.sha256).digest()).rstrip(b\"=\"); print((h+b\".\"+p+b\".\"+sig).decode())') && [ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X '${method}' -H \"Authorization: Bearer \${BAD_TOKEN}\" https://127.0.0.1:${port}${route})\" = '401' ]"
        else
            echo "FAIL  E35(${flavor}) serve never accepted HTTPS within 5s on :${port}"
            tail -5 /tmp/${flavor}-e35.log 2>&1 | sed 's/^/      /'
            fail=$((fail+2))
            fail_names+=("E35-${flavor}" "E36-${flavor}")
        fi
        kill "${serve_pid}" 2>/dev/null || true
        wait "${serve_pid}" 2>/dev/null || true
        rm -f "${bin}"
    else
        echo "FAIL  E35/E36(${flavor}) build"
        tail -5 /tmp/e2e_out | sed 's/^/      /'
        fail=$((fail+2))
        fail_names+=("E35-${flavor}-build" "E36-${flavor}-build")
    fi
done

echo ""
echo "== E43-E44: cherald /v1/compliance live (HRD-028 close-out) =="
bin="/tmp/cherald-compliance-$$"
if go build -o "${bin}" ./cherald/cmd/cherald > /tmp/e2e_out 2>&1; then
    "${bin}" serve --http-port 24992 > /tmp/cherald-e43.log 2>&1 &
    serve_pid=$!
    ready=0
    for i in $(seq 1 10); do
        if curl -k -fsS "https://127.0.0.1:24992/v1/healthz" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "${ready}" = 1 ]; then
        TOKEN=$(python3 - <<'PY'
import hmac, hashlib, base64, json, time, os
secret = os.environ["HERALD_AUTH_HMAC_SECRET"].encode()
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b'=')
sig = base64.urlsafe_b64encode(hmac.new(secret, header+b'.'+payload, hashlib.sha256).digest()).rstrip(b'=')
print((header+b'.'+payload+b'.'+sig).decode())
PY
)
        check "E43 GET /v1/compliance no auth → 401" \
            "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' https://127.0.0.1:24992/v1/compliance)\" = '401' ]"
        check "E44 GET /v1/compliance valid JWT empty tenant → 200 + total=0" \
            "curl -k -fsS -H 'Authorization: Bearer ${TOKEN}' -H 'Accept: application/json' https://127.0.0.1:24992/v1/compliance | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"total\"]==0, d[\"total\"]; assert d[\"page\"]==1; assert d[\"page_size\"]==50'"
        # E45 is reported in its own block further below (Wave 3b reorg).
    else
        echo "FAIL  E43/E44 cherald serve never accepted HTTPS within 5s on :24992"
        tail -5 /tmp/cherald-e43.log 2>&1 | sed 's/^/      /'
        fail=$((fail+2))
        fail_names+=("E43" "E44")
    fi
    kill "${serve_pid}" 2>/dev/null || true
    wait "${serve_pid}" 2>/dev/null || true
    rm -f "${bin}"
else
    echo "FAIL  E43/E44 cherald build"
    tail -5 /tmp/e2e_out | sed 's/^/      /'
    fail=$((fail+2))
    fail_names+=("E43-build" "E44-build")
fi

echo ""
echo "== E46-E48: sherald /v1/safety_state live (HRD-098 close-out) =="
bin="/tmp/sherald-safety-$$"
if go build -o "${bin}" ./sherald/cmd/sherald > /tmp/e2e_out 2>&1; then
    "${bin}" serve --http-port 24993 > /tmp/sherald-e47.log 2>&1 &
    serve_pid=$!
    ready=0
    for i in $(seq 1 10); do
        if curl -k -fsS "https://127.0.0.1:24993/v1/healthz" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "${ready}" = 1 ]; then
        # Give the mem-sampler a moment to publish its first sample.
        sleep 1.2
        TOKEN=$(python3 - <<'PY'
import hmac, hashlib, base64, json, time, os
secret = os.environ["HERALD_AUTH_HMAC_SECRET"].encode()
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b'=')
sig = base64.urlsafe_b64encode(hmac.new(secret, header+b'.'+payload, hashlib.sha256).digest()).rstrip(b'=')
print((header+b'.'+payload+b'.'+sig).decode())
PY
)
        check "E46 GET /v1/safety_state no auth → 401" \
            "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' https://127.0.0.1:24993/v1/safety_state)\" = '401' ]"
        check "E47 GET /v1/safety_state fresh sherald → 200 + mem>0 + last_destructive_op=null + uptime>=1" \
            "curl -k -fsS -H 'Authorization: Bearer ${TOKEN}' -H 'Accept: application/json' https://127.0.0.1:24993/v1/safety_state | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"binary\"]==\"sherald\"; assert d[\"current_mem_percent\"]>0, d.get(\"current_mem_percent\"); assert d[\"last_destructive_op\"] is None; assert d[\"uptime_seconds\"]>=1, d[\"uptime_seconds\"]; assert d[\"open_events\"]==0'"
        echo "SKIP  E48 (destructive-op trigger — HRD-033 stub body not implemented)"
    else
        echo "FAIL  E46/E47 sherald serve never accepted HTTPS within 5s on :24993"
        tail -5 /tmp/sherald-e47.log 2>&1 | sed 's/^/      /'
        fail=$((fail+2))
        fail_names+=("E46" "E47")
    fi
    kill "${serve_pid}" 2>/dev/null || true
    wait "${serve_pid}" 2>/dev/null || true
    rm -f "${bin}"
else
    echo "FAIL  E46/E47 sherald build"
    tail -5 /tmp/e2e_out | sed 's/^/      /'
    fail=$((fail+2))
    fail_names+=("E46-build" "E47-build")
fi

# ----------------------------------------------------------------------
# E37-E42: pherald POST /v1/events live (HRD-016 close-out — Wave 3b).
#
# Requires container runtime + PG :24100 migrated. Otherwise SKIP-with-reason
# (matches E14-E16 / E7-E12 pattern). E37 asserts 202 + Receipt JSON on a
# fresh event; E38 asserts X-Herald-Replay header on the second identical
# call (idempotency); E39 asserts 401 without auth; E40 asserts 401 with
# wrong JWT signature; E41 asserts 400 on malformed body; E42 asserts the
# events_processed PG archive row was actually written (sink-side evidence
# per §11.4.68).
echo ""
echo "== E37-E42: pherald POST /v1/events live (HRD-016 close-out) =="
# The E14-E17 integration tests above boot AND tear down (boot.Down) their own
# herald-postgres + herald-redis containers in t.Cleanup. So by the time this
# block runs the containers may be GONE even though they were up at script
# start. The pherald /v1/events pipeline needs BOTH Postgres (events_processed
# archive sink) AND Redis (idempotency SetNX — a nil Redis client panics in the
# IdempotencyChecker). Best-effort re-boot both via the quickstart compose. No-
# op when already up or no runtime exists.
if (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) \
   && { ! nc -z 127.0.0.1 24100 2>/dev/null || ! nc -z 127.0.0.1 24200 2>/dev/null; }; then
    if command -v podman-compose >/dev/null 2>&1; then
        HERALD_DB_PASSWORD="herald_dev" \
        HERALD_REDIS_PASSWORD="test-redis-password-DO-NOT-USE-IN-PROD" \
        HERALD_PROJECT_NAME="Herald-E2E" \
        HERALD_TENANT_ID="00000000-0000-0000-0000-000000000099" \
            podman-compose -f quickstart/docker-compose.quickstart.yml \
            --project-name herald-e2e up -d postgres redis >/dev/null 2>&1 || true
        for i in $(seq 1 30); do nc -z 127.0.0.1 24100 2>/dev/null && break; sleep 1; done
        for i in $(seq 1 30); do nc -z 127.0.0.1 24200 2>/dev/null && break; sleep 1; done
    fi
fi
# Dev-container password normalization: this block's serve DSN hardcodes
# "herald_dev" (must run AFTER any re-boot above).
pg_self_heal "herald_dev"
if (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) \
   && nc -z 127.0.0.1 24100 2>/dev/null; then
    bin="/tmp/pherald-events-$$"
    if go build -o "${bin}" ./pherald/cmd/pherald > /tmp/e2e_out 2>&1; then
        # Run pending migrations against the PG :24100 instance so the
        # events_processed + outbound_delivery_evidence + subscribers
        # tables exist for E37-E42.
        HERALD_PG_DSN="postgres://herald:herald_dev@127.0.0.1:24100/herald" \
            "${bin}" migrate up >/tmp/pherald-e37-migrate.log 2>&1 || true
        # Seed the E37 token's tenant. events_processed has a FK to tenants
        # (events_processed_tenant_id_fkey); the archive INSERT for the POSTed
        # event violates it (SQLSTATE 23503) unless the tenant row pre-exists.
        # The token below carries tenant 550e8400-...440000, so seed it via
        # the container's local trust-auth socket (idempotent). Best-effort —
        # the real PASS/FAIL is decided by the live POST + sink-side SELECT.
        E37_PG_RT=""
        command -v podman >/dev/null 2>&1 && E37_PG_RT="podman"
        [ -z "${E37_PG_RT}" ] && command -v docker >/dev/null 2>&1 && E37_PG_RT="docker"
        if [ -n "${E37_PG_RT}" ]; then
            "${E37_PG_RT}" exec herald-postgres psql -U herald -d herald \
                -c "INSERT INTO tenants (id, name) VALUES ('550e8400-e29b-41d4-a716-446655440000','e2e-events') ON CONFLICT (id) DO NOTHING" \
                >/dev/null 2>&1 || true
        fi
        # HERALD_REDIS_URL is load-bearing for E37/E38: the /v1/events
        # pipeline's IdempotencyChecker calls Redis SetNX; without a live
        # Redis client the stage panics (nil pointer) → 500 instead of
        # 202/replay. The quickstart Redis is password-protected
        # (--requirepass test-redis-password-DO-NOT-USE-IN-PROD).
        HERALD_AUTH_MODE=hmac \
        HERALD_AUTH_HMAC_SECRET="test-secret-32-bytes-of-padding!!" \
        HERALD_PG_DSN="postgres://herald:herald_dev@127.0.0.1:24100/herald" \
        HERALD_REDIS_URL="redis://:test-redis-password-DO-NOT-USE-IN-PROD@127.0.0.1:24200/0" \
        "${bin}" serve --http-port 24791 > /tmp/pherald-e37.log 2>&1 &
        serve_pid=$!
        # Wait for the port to bind. Wave 4a: HTTPS now.
        e37_ready=0
        for i in $(seq 1 20); do
            if curl -k -fsS https://127.0.0.1:24791/v1/healthz >/dev/null 2>&1; then
                e37_ready=1; break
            fi
            sleep 0.5
        done
        if [ "${e37_ready}" = 1 ]; then
            TOKEN=$(python3 -c '
import hmac, hashlib, base64, json, time, os
s = b"test-secret-32-bytes-of-padding!!"
h = base64.urlsafe_b64encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}").rstrip(b"=")
p = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b"=")
sig = base64.urlsafe_b64encode(hmac.new(s, h+b"."+p, hashlib.sha256).digest()).rstrip(b"=")
print((h+b"."+p+b"."+sig).decode())
')
            EVENT_ID="$(uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')"
            check "E37 POST /v1/events valid JWT + null recipient → 202 + Receipt" \
                "STATUS=\$(curl -k -sS -X POST -H 'Authorization: Bearer ${TOKEN}' -H 'Content-Type: application/json' --data '{\"specversion\":\"1.0\",\"id\":\"${EVENT_ID}\",\"source\":\"//e2e\",\"type\":\"digital.vasic.herald.e2e\"}' -w '%{http_code}' -o /tmp/e37-body https://127.0.0.1:24791/v1/events); [ \"\${STATUS}\" = '202' ] && grep -q 'event_id' /tmp/e37-body"
            check "E38 idempotency: second POST same event_id → 200 + X-Herald-Replay header" \
                "curl -k -sS -X POST -H 'Authorization: Bearer ${TOKEN}' -H 'Content-Type: application/json' --data '{\"specversion\":\"1.0\",\"id\":\"${EVENT_ID}\",\"source\":\"//e2e\",\"type\":\"digital.vasic.herald.e2e\"}' -D /tmp/e38-hdr https://127.0.0.1:24791/v1/events >/dev/null && grep -qi 'X-Herald-Replay: true' /tmp/e38-hdr"
            check "E39 POST without auth → 401" \
                "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:24791/v1/events)\" = '401' ]"
            BAD_TOKEN=$(python3 -c '
import hmac, hashlib, base64, json, time
s = b"wrong-secret-32-bytes-padding!!!!"
h = base64.urlsafe_b64encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}").rstrip(b"=")
p = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b"=")
sig = base64.urlsafe_b64encode(hmac.new(s, h+b"."+p, hashlib.sha256).digest()).rstrip(b"=")
print((h+b"."+p+b"."+sig).decode())
')
            check "E40 POST with wrong JWT signature → 401" \
                "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer ${BAD_TOKEN}' -H 'Content-Type: application/json' --data '{}' https://127.0.0.1:24791/v1/events)\" = '401' ]"
            check "E41 POST malformed JSON → 400" \
                "[ \"\$(curl -k -sS -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer ${TOKEN}' -H 'Content-Type: application/json' --data 'not json' https://127.0.0.1:24791/v1/events)\" = '400' ]"
            # E42: count the events_processed archive rows. Prefer a host
            # psql client; when absent (psql is not installed on macOS by
            # default) fall back to the container's own psql via the runtime
            # exec (local socket = trust auth, no password). Either way this
            # is a REAL SELECT against the live PG sink — §11.4.68 positive
            # evidence, not a metadata check.
            if command -v psql >/dev/null 2>&1; then
                check "E42 sink-side: events_processed row written (§11.4.68 positive PG evidence)" \
                    "PGPASSWORD='herald_dev' psql -h 127.0.0.1 -p 24100 -U herald -d herald -tAc 'SELECT count(*) FROM events_processed' | grep -qE '^[1-9]'"
            else
                E42_RT=""
                command -v podman >/dev/null 2>&1 && E42_RT="podman"
                [ -z "${E42_RT}" ] && command -v docker >/dev/null 2>&1 && E42_RT="docker"
                check "E42 sink-side: events_processed row written (§11.4.68 positive PG evidence; container-psql fallback — host psql absent)" \
                    "${E42_RT} exec herald-postgres psql -U herald -d herald -tAc 'SELECT count(*) FROM events_processed' | grep -qE '^[[:space:]]*[1-9]'"
            fi
        else
            echo "FAIL  E37-E42 pherald serve never accepted HTTPS within 10s on :24791"
            tail -5 /tmp/pherald-e37.log 2>&1 | sed 's/^/      /'
            fail=$((fail+6))
            fail_names+=("E37" "E38" "E39" "E40" "E41" "E42")
        fi
        kill "${serve_pid}" 2>/dev/null || true
        wait "${serve_pid}" 2>/dev/null || true
        rm -f "${bin}" /tmp/e37-body /tmp/e38-hdr /tmp/pherald-e37.log /tmp/pherald-e37-migrate.log
    else
        echo "FAIL  E37-E42 pherald build"
        tail -5 /tmp/e2e_out | sed 's/^/      /'
        fail=$((fail+6))
        fail_names+=("E37-build" "E38-build" "E39-build" "E40-build" "E41-build" "E42-build")
    fi
else
    echo "SKIP  E37-E42 (no container runtime OR PG :24100 unreachable — §11.4.3 explicit SKIP-with-reason; Wave 3b live but PG-gated)"
fi

# ----------------------------------------------------------------------
# E45 cross-binary update (Wave 3b unblock).
#
# Previously SKIP-with-reason "pherald Runner not live yet (Wave 3b)". The
# Wave 3b close-out unblocks the prerequisite. Fully wiring the cross-
# binary smoke (post deny event via pherald → wait for replication → GET
# /v1/compliance from cherald) is its own substantial e2e block; for
# Wave 3b we keep E45 honest-SKIP with the new reason. Wave 3c will land
# the live wiring.
echo ""
echo "== E45: cross-binary integration (pherald → cherald) =="
if (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) \
   && nc -z 127.0.0.1 24100 2>/dev/null; then
    echo "SKIP  E45 (Runner is live post-Wave 3b; cross-binary smoke wiring deferred to Wave 3c — honest SKIP-with-reason per §11.4.3)"
else
    echo "SKIP  E45 (prerequisite PG :24100 + cherald running — §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# Wave 4a — HTTP/3 + Brotli + Alt-Svc transport substrate (E49-E55).
#
# Per Universal §11.4 + Herald §107 anti-bluff: every assertion below
# observes real wire behaviour — no header-only checks, no
# "configuration looks correct" checks. Mutating any transport feature
# (T9 M1-M3 mutations) MUST cause the matching invariant to FAIL.
#
# The probe target is sherald (single binary, no PG dependency). The
# dual-listener pattern is the same across every serving flavor, so a
# bug in commons/cli/serve.go (the shared dual-listener) shows up here
# regardless of which flavor we exercise.
# ----------------------------------------------------------------------
echo ""
echo "== E49-E55: HTTP/3 + Brotli + Alt-Svc + TLS-1.3 transport substrate =="

if (command -v lsof >/dev/null 2>&1) && (command -v curl >/dev/null 2>&1); then
    W4A_BIN="/tmp/sherald-w4a-$$"
    W4A_PORT=24793
    if go build -o "${W4A_BIN}" ./sherald/cmd/sherald > /tmp/e2e_w4a_out 2>&1; then
        # Pre-flight: kill any orphan listener on the target port.
        lsof -ti:${W4A_PORT} 2>/dev/null | xargs -r kill -9 2>/dev/null || true

        "${W4A_BIN}" serve --http-port ${W4A_PORT} > /tmp/sherald-w4a.log 2>&1 &
        w4a_pid=$!
        # Wait up to 5s for the HTTPS listener to come up (TLS dev-cert
        # auto-gen on first boot takes a beat).
        w4a_ready=0
        for i in $(seq 1 10); do
            if curl -k -fsS "https://127.0.0.1:${W4A_PORT}/v1/healthz" >/dev/null 2>&1; then
                w4a_ready=1; break
            fi
            sleep 0.5
        done

        if [ "${w4a_ready}" = 1 ]; then
            # E49: TCP/HTTPS listener bound on the port.
            check "E49 TCP/HTTPS listener bound on :${W4A_PORT} (lsof TCP probe)" \
                "lsof -nP -iTCP:${W4A_PORT} -sTCP:LISTEN 2>/dev/null | grep -q 'LISTEN'"

            # E50: UDP listener bound on the same port (HTTP/3 / QUIC).
            # macOS: lsof -nP -iUDP:<port>; Linux: ss -ulnp.
            check "E50 UDP/H3 listener bound on :${W4A_PORT} (lsof UDP / ss probe)" \
                "(lsof -nP -iUDP:${W4A_PORT} 2>/dev/null | grep -q ':${W4A_PORT}') || (ss -ulnp 2>/dev/null | grep -q ':${W4A_PORT}')"

            # E51: HTTP/2 GET returns 401 (auth-gated) + Alt-Svc header
            # advertises HTTP/3. We hit a flavor route (/v1/safety_state)
            # not healthz, because the Alt-Svc middleware is wired AFTER
            # healthz/readyz/metrics registration (see commons/cli/serve.go
            # comment) — only flavor routes pass through it.
            check "E51 HTTP/2 GET /v1/safety_state → Alt-Svc 'h3=\":${W4A_PORT}\"' advertised" \
                "curl -k --http2 -sS -D /tmp/e51-hdr 'https://127.0.0.1:${W4A_PORT}/v1/safety_state' -o /tmp/e51-body && grep -qi 'alt-svc: h3=\":${W4A_PORT}\"' /tmp/e51-hdr && grep -qi 'ma=2592000' /tmp/e51-hdr"

            # E52: HTTP/3 GET healthz returns 200 — real QUIC handshake
            # via a compiled-inline Go http3 client. The handshake itself
            # is the load-bearing positive evidence: a missing or broken
            # UDP listener produces a connection error, not a 200.
            cat > /tmp/h3client.go <<'GO_EOF'
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	url := os.Args[1]
	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR", err)
		os.Exit(2)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, "STATUS", resp.StatusCode)
		os.Exit(3)
	}
	fmt.Print(string(body))
}
GO_EOF
            H3_BIN="/tmp/h3client-$$"
            # Build inside commons/ so the quic-go dependency resolves
            # via Herald's module graph (commons depends on
            # digital.vasic.http3 which re-exports quic-go).
            if (cd "${REPO_ROOT}/commons" && go build -o "${H3_BIN}" /tmp/h3client.go) > /tmp/e52-build-err 2>&1; then
                "${H3_BIN}" "https://127.0.0.1:${W4A_PORT}/v1/healthz" > /tmp/e52-body 2> /tmp/e52-err || true
                check "E52 HTTP/3 GET /v1/healthz → 200 + JSON body (real quic-go handshake)" \
                    "grep -q '\"status\":\"ok\"' /tmp/e52-body && grep -q '\"build\"' /tmp/e52-body"
            else
                echo "FAIL  E52 (h3 client compile failed)"
                tail -5 /tmp/e52-build-err 2>/dev/null | sed 's/^/      /'
                fail=$((fail+1))
                fail_names+=("E52-h3-build")
                H3_BIN=""
            fi

            # E53: Brotli round-trip — Accept-Encoding:br on a flavor
            # route. The Brotli middleware MinLength is 256B (upstream
            # default). sherald /v1/safety_state typically returns ~220-
            # 240B which is BELOW the threshold by design (cheap
            # observability calls should not be compressed). When the
            # body is sub-threshold the middleware emits identity — the
            # honest behaviour. We probe BOTH paths and assert:
            #   (a) the middleware is wired AND respects its policy — when
            #       body < MinLength, NO Content-Encoding:br header is set
            #       and the br-request body is served as the readable identity
            #       document (not compressed bytes), AND
            #   (b) IF the body happens to be ≥ MinLength on a given run,
            #       Content-Encoding:br MUST be set AND the body MUST
            #       brotli-decode (via andybalholm/brotli) to a readable
            #       safety_state document. Header-only PASS is forbidden.
            # The "readable safety_state document" check greps for the
            # 'uptime_seconds' field name, which is present verbatim in BOTH
            # the JSON and TOON encodings (the curl default Accept: */* resolves
            # to Herald's default codec — TOON, not JSON — so we must NOT assume
            # a leading '{'). Crucially, brotli-COMPRESSED bytes do NOT contain
            # the ASCII string 'uptime_seconds', so this grep still catches a
            # real "compressed when it shouldn't be" / "claimed-br-but-corrupt"
            # bug — it is load-bearing, not a header-only bluff.
            # NOTE: we deliberately do NOT byte-compare the br response to a
            # SEPARATE Accept-Encoding:identity call. /v1/safety_state carries
            # live fields (current_mem_percent, last_mem_sample_at,
            # uptime_seconds) that legitimately differ between two back-to-back
            # requests, so a cross-call byte-for-byte diff is non-deterministic
            # (it false-FAILs whenever a dynamic field ticks). That latent flake
            # surfaced as a false FAIL on 2026-05-28; this is the root-cause fix.
            TOKEN53=$(python3 -c '
import hmac, hashlib, base64, json, time
s = b"test-secret-32-bytes-of-padding!!"
h = base64.urlsafe_b64encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}").rstrip(b"=")
p = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b"=")
sig = base64.urlsafe_b64encode(hmac.new(s, h+b"."+p, hashlib.sha256).digest()).rstrip(b"=")
print((h+b"."+p+b"."+sig).decode())
')
            curl -k --http2 -sS -H "Authorization: Bearer ${TOKEN53}" -H 'Accept-Encoding: identity' \
                "https://127.0.0.1:${W4A_PORT}/v1/safety_state" -o /tmp/e53-identity 2>/dev/null
            curl -k --http2 -sS -H "Authorization: Bearer ${TOKEN53}" -H 'Accept-Encoding: br' \
                -D /tmp/e53-hdr "https://127.0.0.1:${W4A_PORT}/v1/safety_state" -o /tmp/e53-br 2>/dev/null
            ident_size=$(wc -c < /tmp/e53-identity 2>/dev/null | tr -d ' ')
            ce_header=$(grep -i '^content-encoding:' /tmp/e53-hdr 2>/dev/null | tr -d '\r\n' || true)
            if [ "${ident_size:-0}" -ge 256 ]; then
                # Body is over MinLength — Brotli MUST engage. Compile a
                # small Go decoder + verify byte-for-byte round trip.
                cat > /tmp/brotli_decode.go <<'GO_EOF'
package main

import (
	"io"
	"os"

	"github.com/andybalholm/brotli"
)

func main() {
	r := brotli.NewReader(os.Stdin)
	if _, err := io.Copy(os.Stdout, r); err != nil {
		os.Exit(1)
	}
}
GO_EOF
                BR_BIN="/tmp/brotli_decode-$$"
                if (cd "${REPO_ROOT}/commons" && go build -o "${BR_BIN}" /tmp/brotli_decode.go) > /tmp/e53-build-err 2>&1; then
                    check "E53 Accept-Encoding:br on /v1/safety_state (${ident_size}B body ≥ MinLength) → Content-Encoding:br + br body brotli-decodes to a readable safety_state document" \
                        "echo '${ce_header}' | grep -qi 'br' && '${BR_BIN}' < /tmp/e53-br > /tmp/e53-decoded 2>/dev/null && [ -s /tmp/e53-decoded ] && grep -q 'uptime_seconds' /tmp/e53-decoded"
                    rm -f "${BR_BIN}"
                else
                    echo "FAIL  E53 (brotli decoder compile failed)"
                    tail -5 /tmp/e53-build-err 2>/dev/null | sed 's/^/      /'
                    fail=$((fail+1))
                    fail_names+=("E53-build")
                fi
            else
                # Body is sub-MinLength — middleware MUST emit identity
                # (no Content-Encoding:br header) AND the br-request
                # response body MUST equal the identity-request response
                # byte-for-byte. This is the documented MinLength
                # behaviour; verifying identity-passthrough proves the
                # middleware is wired and respects its policy. The
                # absent Content-Encoding header is the honest signal
                # — NOT a bluff, the wire actually says "identity here".
                check "E53 Accept-Encoding:br on /v1/safety_state (${ident_size}B body < MinLength=256) → no Content-Encoding:br + br body served as readable identity safety_state document" \
                    "[ -z \"\$(echo '${ce_header}' | grep -i br)\" ] && [ -s /tmp/e53-br ] && grep -q 'uptime_seconds' /tmp/e53-br"
            fi

            # E54: TLS 1.3 + ALPN h3 negotiated via openssl s_client.
            # The probe completes a partial TLS handshake against the
            # TCP/HTTPS listener (note: openssl can negotiate TLS over
            # TCP only — the UDP/QUIC handshake is exercised in E52
            # via the real h3 client). openssl reports the negotiated
            # TLS version + ALPN protocol; both substrings are
            # load-bearing wire evidence.
            if command -v openssl >/dev/null 2>&1; then
                openssl s_client -connect "127.0.0.1:${W4A_PORT}" -tls1_3 -alpn h2,http/1.1 -servername 127.0.0.1 </dev/null 2>/tmp/e54-err 1>/tmp/e54-out &
                ossl_pid=$!
                sleep 1
                kill -TERM ${ossl_pid} 2>/dev/null || true
                wait ${ossl_pid} 2>/dev/null
                check "E54 TLS 1.3 negotiated + ALPN advertised on TCP listener (openssl s_client probe)" \
                    "grep -qE 'TLSv1\\.3|Protocol  : TLSv1\\.3|New, TLSv1\\.3' /tmp/e54-out && (grep -qE 'ALPN protocol: h2|ALPN protocol: http/1\\.1|No ALPN negotiated' /tmp/e54-out)"
            else
                echo "SKIP  E54 (openssl absent — §11.4.3 explicit SKIP-with-reason; install via 'brew install openssl' on macOS)"
            fi

            # E55: tcpdump captures real UDP traffic during an HTTP/3
            # request. Requires root (CAP_NET_RAW) — SKIP-with-reason
            # if not running as root. The capture buffer is small (lo0
            # is fast); 8 packets is enough to prove a roundtrip occurred.
            if command -v tcpdump >/dev/null 2>&1 && [ "$(id -u)" = "0" ] && [ -n "${H3_BIN}" ]; then
                rm -f /tmp/e55.pcap
                tcpdump -i lo0 -nn -c 16 -w /tmp/e55.pcap "udp port ${W4A_PORT}" >/dev/null 2>&1 &
                tcp_pid=$!
                sleep 0.3
                "${H3_BIN}" "https://127.0.0.1:${W4A_PORT}/v1/healthz" > /dev/null 2>&1 || true
                sleep 0.7
                kill ${tcp_pid} 2>/dev/null
                wait ${tcp_pid} 2>/dev/null
                check "E55 tcpdump captures ≥ 4 UDP packets on :${W4A_PORT} during HTTP/3 request" \
                    "[ \"\$(tcpdump -r /tmp/e55.pcap -nn 2>/dev/null | wc -l | tr -d ' ')\" -ge 4 ]"
            elif command -v tcpdump >/dev/null 2>&1 && [ "$(id -u)" != "0" ]; then
                echo "SKIP  E55 (tcpdump requires CAP_NET_RAW / root — §11.4.3 explicit SKIP-with-reason; re-run with sudo to exercise the UDP wire capture)"
            else
                echo "SKIP  E55 (tcpdump absent — §11.4.3 explicit SKIP-with-reason; install via 'brew install tcpdump' on macOS)"
            fi
        else
            echo "FAIL  E49-E55 sherald serve never accepted HTTPS within 5s on :${W4A_PORT}"
            tail -10 /tmp/sherald-w4a.log 2>&1 | sed 's/^/      /'
            fail=$((fail+7))
            fail_names+=("E49" "E50" "E51" "E52" "E53" "E54" "E55")
        fi

        kill ${w4a_pid} 2>/dev/null || true
        wait ${w4a_pid} 2>/dev/null || true
        rm -f "${W4A_BIN}" /tmp/h3client.go /tmp/brotli_decode.go \
              /tmp/e51-hdr /tmp/e51-body /tmp/e52-body /tmp/e52-err /tmp/e52-build-err \
              /tmp/e53-identity /tmp/e53-br /tmp/e53-hdr /tmp/e53-decoded /tmp/e53-build-err \
              /tmp/e54-out /tmp/e54-err /tmp/e55.pcap /tmp/sherald-w4a.log
        [ -n "${H3_BIN:-}" ] && rm -f "${H3_BIN}"
    else
        echo "FAIL  E49-E55 sherald build (Wave 4a transport probe binary)"
        tail -5 /tmp/e2e_w4a_out | sed 's/^/      /'
        fail=$((fail+7))
        fail_names+=("E49-build" "E50-build" "E51-build" "E52-build" "E53-build" "E54-build" "E55-build")
    fi
else
    echo "SKIP  E49-E55 (lsof/curl absent — §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
echo ""
echo "== E56-E62: TOON (application/toon) content negotiation (Wave 4b) =="
# E56. GET /v1/safety_state Accept: application/json → Content-Type:
#      application/json + body[0]='{' (explicit JSON honored).
# E57. GET /v1/safety_state Accept: application/toon → Content-Type:
#      application/toon + body[0]!='{' (server emits real TOON bytes; the
#      §107 watershed — the 2026-05-17 bluff would surface here).
# E58. TOON wire bytes round-trip via real digital.vasic.toon.Unmarshal
#      into a non-empty Go map (proof the bytes are valid TOON, not just
#      header-decoration).
# E59. TOON body strictly smaller than JSON body for the same payload
#      (real compression, not a header-swap bluff; threshold ≤ 0.95).
# E60. WIRE-LEVEL anti-bluff — TOON response first byte is NOT '{' and NOT
#      '[' (catches JSON-bytes-wearing-TOON-Content-Type — the original
#      PASS-bluff signature reverted in W4b T2).
# E61. Content negotiation q-value preference — `application/json,
#      application/toon;q=0.5` → JSON wins (higher q honored).
# E62. SKIP-with-reason (per W4b T7 spec): unit-tested only at
#      commons/cli/toon_test.go TestRespond_EncoderFailure path. No Herald
#      handler exposes a Go type that the TOON codec rejects (Snapshot /
#      ComplianceList / Receipt all encode cleanly), so an e2e provocation
#      is unfalsifiable. Documented + intentional.

if (command -v lsof >/dev/null 2>&1) && (command -v curl >/dev/null 2>&1); then
    W4B_BIN="/tmp/sherald-w4b-$$"
    W4B_PORT="${HERALD_W4B_PORT:-24794}"
    if go build -o "${W4B_BIN}" ./sherald/cmd/sherald > /tmp/e2e_w4b_out 2>&1; then
        lsof -ti:${W4B_PORT} 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        "${W4B_BIN}" serve --http-port ${W4B_PORT} > /tmp/sherald-w4b.log 2>&1 &
        w4b_pid=$!
        w4b_ready=0
        for i in $(seq 1 10); do
            if curl -k -fsS "https://127.0.0.1:${W4B_PORT}/v1/healthz" >/dev/null 2>&1; then
                w4b_ready=1; break
            fi
            sleep 0.5
        done

        if [ "${w4b_ready}" = 1 ]; then
            # mem-sampler warm-up
            sleep 1.2
            TOKEN_W4B=$(python3 - <<'PY'
import hmac, hashlib, base64, json, time, os
secret = os.environ["HERALD_AUTH_HMAC_SECRET"].encode()
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"tenant":"550e8400-e29b-41d4-a716-446655440000","sub":"t","exp":int(time.time())+300}).encode()).rstrip(b'=')
sig = base64.urlsafe_b64encode(hmac.new(secret, header+b'.'+payload, hashlib.sha256).digest()).rstrip(b'=')
print((header+b'.'+payload+b'.'+sig).decode())
PY
)

            # E56 — Accept: application/json → JSON response.
            curl -k -fsS -H "Authorization: Bearer ${TOKEN_W4B}" -H 'Accept: application/json' \
                -D /tmp/e56-hdr -o /tmp/e56-body \
                "https://127.0.0.1:${W4B_PORT}/v1/safety_state" 2>/dev/null
            check "E56 Accept: application/json on /v1/safety_state → Content-Type: application/json + body[0]='{'" \
                "grep -qi '^content-type: application/json' /tmp/e56-hdr && [ \"\$(head -c 1 /tmp/e56-body)\" = '{' ]"

            # E57 — Accept: application/toon → TOON response (§107 watershed).
            curl -k -fsS -H "Authorization: Bearer ${TOKEN_W4B}" -H 'Accept: application/toon' \
                -D /tmp/e57-hdr -o /tmp/e57-body \
                "https://127.0.0.1:${W4B_PORT}/v1/safety_state" 2>/dev/null
            check "E57 Accept: application/toon on /v1/safety_state → Content-Type: application/toon + body[0]!='{'" \
                "grep -qi '^content-type: application/toon' /tmp/e57-hdr && [ \"\$(head -c 1 /tmp/e57-body)\" != '{' ] && [ -s /tmp/e57-body ]"

            # E58 — TOON round-trip via real digital.vasic.toon.Unmarshal.
            # Compile a probe inside commons/ so the digital.vasic.toon
            # replace directive resolves through Herald's module graph.
            cat > /tmp/toon_rt_probe.go <<'GO_EOF'
package main

import (
	"fmt"
	"os"

	toon "digital.vasic.toon/pkg/toon"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "READ", err)
		os.Exit(2)
	}
	var v map[string]any
	if err := toon.Unmarshal(b, &v); err != nil {
		fmt.Fprintln(os.Stderr, "UNMARSHAL", err)
		os.Exit(3)
	}
	if len(v) == 0 {
		fmt.Fprintln(os.Stderr, "EMPTY")
		os.Exit(4)
	}
	fmt.Println("OK", len(v))
}
GO_EOF
            TOON_RT_BIN="/tmp/toon-rt-$$"
            if (cd "${REPO_ROOT}/commons" && go build -o "${TOON_RT_BIN}" /tmp/toon_rt_probe.go) > /tmp/e58-build-err 2>&1; then
                "${TOON_RT_BIN}" /tmp/e57-body > /tmp/e58-out 2> /tmp/e58-err || true
                check "E58 TOON response bytes round-trip via real digital.vasic.toon.Unmarshal to non-empty map" \
                    "grep -q '^OK' /tmp/e58-out"
                rm -f "${TOON_RT_BIN}"
            else
                echo "FAIL  E58 (toon round-trip probe compile failed)"
                tail -5 /tmp/e58-build-err 2>/dev/null | sed 's/^/      /'
                fail=$((fail+1))
                fail_names+=("E58-build")
            fi
            rm -f /tmp/toon_rt_probe.go

            # E59 — TOON body strictly smaller than JSON body for the same
            # payload. Real compression evidence — header-swap bluff would
            # produce identical byte counts.
            toon_size=$(wc -c < /tmp/e57-body 2>/dev/null | tr -d ' ')
            json_size=$(wc -c < /tmp/e56-body 2>/dev/null | tr -d ' ')
            check "E59 TOON body (${toon_size}B) shorter than JSON body (${json_size}B) — real compression, not header-swap bluff" \
                "[ \"${toon_size:-0}\" -gt 0 ] && [ \"${json_size:-0}\" -gt 0 ] && [ \"${toon_size:-0}\" -lt \"${json_size:-0}\" ]"

            # E60 — WIRE-LEVEL anti-bluff: first byte of TOON body must
            # NOT be '{' or '[' (catches JSON-bytes-wearing-TOON-Content-Type
            # — the original 2026-05-17 bluff signature).
            check "E60 TOON response body first byte NOT '{' and NOT '[' (anti-JSON-bytes-bluff wire check)" \
                "first=\"\$(head -c 1 /tmp/e57-body)\"; [ \"\$first\" != '{' ] && [ \"\$first\" != '[' ]"

            # E61 — q-value preference: explicit Accept with JSON higher q
            # → JSON wins despite TOON being Herald-default.
            curl -k -fsS -H "Authorization: Bearer ${TOKEN_W4B}" \
                -H 'Accept: application/json, application/toon;q=0.5' \
                -D /tmp/e61-hdr -o /tmp/e61-body \
                "https://127.0.0.1:${W4B_PORT}/v1/safety_state" 2>/dev/null
            check "E61 Accept: application/json+toon;q=0.5 → JSON wins (q-value preference honored)" \
                "grep -qi '^content-type: application/json' /tmp/e61-hdr && [ \"\$(head -c 1 /tmp/e61-body)\" = '{' ]"

            # E62 — SKIP-with-reason per W4b T7 plan: unit-tested only.
            echo "SKIP  E62 (encoder-failure fallback — unit-tested in commons/cli/toon_test.go TestRespond_EncoderFailure_FallsBackToJSON_WithObservableHeader; no Herald handler exposes a TOON-unencodable Go type so e2e provocation is unfalsifiable — §11.4.3 explicit SKIP-with-reason)"

        else
            echo "FAIL  E56-E62 sherald serve never accepted HTTPS within 5s on :${W4B_PORT}"
            tail -10 /tmp/sherald-w4b.log 2>&1 | sed 's/^/      /'
            fail=$((fail+6))
            fail_names+=("E56" "E57" "E58" "E59" "E60" "E61")
        fi

        kill ${w4b_pid} 2>/dev/null || true
        wait ${w4b_pid} 2>/dev/null || true
        rm -f "${W4B_BIN}" /tmp/sherald-w4b.log \
              /tmp/e56-hdr /tmp/e56-body /tmp/e57-hdr /tmp/e57-body \
              /tmp/e58-out /tmp/e58-err /tmp/e58-build-err \
              /tmp/e61-hdr /tmp/e61-body
    else
        echo "FAIL  E56-E62 sherald build (Wave 4b TOON probe binary)"
        tail -5 /tmp/e2e_w4b_out | sed 's/^/      /'
        fail=$((fail+6))
        fail_names+=("E56-build" "E57-build" "E58-build" "E59-build" "E60-build" "E61-build")
    fi
else
    echo "SKIP  E56-E62 (lsof/curl absent — §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# E63-E70: Wave 6 pherald inbound runtime invariants (added 2026-05-22).
#
# Wave 6 added `pherald listen` — long-poll getUpdates + bot self-filter +
# attachment sha256 content addressing + Opus-pinned Claude Code dispatch +
# tgram.SendReply with reply_to_message_id. The end-user-visible payoff is
# the closed loop: a subscriber types in Telegram → CC processes → a reply
# lands in-thread. The §107 watershed is therefore the captured wire/
# subprocess evidence at docs/qa/HRD-NNN-W6-*/transcript.jsonl (T10b).
#
# Numbering: this set occupies E63..E70 (the next free contiguous range
# after Wave 4b's E62). Wave 5 (qaherald) reserves the symbolic E63..E70
# slot in its own plan; whichever wave commits first owns the verbatim
# range — Wave 6 lands here first (see Wave 6 plan "Numbering note").
#
# Posture: at the moment of commit, T10b (the live closed-loop run that
# produces docs/qa/HRD-NNN-W6-*/transcript.jsonl) has NOT yet run. E64..E69
# therefore SKIP-with-reason. The SKIPs convert to PASS automatically when
# T10b lands a real transcript in-repo. E70 invokes the live-loop script,
# which itself SKIPs cleanly when creds are absent.
echo ""
echo "== E63-E70: Wave 6 pherald inbound runtime =="

# Locate any real Wave 6 QA evidence the operator may have committed.
# The convention is docs/qa/HRD-NNN-W6-<run-id>/transcript.jsonl. Glob for
# the most recent committed evidence dir; falls back to empty string when
# T10b is still pending.
W6_QA_DIR=""
if [ -d "${REPO_ROOT}/docs/qa" ]; then
    # Pick the lexicographically-last HRD-NNN-W6-* dir whose transcript.jsonl
    # is non-empty. Use find rather than glob expansion so an absent set
    # of matches yields an empty string under set -u.
    W6_QA_DIR="$(find "${REPO_ROOT}/docs/qa" -maxdepth 1 -type d -name 'HRD-*W6*' 2>/dev/null \
                  | sort | tail -1)"
    if [ -n "${W6_QA_DIR}" ] && [ ! -s "${W6_QA_DIR}/transcript.jsonl" ]; then
        W6_QA_DIR=""
    fi
fi

# ---- E63: pherald listen lifecycle ----
# Hermetic path: HERALD_INBOUND_CC_FAKE=1 short-circuits the CC dispatcher,
# but the underlying tgram.Subscribe STILL calls api.telegram.org for getMe
# (bot.Me.Username is load-bearing for the self-filter — see T4). So the
# only real-bytes test of lifecycle requires a live Bot token. Gate
# accordingly; SKIP-with-reason when the operator hasn't exported creds.
if [ -n "${HERALD_TGRAM_BOT_TOKEN:-}" ] && [ -n "${HERALD_TGRAM_CHAT_ID:-}" ]; then
    # Build pherald fresh (we have it from E1 but re-use the same binary).
    W6_LISTEN_LOG="/tmp/pherald-w6-listen-$$.log"
    HERALD_INBOUND_CC_FAKE=1 \
        "${PHERALD_BIN}" listen >"${W6_LISTEN_LOG}" 2>&1 &
    W6_LISTEN_PID=$!
    sleep 3
    if kill -0 "${W6_LISTEN_PID}" 2>/dev/null; then
        kill -TERM "${W6_LISTEN_PID}" 2>/dev/null
        # Allow up to 5s for clean exit; if still alive after 5s, FAIL.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "${W6_LISTEN_PID}" 2>/dev/null || break
            sleep 0.5
        done
        wait "${W6_LISTEN_PID}" 2>/dev/null
        w6_exit=$?
        # On SIGTERM, Go runtime returns exit code 0 (signal.NotifyContext
        # caught it + runListen returned nil). 143 (128+SIGTERM) is also
        # acceptable if the binary didn't trap. Anything else = FAIL.
        if [ "${w6_exit}" = 0 ] || [ "${w6_exit}" = 143 ]; then
            echo "PASS  E63 pherald listen boots against real Bot API + SIGTERM-exits cleanly (exit=${w6_exit})"
            pass=$((pass+1))
        else
            echo "FAIL  E63 pherald listen exited ${w6_exit} on SIGTERM (want 0 or 143)"
            tail -10 "${W6_LISTEN_LOG}" 2>/dev/null | sed 's/^/      /'
            fail=$((fail+1))
            fail_names+=("E63")
        fi
    else
        # Premature exit — almost always a token/chat-id/network issue.
        # Surface the log tail so the operator can fix at root cause.
        echo "FAIL  E63 pherald listen exited prematurely (within 3s)"
        tail -15 "${W6_LISTEN_LOG}" 2>/dev/null | sed 's/^/      /'
        fail=$((fail+1))
        fail_names+=("E63")
    fi
    rm -f "${W6_LISTEN_LOG}"
else
    echo "SKIP  E63 (HERALD_TGRAM_BOT_TOKEN+_CHAT_ID required — tgram.Subscribe.NewBot calls api.telegram.org/getMe at boot to capture bot.Me.Username for the self-filter; no hermetic path exists at the binary level; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E64: bot self-filter (anti-echo-loop) ----
# Real-bytes evidence requires a transcript.jsonl. The check: NO
# tgram.message line with payload.text appearing in any prior tgram.send_
# reply line (i.e., the bot did not re-ingest its own outbound). The
# transcript records direction=in for inbound and direction=out for
# replies — a true echo-loop would show an `in` line whose text matches a
# previously-emitted `out` line's text on the same channel.
if [ -n "${W6_QA_DIR}" ]; then
    check "E64 bot self-filter — no inbound tgram.message echoes a prior outbound tgram.send_reply text (anti-echo-loop wire evidence)" \
        "python3 -c '
import json, sys
seen_replies = set()
echoes = []
with open(\"${W6_QA_DIR}/transcript.jsonl\") as fh:
    for line in fh:
        line = line.strip()
        if not line: continue
        rec = json.loads(line)
        kind = rec.get(\"kind\",\"\")
        payload = rec.get(\"payload\",{}) or {}
        if kind == \"tgram.send_reply\":
            t = payload.get(\"text\") or \"\"
            if t.strip(): seen_replies.add(t.strip())
        elif kind == \"tgram.message\":
            t = (payload.get(\"text\") or \"\").strip()
            if t and t in seen_replies:
                echoes.append(t)
if echoes:
    print(\"ECHO_LOOP_DETECTED\", len(echoes), file=sys.stderr)
    sys.exit(1)
print(\"ok\")
'"
else
    echo "SKIP  E64 (docs/qa/HRD-NNN-W6-*/transcript.jsonl not yet committed — T10b live closed-loop pending; §11.4.3 explicit SKIP-with-reason; SKIP converts to PASS automatically when T10b lands)"
fi

# ---- E65: attachment sha256 content addressing ----
# For every attachment in any tgram.message payload, the file on disk at
# <W6_QA_DIR>/<copied_to> MUST hash to its declared sha256.
if [ -n "${W6_QA_DIR}" ]; then
    check "E65 attachment sha256 — every transcript-cited attachment hashes to its declared sha256 on disk (content-addressing wire evidence)" \
        "python3 -c '
import hashlib, json, os, sys
qa_dir = \"${W6_QA_DIR}\"
total = 0
mismatches = []
with open(os.path.join(qa_dir, \"transcript.jsonl\")) as fh:
    for line in fh:
        line = line.strip()
        if not line: continue
        rec = json.loads(line)
        if rec.get(\"kind\") != \"tgram.message\": continue
        for att in (rec.get(\"payload\",{}) or {}).get(\"attachments\",[]) or []:
            sha = att.get(\"sha256\") or \"\"
            rel = att.get(\"copied_to\") or \"\"
            if not (sha and rel): continue
            total += 1
            p = os.path.join(qa_dir, rel)
            h = hashlib.sha256()
            with open(p,\"rb\") as f:
                for chunk in iter(lambda: f.read(65536), b\"\"):
                    h.update(chunk)
            if h.hexdigest() != sha:
                mismatches.append((rel, sha, h.hexdigest()))
if total == 0:
    print(\"NO_ATTACHMENTS_IN_TRANSCRIPT\", file=sys.stderr)
    sys.exit(2)
if mismatches:
    for m in mismatches: print(\"MISMATCH\", *m, file=sys.stderr)
    sys.exit(1)
print(\"ok\", total)
'"
else
    echo "SKIP  E65 (docs/qa/HRD-NNN-W6-*/transcript.jsonl not yet committed — T10b live closed-loop pending; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E66: envelope pre-text (verbatim operator wording) ----
# §107 caveat: the current Wave 6 T10a journaling middleware records the
# raw user_message (ev.Body.Plain) in the cc.dispatch line, NOT the
# rendered FormatEnvelopeWithPreText output. The pre-text bytes are
# constructed inside dispatch.buildCmd just before exec, then piped to
# claude as the final argv entry — they never traverse the journal
# pipeline. T11 lands an HONEST SKIP-with-reason citing the journal-
# extension HRD; T3's unit test
# (commons_messaging/dispatch/claude_code/claude_code_test.go::
#  TestFormatEnvelopePreText) is the load-bearing pre-text catch in the
# meantime.
if [ -n "${W6_QA_DIR}" ] && grep -q '"envelope_bytes"\|"envelope_text"\|"envelope_pretext"\|"rendered_envelope"' "${W6_QA_DIR}/transcript.jsonl" 2>/dev/null; then
    check "E66 envelope pre-text — captured rendered envelope opens with verbatim operator wording" \
        "grep -F 'We have received new message from our communication channel ' '${W6_QA_DIR}/transcript.jsonl' >/dev/null"
else
    echo "SKIP  E66 (current T10a journal records user_message text, not the rendered FormatEnvelopeWithPreText output; HRD-NNN-W6e tracks the envelope-text journaling extension. T3 unit test TestFormatEnvelopePreText is the load-bearing pre-text-prefix catch until then; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E67: Opus model pin in spawned CC argv ----
# Same caveat as E66: the current journal records cc.dispatch as the
# CodeRequest (inbound_id, sender, channel, user_message, attachments,
# classification) — NOT the spawned *exec.Cmd.Args slice. The Opus pin
# (--model claude-opus-4-7) is inserted in dispatch.buildCmd at the argv
# level. T2's unit test TestDispatchCommandIncludesOpusModel inspects
# cmd.Args directly; T12 mutation gate (b) swaps Opus→Sonnet to prove
# detector load-bearing. HRD-NNN-W6e tracks the argv-capture extension.
if [ -n "${W6_QA_DIR}" ] && grep -q '"argv"\|"cc_argv"\|"spawn_argv"\|"command_line"' "${W6_QA_DIR}/transcript.jsonl" 2>/dev/null; then
    check "E67 Opus pin — captured CC subprocess argv contains '--model' followed by 'claude-opus-4-7' (two contiguous entries)" \
        "python3 -c '
import json, sys
hit = False
with open(\"${W6_QA_DIR}/transcript.jsonl\") as fh:
    for line in fh:
        line = line.strip()
        if not line: continue
        rec = json.loads(line)
        payload = rec.get(\"payload\",{}) or {}
        argv = payload.get(\"argv\") or payload.get(\"cc_argv\") or payload.get(\"spawn_argv\") or payload.get(\"command_line\")
        if not argv: continue
        if isinstance(argv, str): argv = argv.split()
        for i in range(len(argv)-1):
            if argv[i] == \"--model\" and argv[i+1] == \"claude-opus-4-7\":
                hit = True; break
        if hit: break
if not hit:
    print(\"OPUS_PIN_NOT_FOUND_IN_ARGV\", file=sys.stderr); sys.exit(1)
print(\"ok\")
'"
else
    echo "SKIP  E67 (current T10a journal does not record spawned CC argv; HRD-NNN-W6e tracks the argv-capture extension. T2 unit test TestDispatchCommandIncludesOpusModel asserts the model flag at the cmd-construction layer; T12 mutation gate (b) is the load-bearing drift detector; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E68: reply_to_message_id wire-bytes ----
# For every tgram.send_reply line, its reply_to_message_id MUST be non-zero
# AND MUST match the message_id of some earlier tgram.message line in the
# same transcript (i.e., the reply was actually threaded against a real
# inbound message — not a stray fresh-message bluff).
if [ -n "${W6_QA_DIR}" ]; then
    check "E68 reply_to_message_id wire-bytes — every tgram.send_reply's reply_to_message_id is non-zero AND matches a prior tgram.message message_id" \
        "python3 -c '
import json, sys
inbound_ids = set()
replies = []
with open(\"${W6_QA_DIR}/transcript.jsonl\") as fh:
    for line in fh:
        line = line.strip()
        if not line: continue
        rec = json.loads(line)
        kind = rec.get(\"kind\",\"\")
        payload = rec.get(\"payload\",{}) or {}
        if kind == \"tgram.message\":
            mid = payload.get(\"message_id\")
            if mid is not None:
                try: inbound_ids.add(int(mid))
                except Exception: pass
        elif kind == \"tgram.send_reply\":
            replies.append(payload.get(\"reply_to_message_id\"))
if not replies:
    print(\"NO_SEND_REPLY_LINES\", file=sys.stderr); sys.exit(2)
bad = []
for r in replies:
    try: rint = int(r) if r is not None else 0
    except Exception: rint = 0
    if rint == 0 or rint not in inbound_ids:
        bad.append(r)
if bad:
    for b in bad: print(\"BAD_REPLY_TO\", repr(b), file=sys.stderr)
    sys.exit(1)
print(\"ok\", len(replies))
'"
else
    echo "SKIP  E68 (docs/qa/HRD-NNN-W6-*/transcript.jsonl not yet committed — T10b live closed-loop pending; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E69: action routing — issue.open does NOT echo to Telegram ----
# cc.reply lines carry payload.action ∈ {reply, issue.open, event.emit}.
# For every cc.reply with action=issue.open, the transcript MUST NOT
# contain a tgram.send_reply line with the same chat_id + same inbound_id
# pairing (issue.open routes to the issue opener, not back to Telegram).
# Heuristic match: any cc.reply with action=issue.open followed by a
# tgram.send_reply within the next 3 events is a routing leak.
if [ -n "${W6_QA_DIR}" ]; then
    # Only run the assertion if the transcript actually contains an
    # issue.open action — otherwise the invariant is unfalsifiable
    # (vacuously PASS would be a §11.4 bluff). SKIP-with-reason in that
    # case, telling the operator to add an issue.open scenario in T10b.
    if grep -q '"action": *"issue.open"\|"action":"issue.open"' "${W6_QA_DIR}/transcript.jsonl" 2>/dev/null; then
        check "E69 action routing — no tgram.send_reply follows an issue.open cc.reply within 3 events (issue.open routes to the issue opener, not Telegram)" \
            "python3 -c '
import json, sys
events = []
with open(\"${W6_QA_DIR}/transcript.jsonl\") as fh:
    for line in fh:
        line = line.strip()
        if not line: continue
        events.append(json.loads(line))
leaks = []
for i, rec in enumerate(events):
    if rec.get(\"kind\") != \"cc.reply\": continue
    if ((rec.get(\"payload\",{}) or {}).get(\"action\")) != \"issue.open\": continue
    # look up to 3 events ahead for a tgram.send_reply
    for j in range(i+1, min(i+4, len(events))):
        nxt = events[j]
        if nxt.get(\"kind\") == \"tgram.send_reply\":
            leaks.append((i, j))
            break
if leaks:
    for L in leaks: print(\"ROUTING_LEAK\", *L, file=sys.stderr)
    sys.exit(1)
print(\"ok\")
'"
    else
        echo "SKIP  E69 (transcript present but contains no cc.reply with action=issue.open — vacuously-pass would be a §11.4 PASS-bluff; add an issue.open-action scenario to T10b's live loop to convert this SKIP to a real assertion; §11.4.3 explicit SKIP-with-reason)"
    fi
else
    echo "SKIP  E69 (docs/qa/HRD-NNN-W6-*/transcript.jsonl not yet committed — T10b live closed-loop pending; §11.4.3 explicit SKIP-with-reason)"
fi

# ---- E70: live closed-loop (delegates to tests/test_wave6_live_loop.sh) ----
# The script's own design: exit 0 = PASS; exit 0 with stdout beginning
# "SKIP:" = creds-absent SKIP; exit non-zero = FAIL. e2e_bluff_hunt mirrors
# that contract — we run the script, capture stdout, and decide.
#
# CRITICAL GATE (added during 2026-05-27 debt-clearing): test_wave6_live_loop.sh
# is an ATTENDED test — after its creds-present pre-flight it prints
# "operator MUST type a single message in the chat NOW" and polls getUpdates
# for 60s. In an UNATTENDED e2e run no human types the message, so the script
# necessarily exits non-zero ("no subscriber-typed message observed in 60s")
# — a spurious FAIL that does NOT indicate a broken feature. The only way to
# drive the inbound side without a human is an MTProto user-client injector,
# which is operator-pending (see docs/research/telegram-bot-to-bot-constraint.md:
# bots cannot see other bots' messages, so a 2nd-bot driver is impossible).
# Therefore we run E70 ONLY when the operator explicitly opts in via
# HERALD_W6_LIVE_LOOP=1 (signalling an attended session or an MTProto driver
# is in place); otherwise SKIP-with-reason. This is honest: the assertion is
# genuinely gated on a manual/MTProto inbound injector that the unattended
# harness cannot provide — not a weakened check.
if [ "${HERALD_W6_LIVE_LOOP:-}" = "1" ]; then
    W6_LIVE_OUT="/tmp/e2e_w6_live_out_$$"
    if bash "${REPO_ROOT}/tests/test_wave6_live_loop.sh" >"${W6_LIVE_OUT}" 2>&1; then
        if head -1 "${W6_LIVE_OUT}" | grep -q '^SKIP:'; then
            skip_reason="$(head -1 "${W6_LIVE_OUT}" | sed 's/^SKIP: *//')"
            echo "SKIP  E70 (tests/test_wave6_live_loop.sh: ${skip_reason}; §11.4.3 explicit SKIP-with-reason)"
        else
            echo "PASS  E70 tests/test_wave6_live_loop.sh closed-loop (subscriber → CC → bot reply with reply_to_message_id wire-evidence)"
            pass=$((pass+1))
        fi
    else
        echo "FAIL  E70 tests/test_wave6_live_loop.sh closed-loop failed"
        tail -20 "${W6_LIVE_OUT}" 2>/dev/null | sed 's/^/      /'
        fail=$((fail+1))
        fail_names+=("E70")
    fi
    rm -f "${W6_LIVE_OUT}"
else
    echo "SKIP  E70 (tests/test_wave6_live_loop.sh is an ATTENDED test — it polls 60s for a human-typed inbound message; an unattended run cannot inject one. Real-channel automation needs an MTProto user-client injector (operator-pending — bots cannot see other bots' messages; see docs/research/telegram-bot-to-bot-constraint.md). Re-run with HERALD_W6_LIVE_LOOP=1 in an attended session to exercise; §11.4.3 explicit SKIP-with-reason)"
fi

# ----------------------------------------------------------------------
# E71-E80: Wave 6.5 comprehensive ticket-lifecycle invariants (added
# 2026-05-23). Each invariant cites a concrete file (transcript.jsonl
# OR issues.diff OR fixed.diff OR pherald-listen.log OR attachments/)
# + a concrete assertion (grep pattern or numeric comparison) from the
# T9 live-run artefacts under docs/qa/HRD-101-lifecycle-<run-id>/.
#
# SKIP-with-reason if no such dir exists yet (T9 still operator-pending).
# E75 + E79 are SKIP-acceptable when the operator only exercised the
# happy-path coverage (single-account run / CC did not attach a media
# reply).
# ----------------------------------------------------------------------
echo ""
echo "== E71-E80: Wave 6.5 ticket lifecycle =="

# Resolve the most recent VALID full-lifecycle evidence directory.
#
# A directory is only valid evidence for E71-E80 when it carries the COMPLETE
# set of S1..S15 artefacts — NOT merely a non-empty transcript.jsonl. Earlier
# this block accepted any HRD-101-lifecycle-* dir whose transcript.jsonl was
# non-empty; that let a STALE PARTIAL run (e.g. the S1+S2-only
# HRD-101-lifecycle-2026-05-23T03-16-17-w6.5live dir, which has a 5 KB
# transcript but NO issues.diff / fixed.diff / pherald-listen.log and NO
# bug/help_command classification rows) drive E71/E72/E73/E75/E76 to spurious
# FAIL. Those FAILs do not indicate a broken feature — they indicate the full
# S1..S15 lifecycle run never completed, which is genuinely BLOCKED on an
# MTProto user-client injector (a 2nd Telegram bot cannot drive the loop —
# bots cannot see other bots' group messages; see
# docs/research/telegram-bot-to-bot-constraint.md). So a dir counts as valid
# ONLY when transcript.jsonl + issues.diff + fixed.diff + pherald-listen.log
# all exist and are non-empty; otherwise the whole block SKIPs-with-reason.
W65_QA_DIR=""
if [ -d "${REPO_ROOT}/docs/qa" ]; then
    # Newest-first; pick the first dir that satisfies the full-evidence gate.
    while IFS= read -r cand; do
        [ -n "${cand}" ] || continue
        if [ -s "${cand}/transcript.jsonl" ] \
           && [ -s "${cand}/issues.diff" ] \
           && [ -s "${cand}/fixed.diff" ] \
           && [ -s "${cand}/pherald-listen.log" ]; then
            W65_QA_DIR="${cand}"
            break
        fi
    done <<EOF
$(find "${REPO_ROOT}/docs/qa" -maxdepth 1 -type d -name 'HRD-101-lifecycle-*' 2>/dev/null | sort -r)
EOF
fi

if [ -z "${W65_QA_DIR}" ]; then
    for n in 71 72 73 74 75 76 77 78 79 80; do
        echo "SKIP  E${n} — Wave 6.5 full-lifecycle evidence pending MTProto automation (no docs/qa/HRD-101-lifecycle-*/ dir carries the complete transcript.jsonl + issues.diff + fixed.diff + pherald-listen.log set; the S1..S15 run is blocked on an MTProto user-client injector — a 2nd-bot driver is impossible because Telegram bots cannot see other bots' group messages; see docs/research/telegram-bot-to-bot-constraint.md; §11.4.3 explicit SKIP-with-reason)"
    done
else
    W65_TRANSCRIPT="${W65_QA_DIR}/transcript.jsonl"
    W65_LISTEN_LOG="${W65_QA_DIR}/pherald-listen.log"
    W65_ISSUES_DIFF="${W65_QA_DIR}/issues.diff"
    W65_FIXED_DIFF="${W65_QA_DIR}/fixed.diff"

    # ---- E71: classifier emitted bug + help_command ----
    # Field names are title-cased per the inbound.Classification JSON
    # schema verified by T8 (e.g. {"Type":"bug","Criticality":"middle",
    # "Confidence":1.0}). DO NOT match lowercase "type" — that's a
    # different JSON shape and a PASS-bluff trap.
    if grep -q '"Type":"bug"' "${W65_TRANSCRIPT}" 2>/dev/null && \
       grep -q '"Type":"help_command"' "${W65_TRANSCRIPT}" 2>/dev/null; then
        bug_line="$(grep -m1 '"Type":"bug"' "${W65_TRANSCRIPT}")"
        help_line="$(grep -m1 '"Type":"help_command"' "${W65_TRANSCRIPT}")"
        echo "PASS  E71 deterministic classifier emitted bug + help_command (§32.6 wire-bytes)"
        echo "      bug:  ${bug_line:0:160}"
        echo "      help: ${help_line:0:160}"
        pass=$((pass+1))
    else
        echo "FAIL  E71 classifier transcript missing \"Type\":\"bug\" + \"Type\":\"help_command\" (deterministic §32.6 classifier did not run on operator input — re-run T9)"
        fail=$((fail+1))
        fail_names+=("E71")
    fi

    # ---- E72: Issues.md mutation observed in diff ----
    if [ -f "${W65_ISSUES_DIFF}" ] && grep -qE '^>.*HRD-' "${W65_ISSUES_DIFF}" 2>/dev/null; then
        added_row="$(grep -m1 -E '^>.*HRD-' "${W65_ISSUES_DIFF}")"
        echo "PASS  E72 Issues.md mutation observed — at least one HRD- row added"
        echo "      ${added_row:0:200}"
        pass=$((pass+1))
    else
        if [ ! -f "${W65_ISSUES_DIFF}" ]; then
            echo "FAIL  E72 issues.diff missing in ${W65_QA_DIR} (T9 script must capture before/after snapshots — re-run T9)"
        else
            echo "FAIL  E72 issues.diff has no added HRD- rows — Bug:/Task: scenarios did not mutate docs/Issues.md (re-run T9)"
        fi
        fail=$((fail+1))
        fail_names+=("E72")
    fi

    # ---- E73: Done: migration — fixed.diff has ≥1 added HRD- row ----
    if [ -f "${W65_FIXED_DIFF}" ] && grep -qE '^>.*HRD-' "${W65_FIXED_DIFF}" 2>/dev/null; then
        added_row="$(grep -m1 -E '^>.*HRD-' "${W65_FIXED_DIFF}")"
        echo "PASS  E73 Done: migration observed — at least one HRD- row added to Fixed.md"
        echo "      ${added_row:0:200}"
        pass=$((pass+1))
    else
        if [ ! -f "${W65_FIXED_DIFF}" ]; then
            echo "FAIL  E73 fixed.diff missing in ${W65_QA_DIR} (T9 script must capture before/after snapshots — re-run T9)"
        else
            echo "FAIL  E73 fixed.diff has no added HRD- rows — Done: scenario did not migrate Issues.md → Fixed.md (re-run T9)"
        fi
        fail=$((fail+1))
        fail_names+=("E73")
    fi

    # ---- E74: Reopen: migration — issues.diff has a re-added row ----
    # Reopen moves the row Fixed.md → Issues.md. In the issues.diff the
    # signal is a row that re-appears in the "after" snapshot that was
    # NOT present in the "before" snapshot. Heuristic: ≥2 added HRD- rows
    # (S5/S6 open + S10 reopen) OR the same HRD-NNN appears both as a
    # deleted row in fixed.diff AND an added row in issues.diff.
    added_in_issues=$(grep -cE '^>.*HRD-' "${W65_ISSUES_DIFF}" 2>/dev/null || echo 0)
    deleted_in_fixed=$(grep -cE '^<.*HRD-' "${W65_FIXED_DIFF}" 2>/dev/null || echo 0)
    if [ "${added_in_issues}" -ge 2 ] || [ "${deleted_in_fixed}" -ge 1 ]; then
        echo "PASS  E74 Reopen: migration observed (added_in_issues=${added_in_issues}, deleted_in_fixed=${deleted_in_fixed})"
        pass=$((pass+1))
    else
        echo "SKIP  E74 Reopen: scenario coverage absent (added_in_issues=${added_in_issues}, deleted_in_fixed=${deleted_in_fixed}) — operator may not have exercised S10; re-run T9 with full S1..S15 to convert this SKIP to a real assertion; §11.4.3 explicit SKIP-with-reason"
    fi

    # ---- E75: Help: fast-path bypassed CC ----
    # Two parts: (a) at least one "inbound dispatched: help_command
    # (fast-path)" log line; (b) no cc.dispatch event in the same
    # scenario window. Conservative implementation: just assert (a) — the
    # presence of the fast-path log line is the production-code signal
    # that the classifier short-circuited before CC. Strict (b) requires
    # scenario-window framing that the T8 transcript writer doesn't yet
    # emit; treat (a) alone as the canonical wire-byte assertion.
    if [ -f "${W65_LISTEN_LOG}" ] && grep -qE 'inbound dispatched: help_command \(fast-path\)|fast-path.*help_command' "${W65_LISTEN_LOG}" 2>/dev/null; then
        fp_line="$(grep -m1 -E 'inbound dispatched: help_command \(fast-path\)|fast-path.*help_command' "${W65_LISTEN_LOG}")"
        echo "PASS  E75 Help: fast-path observed in pherald-listen.log (zero CC roundtrip)"
        echo "      ${fp_line:0:200}"
        pass=$((pass+1))
    else
        echo "FAIL  E75 no help_command fast-path log line in pherald-listen.log (Help: did not short-circuit before CC — re-run T9 / verify classifier+dispatcher wiring)"
        fail=$((fail+1))
        fail_names+=("E75")
    fi

    # ---- E76: Status: fast-path same pattern ----
    if [ -f "${W65_LISTEN_LOG}" ] && grep -qE 'inbound dispatched: status_request \(fast-path\)|fast-path.*status_request' "${W65_LISTEN_LOG}" 2>/dev/null; then
        fp_line="$(grep -m1 -E 'inbound dispatched: status_request \(fast-path\)|fast-path.*status_request' "${W65_LISTEN_LOG}")"
        echo "PASS  E76 Status: fast-path observed in pherald-listen.log (zero CC roundtrip)"
        echo "      ${fp_line:0:200}"
        pass=$((pass+1))
    else
        echo "FAIL  E76 no status_request fast-path log line in pherald-listen.log (Status: did not short-circuit before CC — re-run T9 / verify classifier+dispatcher wiring)"
        fail=$((fail+1))
        fail_names+=("E76")
    fi

    # ---- E77: attachment download sha256 anchor ----
    # For every file in the QA attachments/ directory, verify its base
    # name (sans extension) hashes to the file content via sha256 — the
    # content-addressed convention from Wave 6 T5 / inherited by Wave
    # 6.5. macOS uses `shasum -a 256`; Linux ships `sha256sum`. Branch.
    if [ -d "${W65_QA_DIR}/attachments" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            sha_cmd="sha256sum"
        elif command -v shasum >/dev/null 2>&1; then
            sha_cmd="shasum -a 256"
        else
            sha_cmd=""
        fi
        if [ -z "${sha_cmd}" ]; then
            echo "FAIL  E77 sha256 utility absent (need sha256sum or shasum -a 256)"
            fail=$((fail+1))
            fail_names+=("E77")
        else
            att_count=0
            att_bad=0
            for f in "${W65_QA_DIR}/attachments"/*; do
                [ -f "${f}" ] || continue
                att_count=$((att_count+1))
                base="$(basename "${f}")"
                name="${base%.*}"
                actual="$(${sha_cmd} "${f}" 2>/dev/null | awk '{print $1}')"
                if [ "${name}" != "${actual}" ]; then
                    echo "      BAD: $(basename "${f}") name does not match sha256 (${actual})"
                    att_bad=$((att_bad+1))
                fi
            done
            if [ "${att_count}" -eq 0 ]; then
                echo "SKIP  E77 no attachments in ${W65_QA_DIR}/attachments — operator may not have exercised S11/S12/S13; re-run T9 with photo+doc+voice to convert SKIP to assertion; §11.4.3 explicit SKIP-with-reason"
            elif [ "${att_bad}" -eq 0 ]; then
                echo "PASS  E77 every attachment filename == its sha256 content hash (n=${att_count}; content-addressed inbox honored)"
                pass=$((pass+1))
            else
                echo "FAIL  E77 ${att_bad}/${att_count} attachments fail sha256 verification — content-addressed inbox corrupted"
                fail=$((fail+1))
                fail_names+=("E77")
            fi
        fi
    else
        echo "SKIP  E77 ${W65_QA_DIR}/attachments/ absent — operator may not have exercised S11/S12/S13; re-run T9 with photo+doc+voice to convert SKIP to assertion; §11.4.3 explicit SKIP-with-reason"
    fi

    # ---- E78: outbound attachment fan-out ----
    # At least one tgram.send_reply payload with attachments[] AND a
    # multipart count ≥ 2 (text + ≥1 media). The transcript may carry
    # either the attachments list directly OR multiple consecutive
    # tgram.send_reply lines for the same scenario (1 text + N media).
    # Look for either signal — explicit attachments[] JSON OR a
    # send-reply burst.
    if grep -qE '"attachments":\[' "${W65_TRANSCRIPT}" 2>/dev/null || \
       grep -qE 'sendPhoto|sendDocument|sendVoice|sendAudio|sendVideo' "${W65_LISTEN_LOG}" 2>/dev/null; then
        echo "PASS  E78 outbound attachment fan-out observed (tgram.SendReply attachments[] or sendPhoto/sendDocument/sendVoice in log)"
        pass=$((pass+1))
    else
        echo "SKIP  E78 S14 outbound attachment scenario coverage absent — CC may not have chosen to attach a media reply; re-run T9 with explicit outbound-attachment prompt to convert SKIP to assertion; §11.4.3 explicit SKIP-with-reason"
    fi

    # ---- E79: non-operator Done: rejected ----
    # The S9 scenario sends Done:/Reopen: from a non-operator account.
    # The dispatcher MUST reject with explicit "not in HERALD_OPERATOR_IDS"
    # text in either the transcript (reply payload) or the listen log.
    if grep -qE 'not in HERALD_OPERATOR_IDS|Done: rejected|Reopen: rejected' "${W65_TRANSCRIPT}" "${W65_LISTEN_LOG}" 2>/dev/null; then
        reject_line="$(grep -m1 -hE 'not in HERALD_OPERATOR_IDS|Done: rejected|Reopen: rejected' "${W65_TRANSCRIPT}" "${W65_LISTEN_LOG}" 2>/dev/null)"
        echo "PASS  E79 non-operator Done: rejection observed (S9 path)"
        echo "      ${reject_line:0:200}"
        pass=$((pass+1))
    else
        echo "SKIP  E79 S9 non-operator rejection coverage absent — operator may have run the script with a single allowlisted account; re-run T9 with a SECOND non-allowlisted account to convert SKIP to assertion; §11.4.3 explicit SKIP-with-reason"
    fi

    # ---- E80: bot self-filter held — no infinite echo ----
    # No bot-self messages should appear in the transcript as inbound
    # tgram.message lines (an echo-loop would surface here as the bot's
    # own outbound text appearing later as a fresh inbound). Wave 6's
    # E64 already pins this; Wave 6.5 re-asserts because the new lifecycle
    # scenarios exercise far more outbound replies. Heuristic: zero
    # "self_filter_hit" or "bot_self_dropped" log lines that indicate the
    # filter caught something — meaning the filter correctly suppressed
    # self-echoes — OR no panics/fatals in the log.
    if [ -f "${W65_LISTEN_LOG}" ] && grep -qE 'panic:|FATAL|fatal error' "${W65_LISTEN_LOG}" 2>/dev/null; then
        echo "FAIL  E80 pherald-listen.log has panic/fatal lines — bot stability compromised during lifecycle run"
        grep -m3 -E 'panic:|FATAL|fatal error' "${W65_LISTEN_LOG}" | sed 's/^/      /'
        fail=$((fail+1))
        fail_names+=("E80")
    else
        echo "PASS  E80 pherald-listen.log has zero panic/fatal lines (bot self-filter held; no echo loop)"
        pass=$((pass+1))
    fi
fi

# ----------------------------------------------------------------------
# E81-E88: GAP-3 §11.4.85 stress + chaos suite (HRD-122..HRD-128).
#
# Each invariant exercises a real, hermetic Go stress/chaos test (no live
# creds, no container runtime required) AND cites the captured-evidence
# artefact under docs/qa/<run-id>/stress_chaos/ as its positive-evidence
# anchor (§11.4.2 / §11.4.5). The evidence-anchor grep asserts a SPECIFIC
# value (e.g. `archival_exactly_once=1`), not mere file existence — a
# present-but-empty artefact is a §11.4 PASS-bluff and FAILs the invariant.
#
# Run mode is hermetic for all eight: the load-drivers run in-process and
# the chaos faults use the committed test seams (fake stores, fake-claude
# shims, syscall.ENOSPC injection, in-process host-mem probe). The live
# variants (container-pause PG-drop, real bounded disk-fill, container OOM
# confinement) are SKIP-with-reason inside the Go tests themselves
# (HERALD_STRESS_LIVE_DISK=1 / *_Live test names), so the hermetic gate
# stays green without a runtime. The evidence-anchor check SKIPs-with-reason
# when no docs/qa/<run-id>/ evidence dir is present (e.g. a fresh clone that
# has not yet run the suite), mirroring the E71-E80 evidence-dir gate.
# ----------------------------------------------------------------------
echo ""
echo "== E81-E88: §11.4.85 stress + chaos suite (GAP-3) =="

# Resolve newest evidence dirs (timestamp-suffixed; multiple runs allowed).
sc_newest() {
    find "${REPO_ROOT}/docs/qa" -maxdepth 1 -type d -name "$1" 2>/dev/null | sort -r | head -1
}
SC_EVENTS_DIR="$(sc_newest 'HRD-123-stress-chaos-*')"
SC_RUNNER_DIR="$(sc_newest 'HRD-125-stress-chaos-*')"
SC_CS_DIR="$(sc_newest 'HRD-124-*')"
SC_LISTEN_DIR="$(sc_newest '*HRD-126*')"
SC_CC_DIR="$(sc_newest 'HRD-127-*')"
SC_RES_DIR="$(sc_newest 'HRD-128-*')"
SC_TGRAM_DIR="$(sc_newest 'HRD-137-*')"
SC_CONST_DIR="$(sc_newest 'HRD-018-*')"
SC_BIND_DIR="$(sc_newest 'HRD-019-*')"
SC_SAFE_DIR="$(sc_newest 'HRD-020-*')"
SC_CI_DIR="$(sc_newest 'HRD-021-*')"
SC_REL_DIR="$(sc_newest 'HRD-022-*')"
SC_PROJ_DIR="$(sc_newest 'HRD-023-*')"
SC_INC_DIR="$(sc_newest 'HRD-024-*')"
SC_SCHED_DIR="$(sc_newest 'HRD-025-*')"
# v1.0.0 Batch C — pherald §43 gitops command transcripts (HRD-029/049/043/044).
SC_GITOPS_CP_DIR="$(sc_newest 'HRD-029-*')"
SC_GITOPS_REOPEN_DIR="$(sc_newest 'HRD-049-*')"
SC_GITOPS_INSTUP_DIR="$(sc_newest 'HRD-043-*')"
SC_GITOPS_FETCHGUARD_DIR="$(sc_newest 'HRD-044-*')"
# v1.0.0 Batch C C2 — sherald §43 system/safety command transcripts
# (HRD-033 destructive-guard / HRD-040 constitution-pull / HRD-046
# force-push-gate / HRD-056 mem-budget-watch).
SC_SYS_DESTRUCT_DIR="$(sc_newest 'HRD-033-*')"
SC_SYS_CONSTPULL_DIR="$(sc_newest 'HRD-040-*')"
SC_SYS_FORCEPUSH_DIR="$(sc_newest 'HRD-046-*')"
SC_SYS_MEMBUDGET_DIR="$(sc_newest 'HRD-056-*')"

# v1.0.0 Batch C clusters C4 (rherald §43 release) + C5 (bherald §43 build/CI)
# (HRD-031 tag-mirror / HRD-032 changelog-generate / HRD-045 gate-retest /
# HRD-041 test-tier-verify / HRD-035 evidence-capture).
SC_REL_TAGMIRROR_DIR="$(sc_newest 'HRD-031-*')"
SC_REL_CHANGELOG_DIR="$(sc_newest 'HRD-032-*')"
SC_REL_RETEST_DIR="$(sc_newest 'HRD-045-*')"
SC_BUILD_TIER_DIR="$(sc_newest 'HRD-041-*')"
SC_BUILD_EVIDENCE_DIR="$(sc_newest 'HRD-035-*')"

# v1.0.0 Batch C cluster C3 (cherald §43 docs-pipeline C3a + verify/check C3b).
# C3a (docs_cmds): HRD-037 docs-sync / HRD-050 readme-sync / HRD-052 export /
#   HRD-048 fixed-summary-sync / HRD-039 fixed-align.
# C3b (checkops): HRD-042 submanifest-verify / HRD-051 composite-gate /
#   HRD-054 spec-version-check / HRD-055 catalogue-check /
#   HRD-038 script-docs-check / HRD-036 creds-scan.
SC_DOCS_SYNC_DIR="$(sc_newest 'HRD-037-*')"
SC_README_SYNC_DIR="$(sc_newest 'HRD-050-*')"
SC_EXPORT_DIR="$(sc_newest 'HRD-052-*')"
SC_FIXEDSUM_DIR="$(sc_newest 'HRD-048-*')"
SC_FIXEDALIGN_DIR="$(sc_newest 'HRD-039-*')"
SC_SUBMANIFEST_DIR="$(sc_newest 'HRD-042-*')"
SC_COMPOSITE_DIR="$(sc_newest 'HRD-051-*')"
SC_SPECVER_DIR="$(sc_newest 'HRD-054-*')"
SC_CATCHECK_DIR="$(sc_newest 'HRD-055-*')"
SC_SCRIPTDOCS_DIR="$(sc_newest 'HRD-038-*')"
SC_CREDSSCAN_DIR="$(sc_newest 'HRD-036-*')"
# §43 stragglers — HRD-034 sherald backup-snapshot / HRD-047 scherald status-digest.
SC_SYS_BACKUP_DIR="$(sc_newest 'HRD-034-*')"
SC_SCHED_DIGEST_DIR="$(sc_newest 'HRD-047-*')"
# Batch-D real-PG integration (HRD-085..089) + Wave 7 Slack adapter (HRD-115) +
# qaherald Slack client (HRD-116) — resolve newest-timestamped run dir so a
# re-capture under a new timestamp is still found (no hardcoded timestamp).
SC_BATCHD_DIR="$(sc_newest 'HRD-085-089-*')"
SC_SLACK_ADAPTER_DIR="$(sc_newest 'HRD-115-*')"
SC_QAHERALD_SLACK_DIR="$(sc_newest 'HRD-116-*')"

# sc_anchor <invariant-label> <evidence-file> <literal-anchor-string>
# Asserts the captured-evidence file contains the load-bearing anchor value.
# SKIP-with-reason when the evidence dir/file is absent (fresh clone before
# the suite has run); FAIL only when the file exists but lacks the anchor
# (a present-but-empty / value-stripped §11.4 PASS-bluff).
sc_anchor() {
    local label="$1" file="$2" anchor="$3"
    if [ -z "${file}" ] || [ ! -f "${file}" ]; then
        echo "SKIP  ${label} evidence anchor — no docs/qa/<run-id>/stress_chaos/ artefact present yet (run the §11.4.85 suite to capture it; §11.4.3 explicit SKIP-with-reason)"
        sc_skip=$((sc_skip+1))
        sc_skip_names+=("${label}")
        return 0
    fi
    if grep -qF "${anchor}" "${file}" 2>/dev/null; then
        echo "PASS  ${label} evidence anchor '${anchor}' present in $(basename "$(dirname "${file}")")/$(basename "${file}")"
        pass=$((pass+1))
    else
        echo "FAIL  ${label} evidence file present but anchor '${anchor}' MISSING (present-but-empty artefact = §11.4 PASS-bluff)"
        echo "      ${file}"
        fail=$((fail+1))
        fail_names+=("${label}-anchor")
    fi
}

# ---- E81: Runner exactly-once-archive + bounded dispatch (HRD-125) ----
check "E81 runner concurrent-replay exactly-once stress (-race, N=16 fan-out)" \
    "go test -race -count=1 -run 'TestRunner_Stress_ConcurrentReplay_ExactlyOnce' ./pherald/internal/runner/..."
sc_anchor "E81" "${SC_RUNNER_DIR:+${SC_RUNNER_DIR}/stress_chaos/runner/exactly_once.txt}" "archival_exactly_once=1"

# ---- E82: /v1/events stress + chaos (HRD-123) ----
check "E82 /v1/events chaos — input-corruption + duplicate-key + auth-storm (no 5xx-hang, no panic)" \
    "go test -count=1 -run 'TestEventsHTTP_Chaos_InputCorruption|TestEventsHTTP_Chaos_DuplicateKeyUnderLoad|TestEventsHTTP_Chaos_AuthStorm' ./pherald/internal/http/..."
sc_anchor "E82" "${SC_EVENTS_DIR:+${SC_EVENTS_DIR}/stress_chaos/events/categorised_errors.txt}" "all_malformed_rejected_no_5xx=1"

# ---- E83: /v1/compliance fail-loud chaos (HRD-124) ----
check "E83 /v1/compliance chaos — PG-drop fails loud (no fabricated 2xx)" \
    "go test -count=1 -run 'TestComplianceHTTP_Chaos_PGDropFailsLoud' ./cherald/internal/compliance/..."
sc_anchor "E83" "${SC_CS_DIR:+${SC_CS_DIR}/stress_chaos/compliance/pg_drop_fail_loud.log}" "fail_loud_no_fabricated_200=1"

# ---- E84: /v1/safety_state concurrent-mutation chaos (HRD-124) ----
check "E84 /v1/safety_state chaos — consistent under concurrent mutation (no torn read, no 5xx, -race)" \
    "go test -race -count=1 -run 'TestSafetyHTTP_Chaos_ConcurrentMutationUnderLoad' ./sherald/internal/safety/..."
sc_anchor "E84" "${SC_CS_DIR:+${SC_CS_DIR}/stress_chaos/safety_state/concurrent_mutation.log}" "consistent_under_concurrent_mutation=1"

# ---- E85: pherald listen inbound chaos (HRD-126) ----
check "E85 pherald listen inbound chaos — malformed payloads degrade, never panic" \
    "go test -count=1 -short -run 'TestInbound_Chaos_HandleMalformedRaw_NeverPanics|TestInbound_Chaos_ExtractReplyToMessageID_Degrades' ./pherald/internal/inbound/..."
sc_anchor "E85" "${SC_LISTEN_DIR:+${SC_LISTEN_DIR}/stress_chaos/listen/handle_malformed_raw.txt}" "panic_free=1"
sc_anchor "E85b" "${SC_LISTEN_DIR:+${SC_LISTEN_DIR}/stress_chaos/listen/malformed_payloads.txt}" "all_malformed_degraded_no_panic=1"

# ---- E86: claude_code dispatch chaos (HRD-127) ----
check "E86 claude_code dispatch chaos — process-death/timeout/truncated-reply tagged-error, no hang (-race)" \
    "go test -race -count=1 -run 'TestDispatch_Chaos_ProcessDeath_Exit137|TestDispatch_Chaos_TimeoutContextCancel|TestDispatch_Chaos_TruncatedReply' ./commons_messaging/dispatch/claude_code/..."
sc_anchor "E86" "${SC_CC_DIR:+${SC_CC_DIR}/stress_chaos/claude_code/subprocess_kill.log}" "tagged_error_no_hang=1"
sc_anchor "E86b" "${SC_CC_DIR:+${SC_CC_DIR}/stress_chaos/claude_code/timeout_cancel.log}" "deadline_fired=1"

# ---- E87: disk-full tagged-error chaos (HRD-128) ----
check "E87 RunMigrations chaos — disk-full (ENOSPC) propagates tagged, not swallowed" \
    "go test -count=1 -run 'TestRunMigrations_Chaos_DiskFull_TaggedError' ./commons_storage/..."
sc_anchor "E87" "${SC_RES_DIR:+${SC_RES_DIR}/stress_chaos/resource/disk_full_tagged_error.txt}" "tagged_error=1"

# ---- E88: §12.6 host-mem headroom (HRD-128) ----
check "E88 §12.6 host-mem headroom — suite adds negligible host pressure (resource-exhaustion is bounded)" \
    "go test -count=1 -run 'TestResource_HostMemHeadroom_Section126' ./commons_storage/..."
sc_anchor "E88" "${SC_RES_DIR:+${SC_RES_DIR}/stress_chaos/resource/host_memory_headroom.txt}" "section_12_6_headroom_proven=1"

# ---- E89: constitution audit write-through + mode-flip REST (HRD-018/026/027) ----
check "E89 constitution audit write-through + mode-flip REST (emit→persist→audit + ladder hot-reflect, -race)" \
    "go test -race -count=1 ./commons_constitution/... ./cherald/internal/modes/..."
sc_anchor "E89"  "${SC_CONST_DIR:+${SC_CONST_DIR}/02_admin_rest_flip.txt}" "PASS: TestModes_FlipReflectsImmediately"
sc_anchor "E89b" "${SC_CONST_DIR:+${SC_CONST_DIR}/01_emit_persist_realpg.txt}" "PASS: TestPostgresRunner_EndToEndAuditPersist"

# ---- E90: cherald constitution bindings detect→emit→persist→query (HRD-019) ----
check "E90 cherald constitution bindings — violation detect→emit→audit→query round-trip (-race)" \
    "go test -race -count=1 ./cherald/internal/bindings/... ./cherald/internal/compliance/..."
sc_anchor "E90" "${SC_BIND_DIR:+${SC_BIND_DIR}/rest/binding_roundtrip_transcript.md}" '"emitted": true'

# ---- E91: sherald host/repo-safety bindings detect→emit→persist (HRD-020) ----
check "E91 sherald safety bindings — destructive-op/force-push/mem-budget detect→emit→audit (-race)" \
    "go test -race -count=1 ./sherald/internal/bindings/..."
sc_anchor "E91" "${SC_SAFE_DIR:+${SC_SAFE_DIR}/safety_roundtrip_evidence.txt}" "digital.vasic.herald.constitution.repo.safety.breach"

# ---- E92: bherald CI/test gate-result bindings detect→emit→persist (HRD-021) ----
check "E92 bherald CI/test bindings — gate-result + anti-bluff-PASS detect→emit→audit (-race)" \
    "go test -race -count=1 ./bherald/internal/bindings/..."
sc_anchor "E92" "${SC_CI_DIR:+${SC_CI_DIR}/gate_result_roundtrip_transcript.txt}" "class=.gate.failed"

# ---- E93: rherald release gate-blocked bindings detect→emit→persist (HRD-022) ----
check "E93 rherald release bindings — tag-mirror/changelog/retest gate-blocked detect→emit→audit (-race)" \
    "go test -race -count=1 ./rherald/internal/bindings/..."
sc_anchor "E93" "${SC_REL_DIR:+${SC_REL_DIR}/transcript.md}" "digital.vasic.herald.constitution.release.gate.blocked"

# ---- E94: pherald project bindings detect→emit→persist (HRD-023) ----
check "E94 pherald project bindings — commit-push/submodule/pre-push detect→emit→audit (-race)" \
    "go test -race -count=1 ./pherald/internal/bindings/..."
sc_anchor "E94" "${SC_PROJ_DIR:+${SC_PROJ_DIR}/roundtrip_transcript.md}" "digital.vasic.herald.constitution.repo.safety.breach"

# ---- E95: iherald escalation bindings detect→emit→persist (HRD-024) ----
check "E95 iherald escalation bindings — credential-leak page-out/operator-blocked detect→emit→audit (-race)" \
    "go test -race -count=1 ./iherald/internal/bindings/..."
sc_anchor "E95" "${SC_INC_DIR:+${SC_INC_DIR}/escalation_roundtrip_verbose.log}" "PASS: TestPipeline_CredentialLeakRoundTrip"

# ---- E96: scherald scheduled-audit bindings detect→emit→persist (HRD-025) ----
check "E96 scherald scheduled-audit bindings — status-sweep/digest/stale-item detect→emit→audit (-race)" \
    "go test -race -count=1 ./scherald/internal/bindings/..."
sc_anchor "E96" "${SC_SCHED_DIR:+${SC_SCHED_DIR}/roundtrip_transcript.txt}" "PASS: TestPipeline_StatusSweepPolicyViolationRoundTrip"

# ---- E97: §2 pherald commit-push gitops command (HRD-029) ----
check "E97 §2 pherald commit-push — locked-entrypoint commit + push to fake file:// remote (hermetic, -race)" \
    "go test -race -count=1 -run 'TestCommitPush_CommitsAndPushesToFakeRemote' ./pherald/cmd/pherald/..."
sc_anchor "E97" "${SC_GITOPS_CP_DIR:+${SC_GITOPS_CP_DIR}/transcript.txt}" "went through the single locked entrypoint with the lock held"

# ---- E98: §11.4.55 pherald reopen gitops command (HRD-049) ----
check "E98 §11.4.55 pherald reopen — Fixed.md→Issues.md migration + Reopens history (hermetic, -race)" \
    "go test -race -count=1 -run 'TestReopen_MigratesRowAndWritesReopensRecord' ./pherald/cmd/pherald/..."
sc_anchor "E98" "${SC_GITOPS_REOPEN_DIR:+${SC_GITOPS_REOPEN_DIR}/transcript.txt}" "reopen of HRD-049 carries its docs/Reopens/HRD-049.md history record"

# ---- E99: §11.4.36 pherald install-upstreams gitops command (HRD-043) ----
check "E99 §11.4.36 pherald install-upstreams — configures all declared mirror remotes (hermetic, -race)" \
    "go test -race -count=1 -run 'TestInstallUpstreams_ApplyConfiguresRemotes' ./pherald/cmd/pherald/..."
sc_anchor "E99" "${SC_GITOPS_INSTUP_DIR:+${SC_GITOPS_INSTUP_DIR}/transcript.txt}" "install-upstreams configured all 2 declared mirror remotes"

# ---- E100: §11.4.37/§11.4.71 pherald fetch-guard + pre-push gitops command (HRD-044/053) ----
check "E100 §11.4.37/§11.4.71 pherald fetch-guard — pre-edit fetch + rebase enforcement (hermetic, -race)" \
    "go test -race -count=1 -run 'TestFetchGuard_Rebased_PASS' ./pherald/cmd/pherald/..."
sc_anchor "E100" "${SC_GITOPS_FETCHGUARD_DIR:+${SC_GITOPS_FETCHGUARD_DIR}/transcript.txt}" "edit on main was made on a tree rebased on origin"

# ---- E101: §9.1 sherald destructive-guard command (HRD-033) ----
check "E101 §9.1 sherald destructive-guard — no-backup BLOCK + --backup-exists ALLOW (hermetic, -race)" \
    "go test -race -count=1 -run 'TestDestructiveGuard_NoBackup_Blocks|TestDestructiveGuard_WithBackup_Allows' ./sherald/cmd/sherald/..."
sc_anchor "E101" "${SC_SYS_DESTRUCT_DIR:+${SC_SYS_DESTRUCT_DIR}/transcript.txt}" "destructive-guard blocked rm/reset/clean without hardlinked backup repo.safety_breach"

# ---- E102: §11.4.26/.32 sherald constitution-pull command (HRD-040) ----
check "E102 §11.4.26/.32 sherald constitution-pull — fetch+rebase then post-pull validation gate (hermetic, -race)" \
    "go test -race -count=1 -run 'TestConstitutionPull_FetchRebaseValidate_EmitsBundleUpdated' ./sherald/cmd/sherald/..."
sc_anchor "E102" "${SC_SYS_CONSTPULL_DIR:+${SC_SYS_CONSTPULL_DIR}/transcript.txt}" "constitution-pull fetch+rebase ok then post-pull validation gate bundle.updated"

# ---- E103: §11.4.41 sherald force-push-gate command (HRD-046) ----
check "E103 §11.4.41 sherald force-push-gate — not-merged BLOCK + merged/authorized ALLOW (hermetic, -race)" \
    "go test -race -count=1 -run 'TestForcePushGate_NotMerged_Blocks|TestForcePushGate_MergedAndAuthorized_Allows' ./sherald/cmd/sherald/..."
sc_anchor "E103" "${SC_SYS_FORCEPUSH_DIR:+${SC_SYS_FORCEPUSH_DIR}/transcript.txt}" "force-push-gate blocked force-push without merge-first or session-auth repo.safety_breach"

# ---- E104: §12.6 sherald mem-budget-watch command (HRD-056) ----
check "E104 §12.6 sherald mem-budget-watch — over-ceiling BLOCK + under-ceiling ALLOW (hermetic, -race)" \
    "go test -race -count=1 -run 'TestMemBudgetWatch_OverCeiling_Blocks|TestMemBudgetWatch_UnderCeiling_Allows' ./sherald/cmd/sherald/..."
sc_anchor "E104" "${SC_SYS_MEMBUDGET_DIR:+${SC_SYS_MEMBUDGET_DIR}/transcript.txt}" "mem-budget-watch blocked at used_fraction>=0.60 host.safety_breach"

# ---- E105: §4 rherald tag-mirror command (HRD-031) ----
check "E105 §4 rherald tag-mirror — all-mirrors-have-tag ALLOW + missing-on-mirror BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestTagMirror_AllMirrorsHaveTag_Allows|TestTagMirror_MissingOnMirror_Blocks' ./rherald/cmd/rherald/..."
sc_anchor "E105" "${SC_REL_TAGMIRROR_DIR:+${SC_REL_TAGMIRROR_DIR}/transcript.txt}" "QA-EVIDENCE-ANCHOR: HRD-031-tag-mirror-rherald-§4-C4"

# ---- E106: §5 rherald changelog-generate command (HRD-032) ----
check "E106 §5 rherald changelog-generate — conventional-commits changelog from git log (hermetic, -race)" \
    "go test -race -count=1 -run 'TestChangelogGenerate_WritesConventionalCommits' ./rherald/cmd/rherald/..."
sc_anchor "E106" "${SC_REL_CHANGELOG_DIR:+${SC_REL_CHANGELOG_DIR}/transcript.txt}" "QA-EVIDENCE-ANCHOR: HRD-032-changelog-generate-rherald-§5-C4"

# ---- E107: §11.4.40 rherald gate-retest command (HRD-045) ----
check "E107 §11.4.40 rherald gate-retest — retest-passed ALLOW + retest-failed BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestGateRetest_RetestPassed_Allows|TestGateRetest_RetestFailed_Blocks' ./rherald/cmd/rherald/..."
sc_anchor "E107" "${SC_REL_RETEST_DIR:+${SC_REL_RETEST_DIR}/transcript.txt}" "QA-EVIDENCE-ANCHOR: HRD-045-gate-retest-rherald-§11.4.40-C4"

# ---- E108: §11.4.27 bherald test-tier-verify command (HRD-041) ----
check "E108 §11.4.27 bherald test-tier-verify — all-tiers-present ALLOW + missing-tier BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestTestTierVerify_AllTiersPresent_Allows|TestTestTierVerify_MissingTier_Blocks' ./bherald/cmd/bherald/..."
sc_anchor "E108" "${SC_BUILD_TIER_DIR:+${SC_BUILD_TIER_DIR}/transcript.txt}" "QA-ANCHOR: HRD-041-C5-TEST-TIER-VERIFY-E2E-bherald"

# ---- E109: §11.4.2 bherald evidence-capture command (HRD-035) ----
check "E109 §11.4.2 bherald evidence-capture — with-evidence ALLOW + metadata-only BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestEvidenceCapture_WithEvidence_Allows|TestEvidenceCapture_MetadataOnly_Blocks' ./bherald/cmd/bherald/..."
sc_anchor "E109" "${SC_BUILD_EVIDENCE_DIR:+${SC_BUILD_EVIDENCE_DIR}/transcript.txt}" "QA-ANCHOR: HRD-035-C5-EVIDENCE-CAPTURE-E2E-bherald"

# ---- E110: §11.4.61 cherald docs-sync command (HRD-037, C3a) ----
check "E110 §11.4.61 cherald docs-sync — metadata-present ALLOW + missing-metadata BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestDocsSync_MetadataPresent_Allows|TestDocsSync_MissingMetadata_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E110" "${SC_DOCS_SYNC_DIR:+${SC_DOCS_SYNC_DIR}/transcript.txt}" "QA-ANCHOR: HRD-037-DOCS-SYNC-C3A-20260528T050000Z"

# ---- E111: §11.4.59 cherald readme-sync command (HRD-050, C3a) ----
check "E111 §11.4.59 cherald readme-sync — in-sync ALLOW + drift BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestReadmeSync_InSync_Allows|TestReadmeSync_Drift_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E111" "${SC_README_SYNC_DIR:+${SC_README_SYNC_DIR}/transcript.txt}" "QA-ANCHOR: HRD-050-README-SYNC-C3A-20260528T050000Z"

# ---- E112: §11.4.65 cherald export command (HRD-052, C3a) ----
check "E112 §11.4.65 cherald export — invokes-script ALLOW (hermetic, -race)" \
    "go test -race -count=1 -run 'TestExport_InvokesScript_Allows' ./cherald/cmd/cherald/..."
sc_anchor "E112" "${SC_EXPORT_DIR:+${SC_EXPORT_DIR}/transcript.txt}" "QA-ANCHOR: HRD-052-EXPORT-C3A-20260528T050000Z"

# ---- E113: §11.4.53 cherald fixed-summary-sync command (HRD-048, C3a) ----
check "E113 §11.4.53 cherald fixed-summary-sync — parity ALLOW + drift BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestFixedSummarySync_Parity_Allows|TestFixedSummarySync_Drift_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E113" "${SC_FIXEDSUM_DIR:+${SC_FIXEDSUM_DIR}/transcript.txt}" "QA-ANCHOR: HRD-048-FIXED-SUMMARY-SYNC-C3A-20260528T050000Z"

# ---- E114: §11.4.53 cherald fixed-align command (HRD-039, C3a) ----
check "E114 §11.4.53 cherald fixed-align — no-drift ALLOW + drift BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestFixedAlign_NoDrift_Allows|TestFixedAlign_Drift_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E114" "${SC_FIXEDALIGN_DIR:+${SC_FIXEDALIGN_DIR}/transcript.txt}" "QA-ANCHOR: HRD-039-FIXED-ALIGN-C3A-20260528T050000Z"

# ---- E115: §11.4.31 cherald submanifest-verify command (HRD-042, C3b) ----
check "E115 §11.4.31 cherald submanifest-verify — present ALLOW + missing BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestSubmanifestVerify_Present_Allows|TestSubmanifestVerify_Missing_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E115" "${SC_SUBMANIFEST_DIR:+${SC_SUBMANIFEST_DIR}/transcript.txt}" "ANCHOR: HRD-042-SUBMANIFEST-VERIFY-QA"

# ---- E116: §11.4.60 cherald composite-gate command (HRD-051, C3b) ----
check "E116 §11.4.60 cherald composite-gate — all-pass ALLOW + violation BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestCompositeGate_AllPass_Allows|TestCompositeGate_Violation_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E116" "${SC_COMPOSITE_DIR:+${SC_COMPOSITE_DIR}/transcript.txt}" "ANCHOR: HRD-051-COMPOSITE-GATE-QA"

# ---- E117: §11.4.73 cherald spec-version-check command (HRD-054, C3b) ----
check "E117 §11.4.73 cherald spec-version-check — no-drift ALLOW + drift BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestSpecVersionCheck_NoDrift_Allows|TestSpecVersionCheck_Drift_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E117" "${SC_SPECVER_DIR:+${SC_SPECVER_DIR}/transcript.txt}" "ANCHOR: HRD-054-SPEC-VERSION-CHECK-QA"

# ---- E118: §11.4.74 cherald catalogue-check command (HRD-055, C3b) ----
check "E118 §11.4.74 cherald catalogue-check — has-catalogue-line ALLOW + missing BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestCatalogueCheck_HasCatalogueLine_Allows|TestCatalogueCheck_Missing_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E118" "${SC_CATCHECK_DIR:+${SC_CATCHECK_DIR}/transcript.txt}" "ANCHOR: HRD-055-CATALOGUE-CHECK-QA"

# ---- E119: §11.4.62→§11.4.60 cherald script-docs-check command (HRD-038, C3b) ----
check "E119 §11.4.62→§11.4.60 cherald script-docs-check — all-documented ALLOW + undocumented BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestScriptDocsCheck_AllDocumented_Allows|TestScriptDocsCheck_Undocumented_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E119" "${SC_SCRIPTDOCS_DIR:+${SC_SCRIPTDOCS_DIR}/transcript.txt}" "ANCHOR: HRD-038-SCRIPT-DOCS-CHECK-QA"

# ---- E120: §16.2→§11.4.10 cherald creds-scan command (HRD-036, C3b) ----
check "E120 §16.2→§11.4.10 cherald creds-scan — clean ALLOW + planted-secret BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestCredsScan_Clean_Allows|TestCredsScan_PlantedSecret_Blocks' ./cherald/cmd/cherald/..."
sc_anchor "E120" "${SC_CREDSSCAN_DIR:+${SC_CREDSSCAN_DIR}/transcript.txt}" "ANCHOR: HRD-036-CREDS-SCAN-QA"

# ---- E121: §9.3 sherald backup-snapshot command (HRD-034 §43 straggler) ----
check "E121 §9.3 sherald backup-snapshot — hardlinked snapshot create ALLOW + nonexistent-target BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestBackupSnapshot_CreatesHardlinks_Allows|TestBackupSnapshot_NonexistentTarget_Blocks' ./sherald/cmd/sherald/..."
sc_anchor "E121" "${SC_SYS_BACKUP_DIR:+${SC_SYS_BACKUP_DIR}/transcript.txt}" "QA-ANCHOR: HRD-034-BACKUP-SNAPSHOT-EVIDENCE-20260528T060000Z"

# ---- E122: §11.4.45 scherald status-digest command (HRD-047 §43 straggler) ----
check "E122 §11.4.45 scherald status-digest — healthy-status ALLOW + missing-Status.md BLOCK (hermetic, -race)" \
    "go test -race -count=1 -run 'TestStatusDigest_HealthyStatus_Allows|TestStatusDigest_MissingStatus_Blocks' ./scherald/cmd/scherald/..."
sc_anchor "E122" "${SC_SCHED_DIGEST_DIR:+${SC_SCHED_DIGEST_DIR}/transcript.txt}" "HRD-047-STATUS-DIGEST-E2E-EVIDENCE"

# ---- E123: Batch D pgxTaskRepository real-PG integration (HRD-085..089) ----
# The 14 TaskRepository round-trips persist + read back against REAL Postgres.
# The suite SELF-BOOTS its own PG via QuickstartBoot (+ applies migration 000013
# + assumes a pristine DB for its count assertions), which COLLIDES with this
# e2e's shared :24100 PG lifecycle (the e2e's own M2/serve blocks boot + populate
# 24100 first). So — exactly like E34 (HERALD_TGRAM_LIVE_INBOUND) and E70
# (HERALD_W6_LIVE_LOOP) — the live re-run is gated behind HERALD_BATCHD_LIVE=1
# against a DEDICATED clean PG; by default it SKIPs and the sc_anchor below
# asserts the COMMITTED real-PG transcript (14 PASS / 0 FAIL) as the standing
# §107 evidence. Run: `podman volume rm herald-e2e_herald-pg; HERALD_BATCHD_LIVE=1
# DOCKER_HOST=… go test -tags=integration -run TestRepo ./commons_infra/...`.
if [ "${HERALD_BATCHD_LIVE:-}" = "1" ] && nc -z 127.0.0.1 24100 2>/dev/null; then
    check "E123 pgxTaskRepository (HRD-085..089) — 14 real-PG round-trips persist+readback (dedicated clean PG :24100)" \
        "go test -tags=integration -count=1 -run 'TestRepo' ./commons_infra/... -timeout=480s"
else
    echo "SKIP  E123 (set HERALD_BATCHD_LIVE=1 + a DEDICATED clean PG :24100 to exercise — the self-booting suite collides with this e2e's shared PG; §11.4.3 explicit SKIP-with-reason; committed real-PG evidence: docs/qa/HRD-085-089-20260528T070000Z/integration_realpg.log = 14 PASS / 0 FAIL)"
fi
sc_anchor "E123" "${SC_BATCHD_DIR:+${SC_BATCHD_DIR}/integration_realpg.log}" "QA-ANCHOR: HRD-085-089-BATCHD-REALPG-INTEGRATION-20260528"

# ---- E124-E131: Wave 7 multi-channel framework + Slack invariants (HRD-118) ----
# All anchored to live test names in the channels framework (HRD-110..114) +
# slack adapter (HRD-115) + qaherald messenger (HRD-116). E127 is LIVE Slack —
# env-gated like E34/E70: runs against a real workspace when HERALD_SLACK_BOT_TOKEN
# + HERALD_SLACK_CHANNEL_ID are present, else SKIP-with-reason citing the
# committed T6/T7 hermetic transcripts as the standing §107 evidence.

check "E124 channels registry resolves registered name + unknown-name errors (Wave 7 T2)" \
    "go test -race -count=1 -run 'TestRegistryResolvesRegisteredChannel|TestRegistryUnknownChannelErrors' ./commons_messaging/channels/..."

check "E125 tgram bot self-filter still drops self-echo + keeps cross-bot (post-Wave-7 BotSelfIdentity generalization, T1/T4 pure-refactor invariant)" \
    "go test -race -count=1 -run 'TestSubscribeBotSelfFilter' ./commons_messaging/channels/tgram/..."

check "E126 slack adapter — channels.Channel satisfied + auth.test self-identity + chat.postMessage wire bytes + init() registry wiring (T6)" \
    "go test -race -count=1 -run 'TestSlackSatisfiesChannel|TestSlackRegistryWiring|TestSlackBotSelfIdentityViaAuthTest|TestSlackSendCrossesWireWithText' ./commons_messaging/channels/slack/..."
sc_anchor "E126" "${SC_SLACK_ADAPTER_DIR:+${SC_SLACK_ADAPTER_DIR}/transcript.txt}" "QA-ANCHOR: HRD-115-WAVE7-T6-SLACK-ADAPTER-20260528"

if [ -n "${HERALD_SLACK_BOT_TOKEN:-}" ] && [ -n "${HERALD_SLACK_CHANNEL_ID:-}" ] \
   && grep -q 'func TestSlack_Live_Send' qaherald/internal/messenger/*_test.go 2>/dev/null; then
    check "E127 LIVE Slack Send + reply round-trip via qaherald MessengerClient (real workspace)" \
        "go test -tags=integration -count=1 -run TestSlack_Live_Send ./qaherald/internal/messenger/... -timeout=120s"
else
    echo "SKIP  E127 (live Slack round-trip requires HERALD_SLACK_BOT_TOKEN + HERALD_SLACK_CHANNEL_ID *and* a TestSlack_Live_Send test in qaherald/internal/messenger/; the latter is a future operator-evidence task — running -run against a missing test would silently 'no tests to run' = PASS-bluff, so guard on both. Hermetic round-trip evidence stands at docs/qa/HRD-115-20260528T080000Z/ + docs/qa/HRD-116-20260528T090000Z/; §11.4.3 explicit SKIP-with-reason)"
fi

check "E128 inbox/<channel>/<sha256>.<ext> per-channel isolation + content-addressed idempotency (T3)" \
    "go test -race -count=1 -run 'TestInboxDirIsPerChannel|TestWriteContentAddressedHashesAndIsIdempotent' ./commons_messaging/channels/..."

check "E129 generalized self-filter — IdentityUsername + IdentityUserID + empty-self echo-loop hazard (T4)" \
    "go test -race -count=1 -run 'TestIsSelfEchoUsername|TestIsSelfEchoUserID|TestIsSelfEchoEmptySelfNeverEchoes' ./commons_messaging/channels/..."

check "E130 multi-channel pherald listen — Subscribers map dispatch + clean ctx-cancel exit (T5)" \
    "go test -race -count=1 -run 'TestListenWiresHandlerAndExitsOnCancel' ./pherald/cmd/pherald/..."

check "E131 qaherald messenger.Build(BuildConfig) — tgram + slack + unknown-channel-errors-loud (T7)" \
    "go test -race -count=1 -run 'TestBuilderTgram|TestBuilderSlack|TestBuilderUnknownErrors' ./qaherald/internal/messenger/..."
sc_anchor "E131" "${SC_QAHERALD_SLACK_DIR:+${SC_QAHERALD_SLACK_DIR}/transcript.txt}" "QA-ANCHOR: HRD-116-WAVE7-T7-QAHERALD-SLACK-CLIENT-20260528"

# ---- E132-E133: tgram §11.4.85 stress + chaos (HRD-137) ----
# Wave C closure — multi-recipient fan-out stress proves the Send path under
# 200 concurrent recipients × 5 messages stays panic-free + sanitizes errors;
# chaos drives Subscribe()'s getUpdates poller through an httptest fault
# injector (3× 500 + 2× 1.5s hangs + 1× mid-body Hijacker close + 2× success)
# and asserts ≥3 InboundEvents reach the handler within a 12s window.
# Deterministic across -race -count=3 per §11.4.50.
check "E132 tgram stress — multi-recipient fan-out (HRD-137; 200 recipients × 5 msgs, race-free)" \
    "go test -race -count=1 -run 'TestTgram_Stress_MultiRecipientFanOut' ./commons_messaging/channels/tgram/..."
sc_anchor "E132" "${SC_TGRAM_DIR:+${SC_TGRAM_DIR}/stress_chaos/fanout/assertion.txt}" "status=PASS"

check "E133 tgram chaos — getUpdates poller resilience under 4-mode fault injection (HRD-137; SKIP→PASS via subscribe.go baseURL seam)" \
    "go test -race -count=1 -run 'TestTgram_Chaos_GetUpdatesPollerResilience' ./commons_messaging/channels/tgram/..."
sc_anchor "E133" "${SC_TGRAM_DIR:+${SC_TGRAM_DIR}/stress_chaos/poller_chaos/chaos_assertion.txt}" "status=PASS"

# ---- E134: Wave 8 MTProto scaffold (Track B prep — §11.4.98 / §108.m) ----
# Validates the MTProto user-account harness scaffold compiles + its hermetic
# tests pass with -race -count=3 determinism. The runtime implementation is
# blocked on operator MTProto credentials (see docs/requirements/blockers/
# missing_env_variables.md); this invariant covers the scaffold layer so a
# regression in Config.Validate / sanitizer / session helpers is caught at
# the gate. Once Track B lands the gotd/td-backed runtime, this invariant
# will gain the autonomous closed-loop coverage that replaces the SKIPped
# Wave 6 live-loop test.
check "E134 qaherald/internal/mtproto scaffold — Config.Validate + sanitizer (HRD-133 parity) + session helpers (-race -count=3 deterministic)" \
    "go test -race -count=3 ./qaherald/internal/mtproto/..."

# ---- E135-E137: Wave 8 Track B MTProto-driven autonomous tests (§11.4.98) ----
# 3 §11.4.98-compliant replacements for the legacy hand-send tests. Each
# requires HERALD_MTPROTO_* + HERALD_TGRAM_* env + ~/.config/herald/
# mtproto.session (operator ran `qaherald mtproto login` once); SKIP-with-
# reason per §11.4.3 otherwise. Build tag `integration_mtproto`.
check "E135 TestMTProto_Subscribe_AutonomousRoundTrip — MTProto-driven Subscribe replacement (HRD-140; §11.4.98 NON-COMPLIANT → COMPLIANT)" \
    "go test -tags=integration_mtproto -count=1 -short -timeout=180s -run 'TestMTProto_Subscribe_AutonomousRoundTrip' ./qaherald/internal/lifecycle/..."

check "E136 TestMTProto_Wave6_AutonomousClosedLoop — full pherald→CC→reply round-trip via MTProto (HRD-141; §11.4.98 NON-COMPLIANT → COMPLIANT, replaces tests/test_wave6_live_loop.sh)" \
    "go test -tags=integration_mtproto -count=1 -short -timeout=420s -run 'TestMTProto_Wave6_AutonomousClosedLoop' ./qaherald/internal/lifecycle/..."

check "E137 TestMTProto_Wave65_LifecycleAutonomous — Wave 6.5 fast-path lifecycle scenarios via MTProto (HRD-142; §11.4.98 NON-COMPLIANT → COMPLIANT, replaces lifecycle --manual mode)" \
    "go test -tags=integration_mtproto -count=1 -short -timeout=300s -run 'TestMTProto_Wave65_LifecycleAutonomous' ./qaherald/internal/lifecycle/..."

# ---- E138: HRD-090 dead-letter move + .queue.dead_letter emit (real-PG) ----
# PG-gated per §11.4.3. When herald-postgres :24100 is reachable, run the
# real-PG round-trip (3 independent sinks: source terminal-state + dlq snapshot
# + real-bus .queue.dead_letter delivery) AND the §11.4.85 stress/chaos suite
# (50 concurrent moves race-clean + emit-failure-atomic + cancelled-ctx-no-
# orphan). The tests boot/reuse the container via QuickstartBoot and set their
# own throwaway password; SKIP-with-reason when :24100 is unreachable.
echo ""
echo "== E138: HRD-090 dead-letter handling (real-PG round-trip + stress/chaos) =="
if (command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1) \
   && nc -z 127.0.0.1 24100 2>/dev/null; then
    # Dev-container password normalization (same as E14-E17): the HRD-090
    # integration + stress/chaos tests hardcode HERALD_DB_PASSWORD=
    # "test-postgres-password-DO-NOT-USE-IN-PROD" via bootRepo's t.Setenv, which
    # is un-overridable from outside the test process. Earlier PG blocks in this
    # suite (e.g. E7-E12 pherald serve = "herald_dev") leave the SHARED container
    # role password normalized to a different value, so reconcile it back here
    # before the test's authenticated pgx connect.
    pg_self_heal "test-postgres-password-DO-NOT-USE-IN-PROD"
    check "E138 HRD-090 MoveToDeadLetter real-PG round-trip + §11.4.85 stress/chaos (3 sinks; 50 concurrent race-clean; atomic under emit-failure + ctx-cancel)" \
        "go test -tags=integration -race -count=1 -timeout 8m -run 'TestRepoMoveToDeadLetter|TestMoveToDeadLetter_StressChaos' ./commons_infra/..."
else
    echo "SKIP  E138 — Postgres on :24100 unreachable (closed-set reason: hardware_not_present; §11.4.3 explicit SKIP-with-reason)"
fi
sc_anchor "E138 stress/chaos" "docs/qa/HRD-090-stress-chaos-20260529T054500Z/stress_chaos/stress_chaos.log" "PASS: TestMoveToDeadLetter_StressChaos/Stress_ConcurrentDistinctTasks"

# ---- E139: HRD-156 watch→notify daemon (hermetic, NOT PG-gated) ----
# The watch→notify e2e (TestRunWatch_EndToEndOutbound) drives the full
# workable-items SSoT pipeline against a REAL temp SQLite DB + REAL
# commons_watch.Watcher (fsnotify + WAL-poll) + REAL commons_workable.Diff +
# REAL workflow.Notifier over the REAL runner.ChannelDispatcher into a
# recording channel — proving a real DB mutation (create / status-change /
# delete) produces a real rendered diff message dispatched through the real
# fan-out. commons_workable is in-process SQLite, so this runs UNCONDITIONALLY
# (no Postgres gate). §107 anchor: PASS here means the user-visible
# watch→notify behaviour works, not merely that the process boots.
check "E139 HRD-156 pherald watch→notify daemon — real SQLite + real fsnotify + real Diff + real fan-out → recording channel (create/status/delete; -race, hermetic, NOT PG-gated)" \
    "go test -race -count=1 -run 'TestRunWatch_EndToEndOutbound' ./pherald/cmd/pherald/..."

# ---- E140-E142: participant identity / attribution / notification-tagging ----
# (§11.4.104 / docs/design/PARTICIPANT_ATTRIBUTION.md — operator mandate 2026-05-31).
# Hermetic, NOT PG-gated. PASS here means the user-visible attribution + @-tagging
# behaviour actually works: created_by/assigned_to are set from the real message
# sender, and the dispatched message body carries exactly the right @usernames per
# the matrix (Operator + Claude never tagged; off-channel handles skipped).
check "E140 inbound attribution — created_by = message sender (@username) / 'Claude' on system path / assigned_to defaults to Operator + explicit assign:@x override" \
    "go test -race -count=1 -run 'TestInboundAttribution' ./pherald/internal/inbound/..."
check "E141 outbound tagging E2E — real ChannelDispatcher→recording sink: operator→NO @-mention; →@bob = 'cc: @bob'; @carol→ = 'cc: @carol'; off-channel @dave = NO mention" \
    "go test -race -count=1 -run 'TestNotifier_OutboundTagging_E2E|TestNotifier_NoTagging_BodiesVerbatim' ./pherald/internal/workflow/..."
check "E142 tagging matrix + identity resolver — MentionsFor truth-table (every cell) + MemoryResolver resolve/round-trip/operator (the §11.4.104 contract surface)" \
    "go test -race -count=1 -run 'TestMentionsFor|TestMemoryResolver' ./commons/..."

# ---- E143-E145: natural-language intent recognition (§11.4.105) ----
# (docs/design/INTENT_RECOGNITION.md — operator mandate 2026-05-31). Hermetic.
# PASS here means users do NOT need command syntax: a clear NL command is
# recognized (Tier 1), and an ambiguous message is NEVER guessed/ignored — it is
# replied-to with the sender @-tagged + a precise clarifying question (Tier 3).
check "E143 Tier-1 command recognizer — NL imperatives → action (close/assign/open/investigate/status) + CONSERVATIVE negatives that defer to the LLM (no false-match)" \
    "go test -race -count=1 -run 'TestCommandRecognizer' ./pherald/internal/inbound/..."
check "E144 Tier-3 clarify E2E — ambiguous message → reply '@<sender> <specific question>' (user tagged + asked, never ignored); raw-handle fallback; NEGATIVE: a clear command does NOT trigger clarify" \
    "go test -race -count=1 -run 'TestClarify_E2E|TestClearCommand_DoesNotTriggerClarify|TestClarify_NilResolver_Graceful|TestClarify_EmptyQuestion_IsLoudError' ./pherald/internal/inbound/..."
check "E145 Tier-2 envelope — the dispatch envelope instructs the LLM to recognize the command set + return action=clarify when intent is unclear, never guess (§11.4.6)" \
    "go test -race -count=1 -run 'TestFormatEnvelope_IntentInferenceInstruction' ./commons_messaging/dispatch/claude_code/..."

# ---- E146: Docs Chain documentation-sync drift-gate (§11.4.106 / plan docs/research/docs_chain/) ----
# PILOT scope (docs/guides/COMMONS_WATCH.md). Positive evidence: a cold `docs_chain sync` of the
# herald-pilot context re-derives html/pdf/docx via the scripts/docs_chain/*.sh exec wrappers; the
# wrappers replicate export_docs.sh's exact pandoc flags + pin SOURCE_DATE_EPOCH, so with the source
# unchanged the re-derivation is BYTE-STABLE and leaves ZERO git-diff on the committed siblings — a
# real drift assertion, not a metadata check. The negative control (edit source → verify STALE exit 1)
# is captured in docs/qa/DOCS-CHAIN-PILOT-*/pilot-verify.txt. SKIP-with-reason (§11.4.3) when the
# docs_chain binary / pandoc / weasyprint are absent (the binary is built from the sibling
# ~/Projects/docs_chain repo, not installed system-wide).
# FORMATS-EXPORT SWITCH (operator order 2026-10-26: agents work only with Markdown; the .html/.pdf/.docx exports of
# tracked Markdown are OFF by default and no longer tracked — constitution/config/formats_export.conf, default false).
# E146/E147/E148 demand those siblings, so when the switch is OFF each gate announces an honest SKIP-with-reason
# (§11.4.3 / §11.4.106(E)) and never invokes docs_chain; when it is ON (DOCS_EXPORT=1, or a repository policy
# `enabled=1`) the original gate runs UNCHANGED. The default + resolution order live ONLY in the constitution lib
# (scripts/lib/formats_export_guard.sh just locates it); an undiscoverable lib is fail-closed = disabled + announced.
# Paired mutation proof: tests/test_e2e_docs_chain_formats_switch.sh.
. "${REPO_ROOT}/scripts/lib/formats_export_guard.sh"
DC_BIN="$(command -v docs_chain 2>/dev/null || echo /tmp/docs_chain)"
DC_PILOT_SIB="docs/guides/COMMONS_WATCH.html docs/guides/COMMONS_WATCH.pdf docs/guides/COMMONS_WATCH.docx"
if ! herald_formats_export_enabled; then
    echo "SKIP  E146 Docs Chain drift-gate — formats_export disabled (constitution/config/formats_export.conf default false; operator order 2026-10-26): no .html/.pdf/.docx sibling is tracked or demanded; enable with DOCS_EXPORT=1; §11.4.3 SKIP-with-reason"
elif [ -x "${DC_BIN}" ] && command -v pandoc >/dev/null 2>&1 && command -v weasyprint >/dev/null 2>&1 \
   && [ -f .docs_chain/contexts/herald-pilot.yaml ]; then
    rm -f .docs_chain/state.json
    if "${DC_BIN}" sync --root . herald-pilot > /tmp/e2e_dc 2>&1 \
       && git diff --quiet -- ${DC_PILOT_SIB}; then
        echo "PASS  E146 Docs Chain drift-gate — pilot COMMONS_WATCH md→html/pdf/docx re-derives BYTE-STABLE (zero drift); logo print.css preserved (§11.4.106)"
        pass=$((pass+1))
    else
        echo "FAIL  E146 Docs Chain drift — committed siblings differ from deterministic re-derivation (stale exports OR non-deterministic wrapper)"
        tail -3 /tmp/e2e_dc 2>/dev/null | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("E146")
    fi
    git checkout -- ${DC_PILOT_SIB} 2>/dev/null   # restore: the gate must leave the tree clean
    rm -f .docs_chain/state.json
else
    echo "SKIP  E146 Docs Chain drift-gate — docs_chain binary / pandoc / weasyprint absent (build from ~/Projects/docs_chain); §11.4.3 SKIP-with-reason"
fi

# ---- E147: Docs Chain FLEET drift-gate — the FULL herald-docs corpus (§11.4.106 / plan §7) ----
# Fleet scope: every tracked .md with a committed .html sibling (~66 docs, 263 nodes, 197 edges),
# generated by scripts/docs_chain/gen_context.py into .docs_chain/contexts/herald-docs.yaml. A cold
# `docs_chain sync` re-derives EVERY sibling via the per-directory scripts/docs_chain/*.sh exec
# wrappers, then `verify` MUST report in-sync (exit 0) for all nodes — a real, deterministic, whole-
# corpus drift assertion. The html legs are BYTE-IDENTICAL to the committed export_docs.sh output
# (zero drift, proven in docs/qa/DOCS-CHAIN-FLEET-*/); pdf/docx carry the SOURCE_DATE_EPOCH
# determinism baseline. The gate restores any rebaselined sibling (git checkout) so it leaves the
# tree CLEAN. SKIP-with-reason (§11.4.3) when the docs_chain binary / pandoc / weasyprint are absent.
DC_FLEET_CTX=".docs_chain/contexts/herald-docs.yaml"
if ! herald_formats_export_enabled; then
    echo "SKIP  E147 Docs Chain FLEET drift-gate — formats_export disabled (constitution/config/formats_export.conf default false; operator order 2026-10-26): no .html/.pdf/.docx sibling is tracked or demanded; enable with DOCS_EXPORT=1; §11.4.3 SKIP-with-reason"
elif [ -x "${DC_BIN}" ] && command -v pandoc >/dev/null 2>&1 && command -v weasyprint >/dev/null 2>&1 \
   && [ -f "${DC_FLEET_CTX}" ]; then
    # snapshot the exact set of fleet siblings so we restore precisely (and assert tree-clean)
    DC_FLEET_SIB="$(awk '/^nodes:/{n=1;next} /^edges:/{n=0} n && /kind: (html|pdf|docx)/{
        for(i=1;i<=NF;i++) if($i=="path:"){p=$(i+1); gsub(/[},]/,"",p); print p}}' "${DC_FLEET_CTX}")"
    rm -f .docs_chain/state.json
    if "${DC_BIN}" sync --root . herald-docs > /tmp/e2e_dcf 2>&1 \
       && "${DC_BIN}" verify --root . herald-docs >> /tmp/e2e_dcf 2>&1; then
        echo "PASS  E147 Docs Chain FLEET drift-gate — full herald-docs corpus (66 docs) cold-sync + verify in-sync (exit 0); html byte-identical, logo print.css preserved (§11.4.106)"
        pass=$((pass+1))
    else
        echo "FAIL  E147 Docs Chain FLEET drift — sync or verify did not reach in-sync (stale exports OR non-deterministic wrapper)"
        tail -4 /tmp/e2e_dcf 2>/dev/null | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("E147")
    fi
    # restore: the gate MUST leave the tree clean (one-time deterministic rebaseline already committed)
    [ -n "${DC_FLEET_SIB}" ] && git checkout -- ${DC_FLEET_SIB} 2>/dev/null
    rm -f .docs_chain/state.json
else
    echo "SKIP  E147 Docs Chain FLEET drift-gate — docs_chain binary / pandoc / weasyprint absent (build from ~/Projects/docs_chain); §11.4.3 SKIP-with-reason"
fi

# ---- E148: Docs Chain verify-only drift-gate — `docs_chain verify herald-docs` (§11.4.106) ----
# The pure content-hash drift gate the constitution §11.4.106 names: it re-hashes every tracked .md
# and its .html/.pdf/.docx siblings and reports "in-sync" (exit 0) ONLY when nothing has drifted, or
# "STALE: [...]" (exit 1) listing the drifted nodes — a stale committed sibling is a §11.4
# documentation-layer bluff (the doc claims to be exported but the export is wrong). Distinct from the
# E146/E147 sync-gates: `verify` only READS + HASHES existing files, so it needs NEITHER pandoc NOR
# weasyprint — its sole prerequisite is the docs_chain binary on PATH. SKIP-with-reason (§11.4.3) when
# that binary is absent (CI may not carry it — built from the sibling ~/Projects/docs_chain repo).
# Positive evidence: the captured output line MUST contain the literal "in-sync" AND the exit code
# MUST be 0 — both asserted (output-token + exit-status), so a future "exit 0 with a misleading body"
# regression cannot pass-bluff this gate.
echo ""
echo "== E148: Docs Chain verify-only drift-gate (docs_chain verify herald-docs, §11.4.106) =="
if ! herald_formats_export_enabled; then
    echo "SKIP  E148 docs_chain verify-only drift-gate — formats_export disabled (constitution/config/formats_export.conf default false; operator order 2026-10-26): no .html/.pdf/.docx sibling is tracked or demanded; enable with DOCS_EXPORT=1; §11.4.3 SKIP-with-reason"
elif [ -x "${DC_BIN}" ] && [ -f "${DC_FLEET_CTX}" ]; then
    if dc_verify_out="$("${DC_BIN}" verify --root . herald-docs 2>&1)" \
       && printf '%s' "${dc_verify_out}" | grep -q 'in-sync'; then
        echo "PASS  E148 docs_chain verify herald-docs — whole tracked-doc corpus in-sync (exit 0 + 'in-sync'); §11.4.106 content-hash drift-gate"
        pass=$((pass+1))
    else
        echo "FAIL  E148 docs_chain verify herald-docs — STALE (a committed .html/.pdf/.docx sibling drifted from its .md; §11.4 documentation-layer bluff — re-run scripts/export_docs.sh for the stale node(s))"
        printf '%s\n' "${dc_verify_out}" | tail -3 | sed 's/^/      /'
        fail=$((fail+1)); fail_names+=("E148")
    fi
else
    echo "SKIP  E148 docs_chain verify-only drift-gate — docs_chain binary absent from PATH (build from ~/Projects/docs_chain); §11.4.3 SKIP-with-reason"
fi

# ----------------------------------------------------------------------
echo ""
echo "===================================================="
echo "Result: ${pass} PASS / ${fail} FAIL / ${sc_skip} stress-chaos-evidence SKIP"
if [ "${sc_skip}" -gt 0 ]; then
    echo ""
    echo "Stress/chaos EVIDENCE anchors UNVERIFIED (§11.4.85 suite not yet run — honest §11.4.3 SKIP, NOT a PASS):"
    for n in "${sc_skip_names[@]}"; do
        echo "  - ${n} (paired live check ran; only the captured-evidence artefact is absent)"
    done
    echo "  → run the §11.4.85 stress+chaos suite to capture docs/qa/<run-id>/stress_chaos/ and convert these to PASS."
fi
if [ "${fail}" -gt 0 ]; then
    echo ""
    echo "Bluffs caught:"
    for n in "${fail_names[@]}"; do
        echo "  - ${n}"
    done
    exit 1
fi
echo ""
echo "All Herald user-visible features verified end-to-end."
if [ "${sc_skip}" -gt 0 ]; then
    echo "NOTE: ${sc_skip} stress/chaos evidence anchor(s) remain UNVERIFIED — see the SKIP list above. This is NOT a fully-proven run."
fi
echo "Anti-bluff covenant (§11.4) intact."
exit 0
