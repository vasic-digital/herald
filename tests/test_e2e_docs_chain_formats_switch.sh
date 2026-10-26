#!/usr/bin/env bash
# tests/test_e2e_docs_chain_formats_switch.sh -- paired test for the formats-export switch guard on the three
# Docs Chain drift-gates (E146 / E147 / E148) of scripts/e2e_bluff_hunt.sh.
#
# Purpose (operator order 2026-10-26: agents work only with Markdown; .html/.pdf/.docx exports are OFF by default,
#   the constitution owns the switch -- constitution/config/formats_export.conf, default `formats_export=false`):
#   E146/E147/E148 demand tracked .html/.pdf/.docx siblings of tracked .md files (a pilot re-derivation, a whole-corpus
#   cold sync + verify, and a verify-only drift gate). Once those siblings are removed from the repository the three
#   gates can only FAIL (STALE / missing nodes) or leave a dirty tree. They are therefore guarded by the shared switch:
#     disabled -> an announced SKIP-with-reason (section 11.4.3 / 11.4.106(E)), docs_chain NEVER invoked, no FAIL;
#     enabled  -> the original check, byte-for-byte unchanged (E148 still FAILs on STALE, PASSes only on exit 0 + "in-sync").
#   The guard lives in scripts/lib/formats_export_guard.sh (finds the constitution lib, fail-closed when it is absent).
#
# What this test proves (all hermetic -- a stub `docs_chain`/`pandoc`/`weasyprint` on PATH, a scratch git sandbox):
#   Part A  the guard: default OFF (control needle: the real constitution lib IS discovered -- the source reads
#           constitution-default, never fail-closed); DOCS_EXPORT=1 ON; conf=true ON; DOCS_EXPORT=0 beats conf=true;
#           a repository policy `enabled=1` ON; an unreadable lib is fail-closed even with DOCS_EXPORT=1.
#   Part B  the real E146..E148 region of e2e_bluff_hunt.sh, extracted and executed:
#           disabled -> 3 SKIP lines naming formats_export, stub never invoked, 0 FAIL;
#           enabled + stub says STALE -> E147 and E148 FAIL (the gates are not weakened);
#           enabled + stub says in-sync -> E146 E147 E148 PASS.
#   Part C  paired mutants (each MUST make this test FAIL): M1 guard replaced by `false`-branch removal (gates run while
#           disabled), M2 guard library always-enabled, M3 E148 weakened to ignore the verify result when enabled,
#           M4 guard library never fail-closed (treats an unreadable lib as enabled).
#
# Usage: bash tests/test_e2e_docs_chain_formats_switch.sh        (exit 0 = all checks passed)
# Side effects: creates and removes a scratch directory under ${TMPDIR:-/tmp}; the e2e region itself writes
#   /tmp/e2e_dc and /tmp/e2e_dcf (its own log files).
# Dependencies: bash, git, awk, sed, grep, mktemp. Cross-references: scripts/e2e_bluff_hunt.sh (E146-E148),
#   scripts/lib/formats_export_guard.sh, constitution/scripts/formats_export_lib.sh, scripts/testing/test_formats_export_flag.sh (parent).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERALD_ROOT="$(cd "$HERE/.." && pwd)"
E2E="$HERALD_ROOT/scripts/e2e_bluff_hunt.sh"
GUARD="$HERALD_ROOT/scripts/lib/formats_export_guard.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/herald_e2e_switch.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
PASSN=0
FAILN=0
ok()  { PASSN=$((PASSN+1)); printf 'ok   %s\n' "$1"; }
bad() { FAILN=$((FAILN+1)); printf 'FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi; }
has() { if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1" "missing [$2]"; fi; }
hasnt() { if printf '%s' "$3" | grep -qF -- "$2"; then bad "$1" "unexpected [$2]"; else ok "$1"; fi; }

# ---------------------------------------------------------------- stubs (hermetic tool environment)
STUBBIN="$TMP/stubbin"
mkdir -p "$STUBBIN"
cat > "$STUBBIN/docs_chain" <<'EOS'
#!/bin/sh
# stub docs_chain: records every invocation; verify answers per STUB_MODE (ok -> "in-sync" rc 0, stale -> STALE rc 1,
# misleading -> STALE body but rc 0)
echo "$*" >> "${STUB_LOG:?STUB_LOG unset}"
case "$1" in
  verify) case "${STUB_MODE:-ok}" in
            ok)         echo "in-sync"; exit 0 ;;
            misleading) echo "STALE: [node_x]"; exit 0 ;;   # exit 0 with a body that is NOT in-sync (E148 must still FAIL)
            *)          echo "STALE: [node_x]"; exit 1 ;;
          esac ;;
  sync)   echo "synced"; exit 0 ;;
  *)      exit 0 ;;
esac
EOS
printf '#!/bin/sh\nexit 0\n' > "$STUBBIN/pandoc"
printf '#!/bin/sh\nexit 0\n' > "$STUBBIN/weasyprint"
chmod +x "$STUBBIN/docs_chain" "$STUBBIN/pandoc" "$STUBBIN/weasyprint"

# ---------------------------------------------------------------- Part A: the guard
echo "== Part A: scripts/lib/formats_export_guard.sh =="
if [ -r "$GUARD" ]; then ok "A0 guard library exists ($GUARD)"; else bad "A0 guard library exists" "missing $GUARD"; fi

guard_resolve() { # [env assignments...] -> "<0|1> <source>"
    env -u DOCS_EXPORT -u FORMATS_EXPORT_LIB -u FORMATS_EXPORT_CONF -u FORMATS_EXPORT_POLICY -u FORMATS_EXPORT_ROOT \
        "$@" bash -c '. "$1" && herald_formats_export_resolve' _ "${GUARD_UNDER_TEST:-$GUARD}" 2>&1
}
guard_enabled_rc() { # [env assignments...] -> rc of herald_formats_export_enabled
    env -u DOCS_EXPORT -u FORMATS_EXPORT_LIB -u FORMATS_EXPORT_CONF -u FORMATS_EXPORT_POLICY -u FORMATS_EXPORT_ROOT \
        "$@" bash -c '. "$1" && herald_formats_export_enabled' _ "${GUARD_UNDER_TEST:-$GUARD}" >/dev/null 2>&1
    echo $?
}

CONF_TRUE="$TMP/conf_true"; printf 'formats_export=true\n' > "$CONF_TRUE"
POLICY_ON="$TMP/policy_on"; printf 'enabled=1\n' > "$POLICY_ON"

# A1 default OFF -- also the control needle: the real constitution lib was DISCOVERED (source constitution-default, never fail-closed)
eq "A1 default: disabled, resolved from the constitution default (control needle: lib discovered)" "0 constitution-default" "$(guard_resolve)"
eq "A1b default: herald_formats_export_enabled rc" "1" "$(guard_enabled_rc)"
eq "A2 DOCS_EXPORT=1 enables"                       "1 env"      "$(guard_resolve DOCS_EXPORT=1)"
eq "A2b DOCS_EXPORT=1 enabled rc"                   "0"          "$(guard_enabled_rc DOCS_EXPORT=1)"
eq "A3 conf=true enables (constitution-level decision)" "1 constitution-default" "$(guard_resolve FORMATS_EXPORT_CONF="$CONF_TRUE")"
eq "A4 DOCS_EXPORT=0 beats conf=true"               "0 env"      "$(guard_resolve FORMATS_EXPORT_CONF="$CONF_TRUE" DOCS_EXPORT=0)"
eq "A5 repository policy enabled=1 enables"         "1 policy"   "$(guard_resolve FORMATS_EXPORT_POLICY="$POLICY_ON")"
eq "A6 unreadable lib is fail-closed even with DOCS_EXPORT=1" "0 fail-closed" "$(guard_resolve FORMATS_EXPORT_LIB="$TMP/no_such_lib.sh" DOCS_EXPORT=1)"
eq "A6b unreadable lib enabled rc is 1"             "1"          "$(guard_enabled_rc FORMATS_EXPORT_LIB="$TMP/no_such_lib.sh" DOCS_EXPORT=1)"

# ---------------------------------------------------------------- Part B: the real E146..E148 region
echo "== Part B: E146-E148 region of scripts/e2e_bluff_hunt.sh =="

extract_region() { # script -> region text on stdout (from the E146 banner to the separator before the Result block)
    awk '/^# ---- E146:/{p=1} p&&/^# -{20,}$/{exit} p{print}' "$1"
}

REGION_REAL="$(extract_region "$E2E")"
REGION_LINES="$(printf '%s\n' "$REGION_REAL" | wc -l)"
if [ "${REGION_LINES:-0}" -gt 40 ] && printf '%s' "$REGION_REAL" | grep -q 'E146' && printf '%s' "$REGION_REAL" | grep -q 'E147' \
   && printf '%s' "$REGION_REAL" | grep -q 'E148'; then
    ok "B0 control needle: extracted region is non-empty ($REGION_LINES lines) and names E146 + E147 + E148"
else
    bad "B0 control needle: region extraction" "lines=$REGION_LINES"
fi

run_region() { # label script_file root stub_mode [env assignments...] -> sets R_OUT R_LOG R_RC
    local label="$1" script="$2" root="$3" mode="$4"; shift 4
    local sb="$TMP/sb_$label"
    rm -rf "$sb"; mkdir -p "$sb/.docs_chain/contexts" "$sb/docs/guides"
    : > "$sb/.docs_chain/contexts/herald-pilot.yaml"
    printf 'nodes:\n  - {id: a, path: docs/a.html, kind: html}\nedges:\n' > "$sb/.docs_chain/contexts/herald-docs.yaml"
    ( cd "$sb" && git init -q . ) >/dev/null 2>&1
    extract_region "$script" > "$sb/region.sh"
    cat > "$sb/h.sh" <<EOH
set -uo pipefail
REPO_ROOT="$root"
pass=0; fail=0; fail_names=()
. ./region.sh
echo "SUMMARY pass=\$pass fail=\$fail names=\${fail_names[*]:-}"
EOH
    : > "$sb/stub.log"
    R_OUT="$(cd "$sb" && env -u DOCS_EXPORT -u FORMATS_EXPORT_LIB -u FORMATS_EXPORT_CONF -u FORMATS_EXPORT_POLICY -u FORMATS_EXPORT_ROOT \
        PATH="$STUBBIN:$PATH" STUB_LOG="$sb/stub.log" STUB_MODE="$mode" "$@" bash ./h.sh 2>&1)"
    R_RC=$?
    R_LOG="$(cat "$sb/stub.log")"
}

# B1 disabled (default)
run_region b1 "$E2E" "$HERALD_ROOT" ok
has   "B1a disabled: E146 announced SKIP naming formats_export" "SKIP  E146" "$R_OUT"
has   "B1b disabled: E147 announced SKIP naming formats_export" "SKIP  E147" "$R_OUT"
has   "B1c disabled: E148 announced SKIP naming formats_export" "SKIP  E148" "$R_OUT"
eq    "B1d disabled: exactly 3 SKIP lines mention formats_export" "3" "$(printf '%s\n' "$R_OUT" | grep -c '^SKIP .*formats_export')"
eq    "B1e disabled: docs_chain never invoked (stub log empty)"   ""  "$R_LOG"
has   "B1f disabled: 0 FAIL, 0 PASS in the summary"               "SUMMARY pass=0 fail=0" "$R_OUT"

# B2 enabled + STALE verify -> the gates are NOT weakened
run_region b2 "$E2E" "$HERALD_ROOT" stale DOCS_EXPORT=1
has   "B2a enabled+stale: E147 FAILs (sync ok, verify STALE)"     "FAIL  E147" "$R_OUT"
has   "B2b enabled+stale: E148 FAILs on STALE"                    "FAIL  E148" "$R_OUT"
has   "B2c enabled+stale: summary counts the failures"            "fail=2" "$R_OUT"
has   "B2d enabled+stale: the stub WAS invoked (verify reached)"  "verify --root . herald-docs" "$R_LOG"
hasnt "B2e enabled+stale: no formats_export SKIP line"            "formats_export" "$R_OUT"

# B3 enabled + in-sync verify
run_region b3 "$E2E" "$HERALD_ROOT" ok DOCS_EXPORT=1
has   "B3a enabled+in-sync: E146 PASS" "PASS  E146" "$R_OUT"
has   "B3b enabled+in-sync: E147 PASS" "PASS  E147" "$R_OUT"
has   "B3c enabled+in-sync: E148 PASS" "PASS  E148" "$R_OUT"
has   "B3d enabled+in-sync: summary 3 PASS / 0 FAIL" "SUMMARY pass=3 fail=0" "$R_OUT"

# B4 enabled + exit 0 with a misleading (not in-sync) body -> E148 must still FAIL (output-token assertion preserved)
run_region b4 "$E2E" "$HERALD_ROOT" misleading DOCS_EXPORT=1
has   "B4a enabled+misleading body (rc 0, STALE text): E148 FAILs" "FAIL  E148" "$R_OUT"

# ---------------------------------------------------------------- Part C: paired mutants
echo "== Part C: paired mutants (each must make Part B/A fail) =="
mutant_detected() { # label script_file guard_lib_file -> 0 when the real assertions FAIL on the mutant
    local label="$1" mscript="$2" mguard="$3" mroot="$TMP/mroot_$1" miss=0
    rm -rf "$mroot"; mkdir -p "$mroot/scripts/lib"
    cp "$mguard" "$mroot/scripts/lib/formats_export_guard.sh"
    # the guard locates the constitution by walking up from ITS OWN directory; give the mutant root a pointer via the lib seam
    local lib; lib="$(cd "$HERALD_ROOT" && bash -c '. scripts/lib/formats_export_guard.sh; _hfe_find_lib' 2>/dev/null)"
    # disabled run: must still SKIP all three and never call docs_chain
    run_region "${label}_off" "$mscript" "$mroot" ok FORMATS_EXPORT_LIB="$lib"
    [ "$(printf '%s\n' "$R_OUT" | grep -c '^SKIP .*formats_export')" = "3" ] || miss=1
    [ -z "$R_LOG" ] || miss=1
    # enabled+stale run: E148 must FAIL
    run_region "${label}_stale" "$mscript" "$mroot" stale DOCS_EXPORT=1 FORMATS_EXPORT_LIB="$lib"
    printf '%s' "$R_OUT" | grep -q 'FAIL  E148' || miss=1
    # an unreadable lib must be fail-closed (3 SKIPs) even with DOCS_EXPORT=1
    run_region "${label}_nolib" "$mscript" "$mroot" ok DOCS_EXPORT=1 FORMATS_EXPORT_LIB="$TMP/no_such_lib.sh"
    [ "$(printf '%s\n' "$R_OUT" | grep -c '^SKIP .*formats_export')" = "3" ] || miss=1
    [ "$miss" = "1" ]
}

# control: the UNMUTATED copy must NOT be detected as a mutant (proves the mutant harness can pass)
cp "$E2E" "$TMP/e2e_clean.sh"; cp "$GUARD" "$TMP/guard_clean.sh" 2>/dev/null || : > "$TMP/guard_clean.sh"
if [ -s "$TMP/guard_clean.sh" ] && ! mutant_detected clean "$TMP/e2e_clean.sh" "$TMP/guard_clean.sh"; then
    ok "C0 control: the unmutated script + guard pass the mutant harness (it can pass)"
else
    bad "C0 control: the unmutated script + guard pass the mutant harness"
fi

# M1: remove the disabled branch from every gate (gates run even when the switch is off)
sed 's/^if ! herald_formats_export_enabled; then$/if false; then/' "$E2E" > "$TMP/e2e_m1.sh" 2>/dev/null
if ! cmp -s "$E2E" "$TMP/e2e_m1.sh" && [ -s "$TMP/guard_clean.sh" ] && mutant_detected m1 "$TMP/e2e_m1.sh" "$TMP/guard_clean.sh"; then
    ok "C1 mutant M1 (disabled branch removed) is detected"
else
    bad "C1 mutant M1 (disabled branch removed) is detected" "mutant not applied or not detected"
fi

# M2: guard library says enabled for everything
if [ -s "$TMP/guard_clean.sh" ]; then
    { cat "$TMP/guard_clean.sh"; printf '\nherald_formats_export_enabled() { return 0; }\n'; } > "$TMP/guard_m2.sh"
    if mutant_detected m2 "$TMP/e2e_clean.sh" "$TMP/guard_m2.sh"; then ok "C2 mutant M2 (guard always enabled) is detected"
    else bad "C2 mutant M2 (guard always enabled) is detected"; fi
else
    bad "C2 mutant M2 (guard always enabled) is detected" "no guard library to mutate"
fi

# M3: E148 drops its output-token assertion when enabled (weakened gate): the grep for "in-sync" becomes `true`; the
#     misleading stub (exit 0, STALE body) must then slip through as a PASS, which the test MUST notice
sed "s/grep -q 'in-sync'/true/" "$E2E" > "$TMP/e2e_m3.sh" 2>/dev/null
if ! cmp -s "$E2E" "$TMP/e2e_m3.sh" && [ -s "$TMP/guard_clean.sh" ]; then
    # M3 weakens the ENABLED path only: detect through run B2 semantics (stale stub must still FAIL E148)
    mroot="$TMP/mroot_m3"; rm -rf "$mroot"; mkdir -p "$mroot/scripts/lib"; cp "$TMP/guard_clean.sh" "$mroot/scripts/lib/formats_export_guard.sh"
    run_region m3_mis "$TMP/e2e_m3.sh" "$mroot" misleading DOCS_EXPORT=1
    if printf '%s' "$R_OUT" | grep -q 'FAIL  E148'; then bad "C3 mutant M3 (E148 weakened when enabled) is detected" "E148 still FAILed on the misleading body: the weakening was not exercised"
    else ok "C3 mutant M3 (E148 weakened when enabled) is detected"; fi
else
    bad "C3 mutant M3 (E148 weakened when enabled) is detected" "mutant not applied"
fi

# M4: guard never fail-closed (unreadable lib treated as enabled)
if [ -s "$TMP/guard_clean.sh" ]; then
    sed 's/echo "0 fail-closed"/echo "1 fail-closed"/' "$TMP/guard_clean.sh" > "$TMP/guard_m4.sh"
    if ! cmp -s "$TMP/guard_clean.sh" "$TMP/guard_m4.sh" && mutant_detected m4 "$TMP/e2e_clean.sh" "$TMP/guard_m4.sh"; then
        ok "C4 mutant M4 (guard not fail-closed) is detected"
    else
        bad "C4 mutant M4 (guard not fail-closed) is detected" "mutant not applied or not detected"
    fi
else
    bad "C4 mutant M4 (guard not fail-closed) is detected" "no guard library to mutate"
fi

echo "----"
echo "RESULT: ${PASSN} passed, ${FAILN} failed"
[ "$FAILN" -eq 0 ]
