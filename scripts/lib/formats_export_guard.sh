#!/usr/bin/env bash
# scripts/lib/formats_export_guard.sh -- Herald's thin reader of the constitution's ONE "formats export" switch.
#
# Purpose (operator order 2026-10-26: agents work only with Markdown; exporting Markdown into .html/.pdf/.docx is OFF by
#   default): the Docs Chain drift-gates E146/E147/E148 of scripts/e2e_bluff_hunt.sh demand tracked .html/.pdf/.docx
#   siblings of tracked .md files. With the exports switched off those siblings are not in the repository, so the gates must
#   announce an honest SKIP instead of failing (or dirtying the tree). The default, the resolution order and the policy
#   file handling live ONLY in constitution/config/formats_export.conf + constitution/scripts/formats_export_lib.sh;
#   this file only LOCATES that library and asks it. Nothing here parses DOCS_EXPORT, the policy file or the conf.
#   Resolution order (owned by the constitution lib): env DOCS_EXPORT > $HERALD_ROOT/docs/context/doc_export.policy
#   containing `enabled=1` > the constitution default (false).
#
# Library discovery: $FORMATS_EXPORT_LIB when set (a set-but-unreadable value is NOT searched past: fail-closed), else the
#   nearest ancestor of this repository holding constitution/scripts/formats_export_lib.sh (Herald is a submodule of a
#   parent that carries the constitution; CLAUDE.md "parent-discovery"). No library found => DISABLED, fail-closed -- the
#   gates then SKIP with that stated reason; never a silent "enabled".
#
# Usage (sourced):
#   . "${REPO_ROOT}/scripts/lib/formats_export_guard.sh"
#   herald_formats_export_enabled      # rc 0 enabled, rc 1 disabled; prints nothing
#   herald_formats_export_resolve      # prints "<0|1> <env|policy|constitution-default|fail-closed>"
# The constitution lib is sourced inside a subshell, so no function or variable of it leaks into the caller.
# Test seams (tests only): FORMATS_EXPORT_LIB (alternative lib path), plus the lib's FORMATS_EXPORT_CONF / FORMATS_EXPORT_POLICY.
# Side effects: none (read-only). Dependencies: bash, the constitution lib.
# Cross-references: scripts/e2e_bluff_hunt.sh (E146-E148), tests/test_e2e_docs_chain_formats_switch.sh (paired mutations),
#   scripts/lib/formats_export.sh of the parent repository (the same wrapper idea), constitution section 11.4.65 / 11.4.106(E).

_HFE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_HFE_ROOT="$(cd "$_HFE_DIR/../.." && pwd)"

# _hfe_find_lib -- prints the path of the constitution formats-export library, or nothing when it cannot be found.
_hfe_find_lib() {
    local d c
    if [ -n "${FORMATS_EXPORT_LIB:-}" ]; then
        [ -r "$FORMATS_EXPORT_LIB" ] && printf '%s\n' "$FORMATS_EXPORT_LIB"
        return 0
    fi
    d="$_HFE_ROOT"
    while :; do
        c="$d/constitution/scripts/formats_export_lib.sh"
        if [ -r "$c" ]; then printf '%s\n' "$c"; return 0; fi
        [ "$d" = "/" ] && break
        d="$(dirname "$d")"
    done
    return 0
}

# herald_formats_export_resolve -- "<0|1> <source>".
herald_formats_export_resolve() {
    local lib
    lib="$(_hfe_find_lib)"
    if [ -z "$lib" ]; then echo "0 fail-closed"; return 0; fi
    (
        FORMATS_EXPORT_ROOT="$_HFE_ROOT"
        export FORMATS_EXPORT_ROOT
        # shellcheck disable=SC1090 # path resolved at run time
        . "$lib" && formats_export_resolve "$_HFE_ROOT"
    )
}

# herald_formats_export_enabled -- rc 0 when the switch is on, rc 1 otherwise (including every unresolvable case).
herald_formats_export_enabled() {
    local r
    r="$(herald_formats_export_resolve)"
    [ "${r%% *}" = "1" ]
}
