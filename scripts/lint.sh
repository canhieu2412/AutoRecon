#!/bin/bash
# ============================================================================
# Auto Recon - lint / smoke-check
# Runs shellcheck when available, always runs `bash -n` on every shell file,
# and py_compile on the Python TUI. Exit non-zero if anything fails.
# ============================================================================
set -u
unset -f grep egrep fgrep sed awk cat head tail sort uniq wc cut tr find 2>/dev/null || true
cd "$(dirname "$(readlink -f "$0")")/.." || exit 2

fail=0
sh_files=(auto_recon.sh lib/*.sh modules/*.sh config/*.sh scripts/*.sh)

echo "== bash -n (syntax) =="
for f in "${sh_files[@]}"; do
    [[ -f "$f" ]] || continue
    if bash -n "$f" 2>/tmp/_lint_err; then
        printf '  ok   %s\n' "$f"
    else
        printf '  FAIL %s\n' "$f"; sed 's/^/       /' /tmp/_lint_err; fail=1
    fi
done
rm -f /tmp/_lint_err

echo "== shellcheck =="
if command -v shellcheck >/dev/null 2>&1; then
    # SC1090/SC1091: dynamic `source`. SC2155: declare+assign (pervasive, style).
    if shellcheck -x -e SC1090,SC1091,SC2155 -S warning "${sh_files[@]}"; then
        echo "  shellcheck clean (warning+)"
    else
        echo "  shellcheck reported issues"; fail=1
    fi
else
    echo "  shellcheck not installed — skipped (apt install shellcheck)"
fi

echo "== python =="
if command -v python3 >/dev/null 2>&1; then
    for pf in modules/shell_tui.py web/server.py scripts/test_web.py; do
        [[ -f "$pf" ]] || continue
        if python3 -m py_compile "$pf"; then
            printf '  ok   %s\n' "$pf"
        else
            printf '  FAIL %s\n' "$pf"; fail=1
        fi
    done
else
    echo "  python3 not installed — skipped"
fi

echo
[[ $fail -eq 0 ]] && echo "LINT PASS" || echo "LINT FAILED"
exit $fail
