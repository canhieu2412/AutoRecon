#!/bin/bash
# ============================================================================
# Auto Recon - headless functional smoke tests for Phases A/B/D/E/F/G/H.
# No live targets: seeds fake scan artifacts and asserts each phase's outputs.
# ============================================================================
set -u
# Neutralise any inherited shell-function shadows (some harnesses export grep/
# sed/awk as functions) so the test uses real binaries deterministically.
unset -f grep egrep fgrep sed awk cat head tail sort uniq wc cut tr find 2>/dev/null || true
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
cd "$ROOT" || exit 2

export SCRIPT_DIR="$ROOT"
export INTERACTIVE=false
export USE_TUI=off

# Source libs + the modules under test (order matters).
source lib/colors.sh; source lib/logger.sh; source lib/net.sh; source lib/tools.sh
source lib/tui.sh 2>/dev/null; source lib/utils.sh; source config/config.sh
source modules/09_privesc.sh; source modules/12_ad_enum.sh
source modules/13_next_steps.sh; source modules/14_pivot.sh; source modules/06_report.sh

pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
assert_file(){ [[ -s "$1" ]] && ok "$2 ($1)" || no "$2 (missing/empty $1)"; }
assert_grep(){ grep -qiE "$2" "$1" 2>/dev/null && ok "$3" || no "$3 (no /$2/ in $1)"; }

WORK="$(mktemp -d)"; RD="${WORK}/results/10.10.10.99"
mkdir -p "$RD/scans"
export RESULT_DIR="$RD"
init_logger "$RD/auto_recon.log"

# ── Seed fake scan artifacts (a mixed Linux/AD-ish box) ──
cat > "$RD/scans/open_ports.txt" <<'EOF'
21,22,80,139,445,3306,88,389
EOF
cat > "$RD/scans/nmap_targeted.nmap" <<'EOF'
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 2.3.4
22/tcp   open  ssh          OpenSSH 7.2
80/tcp   open  http         Apache httpd 2.4.49
139/tcp  open  netbios-ssn  Samba smbd 3.0.20
445/tcp  open  microsoft-ds Samba smbd
3306/tcp open  mysql        MySQL 5.7
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
389/tcp  open  ldap         Microsoft Windows AD LDAP
EOF

echo "== Phase B: manual next-steps =="
run_next_steps 10.10.10.99 "$RD" >/dev/null 2>&1
assert_file "$RD/next_steps.txt" "next_steps.txt generated"
assert_grep "$RD/next_steps.txt" "gobuster dir -u http://10.10.10.99:80" "http cheatsheet present"
assert_grep "$RD/next_steps.txt" "smbclient -N -L //10.10.10.99" "smb cheatsheet present"

echo "== Phase D: GTFOBins resolver + peass staging =="
[[ -n "$(privesc_gtfo_resolve find)" ]] && ok "gtfo resolve: find" || no "gtfo resolve: find"
[[ -n "$(privesc_gtfo_resolve python3)" ]] && ok "gtfo resolve: python3" || no "gtfo resolve: python3"
[[ -z "$(privesc_gtfo_resolve totallynotarealbin)" ]] && ok "gtfo resolve: unknown → empty" || no "gtfo resolve unknown"
# staging: plant a fake linpeas in a POST_TOOLS_DIRS entry
FAKE_TOOLS="${WORK}/tools"; mkdir -p "$FAKE_TOOLS"; echo '#linpeas' > "$FAKE_TOOLS/linpeas.sh"
POST_TOOLS_DIRS="$FAKE_TOOLS" privesc_stage_peass "$RD/shells/serve" 10.10.14.9 >/dev/null 2>&1
assert_file "$RD/shells/serve/linpeas.sh" "peass staged into serve dir"

echo "== Phase E: pivot generator =="
run_pivot 10.10.10.99 "$RD" >/dev/null 2>&1
assert_file "$RD/pivot/proxychains.conf" "proxychains.conf generated"
assert_file "$RD/pivot/tunnel_cheatsheet.txt" "tunnel cheatsheet generated"
assert_grep "$RD/pivot/tunnel_cheatsheet.txt" "ligolo|chisel|sshuttle" "tunnel methods present"
assert_grep "$RD/pivot/proxychains.conf" "socks5 127.0.0.1 1080" "socks proxy line present"

echo "== Phase F: AD lockout-aware cap =="
mkdir -p "$RD/ad"
printf 'Account Lockout Threshold: 5\n' > "$RD/ad/nxc_passpol.txt"
thr=$(ad_passpol_lockout_threshold "$RD/ad/nxc_passpol.txt")
[[ "$thr" == "5" ]] && ok "lockout threshold parsed (=5)" || no "lockout threshold parse (got '$thr')"
printf 'Account Lockout Threshold: None\n' > "$RD/ad/passpol_none.txt"
thr0=$(ad_passpol_lockout_threshold "$RD/ad/passpol_none.txt")
[[ "$thr0" == "0" ]] && ok "lockout 'None' → 0 (unlimited)" || no "lockout None parse (got '$thr0')"

echo "== Phase G: OSCP template + proof =="
report_generate_oscp_template 10.10.10.99 "$RD" >/dev/null 2>&1
assert_file "$RD/oscp_submission.md" "OSCP submission template generated"
assert_grep "$RD/oscp_submission.md" "proof.txt|local.txt" "template references flags"

echo "== Phase H: dry-run hook =="
out=$(DRY_RUN=true run_timed 5 echo SHOULD_NOT_RUN 2>&1)
if echo "$out" | grep -q 'DRY-RUN' && ! echo "$out" | grep -q '^SHOULD_NOT_RUN$'; then
    ok "run_timed honors DRY_RUN (no execution)"
else
    no "run_timed DRY_RUN (out: $out)"
fi
out2=$(DRY_RUN=false run_timed 5 echo REALLY_RAN 2>/dev/null)
[[ "$out2" == "REALLY_RAN" ]] && ok "run_timed executes when DRY_RUN=false" || no "run_timed normal exec (got '$out2')"

echo
echo "phases: ${pass} passed, ${fail} failed"
rm -rf "$WORK"
[[ $fail -eq 0 ]] && exit 0 || exit 1
