#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 13: Manual "Next Steps" cheatsheet (Try Harder helper)
# ----------------------------------------------------------------------------
# OSCP rewards manual enumeration. This phase reads the open ports / service
# banners already collected and emits a per-service, copy-paste list of the
# exact manual commands you'd type next — LHOST/target pre-filled. It runs
# nothing; it just tells you what to do by hand.
# ============================================================================

next_steps_attacker_ip() {
    if declare -F privesc_attacker_ip >/dev/null; then
        privesc_attacker_ip
    else
        ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1
    fi
}

# Print the manual cheatsheet for one port/service pair.
# Args: <port> <service-name> <ip> <lhost>
next_steps_for_service() {
    local port="$1" svc="$2" ip="$3" lhost="$4"
    svc=$(echo "$svc" | tr '[:upper:]' '[:lower:]')
    local title="[$port] ${svc:-unknown}"
    case "$svc" in
        ftp*)
            cat <<EOF
### ${title}
ftp ${ip} ${port}                      # try anonymous / anonymous
wget -m --no-passive ftp://anonymous:anonymous@${ip}:${port}/
nmap -p${port} --script ftp-anon,ftp-bounce,ftp-syst ${ip}
# writable? drop a webshell if a web root is served from the same box.
EOF
            ;;
        ssh*)
            cat <<EOF
### ${title}
ssh -oHostKeyAlgorithms=+ssh-rsa user@${ip} -p ${port}
nmap -p${port} --script ssh2-enum-algos,ssh-auth-methods ${ip}
# have a userlist? OSCP-safe manual check only; hydra is loud (menu [6]).
EOF
            ;;
        smtp*|submission*)
            cat <<EOF
### ${title}
nmap -p${port} --script smtp-commands,smtp-enum-users,smtp-open-relay ${ip}
smtp-user-enum -M VRFY -U users.txt -t ${ip} -p ${port}
EOF
            ;;
        domain|dns*)
            cat <<EOF
### ${title}
dig axfr @${ip} <domain>               # zone transfer
dig any @${ip} <domain>
nslookup -type=any <domain> ${ip}
EOF
            ;;
        http*|https*|http-proxy|http-alt|ssl/http|ssl|nginx|apache|tomcat|iis)
            local proto="http"; [[ "$svc" =~ ssl|https || "$port" == 443 || "$port" == 8443 ]] && proto="https"
            cat <<EOF
### ${title}
whatweb ${proto}://${ip}:${port}
curl -sIk ${proto}://${ip}:${port}/     # headers / server / redirects
gobuster dir -u ${proto}://${ip}:${port} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,html
feroxbuster -u ${proto}://${ip}:${port} -x php,txt,html
nikto -h ${proto}://${ip}:${port}
# check: /robots.txt  /.git/  /backup  default creds  vhosts (Host: header fuzz)
EOF
            ;;
        microsoft-ds|netbios-ssn|smb*)
            cat <<EOF
### ${title}
nxc smb ${ip} -u '' -p '' --shares          # null session shares
smbclient -N -L //${ip}/                     # list shares
smbmap -H ${ip} -u '' -p ''
nmap -p${port} --script smb-vuln-ms17-010,smb-enum-shares,smb-os-discovery ${ip}
enum4linux-ng -A ${ip}
EOF
            ;;
        ldap*)
            cat <<EOF
### ${title}
ldapsearch -x -H ldap://${ip} -s base namingcontexts
ldapsearch -x -H ldap://${ip} -b "DC=domain,DC=local"
nxc ldap ${ip} -u '' -p '' --users
EOF
            ;;
        kerberos*|kpasswd*)
            cat <<EOF
### ${title}
# AD present → use the AD Attack Path (menu [a]).
impacket-GetNPUsers domain/ -no-pass -usersfile users.txt -dc-ip ${ip}   # AS-REP roast
EOF
            ;;
        mysql*)
            cat <<EOF
### ${title}
mysql -h ${ip} -u root -p                    # try root / blank / weak
nmap -p${port} --script mysql-empty-password,mysql-info,mysql-users ${ip}
EOF
            ;;
        ms-sql*|mssql*)
            cat <<EOF
### ${title}
impacket-mssqlclient user:pass@${ip} -windows-auth
nmap -p${port} --script ms-sql-info,ms-sql-empty-password ${ip}
# sa? enable xp_cmdshell for RCE.
EOF
            ;;
        postgres*)
            cat <<EOF
### ${title}
psql -h ${ip} -U postgres                    # try postgres / blank
nmap -p${port} --script pgsql-brute ${ip}
EOF
            ;;
        rdp*|ms-wbt-server)
            cat <<EOF
### ${title}
xfreerdp /v:${ip} /u:user /p:pass +clipboard /cert:ignore
nmap -p${port} --script rdp-ntlm-info ${ip}
EOF
            ;;
        winrm*|wsman*)
            cat <<EOF
### ${title}
evil-winrm -i ${ip} -u user -p pass
nxc winrm ${ip} -u user -p pass
EOF
            ;;
        snmp*)
            cat <<EOF
### ${title}
snmpwalk -v2c -c public ${ip}
onesixtyone ${ip} public
snmp-check ${ip}
EOF
            ;;
        nfs*|rpcbind|nlockmgr|mountd)
            cat <<EOF
### ${title}
showmount -e ${ip}
mkdir -p /mnt/nfs && mount -t nfs ${ip}:/EXPORT /mnt/nfs -o nolock
# no_root_squash? create a SUID root binary on the export → local root.
EOF
            ;;
        redis*)
            cat <<EOF
### ${title}
redis-cli -h ${ip}                           # try: INFO ; CONFIG GET dir
# unauth write → SSH key / webshell via CONFIG SET dir + dbfilename.
EOF
            ;;
        *)
            cat <<EOF
### ${title}
nmap -sCV -p${port} ${ip}                     # deeper script/version scan
searchsploit ${svc}                           # known exploits for this service
# unknown protocol → 'nc ${ip} ${port}' and grab the banner manually.
EOF
            ;;
    esac
    echo ""
}

run_next_steps() {
    local ip="$1" result_dir="$2"
    section_header "PHASE 13: MANUAL NEXT-STEPS (Try Harder)" "$ICON_SCAN"
    ensure_result_layout "$result_dir"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local ports_file="${result_dir}/scans/open_ports.txt"
    local lhost; lhost=$(next_steps_attacker_ip)
    local out="${result_dir}/next_steps.txt"

    if [[ ! -s "$ports_file" && ! -s "$nmap_file" ]]; then
        log_warn "No port-scan output yet — run Port Scan / Service Enum first."
        return 1
    fi

    # Prefer service-aware lines from nmap; fall back to port-only from open_ports.txt.
    {
        echo "=== Manual Next-Steps for ${ip}  (LHOST=${lhost}) ==="
        echo "# Generated ${result_dir##*/}. Run these BY HAND — nothing here executes."
        echo ""
        local emitted=0
        if [[ -s "$nmap_file" ]] && grep -qE '^[0-9]+/.*open' "$nmap_file"; then
            while IFS= read -r line; do
                local port svc
                port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
                svc=$(echo "$line" | awk '{print $3}')
                [[ -z "$port" ]] && continue
                next_steps_for_service "$port" "$svc" "$ip" "$lhost"
                emitted=$((emitted+1))
            done < <(grep -E '^[0-9]+/.*open' "$nmap_file")
        fi
        if (( emitted == 0 )) && [[ -s "$ports_file" ]]; then
            local csv; csv=$(cat "$ports_file")
            local IFS=,
            for port in $csv; do
                [[ "$port" =~ ^[0-9]+$ ]] || continue
                next_steps_for_service "$port" "unknown" "$ip" "$lhost"
            done
        fi
    } > "$out"

    log_success "Manual next-steps → ${out}"
    # Terminal digest: show the service headers so it's useful without opening the file.
    grep -E '^### ' "$out" | sed 's/^### /  ▷ /'
    echo ""
    pause_if_interactive
    return 0
}
