#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 2: Service Enumeration
# ============================================================================

# ── Service Handlers ──

enum_ftp() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/ftp_${port}.txt"
    
    log_scan "FTP enum on port ${port}"
    {
        echo "=== FTP Enumeration - ${ip}:${port} ==="
        echo ""
        
        # Anonymous login check
        echo "--- Anonymous Login Check ---"
        timeout 10 bash -c "echo -e 'USER anonymous\nPASS anonymous@\nLIST\nQUIT' | nc -w5 ${ip} ${port}" 2>/dev/null
        echo ""
        
        # Nmap FTP scripts
        echo "--- Nmap FTP Scripts ---"
        nmap -sV -p "$port" --script="ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-syst" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    
    # Check for anonymous access
    if grep -qi "anonymous.*logged\|230\|Login successful" "$out" 2>/dev/null; then
        print_found "FTP Anonymous Login ALLOWED on port ${port}!"
    fi
    log_success "FTP → ${out}"
}

enum_ssh() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/ssh_${port}.txt"
    
    log_scan "SSH enum on port ${port}"
    {
        echo "=== SSH Enumeration - ${ip}:${port} ==="
        echo ""
        
        # Banner grab
        echo "--- Banner ---"
        timeout 5 nc -w3 "$ip" "$port" < /dev/null 2>/dev/null
        echo ""
        
        # Nmap SSH scripts
        echo "--- Nmap SSH Scripts ---"
        nmap -sV -p "$port" --script="ssh-auth-methods,ssh2-enum-algos,ssh-hostkey" -Pn "$ip" 2>/dev/null

        if command -v ssh-keyscan &>/dev/null; then
            echo ""
            echo "--- ssh-keyscan ---"
            timeout 10 ssh-keyscan -T 5 -p "$port" "$ip" 2>/dev/null
        fi
        
        # ssh-audit if available
        if command -v ssh-audit &>/dev/null; then
            echo ""
            echo "--- SSH Audit ---"
            ssh-audit -p "$port" "$ip" 2>/dev/null
        fi
    } > "$out" 2>&1
    log_success "SSH → ${out}"
}

enum_smb() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/smb.txt"
    
    log_scan "SMB enum on port ${port}"
    {
        echo "=== SMB Enumeration - ${ip} ==="
        echo ""
        
        # enum4linux
        if command -v enum4linux &>/dev/null; then
            echo "--- enum4linux ---"
            timeout 120 enum4linux -a "$ip" 2>/dev/null
            echo ""
        fi
        
        # smbclient list shares
        echo "--- SMB Shares (smbclient) ---"
        smbclient -L "//${ip}" -N 2>/dev/null
        echo ""

        if command -v smbmap &>/dev/null; then
            echo "--- smbmap ---"
            timeout 60 smbmap -H "$ip" -P "$port" 2>/dev/null
            echo ""
        fi
        
        # netexec (modern crackmapexec replacement)
        if command -v netexec &>/dev/null; then
            echo "--- NetExec SMB ---"
            netexec smb "$ip" --shares 2>/dev/null
            echo ""
            echo "--- NetExec Users ---"
            netexec smb "$ip" --users 2>/dev/null
            echo ""
            echo "--- NetExec Pass Policy ---"
            netexec smb "$ip" --pass-pol 2>/dev/null
            echo ""
        fi
        
        # rpcclient null session
        if command -v rpcclient &>/dev/null; then
            echo "--- rpcclient Null Session ---"
            timeout 15 rpcclient -U "" -N "$ip" -c "enumdomusers;enumdomgroups;querydominfo;netshareenumall" 2>/dev/null
            echo ""
        fi
        
        # impacket samrdump
        if command -v impacket-samrdump &>/dev/null; then
            echo "--- Impacket SAMRDump ---"
            timeout 30 impacket-samrdump "$ip" 2>/dev/null | head -50
            echo ""
        fi
        
        # Active Directory Auto-Attacks (Impacket)
        echo "--- Impacket AD Auto-Attacks ---"
        if command -v impacket-GetNPUsers &>/dev/null; then
            echo "[+] AS-REP Roasting (Anonymous)"
            timeout 30 impacket-GetNPUsers -no-pass -dc-ip "$ip" ""/"" 2>/dev/null
        fi
        
        if command -v impacket-GetUserSPNs &>/dev/null; then
            echo "[+] Kerberoasting (Anonymous)"
            timeout 30 impacket-GetUserSPNs -no-pass -dc-ip "$ip" ""/"" 2>/dev/null
        fi
        
        if command -v impacket-secretsdump &>/dev/null; then
            echo "[+] SecretsDump (Anonymous LSA/SAM)"
            timeout 30 impacket-secretsdump -no-pass "${ip}" 2>/dev/null
        fi
        echo ""
        
        # Nmap SMB scripts (vuln included)
        echo "--- Nmap SMB Scripts ---"
        nmap -p 139,445 --script="smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-*,smb-protocols" -Pn "$ip" 2>/dev/null

        # Try to list each share content
        echo ""
        echo "--- Share Content Listing ---"
        smbclient -L "//${ip}" -N 2>/dev/null | grep "Disk" | awk '{print $1}' | while read -r share; do
            echo "  >>> Share: ${share}"
            timeout 10 smbclient "//${ip}/${share}" -N -c "ls" 2>/dev/null
            echo ""
        done
    } > "$out" 2>&1
    
    # Check for null session / anonymous
    if grep -qi "Anonymous\|access\|READ\|mapping.*ok" "$out" 2>/dev/null; then
        print_found "SMB shares accessible!"
    fi
    log_success "SMB → ${out}"
}

enum_snmp() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/snmp.txt"
    
    log_scan "SNMP enum on port ${port}"
    {
        echo "=== SNMP Enumeration - ${ip}:${port} ==="
        echo ""
        
        # snmp-check (pretty output)
        if command -v snmp-check &>/dev/null; then
            echo "--- snmp-check ---"
            timeout 60 snmp-check "$ip" -c public 2>/dev/null
            echo ""
        fi
        
        # snmpwalk - users
        if command -v snmpwalk &>/dev/null; then
            echo "--- snmpwalk: System Info ---"
            timeout 15 snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.1 2>/dev/null
            echo ""
            echo "--- snmpwalk: Running Processes ---"
            timeout 30 snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null | head -50
            echo ""
            echo "--- snmpwalk: Installed Software ---"
            timeout 30 snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null | head -50
            echo ""
            echo "--- snmpwalk: TCP Ports ---"
            timeout 15 snmpwalk -v2c -c public "$ip" 1.3.6.1.2.1.6.13.1.3 2>/dev/null | head -30
            echo ""
            echo "--- snmpwalk: User Accounts ---"
            timeout 15 snmpwalk -v2c -c public "$ip" 1.3.6.1.4.1.77.1.2.25 2>/dev/null
            echo ""
        fi
        
        # onesixtyone brute community strings
        if command -v onesixtyone &>/dev/null; then
            echo "--- onesixtyone (community strings) ---"
            onesixtyone "$ip" public private manager community 2>/dev/null
        fi
        
        echo "--- Nmap SNMP ---"
        nmap -sU -p "$port" --script="snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-users,snmp-win32-services" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    
    if grep -qi "STRING\|running\|Windows\|Linux" "$out" 2>/dev/null; then
        print_found "SNMP community string 'public' works!"
    fi
    log_success "SNMP → ${out}"
}

enum_dns() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/dns_${port}.txt"
    
    log_scan "DNS enum on port ${port}"
    {
        echo "=== DNS Enumeration - ${ip}:${port} ==="
        echo ""
        
        echo "--- Zone Transfer Attempt ---"
        dig axfr @"$ip" 2>/dev/null
        echo ""
        
        echo "--- Reverse DNS ---"
        dig -x "$ip" @"$ip" 2>/dev/null
        echo ""
        
        # dnsrecon
        if command -v dnsrecon &>/dev/null; then
            echo "--- dnsrecon ---"
            timeout 60 dnsrecon -n "$ip" -r "${ip%.*}.0/24" 2>/dev/null | head -50
            echo ""
        fi
        
        # dnsenum
        if command -v dnsenum &>/dev/null; then
            echo "--- dnsenum ---"
            # Try to discover domain from reverse DNS
            local domain
            domain=$(dig -x "$ip" +short 2>/dev/null | head -1 | sed 's/\.$//' | awk -F. '{print $(NF-1)"."$NF}')
            if [[ -n "$domain" ]] && [[ "$domain" != "." ]]; then
                timeout 60 dnsenum --dnsserver "$ip" "$domain" --noreverse 2>/dev/null | head -80
            fi
            echo ""
        fi
        
        # fierce
        if command -v fierce &>/dev/null; then
            echo "--- fierce ---"
            timeout 60 fierce --dns-servers "$ip" --domain "$(dig -x "$ip" +short 2>/dev/null | head -1 | sed 's/\.$//' | awk -F. '{print $(NF-1)"."$NF}')" 2>/dev/null | head -50
            echo ""
        fi
        
        echo "--- Nmap DNS Scripts ---"
        nmap -p "$port" --script="dns-nsid,dns-recursion,dns-service-discovery,dns-zone-transfer" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    
    if grep -qi "XFR size\|Transfer" "$out" 2>/dev/null; then
        print_found "DNS Zone Transfer possible!"
    fi
    log_success "DNS → ${out}"
}

enum_smtp() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/smtp_${port}.txt"
    
    log_scan "SMTP enum on port ${port}"
    {
        echo "=== SMTP Enumeration - ${ip}:${port} ==="
        nmap -p "$port" --script="smtp-enum-users,smtp-commands,smtp-open-relay,smtp-vuln-cve2010-4344" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "SMTP → ${out}"
}

enum_mysql() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/mysql_${port}.txt"
    
    log_scan "MySQL enum on port ${port}"
    {
        echo "=== MySQL Enumeration - ${ip}:${port} ==="
        nmap -sV -p "$port" --script="mysql-info,mysql-enum,mysql-empty-password,mysql-vuln-cve2012-2122,mysql-databases" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    
    if grep -qi "empty password\|anonymous" "$out" 2>/dev/null; then
        print_found "MySQL empty password detected!"
    fi
    log_success "MySQL → ${out}"
}

enum_mssql() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/mssql_${port}.txt"
    
    log_scan "MSSQL enum on port ${port}"
    {
        echo "=== MSSQL Enumeration - ${ip}:${port} ==="
        echo ""

        if command -v netexec &>/dev/null; then
            echo "--- NetExec MSSQL ---"
            timeout 30 netexec mssql "$ip" 2>/dev/null
            echo ""
        fi

        nmap -sV -p "$port" --script="ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "MSSQL → ${out}"
}

enum_rdp() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/rdp_${port}.txt"
    
    log_scan "RDP enum on port ${port}"
    {
        echo "=== RDP Enumeration - ${ip}:${port} ==="
        echo ""

        if command -v netexec &>/dev/null; then
            echo "--- NetExec RDP ---"
            timeout 30 netexec rdp "$ip" 2>/dev/null
            echo ""
        fi

        nmap -sV -p "$port" --script="rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "RDP → ${out}"
}

enum_nfs() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/nfs.txt"
    
    log_scan "NFS enum on port ${port}"
    {
        echo "=== NFS Enumeration - ${ip} ==="
        echo "--- showmount ---"
        showmount -e "$ip" 2>/dev/null
        echo ""

        if command -v rpcinfo &>/dev/null; then
            echo "--- rpcinfo ---"
            timeout 20 rpcinfo -p "$ip" 2>/dev/null
            echo ""
        fi

        nmap -p "$port" --script="nfs-ls,nfs-showmount,nfs-statfs" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    
    if grep -qi "Export list\|/" "$out" 2>/dev/null; then
        print_found "NFS exports found!"
    fi
    log_success "NFS → ${out}"
}

enum_ldap() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/ldap_${port}.txt"
    local scheme="ldap"

    [[ "$port" == "636" || "$port" == "3269" ]] && scheme="ldaps"
    
    log_scan "LDAP enum on port ${port}"
    {
        echo "=== LDAP Enumeration - ${ip}:${port} ==="
        echo "--- ldapsearch ---"
        ldapsearch -x -H "${scheme}://${ip}:${port}" -b "" -s base -LLL "(objectClass=*)" namingcontexts defaultNamingContext rootDomainNamingContext dnsHostName supportedLDAPVersion supportedSASLMechanisms 2>/dev/null
        echo ""

        if command -v netexec &>/dev/null; then
            echo "--- NetExec LDAP ---"
            timeout 30 netexec ldap "$ip" 2>/dev/null
            echo ""
        fi

        nmap -p "$port" --script="ldap-rootdse,ldap-search,ldap-brute" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "LDAP → ${out}"
}

enum_winrm() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/winrm_${port}.txt"
    local scheme="http"

    [[ "$port" == "5986" ]] && scheme="https"
    
    log_scan "WinRM enum on port ${port}"
    {
        echo "=== WinRM Enumeration - ${ip}:${port} ==="
        echo ""

        if command -v curl &>/dev/null; then
            echo "--- HTTP Headers (/wsman) ---"
            timeout 15 curl -skI --max-time 10 "${scheme}://${ip}:${port}/wsman" 2>/dev/null
            echo ""
            echo "--- OPTIONS /wsman ---"
            timeout 15 curl -sk --max-time 10 -X OPTIONS -D - -o /dev/null "${scheme}://${ip}:${port}/wsman" 2>/dev/null
            echo ""
        fi

        if command -v netexec &>/dev/null; then
            echo "--- NetExec WinRM ---"
            timeout 30 netexec winrm "$ip" 2>/dev/null
            echo ""
        fi

        echo "--- Nmap WinRM Scripts ---"
        if [[ "$scheme" == "https" ]]; then
            nmap -sV -p "$port" --script="http-auth-finder,http-headers,http-title,http-ntlm-info,ssl-cert" -Pn "$ip" 2>/dev/null
        else
            nmap -sV -p "$port" --script="http-auth-finder,http-headers,http-title,http-ntlm-info" -Pn "$ip" 2>/dev/null
        fi
    } > "$out" 2>&1

    if grep -qiE "WWW-Authenticate:|WinRM|WSMAN|HTTP/1\.[01] 401" "$out" 2>/dev/null; then
        print_found "WinRM auth surface reachable on port ${port}"
    fi
    log_success "WinRM → ${out}"
}

enum_redis() {
    local ip="$1" port="$2" result_dir="$3"
    local out="${result_dir}/scans/redis_${port}.txt"
    
    log_scan "Redis enum on port ${port}"
    {
        echo "=== Redis Enumeration - ${ip}:${port} ==="
        if command -v redis-cli &>/dev/null; then
            echo "--- redis-cli info ---"
            timeout 10 redis-cli -h "$ip" -p "$port" info 2>/dev/null
        fi
        echo ""
        nmap -sV -p "$port" --script="redis-info" -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "Redis → ${out}"
}

enum_generic() {
    local ip="$1" port="$2" result_dir="$3" service="$4"
    local out="${result_dir}/scans/generic_${port}.txt"
    
    log_scan "Generic enum: ${service} on port ${port}"
    {
        echo "=== Generic Service Enumeration - ${ip}:${port} (${service}) ==="
        echo "--- Banner Grab ---"
        timeout 5 nc -w3 "$ip" "$port" < /dev/null 2>/dev/null
        echo ""
        echo "--- Nmap Version Scan ---"
        nmap -sV -p "$port" --script=default -Pn "$ip" 2>/dev/null
    } > "$out" 2>&1
    log_success "${service}:${port} → ${out}"
}

normalize_nmap_service_name() {
    local service="${1,,}"
    service="${service//|//}"
    service=$(echo "$service" | sed -E 's/[[:space:]]+$//; s/\?+$//')
    echo "$service"
}

parse_open_nmap_services() {
    local nmap_file="$1"

    awk '
        $1 ~ /^[0-9]+\/(tcp|udp)$/ && $2 == "open" {
            version = ""
            for (i = 4; i <= NF; i++) {
                version = version (version ? OFS : "") $i
            }
            split($1, endpoint, "/")
            printf "%s|%s|%s|%s\n", endpoint[1], endpoint[2], $3, version
        }
    ' "$nmap_file"
}

extract_nmap_port_script_block() {
    local nmap_file="$1"
    local port="$2"
    local proto="${3:-tcp}"

    awk -v endpoint="${port}/${proto}" '
        $1 == endpoint {
            capture = 1
            next
        }
        capture {
            if ($0 ~ /^[0-9]+\/(tcp|udp)[[:space:]]+/) {
                exit
            }
            if ($0 ~ /^(\||[[:space:]]+\|)/ || $0 ~ /^[[:space:]]*$/) {
                print
                next
            }
            exit
        }
    ' "$nmap_file"
}

sanitize_inventory_field() {
    printf '%s' "$1" | tr '\t\r\n' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

append_inventory_detail() {
    local current="$1"
    local key="$2"
    local value="$3"

    value=$(sanitize_inventory_field "$value")
    [[ -z "$value" ]] && {
        echo "$current"
        return 0
    }

    if [[ -n "$current" ]]; then
        echo "${current}; ${key}=${value}"
    else
        echo "${key}=${value}"
    fi
}

extract_first_inventory_match() {
    local file="$1"
    local pattern="$2"

    [[ -f "$file" ]] || return 0
    grep -m1 -iE "$pattern" "$file" 2>/dev/null | sed -E 's/^[[:space:]\|_:-]+//; s/[[:space:]]+/ /g'
}

extract_inventory_values() {
    local file="$1"
    local pattern="$2"
    local limit="${3:-5}"

    [[ -f "$file" ]] || return 0
    awk -v pattern="$pattern" -v limit="$limit" '
        BEGIN {
            IGNORECASE = 1
            count = 0
        }
        $0 ~ pattern {
            line = $0
            sub(/^[[:space:]|_:-]+/, "", line)
            sub(/^[^:]+:[[:space:]]*/, "", line)
            gsub(/[[:space:]]+/, " ", line)
            if (line != "" && !seen[line]++) {
                vals[++count] = line
                if (count >= limit) {
                    exit
                }
            }
        }
        END {
            for (i = 1; i <= count; i++) {
                printf "%s%s", vals[i], (i < count ? "; " : "")
            }
        }
    ' "$file"
}

extract_smb_shares() {
    local file="$1"

    [[ -f "$file" ]] || return 0
    grep -E '^[[:space:]]+[[:graph:]]+[[:space:]]+Disk([[:space:]]|$)' "$file" 2>/dev/null | awk '{print $1}' | awk '!seen[$0]++' | head -5 | paste -sd',' -
}

extract_nfs_exports() {
    local file="$1"

    [[ -f "$file" ]] || return 0
    awk '
        BEGIN {
            capture = 0
        }
        /^Export list/ {
            capture = 1
            next
        }
        capture {
            if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^--- /) {
                exit
            }
            if ($1 ~ /^\//) {
                print $1
            }
        }
    ' "$file" 2>/dev/null | awk '!seen[$0]++' | head -5 | paste -sd',' -
}

append_auth_surface_entry() {
    local file="$1" host="$2" port="$3" proto="$4" service="$5" family="$6" surface="$7" version="$8" details="$9" source="${10}"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(sanitize_inventory_field "$host")" \
        "$(sanitize_inventory_field "$port")" \
        "$(sanitize_inventory_field "$proto")" \
        "$(sanitize_inventory_field "$service")" \
        "$(sanitize_inventory_field "$family")" \
        "$(sanitize_inventory_field "$surface")" \
        "$(sanitize_inventory_field "$version")" \
        "$(sanitize_inventory_field "$details")" \
        "$(sanitize_inventory_field "$source")" >> "$file"
}

build_service_inventories() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="$3"
    local auth_file="${result_dir}/scans/auth_surfaces.tsv"
    local windows_file="${result_dir}/scans/windows_auth_inventory.txt"
    local linux_file="${result_dir}/scans/linux_remote_access_inventory.txt"
    local directory_file="${result_dir}/scans/directory_services_inventory.txt"
    local smb_file="${result_dir}/scans/smb.txt"
    local nfs_file="${result_dir}/scans/nfs.txt"
    local win_count=0
    local linux_count=0
    local dir_count=0
    local smb_recorded=0
    local nfs_recorded=0
    local kerberos_seen=0
    local gc_seen=0

    printf 'host\tport\tproto\tservice\tfamily\tsurface\tversion\tkey_details\tsource\n' > "$auth_file"
    {
        echo "=== Windows Auth & Remoting Inventory - ${ip} ==="
        echo ""
    } > "$windows_file"
    {
        echo "=== Linux Remote-Access Inventory - ${ip} ==="
        echo ""
    } > "$linux_file"
    {
        echo "=== Directory Services Inventory - ${ip} ==="
        echo ""
    } > "$directory_file"

    while IFS='|' read -r port proto raw_service version; do
        local service details out source line
        service=$(normalize_nmap_service_name "$raw_service")
        details=""
        source="scans/nmap_targeted.nmap"

        case "$service" in
            ssh)
                out="${result_dir}/scans/ssh_${port}.txt"
                source="scans/ssh_${port}.txt"
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "banner" "$(extract_first_inventory_match "$out" '^SSH-')") 
                details=$(append_inventory_detail "$details" "auth" "$(extract_first_inventory_match "$out" 'authentication methods')") 
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "$service" "linux" "remote_shell" "$version" "$details" "$source"
                printf -- '- SSH %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$linux_file"
                linux_count=$((linux_count + 1))
                ;;
            ftp)
                details=$(append_inventory_detail "$details" "version" "$version")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "$service" "linux" "file_transfer" "$version" "$details" "scans/ftp_${port}.txt"
                printf -- '- FTP %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$linux_file"
                linux_count=$((linux_count + 1))
                ;;
            microsoft-ds|netbios-ssn)
                if (( smb_recorded == 1 )); then
                    continue
                fi
                smb_recorded=1
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "os" "$(extract_inventory_values "$smb_file" 'OS:|OS version:' 1)")
                details=$(append_inventory_detail "$details" "domain" "$(extract_inventory_values "$smb_file" 'Domain Name:|Workgroup:' 1)")
                details=$(append_inventory_detail "$details" "signing" "$(extract_inventory_values "$smb_file" 'message_signing:|signing:' 1)")
                details=$(append_inventory_detail "$details" "shares" "$(extract_smb_shares "$smb_file")")
                if grep -qiE 'Sharename[[:space:]]+Type|Anonymous login successful|enumdomusers|querydominfo|netshareenumall' "$smb_file" 2>/dev/null; then
                    details=$(append_inventory_detail "$details" "anonymous_enum" "likely")
                fi
                append_auth_surface_entry "$auth_file" "$ip" "${port:-445}" "$proto" "smb" "windows" "file_auth" "$version" "$details" "scans/smb.txt"
                printf -- '- SMB %s/%s -> %s\n' "${port:-445}" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                if [[ -n "$(extract_inventory_values "$smb_file" 'Domain Name:|Workgroup:' 1)" ]]; then
                    printf -- '- SMB domain hint %s/%s -> %s\n' "${port:-445}" "$proto" "${details}" >> "$directory_file"
                    dir_count=$((dir_count + 1))
                fi
                ;;
            ldap|ldaps)
                out="${result_dir}/scans/ldap_${port}.txt"
                source="scans/ldap_${port}.txt"
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "naming_contexts" "$(extract_inventory_values "$out" 'namingcontexts?:|defaultNamingContext:|rootDomainNamingContext:' 4)")
                details=$(append_inventory_detail "$details" "dns_host" "$(extract_inventory_values "$out" 'dnsHostName:' 1)")
                details=$(append_inventory_detail "$details" "sasl" "$(extract_inventory_values "$out" 'supportedSASLMechanisms:' 4)")
                if grep -qiE 'namingcontexts?:|defaultNamingContext:|result: 0 Success' "$out" 2>/dev/null; then
                    details=$(append_inventory_detail "$details" "anonymous_bind" "yes")
                fi
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "$service" "windows" "directory_service" "$version" "$details" "$source"
                printf -- '- %s %s/%s -> %s\n' "${service^^}" "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                printf -- '- %s %s/%s -> %s\n' "${service^^}" "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$directory_file"
                dir_count=$((dir_count + 1))
                ;;
            wsman|winrm)
                out="${result_dir}/scans/winrm_${port}.txt"
                source="scans/winrm_${port}.txt"
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "auth" "$(extract_inventory_values "$out" '^WWW-Authenticate:' 4)")
                details=$(append_inventory_detail "$details" "server" "$(extract_inventory_values "$out" '^Server:' 1)")
                details=$(append_inventory_detail "$details" "target" "$(extract_inventory_values "$out" 'Target_Name:' 1)")
                details=$(append_inventory_detail "$details" "dns_name" "$(extract_inventory_values "$out" 'DNS_Computer_Name:' 1)")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "winrm" "windows" "remote_shell" "$version" "$details" "$source"
                printf -- '- WinRM %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                ;;
            ms-wbt-server|rdp)
                out="${result_dir}/scans/rdp_${port}.txt"
                source="scans/rdp_${port}.txt"
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "target" "$(extract_inventory_values "$out" 'Target_Name:' 1)")
                details=$(append_inventory_detail "$details" "dns_domain" "$(extract_inventory_values "$out" 'DNS_Domain_Name:' 1)")
                details=$(append_inventory_detail "$details" "dns_name" "$(extract_inventory_values "$out" 'DNS_Computer_Name:' 1)")
                details=$(append_inventory_detail "$details" "product" "$(extract_inventory_values "$out" 'Product_Version:' 1)")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "rdp" "windows" "desktop" "$version" "$details" "$source"
                printf -- '- RDP %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                if [[ -n "$(extract_inventory_values "$out" 'DNS_Domain_Name:' 1)" || -n "$(extract_inventory_values "$out" 'Target_Name:' 1)" ]]; then
                    printf -- '- RDP NTLM hint %s/%s -> %s\n' "$port" "$proto" "${details}" >> "$directory_file"
                    dir_count=$((dir_count + 1))
                fi
                ;;
            ms-sql*|mssql)
                out="${result_dir}/scans/mssql_${port}.txt"
                source="scans/mssql_${port}.txt"
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "instance" "$(extract_inventory_values "$out" 'Instance name:' 1)")
                details=$(append_inventory_detail "$details" "server_version" "$(extract_inventory_values "$out" '^Version:' 1)")
                details=$(append_inventory_detail "$details" "named_pipe" "$(extract_inventory_values "$out" 'Named pipe:' 1)")
                details=$(append_inventory_detail "$details" "target" "$(extract_inventory_values "$out" 'Target_Name:' 1)")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "mssql" "windows" "database_auth" "$version" "$details" "$source"
                printf -- '- MSSQL %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                ;;
            nfs|rpcbind)
                if (( nfs_recorded == 1 )); then
                    continue
                fi
                nfs_recorded=1
                details=$(append_inventory_detail "$details" "version" "$version")
                details=$(append_inventory_detail "$details" "exports" "$(extract_nfs_exports "$nfs_file")")
                line=$(extract_first_inventory_match "$nfs_file" 'nfs[[:space:]]+[0-9]|mountd[[:space:]]+[0-9]')
                details=$(append_inventory_detail "$details" "rpc" "$line")
                append_auth_surface_entry "$auth_file" "$ip" "${port:-2049}" "$proto" "nfs" "linux" "file_share" "$version" "$details" "scans/nfs.txt"
                printf -- '- NFS %s/%s -> %s\n' "${port:-2049}" "$proto" "${details:-version=${version:-unknown}}" >> "$linux_file"
                linux_count=$((linux_count + 1))
                ;;
            kerberos*|kpasswd*)
                details=$(append_inventory_detail "$details" "version" "$version")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "$service" "windows" "directory_auth" "$version" "$details" "scans/nmap_targeted.nmap"
                printf -- '- %s %s/%s -> %s\n' "${service^^}" "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                if (( kerberos_seen == 0 )); then
                    echo "AD auth indicators detected:" >> "$directory_file"
                    kerberos_seen=1
                fi
                printf '  * %s/%s %s %s\n' "$port" "$proto" "$service" "${version:+(${version})}" >> "$directory_file"
                dir_count=$((dir_count + 1))
                ;;
            msrpc)
                details=$(append_inventory_detail "$details" "version" "$version")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "$service" "windows" "rpc" "$version" "$details" "scans/nmap_targeted.nmap"
                printf -- '- MSRPC %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                windows_count=$((windows_count + 1))
                ;;
        esac

        case "$port" in
            5985|5986)
                if [[ "$service" != "wsman" && "$service" != "winrm" ]]; then
                    out="${result_dir}/scans/winrm_${port}.txt"
                    source="scans/winrm_${port}.txt"
                    details=""
                    details=$(append_inventory_detail "$details" "version" "$version")
                    details=$(append_inventory_detail "$details" "auth" "$(extract_inventory_values "$out" '^WWW-Authenticate:' 4)")
                    details=$(append_inventory_detail "$details" "server" "$(extract_inventory_values "$out" '^Server:' 1)")
                    append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "winrm" "windows" "remote_shell" "$version" "$details" "$source"
                    printf -- '- WinRM %s/%s -> %s\n' "$port" "$proto" "${details:-version=${version:-unknown}}" >> "$windows_file"
                    windows_count=$((windows_count + 1))
                fi
                ;;
            3268|3269)
                details=$(append_inventory_detail "" "version" "$version")
                append_auth_surface_entry "$auth_file" "$ip" "$port" "$proto" "global_catalog" "windows" "directory_service" "$version" "$details" "scans/nmap_targeted.nmap"
                if (( gc_seen == 0 )); then
                    echo "Global Catalog indicators detected:" >> "$directory_file"
                    gc_seen=1
                fi
                printf '  * %s/%s global_catalog %s\n' "$port" "$proto" "${version:+(${version})}" >> "$directory_file"
                dir_count=$((dir_count + 1))
                ;;
        esac
    done < <(parse_open_nmap_services "$nmap_file")

    if (( win_count == 0 )); then
        echo "No Windows auth/remoting surfaces detected from current scan results." >> "$windows_file"
    fi
    if (( linux_count == 0 )); then
        echo "No Linux remote-access surfaces detected from current scan results." >> "$linux_file"
    fi
    if (( dir_count == 0 )); then
        echo "No directory service indicators detected from current scan results." >> "$directory_file"
    fi

    log_success "Auth surfaces → ${auth_file}"
    log_success "Windows auth inventory → ${windows_file}"
    log_success "Linux remote-access inventory → ${linux_file}"
    log_success "Directory services inventory → ${directory_file}"
}

queue_web_target() {
    local web_file="$1"
    local target="$2"
    local reason="${3:-Web service → queued for Phase 3}"

    [[ -n "$target" ]] || return 0
    echo "$target" >> "$web_file"
    log_info "${reason}: ${target}"
}

queue_web_targets_from_service() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="$3"
    local port="$4"
    local proto="$5"
    local service="$6"
    local web_file="${result_dir}/scans/web_ports.txt"
    local scheme
    local target_host
    local script_block=""

    scheme=$(get_web_proto "$port" "$service")
    target_host="${TARGET_DOMAIN:-$ip}"

    queue_web_target "$web_file" "${scheme}://${ip}:${port}"
    if [[ -n "$TARGET_DOMAIN" && "$TARGET_DOMAIN" != "$ip" ]]; then
        queue_web_target "$web_file" "${scheme}://${TARGET_DOMAIN}:${port}"
    elif [[ "$target_host" != "$ip" ]]; then
        queue_web_target "$web_file" "${scheme}://${target_host}:${port}"
    fi

    script_block=$(extract_nmap_port_script_block "$nmap_file" "$port" "$proto")
    [[ -z "$script_block" ]] && return 0

    while read -r target; do
        target=$(echo "$target" | sed -E 's/[)>.,]+$//')
        queue_web_target "$web_file" "$target" "Web redirect/script hint → queued for Phase 3"
    done < <(printf '%s\n' "$script_block" | grep -oE 'https?://[^[:space:]<>"'"'"']+' 2>/dev/null)
}

ensure_service_enum_nmap_results() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local ports=""

    if has_open_ports_in_nmap_file "$nmap_file"; then
        return 0
    fi

    ports=$(normalize_ports_csv "$(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)")
    [[ -n "$ports" ]] || return 1

    log_warn "Targeted nmap results are missing or incomplete. Re-running deep scan from cached ports."
    nmap_deep_scan "$ip" "$result_dir" "$ports" >/dev/null 2>&1
    has_open_ports_in_nmap_file "$nmap_file"
}

# ── Main Service Enum Router ──
run_service_enum() {
    local ip="$1"
    local result_dir="$2"
    
    section_header "PHASE 2: SERVICE ENUMERATION"
    local start=$(timer_start)
    
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    
    if ! ensure_service_enum_nmap_results "$ip" "$result_dir"; then
        log_warn "No nmap results found. Skipping service enum."
        return 1
    fi
    
    # Collect web ports for Phase 3
    > "${result_dir}/scans/web_ports.txt"
    
    local -a pids=()
    local pid=""
    local has_microsoft_ds=false
    local has_nfs=false

    grep -qE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+microsoft-ds\??([[:space:]]|$)' "$nmap_file" 2>/dev/null && has_microsoft_ds=true
    grep -qE '^[0-9]+/tcp[[:space:]]+open[[:space:]]+nfs\??([[:space:]]|$)' "$nmap_file" 2>/dev/null && has_nfs=true
    
    # Parse nmap and route to handlers IN PARALLEL
    while IFS='|' read -r port proto raw_service version; do
        local service
        service=$(normalize_nmap_service_name "$raw_service")
        
        # Route to appropriate handler
        case "$service" in
            ftp)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_ftp "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} FTP:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            ssh)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_ssh "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} SSH:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            smtp|smtps)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_smtp "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} SMTP:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            domain|dns)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_dns "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} DNS:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            wsman|winrm)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_winrm "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} WinRM:${port} ${DIM}(bg PID: ${pid})${NC}"
                queue_web_targets_from_service "$ip" "$result_dir" "$nmap_file" "$port" "$proto" "$service"
                ;;
            http|http-alt|http-proxy|https|https-alt|ssl/http|ssl/https)
                if [[ "$port" == "5985" || "$port" == "5986" ]]; then
                    throttle_jobs "$ENUM_MAX_JOBS"
                    enum_winrm "$ip" "$port" "$result_dir" &
                    pid=$!
                    pids+=("$pid")
                    echo -e "  ${ICON_SCAN} WinRM:${port} ${DIM}(bg PID: ${pid})${NC}"
                fi
                queue_web_targets_from_service "$ip" "$result_dir" "$nmap_file" "$port" "$proto" "$service"
                ;;
            microsoft-ds|netbios-ssn)
                if [[ "$service" == "netbios-ssn" && "$has_microsoft_ds" == "true" ]]; then
                    log_info "Skipping duplicate SMB enum on ${port} (445 already present)"
                    continue
                fi
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_smb "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} SMB:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            mysql|mariadb)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_mysql "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} MySQL:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            ms-sql*|mssql)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_mssql "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} MSSQL:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            ms-wbt-server|rdp)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_rdp "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} RDP:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            nfs|rpcbind)
                if [[ "$service" == "rpcbind" && "$has_nfs" == "true" ]]; then
                    log_info "Skipping duplicate NFS enum on ${port} (2049 already present)"
                    continue
                fi
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_nfs "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} NFS:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            ldap|ldaps)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_ldap "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} LDAP:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            redis)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_redis "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} Redis:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            snmp)
                throttle_jobs "$ENUM_MAX_JOBS"
                enum_snmp "$ip" "$port" "$result_dir" &
                pid=$!
                pids+=("$pid")
                echo -e "  ${ICON_SCAN} SNMP:${port} ${DIM}(bg PID: ${pid})${NC}"
                ;;
            *)
                if is_web_port "$port" "$service"; then
                    queue_web_targets_from_service "$ip" "$result_dir" "$nmap_file" "$port" "$proto" "$service"
                else
                    throttle_jobs "$ENUM_MAX_JOBS"
                    enum_generic "$ip" "$port" "$result_dir" "$service" &
                    pid=$!
                    pids+=("$pid")
                    echo -e "  ${ICON_SCAN} ${service}:${port} ${DIM}(bg PID: ${pid})${NC}"
                fi
                ;;
        esac
    done < <(parse_open_nmap_services "$nmap_file")
    
    # Wait for ALL background enum jobs to finish
    echo ""
    log_info "Waiting for all parallel enum jobs to finish..."
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    log_success "All service enumeration complete!"
    
    dedup_file "${result_dir}/scans/web_ports.txt"
    build_service_inventories "$ip" "$result_dir" "$nmap_file"
    
    local web_count=$(wc -l < "${result_dir}/scans/web_ports.txt" 2>/dev/null || echo 0)
    log_info "Web services found for Phase 3: ${web_count}"
    log_info "Time: $(timer_elapsed $start)"
    
    # Show output from enum files
    echo ""
    for f in "${result_dir}/scans/"*.txt; do
        [[ ! -f "$f" ]] && continue
        local bname=$(basename "$f")
        [[ "$bname" == "open_ports.txt" || "$bname" == "scan_method.txt" || "$bname" == "web_ports.txt" || "$bname" == "alive_hosts.txt" ]] && continue
        echo -e "  ${DIM}── ${bname} ──${NC}"
        cat "$f"
        echo ""
    done
    
    pause_if_interactive
}
