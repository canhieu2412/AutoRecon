#!/bin/bash
# ============================================================================
# AUTO RECON - Tool Dependency Check
# ============================================================================

check_tools() {
    local missing=0
    local tools_critical="nmap nc curl"
    local tools_scan="rustscan nmap nc"
    local tools_web="gobuster feroxbuster ffuf nikto whatweb wafw00f cewl node subfinder"
    local tools_enum="enum4linux smbclient smbmap rpcclient netexec ldapsearch snmp-check dnsrecon dnsenum impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump"
    local tools_windows="evil-winrm xfreerdp certipy bloodhound-python responder impacket-smbclient impacket-psexec impacket-wmiexec impacket-atexec impacket-lookupsid impacket-mssqlclient"
    local tools_linux="ssh ssh-audit sshpass scp rsync sftp showmount rpcinfo mount.nfs redis-cli mysql psql"
    local tools_vuln="searchsploit nuclei sslscan sqlmap"
    local tools_brute="hydra john hashcat"
    local tools_wordlists="cewl crunch rsmangler"
    local tools_other="wfuzz"
    
    print_tool_group() {
        local title="$1"
        local tools="$2"
        local severity="${3:-optional}"
        local tool=""
        local ver=""

        sub_header "$title"
        for tool in $tools; do
            if command -v "$tool" &>/dev/null; then
                ver=""
                case "$tool" in
                    nmap) ver=$(nmap --version 2>/dev/null | head -1 | grep -oP '[\d.]+') ;;
                esac
                echo -e "  ${ICON_OK} ${tool} ${DIM}${ver:+($ver)}${NC}"
            else
                if [[ "$severity" == "critical" ]]; then
                    echo -e "  ${ICON_FAIL} ${RED}${tool} - MISSING (CRITICAL)${NC}"
                    missing=1
                else
                    echo -e "  ${ICON_WARN} ${YELLOW}${tool}${NC}"
                fi
            fi
        done
    }

    print_tool_group "Critical Tools" "$tools_critical" "critical"
    print_tool_group "Port Scanning" "$tools_scan"
    print_tool_group "Web Recon" "$tools_web"
    print_tool_group "Service Enum" "$tools_enum"
    print_tool_group "Windows Operator" "$tools_windows"
    print_tool_group "Linux Operator" "$tools_linux"
    print_tool_group "Vuln Scanning" "$tools_vuln"
    print_tool_group "Brute Force & Cracking" "$tools_brute"
    print_tool_group "Wordlist Toolkit" "$tools_wordlists"
    print_tool_group "Other Tools" "$tools_other"
    
    # Summary
    echo ""
    sub_header "Wordlists"
    [[ -f "$WORDLIST_WEB" ]] && echo -e "  ${ICON_OK} Web: $(basename "$WORDLIST_WEB") ($(wc -l < "$WORDLIST_WEB" 2>/dev/null) lines)" || echo -e "  ${ICON_WARN} ${YELLOW}No web wordlist${NC}"
    [[ -f "$WORDLIST_DNS" ]] && echo -e "  ${ICON_OK} DNS: $(basename "$WORDLIST_DNS") ($(wc -l < "$WORDLIST_DNS" 2>/dev/null) lines)" || echo -e "  ${ICON_WARN} ${YELLOW}No DNS wordlist${NC}"
    [[ -f "$WORDLIST_WEB_SMALL" ]] && echo -e "  ${ICON_OK} Quick: $(basename "$WORDLIST_WEB_SMALL")" || true
    [[ -f "$WORDLIST_WEB_BIG" ]] && echo -e "  ${ICON_OK} Big: $(basename "$WORDLIST_WEB_BIG")" || true
    [[ -d "$CMS_WORDLIST_DIR" ]] && echo -e "  ${ICON_OK} CMS: $(ls "$CMS_WORDLIST_DIR"/*.txt 2>/dev/null | wc -l) wordlists" || true
    [[ -f "$WORDLIST_USERS" ]] && echo -e "  ${ICON_OK} Users: $(basename "$WORDLIST_USERS")" || true
    [[ -f "$WORDLIST_PASS" ]] && echo -e "  ${ICON_OK} Passwords: $(basename "$WORDLIST_PASS")" || true
    
    echo ""
    local total=0 installed=0
    local tool=""
    while read -r tool; do
        [[ -z "$tool" ]] && continue
        total=$((total+1))
        command -v "$tool" &>/dev/null && installed=$((installed+1))
    done < <(printf '%s\n' $tools_critical $tools_scan $tools_web $tools_enum $tools_windows $tools_linux $tools_vuln $tools_brute $tools_wordlists $tools_other | awk '!seen[$0]++')
    echo -e "  ${BOLD}Total: ${installed}/${total} tools installed${NC}"
    
    if [[ $missing -eq 1 ]]; then
        log_error "Critical tools missing. Install them first."
        return 1
    fi
    return 0
}
