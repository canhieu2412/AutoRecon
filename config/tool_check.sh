#!/bin/bash
# ============================================================================
# AUTO RECON - Tool Dependency Check
# ============================================================================

check_tools() {
    local missing=0

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

    # Render from the central registry in lib/tools.sh so the dependency
    # report always matches the tools the modules actually invoke.
    local group
    for group in "${TOOL_GROUP_ORDER[@]}"; do
        print_tool_group \
            "${TOOL_GROUP_LABELS[$group]:-$group}" \
            "${TOOL_GROUPS[$group]}" \
            "${TOOL_GROUP_SEVERITY[$group]:-optional}"
    done

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
    done < <(for g in "${TOOL_GROUP_ORDER[@]}"; do printf '%s\n' ${TOOL_GROUPS[$g]}; done | awk '!seen[$0]++')
    echo -e "  ${BOLD}Total: ${installed}/${total} tools installed${NC}"
    
    if [[ $missing -eq 1 ]]; then
        log_error "Critical tools missing. Install them first."
        return 1
    fi
    return 0
}
