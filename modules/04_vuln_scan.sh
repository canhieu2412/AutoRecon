#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 4: Vulnerability Scanning
# ============================================================================

strip_ansi_stream() {
    sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g'
}

normalize_searchsploit_text() {
    local text="$1"
    echo "$text" | sed -E 's/\([^)]*\)//g; s/\[[^]]*\]//g; s/[^A-Za-z0-9._+ -]+/ /g; s/[[:space:]]+/ /g; s/^ //; s/ $//'
}

normalize_searchsploit_service() {
    local service="$1"
    case "$service" in
        microsoft-ds|netbios-ssn) echo "smb" ;;
        ms-wbt-server) echo "rdp" ;;
        ssl/http|ssl/https|http-proxy) echo "http" ;;
        ms-sql*|mssql) echo "mssql" ;;
        mariadb) echo "mysql" ;;
        *) echo "${service//-/ }" ;;
    esac
}

searchsploit_extract_rows() {
    strip_ansi_stream | awk -F'\\|' '
        /\|/ && $1 !~ /Exploit Title/ {
            title=$1
            path=$2
            gsub(/^[ \t]+|[ \t]+$/, "", title)
            gsub(/^[ \t]+|[ \t]+$/, "", path)
            if (title != "" && path != "" && title !~ /^-+$/) {
                print title "|" path
            }
        }
    '
}

searchsploit_score() {
    local title="$1"
    local path="$2"
    local text="${title} ${path}"

    if grep -Eiq 'auth.?bypass|unauth|remote.+(code|command).+(exec|execution)|rce|code execution|command execution|sql injection|sqli|file upload|deserialization|template injection' <<< "$text"; then
        echo 0
    elif grep -Eiq 'remote|traversal|xxe|xss|ssti|injection|disclosure|overflow|bypass' <<< "$text"; then
        echo 1
    elif grep -Eiq 'privilege escalation|privesc|lpe|local' <<< "$text"; then
        echo 2
    elif grep -Eiq 'dos|denial of service|memory exhaustion' <<< "$text"; then
        echo 4
    else
        echo 3
    fi
}

searchsploit_label() {
    case "$1" in
        0) echo "CRITICAL" ;;
        1) echo "HIGH" ;;
        2) echo "MEDIUM" ;;
        4) echo "LOW" ;;
        *) echo "INFO" ;;
    esac
}

searchsploit_emit_ranked_results() {
    local rows_file="$1"
    local limit="${2:-20}"
    local count=0
    local line=""
    declare -A seen=()
    local -a ranked=()

    while IFS='|' read -r title path; do
        [[ -z "$title" || -z "$path" ]] && continue
        line="${title}|${path}"
        [[ -n "${seen[$line]+x}" ]] && continue
        seen[$line]=1

        local score
        score=$(searchsploit_score "$title" "$path")
        ranked+=("${score}|$(searchsploit_label "$score")|${title}|${path}")
    done < "$rows_file"

    if [[ ${#ranked[@]} -eq 0 ]]; then
        return 1
    fi

    while IFS='|' read -r score label title path; do
        printf '[%s] %s | %s\n' "$label" "$title" "$path"
        count=$((count + 1))
        [[ $count -ge $limit ]] && break
    done < <(printf '%s\n' "${ranked[@]}" | sort -t'|' -k1,1n -k3,3)

    return 0
}

generate_searchsploit_queries() {
    local service_name="$1"
    local banner="$2"
    local normalized_service
    normalized_service=$(normalize_searchsploit_service "$service_name")

    local clean_banner
    clean_banner=$(normalize_searchsploit_text "$banner")

    local version=""
    version=$(echo "$clean_banner" | grep -oPm1 '[0-9]+([._-][0-9A-Za-z]+)+' || true)

    local short_version=""
    [[ -n "$version" ]] && short_version=$(echo "$version" | grep -oPm1 '^[0-9]+(\.[0-9]+)+' || true)

    local prefix="$clean_banner"
    [[ -n "$version" ]] && prefix="${clean_banner%%$version*}"
    prefix=$(normalize_searchsploit_text "$prefix")

    local first_word=""
    local first_two=""
    [[ -n "$prefix" ]] && first_word=$(echo "$prefix" | awk '{print $1}')
    [[ -n "$prefix" ]] && first_two=$(echo "$prefix" | awk '{print $1" "$2}' | sed 's/ $//')

    {
        [[ -n "$prefix" && -n "$version" ]] && echo "$(normalize_searchsploit_text "$prefix $version")"
        [[ -n "$prefix" && -n "$short_version" && "$short_version" != "$version" ]] && echo "$(normalize_searchsploit_text "$prefix $short_version")"
        [[ -n "$first_two" && -n "$version" ]] && echo "$(normalize_searchsploit_text "$first_two $version")"
        [[ -n "$first_word" && -n "$version" ]] && echo "$(normalize_searchsploit_text "$first_word $version")"
        [[ -n "$normalized_service" && -n "$version" ]] && echo "$(normalize_searchsploit_text "$normalized_service $version")"
        [[ -n "$normalized_service" && -n "$short_version" && "$short_version" != "$version" ]] && echo "$(normalize_searchsploit_text "$normalized_service $short_version")"
        [[ -n "$clean_banner" ]] && echo "$clean_banner"
        [[ -n "$prefix" ]] && echo "$prefix"
        [[ -n "$normalized_service" ]] && echo "$normalized_service"
    } | awk 'NF && !seen[$0]++'
}

run_searchsploit_query() {
    local query="$1"
    if grep -q '[0-9]' <<< "$query"; then
        searchsploit --disable-colour -t --strict "$query" 2>/dev/null
    else
        searchsploit --disable-colour -t "$query" 2>/dev/null
    fi
}

offsec_oscp_safe_mode_enabled() {
    [[ "${OFFSEC_OSCP_SAFE_MODE:-false}" == "true" ]]
}

normalize_param_target_value() {
    local target="$1"
    target="${target%%#*}"
    target=$(echo "$target" | sed -E 's/=FUZZ([&#]|$)/=1\1/g; s/=([&#]|$)/=1\1/g')
    printf '%s\n' "$target"
}

normalize_sqlmap_header_value() {
    local headers="$1"
    headers="${headers//\\n/$'\n'}"
    headers="${headers//;/$'\n'}"
    printf '%s' "$headers"
}

build_post_param_target_file() {
    local result_dir="$1"
    local out_file="$2"

    : > "$out_file"

    for pfile in "${result_dir}/web/params_"*.txt; do
        [[ ! -f "$pfile" ]] && continue
        grep "\[POST\]" "$pfile" | while IFS= read -r line; do
            local parsed
            parsed=$(echo "$line" | sed -E 's/.*\[POST\][[:space:]]+([^[:space:]]+)[[:space:]]+→[[:space:]]+(.+)/\1|\2/')
            local url="${parsed%%|*}"
            local data="${parsed#*|}"
            data=$(normalize_param_target_value "$data")
            if [[ "$url" =~ ^https?:// ]] && [[ -n "$data" ]] && [[ "$parsed" == *"|"* ]]; then
                printf '%s|%s\n' "$url" "$data" >> "$out_file"
            fi
        done
    done

    dedup_file "$out_file"
}

build_param_target_file() {
    local result_dir="$1"
    local out_file="$2"

    : > "$out_file"

    for pfile in "${result_dir}/web/params_"*.txt; do
        [[ ! -f "$pfile" ]] && continue
        grep "\[GET\]" "$pfile" | \
            sed -E 's/.*\[GET\][[:space:]]+//' | \
            while IFS= read -r target_url; do
                target_url=$(normalize_param_target_value "$target_url")
                [[ "$target_url" =~ ^https?:// ]] && printf '%s\n' "$target_url" >> "$out_file"
            done
    done

    dedup_file "$out_file"
}

build_web_target_file() {
    local result_dir="$1"
    local out_file="$2"

    : > "$out_file"

    for source_file in "${result_dir}/scans/web_ports.txt" "${result_dir}/web/cms_discovered_paths.txt"; do
        [[ -f "$source_file" ]] || continue
        grep -E '^https?://' "$source_file" >> "$out_file"
    done

    dedup_file "$out_file"
}

run_sqlmap_wizard() {
    local result_dir="$1"
    local get_targets_file="$2"
    local post_targets_file="$3"
    local web_targets_file="$4"

    [[ "${INTERACTIVE:-false}" == "true" ]] || return 0
    offsec_oscp_safe_mode_enabled && return 0

    if ! command -v sqlmap &>/dev/null; then
        log_info "sqlmap not installed; skipping interactive SQLMap wizard."
        return 0
    fi

    local has_get=false
    local has_post=false
    local has_web=false
    [[ -s "$get_targets_file" ]] && has_get=true
    [[ -s "$post_targets_file" ]] && has_post=true
    [[ -s "$web_targets_file" ]] && has_web=true

    if [[ "$has_get" != "true" && "$has_post" != "true" && "$has_web" != "true" ]]; then
        log_info "No discovered web targets available for the SQLMap wizard."
        return 0
    fi

    echo ""
    echo -e "${BOLD}${CYAN}  Interactive SQLMap Wizard${NC}"
    echo -e "${DIM}  Press Enter to keep defaults or skip optional fields${NC}"
    echo -ne "  ${CYAN}▶${NC} Launch SQLMap wizard now? [y/N]: "
    local launch_choice=""
    read -r launch_choice
    [[ "$launch_choice" =~ ^[Yy]$ ]] || return 0

    local source_choice=""
    while true; do
        echo ""
        echo -e "  ${BOLD}Target source${NC}"
        [[ "$has_get" == "true" ]] && echo "    [1] Discovered GET params"
        [[ "$has_post" == "true" ]] && echo "    [2] Discovered POST params"
        [[ "$has_web" == "true" ]] && echo "    [3] Web targets"
        echo "    [4] Custom URL"
        echo -ne "  ${CYAN}▶${NC} Choose source: "
        read -r source_choice
        case "$source_choice" in
            1) [[ "$has_get" == "true" ]] && break ;;
            2) [[ "$has_post" == "true" ]] && break ;;
            3) [[ "$has_web" == "true" ]] && break ;;
            4) break ;;
        esac
        log_warn "Invalid selection. Choose one of the listed sources."
    done

    local selected_url=""
    local default_method="GET"
    local default_data=""
    local list_file=""

    case "$source_choice" in
        1)
            list_file="$get_targets_file"
            default_method="GET"
            ;;
        2)
            list_file="$post_targets_file"
            default_method="POST"
            ;;
        3)
            list_file="$web_targets_file"
            default_method="GET"
            ;;
        4)
            echo -ne "  ${CYAN}▶${NC} Target URL: "
            read -r selected_url
            ;;
    esac

    if [[ -n "$list_file" ]]; then
        echo ""
        echo -e "  ${BOLD}Discovered targets${NC}"
        local idx=1
        if [[ "$source_choice" == "2" ]]; then
            while IFS='|' read -r target_url target_data; do
                [[ -z "$target_url" ]] && continue
                printf '    [%d] %s [data: %s]\n' "$idx" "$target_url" "$target_data"
                idx=$((idx + 1))
            done < "$list_file"
        else
            while IFS= read -r target_url; do
                [[ -z "$target_url" ]] && continue
                printf '    [%d] %s\n' "$idx" "$target_url"
                idx=$((idx + 1))
            done < "$list_file"
        fi

        local target_index=""
        echo -ne "  ${CYAN}▶${NC} Choose target number: "
        read -r target_index
        if ! [[ "$target_index" =~ ^[0-9]+$ ]] || [[ "$target_index" -lt 1 ]]; then
            log_warn "Invalid target selection. Skipping SQLMap wizard run."
            return 0
        fi

        if [[ "$source_choice" == "2" ]]; then
            local selected_line=""
            selected_line=$(sed -n "${target_index}p" "$list_file")
            selected_url="${selected_line%%|*}"
            default_data="${selected_line#*|}"
        else
            selected_url=$(sed -n "${target_index}p" "$list_file")
        fi
    fi

    if [[ ! "$selected_url" =~ ^https?:// ]]; then
        log_warn "A valid http(s) target URL is required for SQLMap."
        return 0
    fi

    local method_input=""
    local data_input=""
    local cookies_input=""
    local headers_input=""
    local risk_input=""
    local level_input=""
    local threads_input=""
    local technique_input=""
    local tamper_input=""

    echo -ne "  ${CYAN}▶${NC} HTTP method [Default: ${default_method}]: "
    read -r method_input
    local sqlmap_method="${method_input:-$default_method}"

    echo -ne "  ${CYAN}▶${NC} Request data/body [Default: ${default_data:-none}]: "
    read -r data_input
    local sqlmap_data="${data_input:-$default_data}"

    echo -ne "  ${CYAN}▶${NC} Cookies [Default: none]: "
    read -r cookies_input

    echo -ne "  ${CYAN}▶${NC} Headers (use ';' between headers) [Default: none]: "
    read -r headers_input

    echo -ne "  ${CYAN}▶${NC} Risk 1-3 [Default: 1]: "
    read -r risk_input
    local sqlmap_risk="${risk_input:-1}"

    echo -ne "  ${CYAN}▶${NC} Level 1-5 [Default: 1]: "
    read -r level_input
    local sqlmap_level="${level_input:-1}"

    echo -ne "  ${CYAN}▶${NC} Threads [Default: 4]: "
    read -r threads_input
    local sqlmap_threads="${threads_input:-4}"

    echo -ne "  ${CYAN}▶${NC} Technique (optional, e.g. BEUSTQ): "
    read -r technique_input

    echo -ne "  ${CYAN}▶${NC} Tamper scripts (optional, comma-separated): "
    read -r tamper_input

    local normalized_headers=""
    normalized_headers=$(normalize_sqlmap_header_value "$headers_input")

    local sqlmap_output_dir="${result_dir}/vulns/sqlmap_output"
    local wizard_out="${result_dir}/vulns/sqlmap_wizard.txt"
    local wizard_cfg="${result_dir}/vulns/sqlmap_wizard_config.txt"
    mkdir -p "$sqlmap_output_dir"

    {
        echo "target=${selected_url}"
        echo "method=${sqlmap_method}"
        echo "data=${sqlmap_data}"
        echo "cookies=${cookies_input}"
        echo "headers=${headers_input}"
        echo "risk=${sqlmap_risk}"
        echo "level=${sqlmap_level}"
        echo "threads=${sqlmap_threads}"
        echo "technique=${technique_input}"
        echo "tamper=${tamper_input}"
    } > "$wizard_cfg"

    local -a sqlmap_cmd=(timeout 600 sqlmap
        -u "$selected_url"
        --batch
        --random-agent
        --output-dir "$sqlmap_output_dir"
        --risk "$sqlmap_risk"
        --level "$sqlmap_level"
        --threads "$sqlmap_threads")

    [[ -n "$sqlmap_method" ]] && sqlmap_cmd+=(--method "$sqlmap_method")
    [[ -n "$sqlmap_data" ]] && sqlmap_cmd+=(--data "$sqlmap_data")
    [[ -n "$cookies_input" ]] && sqlmap_cmd+=(--cookie "$cookies_input")
    [[ -n "$normalized_headers" ]] && sqlmap_cmd+=(--headers "$normalized_headers")
    [[ -n "$technique_input" ]] && sqlmap_cmd+=(--technique "$technique_input")
    [[ -n "$tamper_input" ]] && sqlmap_cmd+=(--tamper "$tamper_input")

    sub_header "Interactive SQLMap Wizard"
    log_scan "Running sqlmap wizard target: ${selected_url}"
    log_command_preview "${sqlmap_cmd[@]}"
    "${sqlmap_cmd[@]}" > "$wizard_out" 2>&1

    if grep -qi "is vulnerable" "$wizard_out" 2>/dev/null; then
        print_found "SQLMap wizard detected injectable parameters! Check sqlmap_wizard.txt"
    else
        log_info "SQLMap wizard run completed. Review sqlmap_wizard.txt for details."
    fi
}

run_vuln_scan() {
    local ip="$1"
    local result_dir="$2"
    
    section_header "PHASE 4: VULNERABILITY SCANNING"
    local start=$(timer_start)
    
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local ports
    ports=$(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)
    local param_targets_file="${result_dir}/vulns/param_targets.txt"
    local post_param_targets_file="${result_dir}/vulns/post_param_targets.txt"
    local web_targets_file="${result_dir}/vulns/web_targets.txt"
    
    if [[ -z "$ports" ]]; then
        log_warn "No open ports. Skipping vuln scan."
        return 0
    fi
    
    # ── 1. Nmap Vuln Scripts ──
    sub_header "Nmap Vulnerability Scripts"
    log_scan "nmap --script vuln on ports: ${ports}"
    
    local -a nmap_vuln_cmd=(timeout "$TOOL_TIMEOUT" nmap --script vuln
        -p "$ports" -Pn
        -oN "${result_dir}/vulns/nmap_vuln.txt"
        "$ip")
    log_command_preview "${nmap_vuln_cmd[@]}"
    "${nmap_vuln_cmd[@]}" 2>/dev/null
    
    if [[ -f "${result_dir}/vulns/nmap_vuln.txt" ]]; then
        # Extract CVEs found
        local cves
        cves=$(grep -oP 'CVE-\d{4}-\d+' "${result_dir}/vulns/nmap_vuln.txt" 2>/dev/null | sort -u)
        if [[ -n "$cves" ]]; then
            print_found "CVEs found:"
            echo "$cves" | while read -r cve; do
                echo -e "    ${RED}→ ${cve}${NC}"
            done
            echo "$cves" > "${result_dir}/vulns/cves_found.txt"
        fi
        
        # Check for VULNERABLE flags
        if grep -qi "VULNERABLE\|State: VULNERABLE" "${result_dir}/vulns/nmap_vuln.txt"; then
            print_found "VULNERABLE services detected! Check nmap_vuln.txt"
        fi
        
        log_success "Nmap vuln scan → ${result_dir}/vulns/nmap_vuln.txt"
    fi
    
    # ── 2. SearchSploit (auto-parse service versions) ──
    sub_header "SearchSploit - Known Exploits"
    
    if command -v searchsploit &>/dev/null && [[ -f "$nmap_file" ]]; then
        log_scan "Searching exploit-db for service versions..."
        
        # Method 1: searchsploit with nmap xml
        if [[ -f "${result_dir}/scans/nmap_targeted.xml" ]]; then
            local auto_raw="${result_dir}/vulns/.searchsploit_auto_raw"
            local auto_rows="${result_dir}/vulns/.searchsploit_auto_rows"
            local -a searchsploit_auto_cmd=(searchsploit --disable-colour --nmap "${result_dir}/scans/nmap_targeted.xml")
            log_command_preview "${searchsploit_auto_cmd[@]}"
            "${searchsploit_auto_cmd[@]}" > "$auto_raw" 2>/dev/null

            searchsploit_extract_rows < "$auto_raw" > "$auto_rows"

            {
                echo "=== Auto SearchSploit Results ==="
                echo ""
                if ! searchsploit_emit_ranked_results "$auto_rows" 30; then
                    echo "No ranked SearchSploit matches found."
                fi
            } > "${result_dir}/vulns/searchsploit_auto.txt"

            rm -f "$auto_raw" "$auto_rows"
            log_success "SearchSploit (auto) → ${result_dir}/vulns/searchsploit_auto.txt"
        fi
        
        # Method 2: manual search per service
        {
            echo "=== Manual SearchSploit Results ==="
            echo ""
            
            grep "^[0-9]" "$nmap_file" | grep "open" | while read -r line; do
                local port_proto
                port_proto=$(echo "$line" | awk '{print $1}')
                local service_name
                service_name=$(echo "$line" | awk '{print $3}' | tr '[:upper:]' '[:lower:]')
                local service_info
                service_info=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^ *//')

                local search_banner
                search_banner=$(normalize_searchsploit_text "$service_info")
                [[ -z "$search_banner" ]] && search_banner="$service_name"

                local tmp_rows="${result_dir}/vulns/.searchsploit_manual_rows"
                : > "$tmp_rows"

                local queries=()
                while IFS= read -r query; do
                    [[ -n "$query" ]] && queries+=("$query")
                done < <(generate_searchsploit_queries "$service_name" "$search_banner")

                local query
                for query in "${queries[@]}"; do
                    run_searchsploit_query "$query" | searchsploit_extract_rows >> "$tmp_rows"
                done

                if [[ -s "$tmp_rows" ]]; then
                    echo "--- ${port_proto} ${service_name} | ${search_banner} ---"
                    echo "Queries: $(printf '%s; ' "${queries[@]}" | sed 's/; $//')"
                    searchsploit_emit_ranked_results "$tmp_rows" 15 || true
                    echo ""
                fi

                rm -f "$tmp_rows"
            done
        } > "${result_dir}/vulns/searchsploit_manual.txt" 2>&1
        
        # Show critical findings
        if grep -Eq '^\[(CRITICAL|HIGH)\]' "${result_dir}/vulns/searchsploit_auto.txt" 2>/dev/null || \
           grep -Eq '^\[(CRITICAL|HIGH)\]' "${result_dir}/vulns/searchsploit_manual.txt" 2>/dev/null; then
            print_found "Potential RCE/PrivEsc exploits found! Check searchsploit results."
        fi
        
        log_success "SearchSploit (manual) → ${result_dir}/vulns/searchsploit_manual.txt"
    else
        log_warn "searchsploit not available or no nmap results"
    fi
    
    # ── 3. Nuclei Scan (modern vuln scanner, 7000+ templates) ──
    if offsec_oscp_safe_mode_enabled; then
        log_warn "OFFSEC_OSCP_SAFE_MODE=true → skipping nuclei to avoid exam-risky mass-vuln scanning behavior."
    elif command -v nuclei &>/dev/null; then
        sub_header "Nuclei Vulnerability Scanner"
        
        # Scan each web port and newly discovered CMS sub-directories
        local web_file="${result_dir}/scans/web_ports.txt"
        local cms_paths="${result_dir}/web/cms_discovered_paths.txt"
        local targets_file="${result_dir}/vulns/.nuclei_targets"
        
        > "$targets_file"
        [[ -f "$web_file" ]] && cat "$web_file" >> "$targets_file"
        [[ -f "$cms_paths" ]] && cat "$cms_paths" >> "$targets_file"
        dedup_file "$targets_file"
        
        # Severities come from config (default includes info+low for fullest recon).
        local nuclei_sev="${NUCLEI_SEVERITY:-info,low,medium,high,critical}"
        local -a nuclei_extra=(); [[ -n "${NUCLEI_EXTRA_FLAGS:-}" ]] && read -r -a nuclei_extra <<< "$NUCLEI_EXTRA_FLAGS"
        log_info "Nuclei severities: ${BOLD}${nuclei_sev}${NC}"

        if [[ -s "$targets_file" ]]; then
            local target_count
            target_count=$(wc -l < "$targets_file" 2>/dev/null || echo 0)
            log_scan "Nuclei scanning ${target_count} web target(s)..."
            # -as = auto-select templates by detected tech; -stats keeps it lively.
            local -a nuclei_web_cmd=(timeout "$TOOL_TIMEOUT" nuclei -l "$targets_file"
                -as -severity "$nuclei_sev"
                -silent -nc "${nuclei_extra[@]}"
                -o "${result_dir}/vulns/nuclei_web.txt")
            log_command_preview "${nuclei_web_cmd[@]}"
            "${nuclei_web_cmd[@]}" 2>/dev/null
        fi
        rm -f "$targets_file"

        # Scan all ports with network templates (same severity set)
        log_scan "Nuclei network scan on ${ip}..."
        local -a nuclei_network_cmd=(timeout "$TOOL_TIMEOUT" nuclei -u "$ip"
            -t network/ -severity "$nuclei_sev"
            -silent -nc "${nuclei_extra[@]}"
            -o "${result_dir}/vulns/nuclei_network.txt")
        log_command_preview "${nuclei_network_cmd[@]}"
        "${nuclei_network_cmd[@]}" 2>/dev/null

        # Merge, de-dupe and prioritise output by severity so critical/high are
        # never buried under info noise. Nuclei lines look like: [id] [proto] [sev] url
        local nuclei_all="${result_dir}/vulns/nuclei_all.txt"
        cat "${result_dir}/vulns/nuclei_web.txt" "${result_dir}/vulns/nuclei_network.txt" 2>/dev/null \
            | awk 'NF' | sort -u > "$nuclei_all"
        if [[ -s "$nuclei_all" ]]; then
            local total; total=$(wc -l < "$nuclei_all")
            log_success "Nuclei found ${total} finding(s) — by severity:"
            local sev c
            for sev in critical high medium low info unknown; do
                c=$(grep -icE "\[${sev}\]" "$nuclei_all" 2>/dev/null || echo 0)
                (( c > 0 )) && printf '    %-9s %s\n' "${sev}:" "$c"
            done
            # Surface the actionable ones inline; info stays in the file.
            local shown=0
            for sev in critical high medium; do
                while IFS= read -r finding; do
                    [[ -z "$finding" ]] && continue
                    print_found "NUCLEI[${sev}]: $finding"
                    shown=$((shown+1))
                done < <(grep -iE "\[${sev}\]" "$nuclei_all" 2>/dev/null)
            done
            (( shown == 0 )) && log_info "Only low/info findings — see $(basename "$nuclei_all") for the full list."
        else
            log_info "Nuclei produced no findings for the selected severities."
        fi
    else
        log_info "nuclei not installed (skipping)"
    fi
    
    # ── 3.5 Auto SQLi Verification (sqlmap on discovered params) ──
    if offsec_oscp_safe_mode_enabled; then
        log_warn "OFFSEC_OSCP_SAFE_MODE=true → skipping sqlmap because OSCP/OSCP+ explicitly prohibit automatic exploitation tools."
    else
        local sqlmap_targets="${result_dir}/vulns/sqlmap_targets.txt"
        local sqlmap_output_dir="${result_dir}/vulns/sqlmap_output"
        build_param_target_file "$result_dir" "$param_targets_file"
        build_post_param_target_file "$result_dir" "$post_param_targets_file"
        build_web_target_file "$result_dir" "$web_targets_file"
        cp "$param_targets_file" "$sqlmap_targets"
        
        if command -v sqlmap &>/dev/null; then
            mkdir -p "$sqlmap_output_dir"

            if [[ -s "$sqlmap_targets" ]]; then
                sub_header "SQLMap Auto-Verification"
                local param_count=$(wc -l < "$sqlmap_targets")
                log_scan "Running SQLMap on ${param_count} GET parameters (timeout 5m)..."

                # Run sqlmap in batch mode
                local -a sqlmap_cmd=(timeout 300 sqlmap -m "$sqlmap_targets"
                    --batch --random-agent --level 1 --risk 1
                    --smart --threads 4
                    --output-dir "$sqlmap_output_dir")
                log_command_preview "${sqlmap_cmd[@]}"
                "${sqlmap_cmd[@]}" > "${result_dir}/vulns/sqlmap_auto.txt" 2>/dev/null

                if grep -qi "is vulnerable" "${result_dir}/vulns/sqlmap_auto.txt" 2>/dev/null; then
                    print_found "SQLMap detected vulnerable parameters! Check sqlmap_auto.txt"
                else
                    log_info "No SQLi found by sqlmap."
                fi
            else
                log_info "No discovered GET parameter targets available for auto SQLMap verification."
            fi

            run_sqlmap_wizard "$result_dir" "$param_targets_file" "$post_param_targets_file" "$web_targets_file"
        elif [[ "${INTERACTIVE:-false}" == "true" ]]; then
            log_info "sqlmap not installed; skipping SQLMap auto-verification and wizard."
        else
            log_info "sqlmap not installed (skipping auto verification)"
        fi
    fi
    
    # ── 3.5.5 Auto LFI Verification (ffuf with regex match) ──
    if command -v ffuf &>/dev/null; then
        local lfi_wordlist="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
        local lfi_targets="${result_dir}/vulns/lfi_targets.txt"
        local lfi_out="${result_dir}/vulns/lfi_auto.txt"
        build_param_target_file "$result_dir" "$param_targets_file"
        > "$lfi_targets"
        > "$lfi_out"
        
        # Only proceed if we have LFI wordlist and param targets 
        if [[ -f "$lfi_wordlist" ]] && [[ -s "$param_targets_file" ]]; then
            # Reuse the normalized GET-parameter inventory collected from web recon.
            # It looks like: http://target/?param=1. We must replace =1 with =FUZZ
            sed 's/=[^&]*/=FUZZ/g' "$param_targets_file" > "$lfi_targets"
            
            if [[ -s "$lfi_targets" ]]; then
                sub_header "Local File Inclusion (LFI) Auto-Verification"
                log_scan "Running LFI verification using $(wc -l < "$lfi_wordlist" 2>/dev/null) payloads..."
                
                # We use -mr (Match Regex) to explicitly search for root:x:0:0 or [fonts]/[extensions]
                # This guarantees zero false positives.
                while read -r target_url; do
                    [[ -z "$target_url" ]] && continue
                    log_info "Testing LFI: ${target_url}"
                    local -a lfi_cmd=(timeout "$TOOL_TIMEOUT" ffuf
                        -u "$target_url"
                        -w "$lfi_wordlist"
                        -mr 'root:x:0:0|\[fonts\]|\[extensions\]'
                        -s
                        -t "$FUZZ_THREADS")
                    log_command_preview "${lfi_cmd[@]}"
                    "${lfi_cmd[@]}" >> "$lfi_out" 2>/dev/null
                done < "$lfi_targets"
                
                if [[ -s "$lfi_out" ]]; then
                    print_found "CRITICAL: LFI Exploits verified! Check lfi_auto.txt"
                else
                    log_info "No LFI vulnerabilities detected."
                fi
            fi
        fi
    fi
    
    # ── 3.6 Metasploit Module Mapping ──
    if offsec_oscp_safe_mode_enabled; then
        log_warn "OFFSEC_OSCP_SAFE_MODE=true → skipping Metasploit mapping to keep the workflow exam-safe."
    elif command -v msfconsole &>/dev/null && [[ -f "${result_dir}/vulns/cves_found.txt" ]]; then
        sub_header "Metasploit Module Mapping"
        log_scan "Mapping found CVEs to Metasploit exploits..."
        local msf_out="${result_dir}/vulns/msf_mapping.txt"
        > "$msf_out"
        
        while read -r cve; do
            [[ -z "$cve" ]] && continue
            echo "--- $cve ---" >> "$msf_out"
            # search using msfconsole -q -x "search cve:XXXX; exit"
            # It takes ~5 secs per call, so we output to file
            timeout 45 msfconsole -q -x "search cve:$cve; exit" | grep "exploit/" >> "$msf_out" 2>/dev/null
            echo "" >> "$msf_out"
        done < "${result_dir}/vulns/cves_found.txt"
        
        if grep -q "exploit/" "$msf_out" 2>/dev/null; then
            print_found "Metasploit modules found for your CVEs!"
        fi
    fi
    
    # ── 4. Combine all vulnerability findings ──
    sub_header "Vulnerability Summary"
    {
        echo "=== Vulnerability Summary for ${ip} ==="
        echo "Generated: $(date)"
        echo ""
        
        # CVEs
        if [[ -f "${result_dir}/vulns/cves_found.txt" ]]; then
            echo "## CVEs Found"
            cat "${result_dir}/vulns/cves_found.txt"
            echo ""
        fi
        
        # Vulnerable services from nmap
        if [[ -f "${result_dir}/vulns/nmap_vuln.txt" ]]; then
            echo "## Nmap Vuln Script Findings"
            grep -A5 "VULNERABLE\|CVE" "${result_dir}/vulns/nmap_vuln.txt" 2>/dev/null
            echo ""
        fi
        
        # Nuclei findings
        for nf in "${result_dir}/vulns/nuclei_"*.txt; do
            [[ ! -f "$nf" ]] && continue
            echo "## Nuclei Findings ($(basename "$nf"))"
            cat "$nf"
            echo ""
        done
        
        # SearchSploit matches
        if [[ -f "${result_dir}/vulns/searchsploit_auto.txt" ]]; then
            echo "## SearchSploit Matches"
            cat "${result_dir}/vulns/searchsploit_auto.txt"
            echo ""
        fi

        if [[ -f "${result_dir}/vulns/searchsploit_manual.txt" ]]; then
            echo "## SearchSploit Manual Triage"
            cat "${result_dir}/vulns/searchsploit_manual.txt"
            echo ""
        fi
        
        # SQLMap Verify
        if [[ -f "${result_dir}/vulns/sqlmap_auto.txt" ]] && grep -qi "is vulnerable" "${result_dir}/vulns/sqlmap_auto.txt"; then
            echo "## SQLMap Verifications (CRITICAL)"
            grep -B 1 -A 5 "is vulnerable" "${result_dir}/vulns/sqlmap_auto.txt"
            echo ""
        fi

        if [[ -f "${result_dir}/vulns/sqlmap_wizard.txt" ]]; then
            echo "## SQLMap Wizard Run"
            cat "${result_dir}/vulns/sqlmap_wizard.txt"
            echo ""
        fi
        
        # MSF Mapping
        if [[ -f "${result_dir}/vulns/msf_mapping.txt" ]] && grep -q "exploit/" "${result_dir}/vulns/msf_mapping.txt"; then
            echo "## Metasploit Modules Mapping"
            cat "${result_dir}/vulns/msf_mapping.txt"
            echo ""
        fi
    } > "${result_dir}/vulns/summary.txt"
    
    log_success "Vulnerability summary → ${result_dir}/vulns/summary.txt"
    log_info "Time: $(timer_elapsed $start)"
    
    # Show vuln output
    echo ""
    for f in "${result_dir}/vulns/"*.txt; do
        [[ ! -f "$f" ]] && continue
        echo -e "  ${DIM}── $(basename "$f") ──${NC}"
        cat "$f"
        echo ""
    done
    
    pause_if_interactive
}
