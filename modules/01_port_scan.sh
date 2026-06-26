#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 1: Port Scanning (Multi-Engine + Chunked Parallel)
# ============================================================================

is_quick_scan() {
    [[ "$SCAN_MODE" == "quick" ]]
}

normalize_ports_csv() {
    tr ',[:space:]' '\n' <<< "${1:-}" | awk '
        /^[0-9]+$/ && $1 >= 1 && $1 <= 65535 && !seen[$1]++ { ports[++count] = $1 }
        END {
            for (i = 1; i <= count; i++) {
                printf "%s%s", ports[i], (i < count ? "," : "")
            }
        }
    '
}

extract_open_ports_from_nmap_file() {
    local nmap_file="$1"
    [[ -s "$nmap_file" ]] || return 1

    awk '
        $1 ~ /^[0-9]+\/(tcp|udp)$/ && $2 == "open" {
            split($1, port_parts, "/")
            print port_parts[1]
        }
    ' "$nmap_file" | sort -un | tr '\n' ',' | sed 's/,$//'
}

has_open_ports_in_nmap_file() {
    local nmap_file="$1"
    [[ -n "$(extract_open_ports_from_nmap_file "$nmap_file")" ]]
}

# ── Full Parallel NC Scan (65535 ports) ──
scan_nc_full() {
    local ip="$1"
    local result_dir="$2"
    local threads="${NC_PARALLEL:-300}"

    if is_quick_scan; then
        scan_nc_simple "$ip" "$result_dir"
        return $?
    fi
    
    log_scan "Engine: NC Full (65535 ports, ${threads} parallel)..."
    echo ""
    
    local tmp_file="${result_dir}/scans/.nc_full_tmp"
    > "$tmp_file"
    
    # Run netcat over all 65535 ports using xargs. Print open ports in real-time.
    seq 1 65535 | timeout "$SCAN_TIMEOUT" xargs -P "$threads" -I{} \
        sh -c "nc -znv -w1 ${ip} {} 2>&1 | grep -qi 'open\|succeeded' && echo -e '    \033[0;32m⚡ Port {} OPEN\033[0m' >&2 && echo {}" \
        >> "$tmp_file" 2>/dev/null
        
    echo ""
    
    local ports
    ports=$(sort -un "$tmp_file" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    rm -f "$tmp_file"
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "nc" > "${result_dir}/scans/scan_method.txt"
        log_success "NC Full found: ${ports}"
        return 0
    fi
    
    log_warn "NC Full returned no results"
    return 1
}

# ── Chunked Parallel Nmap Scan ──
scan_nmap_chunked() {
    local ip="$1"
    local result_dir="$2"
    local chunks="${PORT_CHUNKS:-5}"
    local total=65535
    local chunk_size=$(( total / chunks ))
    local tmp_dir="${result_dir}/scans/.nmap_chunks"
    
    mkdir -p "$tmp_dir"
    
    local scan_flag="-sT"
    check_root && scan_flag="-sS"

    if is_quick_scan; then
        log_scan "Engine: Nmap quick (${scan_flag}, top ports)"
        local -a quick_cmd=(timeout "$SCAN_TIMEOUT" nmap "$scan_flag" -p "$TOP_PORTS" --min-rate 3000 -Pn --open
            -oG "${result_dir}/scans/.nmap_quick.gnmap" "$ip")
        log_command_preview "${quick_cmd[@]}"
        "${quick_cmd[@]}" 2>/dev/null
        local rc=$?

        if [[ $rc -eq 124 ]]; then
            rm -f "${result_dir}/scans/.nmap_quick.gnmap"
            log_warn "Nmap quick timed out"
            return 1
        fi

        local quick_ports=""
        quick_ports=$(grep -oP '\d+/open' "${result_dir}/scans/.nmap_quick.gnmap" 2>/dev/null | grep -oP '^\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
        rm -f "${result_dir}/scans/.nmap_quick.gnmap"

        if [[ -n "$quick_ports" ]]; then
            echo "$quick_ports" > "${result_dir}/scans/open_ports.txt"
            echo "nmap_quick" > "${result_dir}/scans/scan_method.txt"
            log_success "Nmap quick found: ${quick_ports}"
            return 0
        fi

        log_warn "Nmap quick returned no results"
        return 1
    fi
    
    log_scan "Engine: Nmap chunked parallel (${chunks} chunks, ${scan_flag})"
    echo ""
    
    local pids=()
    
    for ((i=0; i<chunks; i++)); do
        local start_port=$(( i * chunk_size + 1 ))
        local end_port=$(( (i + 1) * chunk_size ))
        [[ $i -eq $((chunks - 1)) ]] && end_port=$total
        
        (
            local -a chunk_cmd=(timeout "$SCAN_TIMEOUT" nmap "$scan_flag" -p "${start_port}-${end_port}" --min-rate 3000 -Pn --open
                -oG "${tmp_dir}/chunk_${i}.gnmap" "$ip")
            log_command_preview "${chunk_cmd[@]}"
            "${chunk_cmd[@]}" 2>/dev/null
        ) &
        pids+=($!)
        echo -e "  ${ICON_SCAN} Chunk $((i+1))/${chunks}: ports ${start_port}-${end_port} ${DIM}(PID: $!)${NC}"
    done
    
    echo ""
    log_info "Waiting for all ${chunks} nmap chunks..."
    
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    echo ""
    
    # Merge results
    local ports=""
    ports=$(cat "${tmp_dir}"/chunk_*.gnmap 2>/dev/null | grep -oP '\d+/open' | grep -oP '^\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
    rm -rf "$tmp_dir"
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "nmap_chunked" > "${result_dir}/scans/scan_method.txt"
        log_success "Nmap chunked found: ${ports}"
        return 0
    fi
    
    log_warn "Nmap chunked returned no results"
    return 1
}

# ── RustScan Engine ──
scan_rustscan() {
    local ip="$1"
    local result_dir="$2"
    
    if ! command -v rustscan &>/dev/null; then
        return 1
    fi
    
    log_scan "Engine: RustScan (timeout: ${SCAN_TIMEOUT}s)..."
    local output
    local -a rustscan_cmd=(timeout "$SCAN_TIMEOUT" rustscan -a "$ip" --ulimit 5000 -b 1500 -- -Pn)
    log_command_preview "${rustscan_cmd[@]}"
    output=$("${rustscan_cmd[@]}" 2>/dev/null)
    local rc=$?
    
    [[ $rc -eq 124 ]] && { log_warn "RustScan timed out"; return 1; }
    
    local ports
    ports=$(echo "$output" | grep -oP '\d+/open' | grep -oP '^\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
    [[ -z "$ports" ]] && ports=$(echo "$output" | grep -oP 'Open [\d.]+:\K\d+' | sort -un | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "rustscan" > "${result_dir}/scans/scan_method.txt"
        log_success "RustScan found: ${ports}"
        return 0
    fi
    
    log_warn "RustScan returned no results"
    return 1
}

# ── Naabu (ProjectDiscovery fast SYN/CONNECT scanner) ──
scan_naabu() {
    local ip="$1"
    local result_dir="$2"

    if ! command -v naabu &>/dev/null; then
        return 1
    fi

    log_scan "Engine: naabu (timeout: ${SCAN_TIMEOUT}s)..."
    local output
    # -p - = all ports when full scan; otherwise naabu's default top ports.
    local -a naabu_cmd=(timeout "$SCAN_TIMEOUT" naabu -host "$ip" -silent -no-color)
    is_quick_scan || naabu_cmd+=(-p -)
    log_command_preview "${naabu_cmd[@]}"
    output=$("${naabu_cmd[@]}" 2>/dev/null)
    local rc=$?

    [[ $rc -eq 124 ]] && { log_warn "naabu timed out"; return 1; }

    local ports
    ports=$(echo "$output" | grep -oP ':\K\d+' | sort -un | tr '\n' ',' | sed 's/,$//')

    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "naabu" > "${result_dir}/scans/scan_method.txt"
        log_success "naabu found: ${ports}"
        return 0
    fi

    log_warn "naabu returned no results"
    return 1
}

# ── Simple NC Scan (top ports only) ──
scan_nc_simple() {
    local ip="$1"
    local result_dir="$2"
    
    log_scan "Engine: NC quick (top ports, ${NC_PARALLEL} parallel)..."
    
    local tmp_file="${result_dir}/scans/.nc_tmp"
    
    # Expand TOP_PORTS into individual port numbers
    echo "$TOP_PORTS" | tr ',' '\n' | while read -r range; do
        if [[ "$range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            seq "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        else
            echo "$range"
        fi
    done | timeout "$SCAN_TIMEOUT" xargs -P"${NC_PARALLEL}" -I{} \
        sh -c "nc -znv -w1 ${ip} {} 2>&1 | grep -qi 'open\|succeeded' && echo {}" \
        > "$tmp_file" 2>/dev/null
    
    local ports
    ports=$(sort -un "$tmp_file" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    rm -f "$tmp_file"
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "nc" > "${result_dir}/scans/scan_method.txt"
        log_success "NC found: ${ports}"
        return 0
    fi
    
    log_warn "NC returned no results"
    return 1
}

# ── Simple Nmap (non-chunked) ──
scan_nmap_simple() {
    local ip="$1"
    local result_dir="$2"
    local nmap_timeout=$((SCAN_TIMEOUT * 2))
    
    local nmap_args="-p- --min-rate 3000 -Pn --open"
    check_root && nmap_args="-sS ${nmap_args} --min-rate 5000" || nmap_args="-sT ${nmap_args}"
    
    log_scan "Engine: Nmap single (timeout: ${nmap_timeout}s)..."
    
    local output
    local -a nmap_cmd
    read -r -a nmap_cmd <<< "$nmap_args"
    nmap_cmd=(timeout "$nmap_timeout" nmap "${nmap_cmd[@]}" "$ip")
    log_command_preview "${nmap_cmd[@]}"
    output=$("${nmap_cmd[@]}" 2>/dev/null)
    
    if [[ $? -eq 124 ]]; then
        log_warn "Nmap full scan timed out. Trying top 1000..."
        local top_args="--top-ports 1000 --min-rate 5000 -Pn --open"
        check_root && top_args="-sS ${top_args}" || top_args="-sT ${top_args}"
        local -a top_cmd
        read -r -a top_cmd <<< "$top_args"
        top_cmd=(timeout "$SCAN_TIMEOUT" nmap "${top_cmd[@]}" "$ip")
        log_command_preview "${top_cmd[@]}"
        output=$("${top_cmd[@]}" 2>/dev/null)
    fi
    
    local ports
    ports=$(echo "$output" | grep "^[0-9]" | grep "open" | cut -d'/' -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "nmap" > "${result_dir}/scans/scan_method.txt"
        log_success "Nmap found: ${ports}"
        return 0
    fi
    
    log_warn "Nmap returned no results"
    return 1
}


nmap_deep_scan() {
    local ip="$1"
    local result_dir="$2"
    local ports="$3"

    ports=$(normalize_ports_csv "$ports")
    [[ -z "$ports" ]] && return 1
    
    sub_header "Nmap Deep Scan (-sC -sV -A)"
    log_scan "Targeted scan on ports: ${ports}"

    rm -f "${result_dir}/scans/nmap_targeted.nmap" \
          "${result_dir}/scans/nmap_targeted.xml" \
          "${result_dir}/scans/nmap_targeted.gnmap"
    
    local -a deep_cmd=(timeout "$NMAP_DEEP_TIMEOUT" nmap -sC -sV -O -A
        -p "$ports"
        -Pn
        --open
        -oN "${result_dir}/scans/nmap_targeted.nmap"
        -oX "${result_dir}/scans/nmap_targeted.xml"
        -oG "${result_dir}/scans/nmap_targeted.gnmap"
        "$ip")
    log_command_preview "${deep_cmd[@]}"
    "${deep_cmd[@]}" 2>/dev/null
    local rc=$?

    if [[ $rc -eq 124 ]]; then
        log_warn "Deep scan timed out after ${NMAP_DEEP_TIMEOUT}s"
    fi

    if has_open_ports_in_nmap_file "${result_dir}/scans/nmap_targeted.nmap"; then
        log_success "Deep scan complete"
        echo ""
        
        # Display results table
        print_table_header
        grep "^[0-9]" "${result_dir}/scans/nmap_targeted.nmap" | grep "open" | while read -r line; do
            local port=$(echo "$line" | awk '{print $1}')
            local state=$(echo "$line" | awk '{print $2}')
            local svc=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^ *//')
            print_table_row "$port" "$state" "$svc"
        done
        echo ""
        
        # Show full nmap output
        echo -e "  ${DIM}── Full nmap output ──${NC}"
        cat "${result_dir}/scans/nmap_targeted.nmap"
        echo ""
        return 0
    fi
    
    log_error "Deep scan failed or timed out"
    return 1
}

# ── Masscan Engine (fastest for large scans) ──
scan_masscan() {
    local ip="$1"
    local result_dir="$2"
    local port_spec="1-65535"
    
    if ! command -v masscan &>/dev/null; then return 1; fi
    if ! check_root; then log_warn "masscan requires root"; return 1; fi

    is_quick_scan && port_spec="$TOP_PORTS"
    
    log_scan "Engine: Masscan (timeout: ${SCAN_TIMEOUT}s)..."
    
    local -a masscan_cmd=(timeout "$SCAN_TIMEOUT" masscan "$ip" "-p${port_spec}" --rate 1000
        -oL "${result_dir}/scans/.masscan_tmp")
    log_command_preview "${masscan_cmd[@]}"
    "${masscan_cmd[@]}" 2>/dev/null
    
    local ports
    ports=$(grep "^open" "${result_dir}/scans/.masscan_tmp" 2>/dev/null | awk '{print $3}' | sort -un | tr '\n' ',' | sed 's/,$//')
    rm -f "${result_dir}/scans/.masscan_tmp"
    
    if [[ -n "$ports" ]]; then
        echo "$ports" > "${result_dir}/scans/open_ports.txt"
        echo "masscan" > "${result_dir}/scans/scan_method.txt"
        log_success "Masscan found: ${ports}"
        return 0
    fi
    
    log_warn "Masscan returned no results"
    return 1
}

# ── UDP Scan (top ports - SNMP, TFTP, DNS, NFS, etc.) ──
scan_udp() {
    local ip="$1"
    local result_dir="$2"
    
    sub_header "UDP Scan (top 50 ports)"
    log_scan "nmap -sU --top-ports 50 (this takes a while)..."
    
    local -a udp_cmd=(timeout 300 nmap -sU --top-ports 50 --min-rate 500 -Pn --open
        -oN "${result_dir}/scans/udp_scan.nmap"
        -oG "${result_dir}/scans/udp_scan.gnmap"
        "$ip")
    log_command_preview "${udp_cmd[@]}"
    "${udp_cmd[@]}" 2>/dev/null
    
    if [[ -f "${result_dir}/scans/udp_scan.nmap" ]]; then
        local udp_ports
        udp_ports=$(grep "^[0-9]" "${result_dir}/scans/udp_scan.nmap" | grep "open" | grep -v "filtered" | cut -d'/' -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
        
        if [[ -n "$udp_ports" ]]; then
            echo "$udp_ports" > "${result_dir}/scans/udp_open_ports.txt"
            log_success "UDP open ports: ${udp_ports}"
            
            # Show UDP results
            grep "^[0-9]" "${result_dir}/scans/udp_scan.nmap" | grep "open" | grep -v "filtered" | while read -r line; do
                print_found "UDP: $line"
            done
        else
            log_info "No open UDP ports found"
        fi
    fi
}

hydrate_cached_port_results() {
    local result_dir="$1"
    local nmap_targeted="${result_dir}/scans/nmap_targeted.nmap"
    local open_ports_file="${result_dir}/scans/open_ports.txt"
    local scan_method_file="${result_dir}/scans/scan_method.txt"

    has_open_ports_in_nmap_file "$nmap_targeted" || return 1

    if [[ ! -s "$open_ports_file" ]]; then
        local cached_ports=""
        cached_ports=$(extract_open_ports_from_nmap_file "$nmap_targeted")
        if [[ -n "$cached_ports" ]]; then
            echo "$cached_ports" > "$open_ports_file"
        fi
    else
        local normalized_ports=""
        normalized_ports=$(normalize_ports_csv "$(cat "$open_ports_file" 2>/dev/null)")
        [[ -n "$normalized_ports" ]] && echo "$normalized_ports" > "$open_ports_file"
    fi

    [[ -s "$scan_method_file" ]] || echo "cached_nmap" > "$scan_method_file"
    [[ -s "$open_ports_file" ]]
}

# ── Main Port Scan Orchestrator ──
run_port_scan() {
    local ip="$1"
    local result_dir="$2"
    local nmap_targeted="${result_dir}/scans/nmap_targeted.nmap"
    local open_ports_file="${result_dir}/scans/open_ports.txt"
    local scan_method_file="${result_dir}/scans/scan_method.txt"
    local cached_ports=""
    local reuse_cached_ports=false
    
    if (( PORT_CHUNKS < 1 )); then
        log_warn "PORT_CHUNKS=${PORT_CHUNKS} is invalid. Resetting to 1."
        PORT_CHUNKS=1
    fi

    if [[ -s "$open_ports_file" ]]; then
        cached_ports=$(normalize_ports_csv "$(cat "$open_ports_file" 2>/dev/null)")
        if [[ -n "$cached_ports" ]]; then
            echo "$cached_ports" > "$open_ports_file"
        else
            rm -f "$open_ports_file"
        fi
    fi

    # Resume check
    if [[ -s "$nmap_targeted" ]]; then
        if ! hydrate_cached_port_results "$result_dir"; then
            if [[ -n "$cached_ports" ]]; then
                log_warn "Cached deep scan is incomplete. Re-running targeted nmap from cached ports."
                rm -f "$nmap_targeted" \
                      "${result_dir}/scans/nmap_targeted.xml" \
                      "${result_dir}/scans/nmap_targeted.gnmap"
                reuse_cached_ports=true
            else
                log_warn "Cached nmap results are incomplete. Re-running port scan."
            fi
        fi
    elif [[ -n "$cached_ports" ]]; then
        log_info "Open ports cache found without deep scan results. Re-running targeted nmap only."
        [[ -s "$scan_method_file" ]] || echo "cached_ports" > "$scan_method_file"
        reuse_cached_ports=true
    fi

    if [[ -s "$nmap_targeted" ]] && \
       [[ -s "$open_ports_file" ]] && \
       [[ -s "$scan_method_file" ]]; then
        if [[ "$INTERACTIVE" == "true" ]]; then
            log_info "Port scan results already exist. Skip? (y/n): "
            read -r skip
        else
            local skip="y"
        fi

        if [[ "$skip" == "y" || "$skip" == "Y" ]]; then
            log_info "Skipping port scan (using cached results)"
            return 0
        fi
    fi
    
    section_header "PHASE 1: PORT SCANNING"
    local start=$(timer_start)
    
    local success=1

    if [[ "$reuse_cached_ports" == "true" ]]; then
        success=0
    else
        case "$SCAN_METHOD" in
            rustscan)
                scan_rustscan "$ip" "$result_dir" && success=0 ;;
            naabu)
                scan_naabu "$ip" "$result_dir" && success=0 ;;
            masscan)
                scan_masscan "$ip" "$result_dir" && success=0 ;;
            nmap)
                scan_nmap_chunked "$ip" "$result_dir" && success=0 ;;
            nmap-single)
                scan_nmap_simple "$ip" "$result_dir" && success=0 ;;
            nc)
                scan_nc_full "$ip" "$result_dir" && success=0 ;;
            nc-quick)
                scan_nc_simple "$ip" "$result_dir" && success=0 ;;
            auto|*)
                if is_quick_scan; then
                    scan_masscan "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_nmap_chunked "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_nc_simple "$ip" "$result_dir" && success=0
                else
                    # Auto rotation: fastest to slowest
                    scan_rustscan "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_naabu "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_masscan "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_nmap_chunked "$ip" "$result_dir" && success=0
                    [[ $success -ne 0 ]] && scan_nc_full "$ip" "$result_dir" && success=0
                fi
                ;;
        esac
    fi
    
    if [[ $success -ne 0 ]]; then
        log_error "All scan engines failed. No open ports found."
        log_info "Time: $(timer_elapsed $start)"
        return 1
    fi
    
    # Run UDP scan in background WHILE deep scan runs (saves ~5 min)
    scan_udp "$ip" "$result_dir" &
    local udp_pid=$!
    echo -e "  ${DIM}→ UDP scan running in background (PID: ${udp_pid})${NC}"
    
    # Run deep nmap scan on found ports (foreground)
    local ports
    ports=$(normalize_ports_csv "$(cat "$open_ports_file" 2>/dev/null)")
    if [[ -z "$ports" ]]; then
        log_error "Port scan did not produce a usable port list."
        wait "$udp_pid" 2>/dev/null
        log_info "Time: $(timer_elapsed $start)"
        return 1
    fi
    echo "$ports" > "$open_ports_file"

    if ! has_open_ports_in_nmap_file "$nmap_targeted"; then
        nmap_deep_scan "$ip" "$result_dir" "$ports"
    else
        log_info "Using cached deep scan results"
    fi
    
    # Wait for UDP to finish
    if kill -0 "$udp_pid" 2>/dev/null; then
        log_info "Waiting for UDP scan to finish..."
        wait "$udp_pid" 2>/dev/null
    fi
    
    echo ""
    log_info "Scan method: $(cat "${result_dir}/scans/scan_method.txt" 2>/dev/null)"
    log_info "Time: $(timer_elapsed $start)"
    
    echo ""
    pause_if_interactive
    return 0
}
