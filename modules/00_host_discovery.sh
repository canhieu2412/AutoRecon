#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 0: Host Discovery
# ============================================================================

run_host_discovery() {
    local target="$1"
    local result_dir="$2"
    local target_type="$3"
    
    section_header "PHASE 0: HOST DISCOVERY"
    local start=$(timer_start)
    
    # Single IP → just check if alive, skip sweep
    if [[ "$target_type" == "ip" ]]; then
        log_scan "Checking if ${target} is alive..."
        
        # Quick ping check
        if ping -c 1 -W 2 "$target" &>/dev/null; then
            log_success "Host ${target} is UP (ICMP reply)"
            echo "$target" > "${result_dir}/scans/alive_hosts.txt"
        else
            log_warn "No ICMP reply - host may block ping. Continuing anyway..."
            echo "$target" > "${result_dir}/scans/alive_hosts.txt"
        fi
        
        log_info "Time: $(timer_elapsed $start)"
        return 0
    fi
    
    # CIDR range → ping sweep
    if [[ "$target_type" == "cidr" ]]; then
        log_scan "Running ping sweep on ${target}..."
        
        # Method 1: nmap ping sweep
        log_info "nmap -sn ${target}"
        nmap -sn "$target" -oG "${result_dir}/scans/ping_sweep.gnmap" 2>/dev/null | \
            grep "Up" | awk '{print $2}' > "${result_dir}/scans/alive_hosts.txt"
        
        local count=$(wc -l < "${result_dir}/scans/alive_hosts.txt" 2>/dev/null || echo 0)
        
        if [[ $count -eq 0 ]]; then
            log_warn "No hosts found with ping sweep. Trying with -Pn..."
            nmap -Pn -sn "$target" 2>/dev/null | \
                grep "Nmap scan report" | awk '{print $NF}' | tr -d '()' > "${result_dir}/scans/alive_hosts.txt"
            count=$(wc -l < "${result_dir}/scans/alive_hosts.txt" 2>/dev/null || echo 0)
        fi
        
        log_success "Found ${count} alive host(s)"
        
        if [[ $count -gt 0 ]]; then
            while read -r ip; do
                print_found "$ip"
            done < "${result_dir}/scans/alive_hosts.txt"
        fi
        
        log_info "Time: $(timer_elapsed $start)"
        return 0
    fi
    
    # File with list of IPs
    if [[ "$target_type" == "file" ]]; then
        log_scan "Checking hosts from file: ${target}"
        > "${result_dir}/scans/alive_hosts.txt"
        
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if ping -c 1 -W 1 "$ip" &>/dev/null; then
                echo "$ip" >> "${result_dir}/scans/alive_hosts.txt"
                print_found "$ip - UP"
            else
                echo "$ip" >> "${result_dir}/scans/alive_hosts.txt"  # Add anyway
                log_warn "$ip - no ICMP reply (added anyway)"
            fi
        done < "$target"
        
        local count=$(wc -l < "${result_dir}/scans/alive_hosts.txt")
        log_success "Total: ${count} host(s)"
        log_info "Time: $(timer_elapsed $start)"
        return 0
    fi
}
