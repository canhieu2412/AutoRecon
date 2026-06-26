#!/bin/bash
# ============================================================================
#
#     █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
#    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
#    ███████║██║   ██║   ██║   ██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
#    ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
#    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
#    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
#
#    Auto Recon - One-click reconnaissance framework
#    Author: Canhieu
#    Version: 3.7 - Interactive Menu Edition
#
# ============================================================================

set -o pipefail

# Get script directory (resolve symlinks so it can be run globally via /usr/local/bin)
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
MAIN_PID=$BASHPID
PHASE_LAST_ACTION=""

# ── Source all libraries ──
source "${SCRIPT_DIR}/lib/colors.sh"
source "${SCRIPT_DIR}/lib/logger.sh"
source "${SCRIPT_DIR}/lib/net.sh"
source "${SCRIPT_DIR}/lib/tools.sh"
source "${SCRIPT_DIR}/lib/tui.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/config/config.sh"
source "${SCRIPT_DIR}/config/tool_check.sh"

# ── Source all modules ──
source "${SCRIPT_DIR}/modules/00_host_discovery.sh"
source "${SCRIPT_DIR}/modules/01_port_scan.sh"
source "${SCRIPT_DIR}/modules/02_service_enum.sh"
source "${SCRIPT_DIR}/modules/03_web_recon.sh"
source "${SCRIPT_DIR}/modules/04_vuln_scan.sh"
source "${SCRIPT_DIR}/modules/05_brute_force.sh"
source "${SCRIPT_DIR}/modules/06_report.sh"
source "${SCRIPT_DIR}/modules/08_wordlist_toolkit.sh"
source "${SCRIPT_DIR}/modules/09_privesc.sh"
source "${SCRIPT_DIR}/modules/10_web_modern.sh"

# ── Cleanup trap (kill background processes on exit/Ctrl+C) ──
cleanup() {
    [[ $BASHPID -ne $MAIN_PID ]] && return 0
    local bg_pids=""
    local has_temp_artifacts=false
    bg_pids=$(jobs -p 2>/dev/null || true)

    if [[ -n "$RESULT_DIR" ]] && [[ \
        -d "${RESULT_DIR}/scans/.port_chunks" || \
        -d "${RESULT_DIR}/scans/.nmap_chunks" || \
        -f "${RESULT_DIR}/scans/.masscan_tmp" || \
        -f "${RESULT_DIR}/scans/.nc_tmp" \
    ]]; then
        has_temp_artifacts=true
    fi

    [[ -z "$bg_pids" && "$has_temp_artifacts" != "true" ]] && return 0

    echo ""
    echo -e "  ${YELLOW}Cleaning up background processes...${NC}"
    [[ -n "$bg_pids" ]] && printf '%s\n' "$bg_pids" | xargs -r kill 2>/dev/null
    [[ -n "$RESULT_DIR" ]] && rm -rf "${RESULT_DIR}/scans/.port_chunks" "${RESULT_DIR}/scans/.nmap_chunks" "${RESULT_DIR}/scans/.masscan_tmp" "${RESULT_DIR}/scans/.nc_tmp" 2>/dev/null
    echo -e "  ${DIM}Done.${NC}"
}
trap cleanup EXIT INT TERM

is_supported_scan_method() {
    case "$1" in
        auto|rustscan|naabu|masscan|nmap|nmap-single|nc|nc-quick)
            return 0
            ;;
    esac
    return 1
}

is_supported_engagement_profile() {
    case "$1" in
        balanced|offsec-lab|htb|thm|boot2root|custom)
            return 0
            ;;
    esac
    return 1
}

engagement_profile_label() {
    case "$1" in
        balanced) echo "Balanced" ;;
        offsec-lab) echo "OffSec Lab" ;;
        htb) echo "HTB" ;;
        thm) echo "THM" ;;
        boot2root) echo "Boot2Root" ;;
        custom) echo "Custom" ;;
        *) echo "$1" ;;
    esac
}

engagement_profile_hint() {
    case "$1" in
        balanced) echo "Safe defaults for mixed labs and day-to-day recon." ;;
        offsec-lab) echo "Exam/lab-safe posture for OffSec-style practice." ;;
        htb) echo "Aggressive deep recon for HTB single-target workflows." ;;
        thm) echo "Moderate depth for THM rooms and guided labs." ;;
        boot2root) echo "Most aggressive depth for standalone boot2root targets." ;;
        custom) echo "Manual tuning mode; your changes will be preserved." ;;
        *) echo "Unknown profile." ;;
    esac
}

mark_profile_custom() {
    ENGAGEMENT_PROFILE="custom"
}

apply_engagement_profile() {
    local profile="$1"
    [[ -z "$profile" ]] && profile="balanced"

    case "$profile" in
        balanced)
            SCAN_METHOD="auto"
            SCAN_MODE="normal"
            PORT_CHUNKS=8
            ENUM_MAX_JOBS=8
            RECURSION_DEPTH=4
            FUZZ_THREADS=75
            WEB_FUZZ_TOOL="auto"
            SCAN_TIMEOUT=120
            TOOL_TIMEOUT=420
            NMAP_DEEP_TIMEOUT=900
            AUTO_UPDATE_ETC_HOSTS=true
            AUTO_RESUME_PIPELINE=true
            PIPELINE_CONTINUE_ON_FAILURE=true
            SQLMAP_ALL_IN_ONE_TIMEOUT=300
            SQLMAP_OPERATOR_TIMEOUT=180
            SQLMAP_OPERATOR_MAX_TARGETS=8
            OFFSEC_OSCP_SAFE_MODE=false
            ;;
        offsec-lab)
            SCAN_METHOD="auto"
            SCAN_MODE="normal"
            PORT_CHUNKS=6
            ENUM_MAX_JOBS=6
            RECURSION_DEPTH=3
            FUZZ_THREADS=40
            WEB_FUZZ_TOOL="auto"
            SCAN_TIMEOUT=120
            TOOL_TIMEOUT=300
            NMAP_DEEP_TIMEOUT=900
            AUTO_UPDATE_ETC_HOSTS=true
            AUTO_RESUME_PIPELINE=true
            PIPELINE_CONTINUE_ON_FAILURE=true
            SQLMAP_ALL_IN_ONE_TIMEOUT=300
            SQLMAP_OPERATOR_TIMEOUT=180
            SQLMAP_OPERATOR_MAX_TARGETS=6
            OFFSEC_OSCP_SAFE_MODE=true
            ;;
        htb)
            SCAN_METHOD="auto"
            SCAN_MODE="normal"
            PORT_CHUNKS=8
            ENUM_MAX_JOBS=8
            RECURSION_DEPTH=5
            FUZZ_THREADS=80
            WEB_FUZZ_TOOL="auto"
            SCAN_TIMEOUT=150
            TOOL_TIMEOUT=480
            NMAP_DEEP_TIMEOUT=900
            AUTO_UPDATE_ETC_HOSTS=true
            AUTO_RESUME_PIPELINE=true
            PIPELINE_CONTINUE_ON_FAILURE=true
            SQLMAP_ALL_IN_ONE_TIMEOUT=420
            SQLMAP_OPERATOR_TIMEOUT=240
            SQLMAP_OPERATOR_MAX_TARGETS=10
            OFFSEC_OSCP_SAFE_MODE=false
            ;;
        thm)
            SCAN_METHOD="auto"
            SCAN_MODE="normal"
            PORT_CHUNKS=6
            ENUM_MAX_JOBS=6
            RECURSION_DEPTH=4
            FUZZ_THREADS=60
            WEB_FUZZ_TOOL="auto"
            SCAN_TIMEOUT=120
            TOOL_TIMEOUT=360
            NMAP_DEEP_TIMEOUT=900
            AUTO_UPDATE_ETC_HOSTS=true
            AUTO_RESUME_PIPELINE=true
            PIPELINE_CONTINUE_ON_FAILURE=true
            SQLMAP_ALL_IN_ONE_TIMEOUT=300
            SQLMAP_OPERATOR_TIMEOUT=180
            SQLMAP_OPERATOR_MAX_TARGETS=8
            OFFSEC_OSCP_SAFE_MODE=false
            ;;
        boot2root)
            SCAN_METHOD="auto"
            SCAN_MODE="full"
            PORT_CHUNKS=10
            ENUM_MAX_JOBS=10
            RECURSION_DEPTH=5
            FUZZ_THREADS=90
            WEB_FUZZ_TOOL="auto"
            SCAN_TIMEOUT=180
            TOOL_TIMEOUT=540
            NMAP_DEEP_TIMEOUT=1200
            AUTO_UPDATE_ETC_HOSTS=true
            AUTO_RESUME_PIPELINE=true
            PIPELINE_CONTINUE_ON_FAILURE=true
            SQLMAP_ALL_IN_ONE_TIMEOUT=480
            SQLMAP_OPERATOR_TIMEOUT=300
            SQLMAP_OPERATOR_MAX_TARGETS=12
            OFFSEC_OSCP_SAFE_MODE=false
            ;;
        custom)
            ENGAGEMENT_PROFILE="custom"
            return 0
            ;;
        *)
            return 1
            ;;
    esac

    ENGAGEMENT_PROFILE="$profile"
    return 0
}

print_usage() {
    cat <<EOF
Usage:
  ./auto_recon.sh [--profile PROFILE] [--offsec-safe|--no-offsec-safe] [--tui|--no-tui] [target]

Profiles:
  balanced     Mixed-lab defaults
  offsec-lab   OffSec-safe practice profile
  htb          Deeper HTB recon preset
  thm          Moderate THM preset
  boot2root    Most aggressive standalone preset
  custom       Keep manual tuning as-is

Interface:
  --tui        Force the gum-backed TUI (requires: sudo apt install gum)
  --no-tui     Force the classic text menu
               (default: auto — TUI when gum is installed and stdout is a TTY)
EOF
}

phase_state_file() {
    local phase="$1"
    local result_dir="$2"
    echo "${result_dir}/state/${phase}.env"
}

write_phase_state() {
    local phase="$1"
    local result_dir="$2"
    local status="$3"
    local started_at="${4:-}"
    local finished_at="${5:-}"
    local duration_seconds="${6:-0}"
    local detail="${7:-}"
    local state_file

    state_file=$(phase_state_file "$phase" "$result_dir")
    ensure_result_layout "$result_dir" || return 1

    {
        printf 'phase=%q\n' "$phase"
        printf 'status=%q\n' "$status"
        printf 'started_at=%q\n' "$started_at"
        printf 'finished_at=%q\n' "$finished_at"
        printf 'duration_seconds=%q\n' "$duration_seconds"
        printf 'detail=%q\n' "$detail"
    } > "$state_file"
}

phase_state_status() {
    local phase="$1"
    local result_dir="$2"
    read_metadata_value "$(phase_state_file "$phase" "$result_dir")" status 2>/dev/null
}

phase_requires_artifacts() {
    case "$1" in
        port_scan|service_enum|web_recon|vuln_scan|privesc|sqlmap_all_in_one|sqlmap_operator|wordlist_toolkit|report)
            return 0
            ;;
    esac
    return 1
}

phase_output_ready() {
    local phase="$1"
    local result_dir="$2"

    case "$phase" in
        port_scan)
            [[ -s "${result_dir}/scans/open_ports.txt" ]] && [[ -s "${result_dir}/scans/scan_method.txt" ]]
            ;;
        service_enum)
            [[ -s "${result_dir}/scans/nmap_targeted.nmap" ]] && [[ -f "${result_dir}/scans/web_ports.txt" ]]
            ;;
        web_recon)
            compgen -G "${result_dir}/web/fingerprint_*.txt" >/dev/null || \
            compgen -G "${result_dir}/web/feroxbuster_*.txt" >/dev/null || \
            compgen -G "${result_dir}/web/gobuster_d*.txt" >/dev/null || \
            compgen -G "${result_dir}/web/ffuf_*.json" >/dev/null || \
            compgen -G "${result_dir}/web/nikto_*.txt" >/dev/null || \
            [[ -s "${result_dir}/web/subdomain_web_targets.txt" ]] || \
            [[ -s "${result_dir}/web/discovered_hostnames.txt" ]]
            ;;
        vuln_scan)
            [[ -s "${result_dir}/vulns/summary.txt" ]]
            ;;
        privesc)
            [[ -s "${result_dir}/privesc/summary.txt" ]]
            ;;
        sqlmap_all_in_one)
            [[ -s "${result_dir}/vulns/sqlmap_all_in_one_summary.txt" ]]
            ;;
        sqlmap_operator)
            [[ -s "${result_dir}/vulns/sqlmap_operator_summary.txt" ]] && [[ -s "${result_dir}/vulns/sqlmap_operator_commands.txt" ]]
            ;;
        wordlist_toolkit)
            [[ -s "${result_dir}/wordlists/summary.txt" ]] || [[ -s "${result_dir}/wordlists/custom_all.txt" ]]
            ;;
        brute_force)
            [[ "$(phase_state_status "$phase" "$result_dir")" == "completed" ]]
            ;;
        report)
            [[ -s "${result_dir}/report.md" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

skip_phase_with_state() {
    local phase="$1"
    local title="$2"
    local result_dir="$3"
    local reason="$4"
    local now

    now=$(date '+%Y-%m-%d %H:%M:%S %Z')
    write_phase_state "$phase" "$result_dir" "skipped" "$now" "$now" 0 "$reason"
    log_info "Skipping ${title}: ${reason}"
    PHASE_LAST_ACTION="skipped"
}

run_phase_with_state() {
    local phase="$1"
    local title="$2"
    local _target="$3"
    local result_dir="$4"
    shift 4

    ensure_result_layout "$result_dir" || return 1

    if [[ "$AUTO_RESUME_PIPELINE" == "true" ]] && phase_output_ready "$phase" "$result_dir"; then
        skip_phase_with_state "$phase" "$title" "$result_dir" "existing output reused"
        PHASE_LAST_ACTION="reused"
        show_phase_digest "$phase" "$result_dir"
        tui_after_phase "$phase" "$result_dir"
        return 0
    fi

    local started_at finished_at start_epoch end_epoch duration rc status detail
    started_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
    start_epoch=$(date +%s)
    write_phase_state "$phase" "$result_dir" "running" "$started_at" "" 0 "in progress"

    "$@"
    rc=$?

    finished_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
    end_epoch=$(date +%s)
    duration=$((end_epoch - start_epoch))
    status="completed"
    detail="completed successfully"

    if (( rc != 0 )); then
        status="failed"
        detail="command returned ${rc}"
    elif phase_requires_artifacts "$phase" && ! phase_output_ready "$phase" "$result_dir"; then
        status="partial"
        detail="phase finished without expected artifacts"
    fi

    write_phase_state "$phase" "$result_dir" "$status" "$started_at" "$finished_at" "$duration" "$detail"
    PHASE_LAST_ACTION="executed"

    if [[ "$status" != "failed" ]]; then
        show_phase_digest "$phase" "$result_dir"
    fi

    if [[ "$status" == "failed" || "$status" == "partial" ]]; then
        log_warn "${title} ended with status: ${status}"
    fi

    tui_after_phase "$phase" "$result_dir"
    return "$rc"
}

show_phase_digest() {
    local phase="$1"
    local result_dir="$2"
    local summary_file=""

    echo ""
    echo -e "  ${BOLD}${CYAN}Result Digest: ${phase}${NC}"

    case "$phase" in
        port_scan)
            [[ -f "${result_dir}/scans/scan_method.txt" ]] && \
                echo -e "  ${DIM}Scan method: $(cat "${result_dir}/scans/scan_method.txt" 2>/dev/null)${NC}"
            [[ -f "${result_dir}/scans/open_ports.txt" ]] && \
                echo -e "  ${DIM}Open ports:${NC} $(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)"
            ;;
        service_enum)
            if [[ -f "${result_dir}/scans/nmap_targeted.nmap" ]]; then
                grep -E '^PORT[[:space:]]+STATE[[:space:]]+SERVICE|^[0-9]+/(tcp|udp)' "${result_dir}/scans/nmap_targeted.nmap" 2>/dev/null | head -n 20
            fi
            if [[ -f "${result_dir}/scans/web_ports.txt" ]] && [[ -s "${result_dir}/scans/web_ports.txt" ]]; then
                echo ""
                echo -e "  ${DIM}Web targets queued:${NC}"
                head -n 10 "${result_dir}/scans/web_ports.txt"
            fi
            ;;
        web_recon)
            if [[ -f "${result_dir}/web/subdomain_web_targets.txt" ]] && [[ -s "${result_dir}/web/subdomain_web_targets.txt" ]]; then
                echo -e "  ${DIM}Web inventory:${NC}"
                head -n 12 "${result_dir}/web/subdomain_web_targets.txt"
            elif [[ -f "${result_dir}/web/discovered_hostnames.txt" ]] && [[ -s "${result_dir}/web/discovered_hostnames.txt" ]]; then
                echo -e "  ${DIM}Discovered hostnames:${NC}"
                head -n 12 "${result_dir}/web/discovered_hostnames.txt"
            else
                echo -e "  ${DIM}No web digest artifacts yet.${NC}"
            fi
            ;;
        vuln_scan)
            summary_file="${result_dir}/vulns/summary.txt"
            [[ -f "$summary_file" ]] && head -n 60 "$summary_file"
            ;;
        privesc)
            summary_file="${result_dir}/privesc/summary.txt"
            [[ -f "$summary_file" ]] && head -n 40 "$summary_file"
            [[ -s "${result_dir}/privesc/cve_hints.txt" ]] && \
                grep -E '^[[:space:]]*\[' "${result_dir}/privesc/cve_hints.txt" 2>/dev/null | head -n 12
            ;;
        sqlmap_all_in_one)
            summary_file="${result_dir}/vulns/sqlmap_all_in_one_summary.txt"
            [[ -f "$summary_file" ]] && head -n 80 "$summary_file"
            ;;
        sqlmap_operator)
            summary_file="${result_dir}/vulns/sqlmap_operator_summary.txt"
            [[ -f "$summary_file" ]] && head -n 80 "$summary_file"
            ;;
        wordlist_toolkit)
            if declare -F wordlist_show_summary >/dev/null; then
                wordlist_show_summary "$result_dir"
            fi
            ;;
        brute_force)
            if declare -F operator_toolkit_refresh_credentials >/dev/null; then
                operator_toolkit_refresh_credentials "$result_dir"
            fi
            if declare -F operator_toolkit_show_summary >/dev/null; then
                operator_toolkit_show_summary "$result_dir"
            else
                local brute_hits
                brute_hits=$(grep -Rhc "login:" "${result_dir}/loot"/*_brute.txt 2>/dev/null | awk '{s+=$1} END {print s+0}')
                echo -e "  ${DIM}Credential hits recorded:${NC} ${brute_hits:-0}"
            fi
            ;;
        report)
            echo -e "  ${DIM}Report digest printed above. Markdown: ${result_dir}/report.md${NC}"
            ;;
        *)
            echo -e "  ${DIM}No terminal digest for this phase.${NC}"
            ;;
    esac

    echo ""
}

run_phase_explicit() {
    local previous_resume="$AUTO_RESUME_PIPELINE"
    AUTO_RESUME_PIPELINE=false
    run_phase_with_state "$@"
    local rc=$?
    AUTO_RESUME_PIPELINE="$previous_resume"
    return "$rc"
}

mark_phase_failed_with_state() {
    local phase="$1"
    local title="$2"
    local result_dir="$3"
    local detail="$4"
    local now

    now=$(date '+%Y-%m-%d %H:%M:%S %Z')
    write_phase_state "$phase" "$result_dir" "failed" "$now" "$now" 0 "$detail"
    log_error "${title} failed: ${detail}"
    PHASE_LAST_ACTION="failed"
}

prepare_sqlmap_target_inventory() {
    local result_dir="$1"
    local out_file="$2"
    local source_file="${result_dir}/vulns/param_targets.txt"

    ensure_result_layout "$result_dir" || return 1
    build_param_target_file "$result_dir" "$source_file"
    cp "$source_file" "$out_file" 2>/dev/null || : > "$out_file"
    dedup_file "$out_file"
    [[ -s "$out_file" ]]
}

sqlmap_all_in_one_level() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        htb) echo 2 ;;
        boot2root) echo 3 ;;
        *) echo 1 ;;
    esac
}

sqlmap_all_in_one_risk() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        htb|boot2root) echo 2 ;;
        *) echo 1 ;;
    esac
}

sqlmap_all_in_one_threads() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        htb) echo 5 ;;
        boot2root) echo 6 ;;
        *) echo 4 ;;
    esac
}

sqlmap_operator_level() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        htb) echo 3 ;;
        boot2root) echo 4 ;;
        *) echo 2 ;;
    esac
}

sqlmap_operator_risk() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        boot2root) echo 3 ;;
        *) echo 2 ;;
    esac
}

sqlmap_operator_threads() {
    case "${ENGAGEMENT_PROFILE:-balanced}" in
        htb) echo 4 ;;
        boot2root) echo 5 ;;
        *) echo 3 ;;
    esac
}

sqlmap_target_parameter_list() {
    local url="$1"
    local params=""

    params=$(echo "$url" | awk -F'?' 'NF > 1 { print $2 }' | tr '&' '\n' | cut -d'=' -f1 | awk 'NF && !seen[$0]++' | paste -sd, -)
    printf '%s\n' "$params"
}

sqlmap_target_slug() {
    local url="$1"
    local slug

    slug=$(sanitize_filename_component "$(echo "$url" | sed 's#^[A-Za-z0-9+.-]*://##')")
    [[ -z "$slug" ]] && slug="target"
    printf '%s\n' "${slug:0:80}"
}

run_sqlmap_all_in_one_workflow() {
    local ip="$1"
    local result_dir="$2"
    local start
    local targets_file="${result_dir}/vulns/sqlmap_all_in_one_targets.txt"
    local out_file="${result_dir}/vulns/sqlmap_all_in_one.txt"
    local summary_file="${result_dir}/vulns/sqlmap_all_in_one_summary.txt"
    local output_dir="${result_dir}/vulns/sqlmap_all_in_one_data"
    local target_count
    local level
    local risk
    local threads
    local sqlmap_rc=0
    local verified_count=0

    section_header "SQLMAP ALL-IN-ONE WORKFLOW"
    start=$(timer_start)
    ensure_result_layout "$result_dir" || return 1

    prepare_sqlmap_target_inventory "$result_dir" "$targets_file" || return 1
    mkdir -p "$output_dir"

    target_count=$(wc -l < "$targets_file" 2>/dev/null || echo 0)
    level=$(sqlmap_all_in_one_level)
    risk=$(sqlmap_all_in_one_risk)
    threads=$(sqlmap_all_in_one_threads)

    sub_header "SQLMap All-in-One"
    log_scan "Running SQLMap batch workflow on ${target_count} parameterized URL(s)..."

    local -a sqlmap_cmd=(timeout "${SQLMAP_ALL_IN_ONE_TIMEOUT:-300}" sqlmap
        -m "$targets_file"
        --batch
        --random-agent
        --smart
        --level "$level"
        --risk "$risk"
        --threads "$threads"
        --output-dir "$output_dir")
    log_command_preview "${sqlmap_cmd[@]}"
    "${sqlmap_cmd[@]}" > "$out_file" 2>/dev/null || sqlmap_rc=$?

    verified_count=$(grep -c "is vulnerable" "$out_file" 2>/dev/null || true)
    [[ -n "$verified_count" ]] || verified_count=0

    {
        echo "=== SQLMap All-in-One Summary ==="
        echo "Generated: $(date)"
        echo "Target: ${TARGET_DISPLAY:-$ip}"
        echo "Profile: $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")"
        echo "OffSec Safe Mode: $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "ON" || echo "OFF")"
        echo "Targets queued: ${target_count}"
        echo "Timeout: ${SQLMAP_ALL_IN_ONE_TIMEOUT:-300}s"
        echo "Level/Risk/Threads: ${level}/${risk}/${threads}"
        echo "Output Dir: ${output_dir}"
        echo "Verified findings: ${verified_count}"
        echo ""
        echo "Targets:"
        cat "$targets_file"
        if [[ $verified_count -gt 0 ]]; then
            echo ""
            echo "Verified injectable parameters:"
            grep -B 1 -A 5 "is vulnerable" "$out_file" 2>/dev/null
        fi
    } > "$summary_file"

    if [[ $sqlmap_rc -ne 0 ]]; then
        log_warn "SQLMap exited with status ${sqlmap_rc}; captured output may be partial."
    fi

    if [[ $verified_count -gt 0 ]]; then
        print_found "SQLMap All-in-One verified ${verified_count} injectable target(s)."
    else
        log_info "SQLMap All-in-One did not verify SQL injection."
    fi

    log_success "SQLMap All-in-One summary → ${summary_file}"
    log_info "Time: $(timer_elapsed "$start")"
    pause_if_interactive
}

run_sqlmap_operator_workflow() {
    local ip="$1"
    local result_dir="$2"
    local start
    local targets_file="${result_dir}/vulns/sqlmap_operator_targets.txt"
    local commands_file="${result_dir}/vulns/sqlmap_operator_commands.txt"
    local summary_file="${result_dir}/vulns/sqlmap_operator_summary.txt"
    local log_dir="${result_dir}/vulns/sqlmap_operator"
    local output_dir="${result_dir}/vulns/sqlmap_operator_data"
    local total_targets
    local limit
    local executed_targets=0
    local verified_targets=0
    local level
    local risk
    local threads
    local timeout_seconds
    local url=""

    section_header "SQLMAP OPERATOR WORKFLOW"
    start=$(timer_start)
    ensure_result_layout "$result_dir" || return 1

    prepare_sqlmap_target_inventory "$result_dir" "$targets_file" || return 1
    mkdir -p "$log_dir" "$output_dir"
    : > "$commands_file"

    total_targets=$(wc -l < "$targets_file" 2>/dev/null || echo 0)
    limit="${SQLMAP_OPERATOR_MAX_TARGETS:-8}"
    level=$(sqlmap_operator_level)
    risk=$(sqlmap_operator_risk)
    threads=$(sqlmap_operator_threads)
    timeout_seconds="${SQLMAP_OPERATOR_TIMEOUT:-180}"

    sub_header "SQLMap Operator"
    log_scan "Running operator workflow on up to ${limit} parameterized URL(s) out of ${total_targets}..."

    while IFS= read -r url; do
        local params
        local slug
        local out_file
        local sqlmap_rc=0
        local -a sqlmap_cmd

        [[ -z "$url" ]] && continue
        (( executed_targets >= limit )) && break

        executed_targets=$((executed_targets + 1))
        params=$(sqlmap_target_parameter_list "$url")
        slug=$(sqlmap_target_slug "$url")
        out_file=$(printf '%s/%02d_%s.txt' "$log_dir" "$executed_targets" "$slug")

        sqlmap_cmd=(timeout "$timeout_seconds" sqlmap
            -u "$url"
            --batch
            --random-agent
            --smart
            --level "$level"
            --risk "$risk"
            --threads "$threads"
            --output-dir "$output_dir")
        [[ -n "$params" ]] && sqlmap_cmd+=(-p "$params")

        printf '%s\n' "$(format_command_preview "${sqlmap_cmd[@]}")" >> "$commands_file"
        log_scan "Operator target ${executed_targets}/${limit}: ${url}"
        log_command_preview "${sqlmap_cmd[@]}"
        "${sqlmap_cmd[@]}" > "$out_file" 2>/dev/null || sqlmap_rc=$?

        if grep -qi "is vulnerable" "$out_file" 2>/dev/null; then
            verified_targets=$((verified_targets + 1))
            print_found "SQLMap operator verified injection on ${url}"
        fi

        if [[ $sqlmap_rc -ne 0 ]]; then
            log_warn "Operator run for ${url} exited with status ${sqlmap_rc}; log saved to $(basename "$out_file")."
        fi
    done < "$targets_file"

    {
        echo "=== SQLMap Operator Workflow Summary ==="
        echo "Generated: $(date)"
        echo "Target: ${TARGET_DISPLAY:-$ip}"
        echo "Profile: $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")"
        echo "OffSec Safe Mode: $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "ON" || echo "OFF")"
        echo "Targets discovered: ${total_targets}"
        echo "Targets executed: ${executed_targets}"
        echo "Execution limit: ${limit}"
        echo "Timeout per target: ${timeout_seconds}s"
        echo "Level/Risk/Threads: ${level}/${risk}/${threads}"
        echo "Commands File: ${commands_file}"
        echo "Per-target Logs: ${log_dir}"
        echo "Session Output Dir: ${output_dir}"
        echo "Verified findings: ${verified_targets}"
        if (( total_targets > executed_targets )); then
            echo "Deferred targets: $((total_targets - executed_targets))"
        fi
        echo ""
        echo "Executed Targets:"
        head -n "$executed_targets" "$targets_file"
        if (( verified_targets > 0 )); then
            echo ""
            echo "Verified injectable targets:"
            grep -H -i "is vulnerable" "${log_dir}/"*.txt 2>/dev/null | head -n "$executed_targets"
        fi
    } > "$summary_file"

    if [[ $verified_targets -gt 0 ]]; then
        print_found "SQLMap operator workflow verified ${verified_targets} injectable target(s)."
    else
        log_info "SQLMap operator workflow finished without verified SQL injection."
    fi

    log_success "SQLMap operator summary → ${summary_file}"
    log_info "Time: $(timer_elapsed "$start")"
    pause_if_interactive
}

can_run_sqlmap_workflow() {
    local phase="$1"
    local title="$2"
    local result_dir="$3"
    local precheck_file="${result_dir}/vulns/.${phase}_precheck_targets.txt"

    ensure_result_layout "$result_dir" || return 1

    if [[ "${OFFSEC_OSCP_SAFE_MODE:-false}" == "true" ]]; then
        skip_phase_with_state "$phase" "$title" "$result_dir" "OFFSEC_OSCP_SAFE_MODE=true"
        log_warn "${title} is disabled while OffSec-safe mode is ON."
        return 1
    fi

    if ! command -v sqlmap &>/dev/null; then
        mark_phase_failed_with_state "$phase" "$title" "$result_dir" "sqlmap command not available"
        return 1
    fi

    if ! prepare_sqlmap_target_inventory "$result_dir" "$precheck_file"; then
        rm -f "$precheck_file"
        skip_phase_with_state "$phase" "$title" "$result_dir" "no GET parameters discovered by web recon"
        log_warn "No parameter inventory found. Run Web Recon first and make sure params were discovered."
        return 1
    fi

    rm -f "$precheck_file"
    return 0
}

# ══════════════════════════════════════════════
# MENU SYSTEM
# ══════════════════════════════════════════════

draw_main_menu() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
     ___        __         ____                      
    /   | __  _/ /_____   / __ \___  _________  ____ 
   / /| |/ / / / __/ __ \ / /_/ / _ \/ ___/ __ \/ __ \
  / ___ / /_/ / /_/ /_/ // _, _/  __/ /__/ /_/ / / / /
 /_/  |_\__,_/\__/\____//_/ |_|\___/\___/\____/_/ /_/ 
EOF
    echo -e "        ${BOLD}Auto Recon v${APP_VERSION:-3.7}${NC}${CYAN}  |  Author: Canhieu"
    echo -e "        One-click recon for authorized labs, CTFs and pentest workflows"
    echo -e "${NC}"
    
    # Status bar
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [[ -n "$TARGET" ]]; then
        echo -e "  ${BOLD}Target:${NC}  ${GREEN}${TARGET_DISPLAY:-$TARGET}${NC}  ${DIM}(${TARGET_TYPE})${NC}"
        echo -e "  ${BOLD}Output:${NC}  ${DIM}${RESULT_DIR}${NC}"
        echo -e "  ${BOLD}Profile:${NC} ${DIM}$(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")${NC} | ${BOLD}OffSec-safe:${NC} $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}")"
        
        # Show scan status
        local status=""
        [[ -f "${RESULT_DIR}/scans/open_ports.txt" ]] && status+="${GREEN}●${NC} Ports "
        [[ -f "${RESULT_DIR}/scans/nmap_targeted.nmap" ]] && status+="${GREEN}●${NC} Services "
        [[ -d "${RESULT_DIR}/web" ]] && [[ $(ls "${RESULT_DIR}/web/"*.txt 2>/dev/null | wc -l) -gt 0 ]] && status+="${GREEN}●${NC} Web "
        [[ -f "${RESULT_DIR}/vulns/summary.txt" ]] && status+="${GREEN}●${NC} Vulns "
        [[ -f "${RESULT_DIR}/privesc/summary.txt" ]] && status+="${GREEN}●${NC} PrivEsc "
        [[ -f "${RESULT_DIR}/vulns/sqlmap_all_in_one_summary.txt" || -f "${RESULT_DIR}/vulns/sqlmap_operator_summary.txt" ]] && status+="${GREEN}●${NC} SQLi "
        [[ -f "${RESULT_DIR}/toolkit/credential_cache.tsv" || -f "${RESULT_DIR}/toolkit/sessions/generated_commands.txt" ]] && status+="${GREEN}●${NC} Toolkit "
        [[ -f "${RESULT_DIR}/wordlists/summary.txt" || -f "${RESULT_DIR}/wordlists/custom_all.txt" ]] && status+="${GREEN}●${NC} Words "
        [[ -f "${RESULT_DIR}/report.md" ]] && status+="${GREEN}●${NC} Report "
        [[ -n "$status" ]] && echo -e "  ${BOLD}Done:${NC}    ${status}"
    else
        echo -e "  ${YELLOW}⚠ No target set${NC}"
    fi
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Menu items
    echo -e "  ${BOLD}${WHITE}─── SCAN ─────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[1]${NC} 🚀 Full Auto Scan     ${DIM}(all phases, 1 click)${NC}"
    echo -e "  ${CYAN}[2]${NC} 🔌 Port Scan           ${DIM}(${SCAN_METHOD}, ${PORT_CHUNKS} chunks)${NC}"
    echo -e "  ${CYAN}[3]${NC} 🔧 Service Enumeration ${DIM}(auto-detect services)${NC}"
    echo -e "  ${CYAN}[4]${NC} 🌐 Web Recon           ${DIM}(fuzz depth: ${RECURSION_DEPTH})${NC}"
    echo -e "  ${CYAN}[5]${NC} ⚠️  Vulnerability Scan  ${DIM}(nmap + searchsploit)${NC}"
    echo -e "  ${CYAN}[p]${NC} 🪜 Priv-Esc Handoff    ${DIM}(CVE hints + linpeas/winpeas + GTFOBins)${NC}"
    echo -e "  ${CYAN}[6]${NC} 🔑 Brute / Toolkit     ${DIM}(hydra + operator toolkit, $([ "$AUTO_BRUTE" = true ] && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}"))${NC}"
    echo -e "  ${CYAN}[s]${NC} 🧪 SQLi Workflows      ${DIM}(SQLMap all-in-one + operator)${NC}"
    echo -e "  ${CYAN}[w]${NC} 🧬 Wordlist Toolkit    ${DIM}(CeWL + target seeds + crunch + rsmangler)${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}─── OUTPUT ───────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[7]${NC} 📄 Generate Report"
    echo -e "  ${CYAN}[8]${NC} 📂 View Results        ${DIM}(browse output files)${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}─── CONFIG ───────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[9]${NC} ⚙️  Settings"
    echo -e "  ${CYAN}[t]${NC} 🎯 Change Target"
    echo -e "  ${CYAN}[c]${NC} 🔍 Check Tools"
    echo ""
    echo -e "  ${CYAN}[0]${NC} ❌ Exit"
    echo ""
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "  ${BOLD}Choose [0-9/s/w/p/t/c]:${NC} "
}

# gum-backed main menu. Echoes a single choice token compatible with the
# existing dispatch case (1-9, p, s, w, t, c, 0).
tui_main_menu() {
    clear
    local subtitle="No target set"
    if [[ -n "$TARGET" ]]; then
        local done_marks=""
        [[ -f "${RESULT_DIR}/scans/open_ports.txt" ]] && done_marks+="ports "
        [[ -f "${RESULT_DIR}/scans/nmap_targeted.nmap" ]] && done_marks+="services "
        [[ -f "${RESULT_DIR}/vulns/summary.txt" ]] && done_marks+="vulns "
        [[ -f "${RESULT_DIR}/privesc/summary.txt" ]] && done_marks+="privesc "
        [[ -f "${RESULT_DIR}/report.md" ]] && done_marks+="report "
        subtitle="${TARGET_DISPLAY:-$TARGET} (${TARGET_TYPE}) | $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")${done_marks:+ | done: ${done_marks}}"
    fi
    tui_header "Auto Recon v${APP_VERSION:-4.0}" "$subtitle" >&2

    local sel
    sel=$(tui_choose "Choose an action" \
        "1  🚀 Full Auto Scan" \
        "2  🔌 Port Scan" \
        "3  🔧 Service Enumeration" \
        "4  🌐 Web Recon" \
        "5  ⚠️  Vulnerability Scan" \
        "p  🪜 Priv-Esc Handoff" \
        "6  🔑 Brute / Toolkit" \
        "s  🧪 SQLi Workflows" \
        "w  🧬 Wordlist Toolkit" \
        "7  📄 Generate Report" \
        "8  📂 View Results" \
        "9  ⚙️  Settings" \
        "t  🎯 Change Target" \
        "c  🔍 Check Tools" \
        "0  ❌ Exit")
    # Token = first whitespace-delimited field.
    printf '%s\n' "${sel%%[[:space:]]*}"
}

draw_settings_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ⚙️  SETTINGS"
    echo -e "${NC}"
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}[p]${NC} Profile:          ${BOLD}$(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")${NC}"
    echo -e "      ${DIM}balanced|offsec-lab|htb|thm|boot2root|custom${NC}"
    echo -e "      ${DIM}$(engagement_profile_hint "${ENGAGEMENT_PROFILE:-balanced}")${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} Scan Engine:      ${BOLD}${SCAN_METHOD}${NC}"
    echo -e "      ${DIM}auto|rustscan|masscan|nmap|nc${NC}"
    echo ""
    echo -e "  ${CYAN}[2]${NC} Scan Mode:        ${BOLD}${SCAN_MODE}${NC}"
    echo -e "      ${DIM}(quick=top1000 / normal / full=65535)${NC}"
    echo ""
    echo -e "  ${CYAN}[3]${NC} Port Chunks:      ${BOLD}${PORT_CHUNKS}${NC}"
    echo -e "      ${DIM}(split 65535 ports into N parallel jobs)${NC}"
    echo ""
    echo -e "  ${CYAN}[4]${NC} Fuzz Depth:       ${BOLD}${RECURSION_DEPTH}${NC}"
    echo -e "      ${DIM}(recursive web fuzzing levels)${NC}"
    echo ""
    echo -e "  ${CYAN}[5]${NC} Fuzz Threads:     ${BOLD}${FUZZ_THREADS}${NC}"
    echo ""
    echo -e "  ${CYAN}[a]${NC} Web Fuzz Tool:    ${BOLD}${WEB_FUZZ_TOOL}${NC}"
    echo -e "      ${DIM}auto|feroxbuster|gobuster|ffuf${NC}"
    echo ""
    echo -e "  ${CYAN}[6]${NC} Scan Timeout:     ${BOLD}${SCAN_TIMEOUT}s${NC}"
    echo -e "      ${DIM}(per-engine timeout before rotation)${NC}"
    echo ""
    echo -e "  ${CYAN}[7]${NC} Brute Force:      $([ "$AUTO_BRUTE" = true ] && echo "${GREEN}${BOLD}ON${NC}" || echo "${RED}${BOLD}OFF${NC}")"
    echo ""
    echo -e "  ${CYAN}[8]${NC} Wordlist:         ${BOLD}$(basename "${WORDLIST_WEB}" 2>/dev/null)${NC}"
    local wl_count=$(wc -l < "$WORDLIST_WEB" 2>/dev/null || echo "?")
    echo -e "      ${DIM}${wl_count} lines | quick=$(basename "$WORDLIST_WEB_SMALL") | full=$(basename "$WORDLIST_WEB_BIG")${NC}"
    echo ""
    echo -e "  ${CYAN}[9]${NC} Hosts Auto-Map:   $([ "$AUTO_UPDATE_ETC_HOSTS" = true ] && echo "${GREEN}${BOLD}ON${NC}" || echo "${RED}${BOLD}OFF${NC}")"
    echo -e "      ${DIM}(append discovered lab domains to /etc/hosts when root)${NC}"
    echo ""
    echo -e "  ${CYAN}[o]${NC} OffSec Safe Mode: $([ "$OFFSEC_OSCP_SAFE_MODE" = true ] && echo "${GREEN}${BOLD}ON${NC}" || echo "${RED}${BOLD}OFF${NC}")"
    echo -e "      ${DIM}(skip exam-risky vuln helpers such as sqlmap/nuclei/metasploit mapping)${NC}"
    echo ""
    echo -e "  ${CYAN}[0]${NC} ← Back"
    echo ""
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "  ${BOLD}Choose [0-9/a/p/o]:${NC} "
}

draw_sqli_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  🧪 SQLI WORKFLOWS"
    echo -e "${NC}"
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    if [[ -n "$TARGET" ]]; then
        echo -e "  ${BOLD}Target:${NC}  ${GREEN}${TARGET_DISPLAY:-$TARGET}${NC}"
        echo -e "  ${BOLD}Profile:${NC} ${DIM}$(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")${NC}"
        echo -e "  ${BOLD}OffSec-safe:${NC} $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}")"
    else
        echo -e "  ${YELLOW}⚠ No target set${NC}"
    fi
    echo ""
    echo -e "  ${CYAN}[1]${NC} SQLMap All-in-One"
    echo -e "      ${DIM}(batch run against discovered GET parameters; profile tunes level/risk/threads)${NC}"
    echo ""
    echo -e "  ${CYAN}[2]${NC} SQLMap Operator Workflow"
    echo -e "      ${DIM}(per-target runs + saved repro commands + session artifacts)${NC}"
    echo ""
    echo -e "  ${CYAN}[0]${NC} ← Back"
    echo ""
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -ne "  ${BOLD}Choose [0-2]:${NC} "
}

# ── Configure target context from IP / CIDR / file / domain ──
configure_target() {
    local input_target="$1"
    local silent="${2:-false}"
    local target_type

    input_target=$(trim_whitespace "$input_target")
    [[ -z "$input_target" ]] && return 1

    target_type=$(detect_target_type "$input_target")
    [[ "$target_type" == "unknown" ]] && return 1

    TARGET_INPUT="$input_target"
    TARGET="$input_target"
    TARGET_TYPE="$target_type"
    TARGET_DOMAIN=""
    TARGET_LABEL=""
    TARGET_DISPLAY="$input_target"

    if [[ "$target_type" == "domain" ]]; then
        [[ "$silent" != "true" ]] && echo -e "  ${DIM}Resolving domain ${TARGET}...${NC}"

        local resolved_ip
        resolved_ip=$(getent ahosts "$TARGET" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]' | head -1)
        [[ -z "$resolved_ip" ]] && resolved_ip=$(ping -c 1 "$TARGET" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)

        [[ -z "$resolved_ip" ]] && return 1

        TARGET_DOMAIN="$TARGET"
        TARGET="$resolved_ip"
        export TARGET_DOMAIN
        TARGET_DISPLAY="${TARGET_DOMAIN} (${TARGET})"
    fi

    local result_label
    result_label=$(get_result_label "$input_target" "$target_type" "$TARGET" "$TARGET_DOMAIN")
    TARGET_LABEL="$result_label"
    RESULT_DIR=$(setup_results_dir "$result_label" "$SCRIPT_DIR")
    ensure_result_layout "$RESULT_DIR"
    write_target_context "$RESULT_DIR" "$TARGET_INPUT" "$TARGET_TYPE" "$TARGET" "$TARGET_DOMAIN" "$TARGET_LABEL" "$TARGET_DISPLAY"
    init_logger "${RESULT_DIR}/auto_recon.log"
    return 0
}

# ── Set Target ──
set_target() {
    echo ""
    if tui_enabled; then
        input_target=$(tui_input "Enter target (IP / CIDR / file / domain)" "")
    else
        echo -ne "  ${BOLD}Enter target (IP / CIDR / file / domain):${NC} "
        read -r input_target
    fi

    if [[ -z "$input_target" ]]; then
        echo -e "  ${RED}No target entered.${NC}"
        sleep 1
        return 1
    fi
    
    if ! configure_target "$input_target"; then
        echo -e "  ${RED}Invalid target: ${input_target}${NC}"
        echo -e "  ${DIM}Expected: IP (10.10.10.1), CIDR (10.10.10.0/24), file path, or resolvable domain${NC}"
        sleep 2
        return 1
    fi
    
    if [[ -n "$TARGET_DOMAIN" ]]; then
        echo -e "  ${ICON_OK} Resolved to: ${GREEN}${TARGET}${NC}"
        echo -e "  ${ICON_OK} Target set: ${GREEN}${TARGET_DOMAIN}${NC} (${TARGET})"
    else
        echo -e "  ${ICON_OK} Target set: ${GREEN}${TARGET_DISPLAY:-$TARGET}${NC} (${TARGET_TYPE})"
    fi
    sleep 1
    return 0
}

# ── Check if target is set ──
require_target() {
    if [[ -z "$TARGET" ]]; then
        echo ""
        echo -e "  ${YELLOW}⚠ Set a target first!${NC}"
        echo ""
        set_target
        return $?
    fi
    return 0
}

# ── View Results Files ──
view_results() {
    if [[ -z "$RESULT_DIR" ]] || [[ ! -d "$RESULT_DIR" ]]; then
        echo -e "  ${YELLOW}No results yet. Run a scan first.${NC}"
        echo -e "  ${YELLOW}Press Enter...${NC}"
        read -r
        return
    fi
    
    while true; do
        clear
        echo -e "${BOLD}${CYAN}  📂 RESULTS: ${TARGET}${NC}"
        echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        local files=()
        local i=1
        
        while IFS= read -r file; do
            files+=("$file")
            local fname="${file#${RESULT_DIR}/}"
            local fsize=$(du -h "$file" 2>/dev/null | awk '{print $1}')
            echo -e "  ${CYAN}[${i}]${NC} ${fname} ${DIM}(${fsize})${NC}"
            i=$((i+1))
        done < <(find "$RESULT_DIR" -type f \( -name "*.txt" -o -name "*.nmap" -o -name "*.xml" -o -name "*.md" -o -name "*.html" -o -name "*.json" -o -name "*.log" \) 2>/dev/null | sort)
        
        if [[ ${#files[@]} -eq 0 ]]; then
            echo -e "  ${YELLOW}No output files yet.${NC}"
        fi
        
        echo ""
        echo -e "  ${CYAN}[0]${NC} ← Back"
        echo ""
        echo -ne "  ${BOLD}View file [number]:${NC} "
        read -r choice
        
        [[ "$choice" == "0" || -z "$choice" ]] && return
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#files[@]} )); then
            local selected="${files[$((choice-1))]}"
            clear
            echo -e "${BOLD}${CYAN}  📄 $(basename "$selected")${NC}"
            echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            cat "$selected"
            echo ""
            echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "  ${YELLOW}Press Enter to go back...${NC}"
            read -r
        fi
    done
}

# ── Settings Menu Handler ──
settings_menu() {
    while true; do
        draw_settings_menu
        read -r choice
        
        case "$choice" in
            p|P)
                echo -ne "  Profile (balanced/offsec-lab/htb/thm/boot2root/custom): "
                read -r val
                if [[ -n "$val" ]]; then
                    if apply_engagement_profile "$val"; then
                        echo -e "  ${ICON_OK} Profile applied: $(engagement_profile_label "$ENGAGEMENT_PROFILE")"
                    else
                        echo -e "  ${RED}Unsupported profile: ${val}${NC}"
                    fi
                    sleep 1
                fi
                ;;
            1)
                echo -ne "  Scan engine (auto/rustscan/masscan/nmap/nmap-single/nc/nc-quick): "
                read -r val
                if [[ -n "$val" ]]; then
                    if is_supported_scan_method "$val"; then
                        SCAN_METHOD="$val"
                        mark_profile_custom
                    else
                        echo -e "  ${RED}Unsupported scan engine: ${val}${NC}"
                        sleep 1
                    fi
                fi
                ;;
            2)
                echo -ne "  Scan mode (quick/normal/full): "
                read -r val
                case "$val" in
                    quick|normal|full)
                        SCAN_MODE="$val"
                        mark_profile_custom
                        ;;
                    "")
                        ;;
                    *)
                        echo -e "  ${RED}Invalid scan mode: ${val}${NC}"
                        sleep 1
                        ;;
                esac
                ;;
            3)
                echo -ne "  Port chunks (number of parallel jobs, e.g. 5, 10, 20): "
                read -r val
                if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 )); then
                    PORT_CHUNKS="$val"
                    mark_profile_custom
                elif [[ -n "$val" ]]; then
                    echo -e "  ${RED}Port chunks must be >= 1${NC}"
                    sleep 1
                fi
                ;;
            4)
                echo -ne "  Recursion depth (1-10): "
                read -r val
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    RECURSION_DEPTH="$val"
                    mark_profile_custom
                fi
                ;;
            5)
                echo -ne "  Fuzz threads (default 50): "
                read -r val
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    FUZZ_THREADS="$val"
                    mark_profile_custom
                fi
                ;;
            a|A)
                echo -ne "  Web fuzz tool (auto/feroxbuster/gobuster/ffuf): "
                read -r val
                if [[ -n "$val" ]]; then
                    if is_supported_web_fuzz_tool "$val"; then
                        WEB_FUZZ_TOOL="$val"
                        mark_profile_custom
                    else
                        echo -e "  ${RED}Unsupported web fuzz tool: ${val}${NC}"
                        sleep 1
                    fi
                fi
                ;;
            6)
                echo -ne "  Scan timeout in seconds (default 120): "
                read -r val
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    SCAN_TIMEOUT="$val"
                    mark_profile_custom
                fi
                ;;
            7)
                if [[ "$AUTO_BRUTE" == "true" ]]; then
                    AUTO_BRUTE=false
                    echo -e "  ${RED}Brute force: OFF${NC}"
                else
                    AUTO_BRUTE=true
                    echo -e "  ${GREEN}Brute force: ON${NC}"
                fi
                mark_profile_custom
                sleep 0.5
                ;;
            8)
                echo -ne "  Wordlist path (or 'builtin' / 'small' / 'medium' / 'big'): "
                read -r val
                case "$val" in
                    builtin)
                        WORDLIST_WEB="$BUILTIN_WORDLIST"
                        mark_profile_custom
                        echo -e "  ${ICON_OK} Using built-in wordlist (404 lines)" ;;
                    small)
                        WORDLIST_WEB="$WORDLIST_WEB_SMALL"
                        mark_profile_custom
                        echo -e "  ${ICON_OK} Using small: $(basename "$WORDLIST_WEB_SMALL")" ;;
                    medium)
                        WORDLIST_WEB="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
                        [[ ! -f "$WORDLIST_WEB" ]] && WORDLIST_WEB="/usr/share/dirb/wordlists/big.txt"
                        mark_profile_custom
                        echo -e "  ${ICON_OK} Using medium: $(basename "$WORDLIST_WEB")" ;;
                    big)
                        WORDLIST_WEB="$WORDLIST_WEB_BIG"
                        mark_profile_custom
                        echo -e "  ${ICON_OK} Using big: $(basename "$WORDLIST_WEB_BIG")" ;;
                    *)
                        if [[ -f "$val" ]]; then
                            WORDLIST_WEB="$val"
                            mark_profile_custom
                            echo -e "  ${ICON_OK} Wordlist: $val ($(wc -l < "$val") lines)"
                        else
                            echo -e "  ${RED}File not found${NC}"
                        fi ;;
                esac
                sleep 1
                ;;
            9)
                if [[ "$AUTO_UPDATE_ETC_HOSTS" == "true" ]]; then
                    AUTO_UPDATE_ETC_HOSTS=false
                    echo -e "  ${RED}Hosts auto-map: OFF${NC}"
                else
                    AUTO_UPDATE_ETC_HOSTS=true
                    echo -e "  ${GREEN}Hosts auto-map: ON${NC}"
                fi
                mark_profile_custom
                sleep 0.5
                ;;
            o|O)
                if [[ "$OFFSEC_OSCP_SAFE_MODE" == "true" ]]; then
                    OFFSEC_OSCP_SAFE_MODE=false
                    echo -e "  ${RED}OffSec safe mode: OFF${NC}"
                else
                    OFFSEC_OSCP_SAFE_MODE=true
                    echo -e "  ${GREEN}OffSec safe mode: ON${NC}"
                fi
                mark_profile_custom
                sleep 0.5
                ;;
            0|"")
                return ;;
        esac
    done
}

sqli_menu() {
    while true; do
        draw_sqli_menu
        read -r choice

        case "$choice" in
            1)
                require_target || continue
                clear
                if can_run_sqlmap_workflow "sqlmap_all_in_one" "SQLMap All-in-One" "$RESULT_DIR"; then
                    run_phase_explicit "sqlmap_all_in_one" "SQLMap All-in-One" "$TARGET" "$RESULT_DIR" run_sqlmap_all_in_one_workflow "$TARGET" "$RESULT_DIR"
                fi
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            2)
                require_target || continue
                clear
                if can_run_sqlmap_workflow "sqlmap_operator" "SQLMap Operator Workflow" "$RESULT_DIR"; then
                    run_phase_explicit "sqlmap_operator" "SQLMap Operator Workflow" "$TARGET" "$RESULT_DIR" run_sqlmap_operator_workflow "$TARGET" "$RESULT_DIR"
                fi
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            0|"")
                return
                ;;
            *)
                echo -e "  ${RED}Invalid option${NC}"
                sleep 0.5
                ;;
        esac
    done
}

# ── Full Auto Scan ──
run_full_auto() {
    require_target || return
    local previous_interactive="$INTERACTIVE"
    local previous_target_input="$TARGET_INPUT"
    local previous_target_domain="$TARGET_DOMAIN"
    local previous_target_label="$TARGET_LABEL"
    local previous_target_display="$TARGET_DISPLAY"
    local previous_live_tracker="${TUI_LIVE_TRACKER:-0}"
    INTERACTIVE=false
    TUI_LIVE_TRACKER=1
    
    clear
    echo -e "${BOLD}${GREEN}"
    echo "  ═══════════════════════════════════════════════"
    echo "   🚀 FULL AUTO SCAN: ${TARGET_DISPLAY:-$TARGET}"
    echo "  ═══════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "  ${DIM}Profile: $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}") | Engine: ${SCAN_METHOD} | Mode: ${SCAN_MODE} | Chunks: ${PORT_CHUNKS} | Depth: ${RECURSION_DEPTH}${NC}"
    echo ""
    
    local global_start=$(timer_start)
    
    # Phase 0: Host Discovery (for CIDR / target list)
    if [[ "$TARGET_TYPE" == "cidr" || "$TARGET_TYPE" == "file" ]]; then
        run_phase_with_state "host_discovery" "Host Discovery" "$TARGET" "$RESULT_DIR" run_host_discovery "$TARGET" "$RESULT_DIR" "$TARGET_TYPE"

        if [[ -f "${RESULT_DIR}/scans/alive_hosts.txt" ]]; then
            while read -r ip; do
                [[ -z "$ip" ]] && continue
                local ip_result_dir
                local ip_target_type="ip"
                local ip_result_label
                local ip_display="$ip"
                ip_target_type=$(detect_target_type "$ip")
                if [[ "$ip_target_type" == "domain" ]]; then
                    ip_result_label=$(sanitize_filename_component "$ip")
                    ip_display="$ip"
                else
                    ip_result_label=$(get_result_label "$ip" "$ip_target_type")
                fi
                ip_result_dir=$(setup_results_dir "$ip_result_label" "$SCRIPT_DIR")
                init_logger "${ip_result_dir}/auto_recon.log"
                TARGET_DOMAIN=""
                if [[ "$ip_target_type" == "domain" ]]; then
                    TARGET_DOMAIN="$ip"
                fi
                export TARGET_DOMAIN
                write_target_context "$ip_result_dir" "$ip" "$ip_target_type" "$ip" "$TARGET_DOMAIN" "$ip_result_label" "$ip_display"

                echo -e "\n${BOLD}${YELLOW}══════ Scanning: ${ip} ══════${NC}"
                _run_single_pipeline "$ip" "$ip_result_dir"
            done < "${RESULT_DIR}/scans/alive_hosts.txt"
        else
            log_warn "Host discovery produced no alive_hosts.txt entries"
        fi
    else
        _run_single_pipeline "$TARGET" "$RESULT_DIR"
    fi
    
    echo ""
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${ICON_OK} ${BOLD}FULL SCAN COMPLETE${NC}"
    echo -e "  ${DIM}Total time: $(timer_elapsed $global_start)${NC}"
    echo -e "  ${DIM}Results: ${RESULT_DIR}${NC}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    if [[ "$TARGET_TYPE" != "cidr" && "$TARGET_TYPE" != "file" ]]; then
        tui_pipeline_overview "$RESULT_DIR"
    fi
    TUI_LIVE_TRACKER="$previous_live_tracker"
    INTERACTIVE="$previous_interactive"
    TARGET_INPUT="$previous_target_input"
    TARGET_DOMAIN="$previous_target_domain"
    TARGET_LABEL="$previous_target_label"
    TARGET_DISPLAY="$previous_target_display"
    export TARGET_DOMAIN
    pause_if_interactive "Press Enter to return to menu..."
}

_run_single_pipeline() {
    local ip="$1"
    local result_dir="$2"

    ensure_result_layout "$result_dir" || return 1
    local reran_pipeline=false

    run_phase_with_state "port_scan" "Port Scan" "$ip" "$result_dir" run_port_scan "$ip" "$result_dir"
    [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true

    if ! phase_output_ready "port_scan" "$result_dir"; then
        log_error "No open ports found on ${ip}."
        return 1
    fi

    run_phase_with_state "service_enum" "Service Enumeration" "$ip" "$result_dir" run_service_enum "$ip" "$result_dir"
    [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true

    if ! phase_output_ready "service_enum" "$result_dir"; then
        if [[ "$PIPELINE_CONTINUE_ON_FAILURE" != "true" ]]; then
            return 1
        fi
        skip_phase_with_state "web_recon" "Web Reconnaissance" "$result_dir" "service enumeration did not produce reusable artifacts"
    elif [[ -s "${result_dir}/scans/web_ports.txt" ]]; then
        run_phase_with_state "web_recon" "Web Reconnaissance" "$ip" "$result_dir" run_web_recon "$ip" "$result_dir"
        [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true
    else
        skip_phase_with_state "web_recon" "Web Reconnaissance" "$result_dir" "no web services detected"
    fi

    if phase_output_ready "service_enum" "$result_dir"; then
        run_phase_with_state "wordlist_toolkit" "Wordlist Toolkit" "$ip" "$result_dir" run_wordlist_toolkit_auto "$ip" "$result_dir"
        [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true
    else
        skip_phase_with_state "wordlist_toolkit" "Wordlist Toolkit" "$result_dir" "service enumeration did not produce reusable artifacts"
    fi

    run_phase_with_state "vuln_scan" "Vulnerability Scan" "$ip" "$result_dir" run_vuln_scan "$ip" "$result_dir"
    [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true

    run_phase_with_state "privesc" "Privilege Escalation Handoff" "$ip" "$result_dir" run_privesc "$ip" "$result_dir"
    [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true

    if [[ "$AUTO_BRUTE" == "true" || "$AUTO_BRUTE" == "interactive" ]]; then
        run_phase_with_state "brute_force" "Brute Force" "$ip" "$result_dir" run_brute_force "$ip" "$result_dir"
        [[ "$PHASE_LAST_ACTION" == "executed" ]] && reran_pipeline=true
    else
        skip_phase_with_state "brute_force" "Brute Force" "$result_dir" "AUTO_BRUTE disabled"
    fi

    if [[ "$AUTO_RESUME_PIPELINE" == "true" && "$reran_pipeline" != "true" ]] && phase_output_ready "report" "$result_dir"; then
        skip_phase_with_state "report" "Report Generation" "$result_dir" "existing report is current for reused outputs"
    else
        run_phase_with_state "report" "Report Generation" "$ip" "$result_dir" run_report "$ip" "$result_dir"
    fi
}

# ══════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════

main() {
    ENGAGEMENT_PROFILE="${ENGAGEMENT_PROFILE:-balanced}"
    if ! apply_engagement_profile "$ENGAGEMENT_PROFILE"; then
        ENGAGEMENT_PROFILE="custom"
    fi

    local cli_target=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile)
                shift
                [[ -z "${1:-}" ]] && { echo "Missing value for --profile"; print_usage; return 1; }
                if ! apply_engagement_profile "$1"; then
                    echo "Unsupported profile: $1"
                    print_usage
                    return 1
                fi
                shift
                ;;
            --offsec-safe)
                OFFSEC_OSCP_SAFE_MODE=true
                [[ "${ENGAGEMENT_PROFILE}" != "custom" && "${ENGAGEMENT_PROFILE}" != "offsec-lab" ]] && ENGAGEMENT_PROFILE="custom"
                shift
                ;;
            --no-offsec-safe)
                OFFSEC_OSCP_SAFE_MODE=false
                [[ "${ENGAGEMENT_PROFILE}" == "offsec-lab" ]] && ENGAGEMENT_PROFILE="custom"
                shift
                ;;
            --tui)
                USE_TUI="on"
                shift
                ;;
            --no-tui)
                USE_TUI="off"
                shift
                ;;
            --help|-h)
                print_usage
                return 0
                ;;
            --)
                shift
                [[ $# -gt 0 ]] && cli_target="$1"
                break
                ;;
            -*)
                echo "Unknown option: $1"
                print_usage
                return 1
                ;;
            *)
                if [[ -n "$cli_target" ]]; then
                    echo "Only one positional target is supported."
                    print_usage
                    return 1
                fi
                cli_target="$1"
                shift
                ;;
        esac
    done

    # If target passed as argument, set it
    if [[ -n "$cli_target" ]]; then
        if ! configure_target "$cli_target" true; then
            TARGET=""
            TARGET_INPUT=""
            TARGET_TYPE=""
            TARGET_DOMAIN=""
            TARGET_LABEL=""
            TARGET_DISPLAY=""
            RESULT_DIR=""
        fi
    fi
    
    # Main menu loop
    while true; do
        if tui_enabled; then
            choice=$(tui_main_menu)
        else
            draw_main_menu
            read -r choice
        fi

        case "$choice" in
            1) run_full_auto ;;
            2)
                require_target || continue
                clear
                run_phase_explicit "port_scan" "Port Scan" "$TARGET" "$RESULT_DIR" run_port_scan "$TARGET" "$RESULT_DIR"
                ;;
            3)
                require_target || continue
                clear
                if [[ ! -f "${RESULT_DIR}/scans/nmap_targeted.nmap" ]]; then
                    echo -e "  ${YELLOW}⚠ Run Port Scan first (option 2)${NC}"
                    sleep 2
                    continue
                fi
                run_phase_explicit "service_enum" "Service Enumeration" "$TARGET" "$RESULT_DIR" run_service_enum "$TARGET" "$RESULT_DIR"
                ;;
            4)
                require_target || continue
                clear
                if [[ ! -f "${RESULT_DIR}/scans/web_ports.txt" ]] || [[ ! -s "${RESULT_DIR}/scans/web_ports.txt" ]]; then
                    echo -e "  ${YELLOW}⚠ Run Service Enumeration first (option 3) to detect web services${NC}"
                    sleep 2
                    continue
                fi
                run_phase_explicit "web_recon" "Web Reconnaissance" "$TARGET" "$RESULT_DIR" run_web_recon "$TARGET" "$RESULT_DIR"
                ;;
            5)
                require_target || continue
                clear
                if [[ ! -f "${RESULT_DIR}/scans/open_ports.txt" ]]; then
                    echo -e "  ${YELLOW}⚠ Run Port Scan first (option 2)${NC}"
                    sleep 2
                    continue
                fi
                run_phase_explicit "vuln_scan" "Vulnerability Scan" "$TARGET" "$RESULT_DIR" run_vuln_scan "$TARGET" "$RESULT_DIR"
                ;;
            p|P)
                require_target || continue
                clear
                if [[ ! -f "${RESULT_DIR}/scans/nmap_targeted.nmap" ]]; then
                    echo -e "  ${YELLOW}⚠ Run Service Enumeration first (option 3) for accurate CVE hints${NC}"
                    sleep 2
                fi
                run_phase_explicit "privesc" "Privilege Escalation Handoff" "$TARGET" "$RESULT_DIR" run_privesc "$TARGET" "$RESULT_DIR"
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            6)
                require_target || continue
                clear
                local previous_auto_brute="$AUTO_BRUTE"
                AUTO_BRUTE="interactive"
                run_phase_explicit "brute_force" "Brute Force" "$TARGET" "$RESULT_DIR" run_brute_force "$TARGET" "$RESULT_DIR"
                AUTO_BRUTE="$previous_auto_brute"
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            w|W)
                require_target || continue
                clear
                run_phase_explicit "wordlist_toolkit" "Wordlist Toolkit" "$TARGET" "$RESULT_DIR" run_wordlist_toolkit "$TARGET" "$RESULT_DIR"
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            7)
                require_target || continue
                clear
                run_phase_explicit "report" "Report Generation" "$TARGET" "$RESULT_DIR" run_report "$TARGET" "$RESULT_DIR"
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            s|S) sqli_menu ;;
            8) view_results ;;
            9) settings_menu ;;
            t|T) set_target ;;
            c|C)
                clear
                banner
                check_tools
                echo ""
                echo -e "  ${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
            0|q|Q)
                echo ""
                echo -e "  ${DIM}Goodbye!${NC}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "  ${RED}Invalid option${NC}"
                sleep 0.5
                ;;
        esac
    done
}

# Run
main "$@"
