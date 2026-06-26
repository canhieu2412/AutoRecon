#!/bin/bash
# ============================================================================
# AUTO RECON - Logging Framework
# ============================================================================

LOG_FILE=""

init_logger() {
    LOG_FILE="$1"
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== Auto Recon Log - $(date) ===" > "$LOG_FILE"
}

_log() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date '+%H:%M:%S')
    
    case "$level" in
        INFO)    echo -e "  ${ICON_INFO} ${msg}" ;;
        OK)      echo -e "  ${ICON_OK} ${GREEN}${msg}${NC}" ;;
        WARN)    echo -e "  ${ICON_WARN} ${YELLOW}${msg}${NC}" ;;
        ERROR)   echo -e "  ${ICON_FAIL} ${RED}${msg}${NC}" ;;
        SCAN)    echo -e "  ${ICON_SCAN} ${CYAN}${msg}${NC}" ;;
    esac
    
    [[ -n "$LOG_FILE" ]] && echo "[${timestamp}] [${level}] ${msg}" >> "$LOG_FILE"
}

log_info()    { _log "INFO" "$1"; }
log_success() { _log "OK" "$1"; }
log_warn()    { _log "WARN" "$1"; }
log_error()   { _log "ERROR" "$1"; }
log_scan()    { _log "SCAN" "$1"; }

format_command_preview() {
    local preview=""
    printf -v preview '%q ' "$@"
    echo "${preview% }"
}

log_command_preview() {
    local preview
    local timestamp
    preview=$(format_command_preview "$@")
    timestamp=$(date '+%H:%M:%S')
    echo -e "  ${DIM}Command: ${preview}${NC}"
    [[ -n "$LOG_FILE" ]] && echo "[${timestamp}] [CMD] ${preview}" >> "$LOG_FILE"
    # Collect every executed command into a copy-paste-ready PoC file per target
    # so it can be dropped straight into a report / exam write-up.
    if [[ -n "${RESULT_DIR:-}" && -d "${RESULT_DIR}" ]]; then
        local poc="${RESULT_DIR}/commands_poc.txt"
        # Skip exact consecutive duplicates to keep the PoC log tidy.
        if [[ "$(tail -n1 "$poc" 2>/dev/null)" != "$preview" ]]; then
            printf '%s\n' "$preview" >> "$poc"
        fi
    fi
    return 0
}

# Log command output to file only (no terminal noise)
log_cmd() {
    local label="$1"
    shift
    echo "[CMD] $label: $*" >> "$LOG_FILE" 2>&1
    "$@" >> "$LOG_FILE" 2>&1
    return $?
}

# Run a command with live output to terminal AND log
run_logged() {
    local label="$1"
    shift
    log_scan "Running: $label"
    "$@" 2>&1 | tee -a "$LOG_FILE"
    return ${PIPESTATUS[0]}
}
