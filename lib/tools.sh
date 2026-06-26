#!/bin/bash
# ============================================================================
# AUTO RECON - Tool Registry & Execution Wrappers
# ----------------------------------------------------------------------------
# Single source of truth for which external tools the project knows about,
# how they group in the dependency report, and which fallbacks substitute for
# a missing "preferred" tool. Modules call have_tool / pick_tool / run_timed
# instead of re-implementing command -v + timeout + logging everywhere.
# ============================================================================

# ── Capability groups (ordered) ──────────────────────────────────────────
# Keep this list authoritative: config/tool_check.sh renders from it so the
# dependency report never drifts from what the modules actually use.
TOOL_GROUP_ORDER=(
    critical scan web_modern web enum windows linux vuln privesc brute wordlists other
)

declare -A TOOL_GROUPS=(
    [critical]="nmap nc curl"
    [scan]="rustscan masscan naabu nmap nc"
    [web_modern]="httpx-toolkit katana gowitness gospider hakrawler arjun dalfox"
    [web]="gobuster feroxbuster ffuf nikto whatweb wafw00f cewl node subfinder dnsx wpscan joomscan droopescan git-dumper"
    [enum]="enum4linux enum4linux-ng smbclient smbmap rpcclient netexec ldapsearch snmp-check dnsrecon dnsenum impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump"
    [windows]="evil-winrm xfreerdp certipy bloodhound-python responder impacket-smbclient impacket-psexec impacket-wmiexec impacket-atexec impacket-lookupsid impacket-mssqlclient"
    [linux]="ssh ssh-audit sshpass scp rsync sftp showmount rpcinfo mount.nfs redis-cli mysql psql"
    [vuln]="searchsploit nuclei sslscan sqlmap"
    [privesc]="curl wget python3"
    [brute]="hydra john hashcat"
    [wordlists]="cewl crunch rsmangler"
    [other]="wfuzz jq gum"
)

declare -A TOOL_GROUP_LABELS=(
    [critical]="Critical Tools"
    [scan]="Port Scanning"
    [web_modern]="Modern Web Recon (httpx/katana/...)"
    [web]="Web Recon"
    [enum]="Service Enum"
    [windows]="Windows Operator"
    [linux]="Linux Operator"
    [vuln]="Vuln Scanning"
    [privesc]="Privilege Escalation Handoff"
    [brute]="Brute Force & Cracking"
    [wordlists]="Wordlist Toolkit"
    [other]="Other Tools"
)

# Severity per group (only critical aborts).
declare -A TOOL_GROUP_SEVERITY=(
    [critical]="critical"
)

# ── Availability ──────────────────────────────────────────────────────────
have_tool() { command -v "$1" &>/dev/null; }

# Echo the first available tool from the arguments; return 1 if none exist.
# Records the choice so callers/reports can show what actually ran.
declare -A TOOL_SELECTION=()
pick_tool() {
    local capability="$1"; shift
    local candidate
    for candidate in "$@"; do
        if have_tool "$candidate"; then
            TOOL_SELECTION["$capability"]="$candidate"
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    TOOL_SELECTION["$capability"]="(none)"
    return 1
}

# ── Execution ─────────────────────────────────────────────────────────────
# Run a command with a timeout and a logged command preview. Returns the
# command's exit status (124 on timeout). Output goes to stdout/stderr as-is
# so callers can pipe/tee. Falls back to running without `timeout` if absent.
run_timed() {
    local seconds="$1"; shift
    if declare -F log_command_preview >/dev/null; then
        log_command_preview "$@"
    fi
    if have_tool timeout; then
        timeout "$seconds" "$@"
    else
        "$@"
    fi
}

# Like run_timed but silences stderr (common for noisy scanners).
run_timed_quiet() {
    local seconds="$1"; shift
    run_timed "$seconds" "$@" 2>/dev/null
}

# Append a human-readable note about which tool serviced a capability into
# the result dir, so the report can surface tool coverage/fallbacks used.
record_tool_choice() {
    local result_dir="$1" capability="$2" chosen="$3"
    [[ -z "$result_dir" ]] && return 0
    mkdir -p "${result_dir}/state" 2>/dev/null
    printf '%s=%s\n' "$capability" "$chosen" >> "${result_dir}/state/tool_choices.env"
}
