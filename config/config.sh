#!/bin/bash
# ============================================================================
# AUTO RECON - Configuration
# ============================================================================

# ── Metadata ──
APP_VERSION="5.0"

# ── Scan Settings ──
SCAN_METHOD="auto"          # auto | rustscan | naabu | masscan | nmap | nmap-single | nc | nc-quick
SCAN_MODE="normal"          # quick | normal | full
SCAN_TIMEOUT=120            # Seconds before switching to next scan engine
NC_PARALLEL=100             # Parallel nc connections
THREADS=50                  # Default threads for tools
PORT_CHUNKS=8               # Number of parallel chunks for port scanning
PARALLEL_MODE=true          # Run service enum & web recon jobs in parallel
ENUM_MAX_JOBS=8             # Max background enum jobs to avoid self-inflicted overload
INTERACTIVE=true            # Prompt between phases when running from the menu
USE_TUI="auto"              # auto | on | off — gum-backed TUI (falls back to classic menu)
WEB_DISCOVER_HOSTNAMES=true # Try to infer domains/vhosts from IP-based web targets
AUTO_UPDATE_ETC_HOSTS=true  # Append discovered lab hostnames to /etc/hosts when running as root
AUTO_RESUME_PIPELINE=true   # Reuse completed phase outputs during full auto runs
PIPELINE_CONTINUE_ON_FAILURE=true # Keep later phases running when a non-critical phase fails

# ── Tool Timeouts ──
TOOL_TIMEOUT=420            # Per-tool timeout (seconds)
NMAP_DEEP_TIMEOUT=900       # Nmap deep scan timeout

# ── Web Fuzzing ──
RECURSION_DEPTH=4           # Recursive fuzzing depth
FUZZ_THREADS=75             # Fuzzing threads
WEB_FUZZ_TOOL="auto"        # auto | feroxbuster | gobuster | ffuf
FUZZ_EXTENSIONS="php,html,txt,bak,old,conf,zip,tar.gz,asp,aspx,jsp,py,sh,xml,json,log,sql,db"

# ── Reporting ──
REPORT_PREVIEW_LINES=80     # Default preview lines for large artifacts in reports
REPORT_FINDING_LIMIT=100    # Cap per-artifact findings in markdown report
REPORT_FILE_INDEX_LIMIT=400 # Cap indexed files in the report appendix

# ── SQLi Workflows ──
SQLMAP_ALL_IN_ONE_TIMEOUT=300 # Timeout (seconds) for profile-aware batch SQLMap runs
SQLMAP_OPERATOR_TIMEOUT=180   # Timeout (seconds) per target in the operator workflow
SQLMAP_OPERATOR_MAX_TARGETS=8 # Max parameterized URLs executed per operator workflow run

# ── Engagement Profiles ──
ENGAGEMENT_PROFILE="balanced" # balanced | offsec-lab | htb | thm | boot2root | custom
OFFSEC_OSCP_SAFE_MODE=false # Skip exam-risky modules such as sqlmap/nuclei/metasploit mapping

# ── Execution mode ──
DRY_RUN=false               # true → print the command plan for every phase, execute nothing (--dry-run)

# ── Post-exploitation tooling (Phase D/E) ──
# Directories searched for local peas/pspy binaries to auto-stage into the serve dir.
POST_TOOLS_DIRS="/usr/share/peass /usr/share/peass-ng /opt/peass /opt/tools /usr/share/pspy ${HOME}/tools"

# ── Wordlists (prefer seclists → dirb → builtin fallback) ──
BUILTIN_WORDLIST="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/wordlists/builtin.txt"

# Small wordlist (~4K) for quick mode
if [[ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]]; then
    WORDLIST_WEB_SMALL="/usr/share/seclists/Discovery/Web-Content/common.txt"
elif [[ -f "/usr/share/dirb/wordlists/common.txt" ]]; then
    WORDLIST_WEB_SMALL="/usr/share/dirb/wordlists/common.txt"
else
    WORDLIST_WEB_SMALL="$BUILTIN_WORDLIST"
fi

# Medium wordlist (~220K) - DEFAULT for normal/full scan
if [[ -f "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" ]]; then
    WORDLIST_WEB="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
elif [[ -f "/usr/share/dirb/wordlists/big.txt" ]]; then
    WORDLIST_WEB="/usr/share/dirb/wordlists/big.txt"
else
    WORDLIST_WEB="$WORDLIST_WEB_SMALL"
fi

# Big wordlist (~1.2M) for full mode
if [[ -f "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt" ]]; then
    WORDLIST_WEB_BIG="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt"
else
    WORDLIST_WEB_BIG="$WORDLIST_WEB"
fi

# CMS-specific wordlists directory
CMS_WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content/CMS/trickest-cms-wordlist"

if [[ -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
    WORDLIST_DNS="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
elif [[ -f "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt" ]]; then
    WORDLIST_DNS="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
else
    WORDLIST_DNS=""
fi

if [[ -f "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" ]]; then
    WORDLIST_USERS="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
else
    WORDLIST_USERS=""
fi

if [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
    WORDLIST_PASS="/usr/share/wordlists/rockyou.txt"
elif [[ -f "/usr/share/seclists/Passwords/darkweb2017-top100.txt" ]]; then
    WORDLIST_PASS="/usr/share/seclists/Passwords/darkweb2017-top100.txt"
else
    WORDLIST_PASS=""
fi

# ── Brute Force ──
AUTO_BRUTE=false

# ── Active Directory password spraying ──
AD_SPRAY_MAX=40             # Số password tối đa khi spray tự động (giảm để tránh lockout)
# Wordlist fallback khi không tìm thấy list AD nào trên máy (sẽ tải + cache 1 lần):
AD_PASS_WORDLIST_URL="https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/Passwords.txt"

# ── Output ──
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_BASE="${BASE_DIR}/results"

# ── Target (set dynamically) ──
TARGET=""
TARGET_INPUT=""
TARGET_TYPE=""
TARGET_LABEL=""
TARGET_DISPLAY=""
RESULT_DIR=""

# ── Persisted user overrides (edited from the GUI Settings page or by hand) ──
# Sourced LAST so it wins over the defaults above. Applies to both the CLI and
# the web GUI. Safe to delete to fall back to defaults. gitignored.
_USER_CONFIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/user_config.sh"
[[ -f "$_USER_CONFIG" ]] && source "$_USER_CONFIG"
