#!/bin/bash
# ============================================================================
# AUTO RECON - Color & Display Library
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Icons
ICON_OK="[${GREEN}✔${NC}]"
ICON_FAIL="[${RED}✘${NC}]"
ICON_WARN="[${YELLOW}!${NC}]"
ICON_INFO="[${BLUE}ℹ${NC}]"
ICON_SCAN="[${CYAN}⟳${NC}]"
ICON_FOUND="[${GREEN}★${NC}]"

banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
     _         _          ____                      
    / \  _   _| |_ ___   |  _ \ ___  ___ ___  _ __  
   / _ \| | | | __/ _ \  | |_) / _ \/ __/ _ \| '_ \ 
  / ___ \ |_| | || (_) | |  _ <  __/ (_| (_) | | | |
 /_/   \_\__,_|\__\___/  |_| \_\___|\___\___/|_| |_|
                                            v1.0
EOF
    echo -e "${NC}"
    echo -e "${DIM}  One-click reconnaissance for OSCP / Boot2Root${NC}"
    echo -e "${DIM}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

section_header() {
    local title="$1"
    local icon="${2:-$ICON_SCAN}"
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${icon} ${BOLD}${WHITE}${title}${NC}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

sub_header() {
    local title="$1"
    echo -e "\n  ${BLUE}──── ${BOLD}${title}${NC} ${BLUE}────${NC}"
}

print_found() {
    echo -e "  ${ICON_FOUND} ${GREEN}$1${NC}"
}

print_status() {
    echo -e "  ${ICON_INFO} $1"
}

print_progress() {
    local current=$1
    local total=$2
    local label="${3:-Progress}"
    local pct=$((current * 100 / total))
    local filled=$((pct / 2))
    local empty=$((50 - filled))
    printf "\r  ${ICON_SCAN} ${label}: [${GREEN}"
    printf '█%.0s' $(seq 1 $filled 2>/dev/null)
    printf "${DIM}"
    printf '░%.0s' $(seq 1 $empty 2>/dev/null)
    printf "${NC}] ${BOLD}${pct}%%${NC} (${current}/${total})"
}

print_table_header() {
    printf "  ${BOLD}%-8s %-10s %-30s${NC}\n" "PORT" "STATE" "SERVICE"
    echo -e "  ${DIM}──────── ────────── ──────────────────────────────${NC}"
}

print_table_row() {
    local port="$1"
    local state="$2"
    local service="$3"
    if [[ "$state" == "open" ]]; then
        printf "  ${GREEN}%-8s${NC} ${GREEN}%-10s${NC} %-30s\n" "$port" "$state" "$service"
    else
        printf "  ${YELLOW}%-8s${NC} ${YELLOW}%-10s${NC} %-30s\n" "$port" "$state" "$service"
    fi
}

elapsed_time() {
    local start=$1
    local end=$(date +%s)
    local diff=$((end - start))
    local mins=$((diff / 60))
    local secs=$((diff % 60))
    echo "${mins}m ${secs}s"
}
