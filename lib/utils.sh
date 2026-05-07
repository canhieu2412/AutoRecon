#!/bin/bash
# ============================================================================
# AUTO RECON - Utility Functions
# ============================================================================

# Validate IPv4 address
is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra octets <<< "$ip"
    for o in "${octets[@]}"; do
        (( o >= 0 && o <= 255 )) || return 1
    done
    return 0
}

# Validate CIDR notation
is_valid_cidr() {
    local cidr="$1"
    [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
    local ip="${cidr%/*}"
    local mask="${cidr#*/}"
    is_valid_ip "$ip" && (( mask >= 0 && mask <= 32 ))
}

# Validate domain name
is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]] && return 0
    return 1
}

is_supported_web_fuzz_tool() {
    case "$1" in
        auto|feroxbuster|gobuster|ffuf)
            return 0
            ;;
    esac
    return 1
}

trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}

# Check if input is IP, CIDR, file, or domain
detect_target_type() {
    local target="$1"
    if is_valid_ip "$target"; then
        echo "ip"
    elif is_valid_cidr "$target"; then
        echo "cidr"
    elif [[ -f "$target" ]]; then
        echo "file"
    elif is_valid_domain "$target"; then
        echo "domain"
    else
        echo "unknown"
    fi
}

# Parse open ports from rustscan output
parse_rustscan_ports() {
    grep -oP '\d+' | sort -un | tr '\n' ',' | sed 's/,$//'
}

# Parse open ports from nmap output  
parse_nmap_ports() {
    grep "^[0-9]" | grep "open" | cut -d'/' -f1 | sort -un | tr '\n' ',' | sed 's/,$//'
}

# Parse nmap service info: "port/proto service version"
parse_nmap_services() {
    local nmap_file="$1"
    grep "^[0-9]" "$nmap_file" | grep "open" | while read -r line; do
        local port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        local proto=$(echo "$line" | awk '{print $1}' | cut -d'/' -f2)
        local service=$(echo "$line" | awk '{print $3}')
        local version=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
        echo "${port}|${proto}|${service}|${version}"
    done
}

# Check if port is a web port
is_web_port() {
    local port="$1"
    local service="${2:-}"
    local web_ports="80 443 8080 8443 8000 8888 8008 9090 3000 5000 8081 8082 8181 9000 9443"
    for wp in $web_ports; do
        [[ "$port" == "$wp" ]] && return 0
    done
    # Also check service name
    [[ "$service" =~ http|https|web|tomcat|nginx|apache|iis ]] && return 0
    return 1
}

# Get protocol for web port
get_web_proto() {
    local port="$1"
    local service="${2:-}"
    if [[ "$port" == "443" || "$port" == "8443" || "$port" == "9443" ]] || [[ "$service" =~ ssl|https ]]; then
        echo "https"
    else
        echo "http"
    fi
}

# Create results directory structure
ensure_result_layout() {
    local result_dir="$1"
    [[ -z "$result_dir" ]] && return 1

    mkdir -p "${result_dir}/scans"
    mkdir -p "${result_dir}/web"
    mkdir -p "${result_dir}/vulns"
    mkdir -p "${result_dir}/loot"
    mkdir -p "${result_dir}/toolkit"
    mkdir -p "${result_dir}/wordlists"
    mkdir -p "${result_dir}/state"
}

setup_results_dir() {
    local target="$1"
    local base_dir="$2"
    local result_dir="${base_dir}/results/${target}"

    ensure_result_layout "$result_dir"

    echo "$result_dir"
}

sanitize_filename_component() {
    local value="$1"
    echo "$value" | sed 's/[^A-Za-z0-9._-]/_/g'
}

get_result_label() {
    local raw_target="$1"
    local target_type="$2"
    local resolved_target="${3:-}"
    local target_domain="${4:-}"

    case "$target_type" in
        cidr)
            sanitize_filename_component "network_${raw_target}"
            ;;
        file)
            sanitize_filename_component "targets_$(basename "$raw_target")"
            ;;
        domain)
            sanitize_filename_component "${target_domain}_${resolved_target}"
            ;;
        *)
            sanitize_filename_component "$raw_target"
            ;;
    esac
}

write_target_context() {
    local result_dir="$1"
    local input_target="$2"
    local target_type="$3"
    local resolved_target="$4"
    local target_domain="$5"
    local label="${6:-}"
    local display="${7:-}"
    local context_file="${result_dir}/state/target_context.env"

    ensure_result_layout "$result_dir" || return 1

    {
        printf 'configured_at=%q\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'input_target=%q\n' "$input_target"
        printf 'target_type=%q\n' "$target_type"
        printf 'resolved_target=%q\n' "$resolved_target"
        printf 'target_domain=%q\n' "$target_domain"
        printf 'target_label=%q\n' "$label"
        printf 'target_display=%q\n' "$display"
        printf 'result_dir=%q\n' "$result_dir"
    } > "$context_file"
}

read_metadata_value() {
    local file="$1"
    local key="$2"
    [[ -f "$file" ]] || return 1

    local current_key=""
    local raw_value=""
    while IFS='=' read -r current_key raw_value; do
        [[ "$current_key" == "$key" ]] || continue
        eval "printf '%s\n' ${raw_value}"
        return 0
    done < "$file"

    return 1
}

# Timer helpers
timer_start() { date +%s; }

timer_elapsed() {
    local start=$1
    local now=$(date +%s)
    local diff=$((now - start))
    printf "%dm %ds" $((diff/60)) $((diff%60))
}

# Dedup lines in file
dedup_file() {
    local file="$1"
    [[ -f "$file" ]] && sort -u "$file" -o "$file"
}

pause_if_interactive() {
    local message="${1:-Press Enter to continue...}"
    [[ "$INTERACTIVE" != "true" ]] && return 0
    echo -e "  ${YELLOW}${message}${NC}"
    read -r
}

throttle_jobs() {
    local max_jobs="${1:-1}"
    while (( $(jobs -rp | wc -l) >= max_jobs )); do
        wait -n 2>/dev/null || break
    done
}

# Check if running as root
check_root() {
    [[ $EUID -eq 0 ]] && return 0 || return 1
}

# Top 1000 common ports (nmap default)
TOP_PORTS="1,3,5,7,9,13,17,19,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
