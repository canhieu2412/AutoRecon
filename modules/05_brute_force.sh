#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 5: Brute Force (Optional/Interactive)
# ============================================================================

[[ -f "${SCRIPT_DIR}/modules/07_operator_toolkit.sh" ]] && source "${SCRIPT_DIR}/modules/07_operator_toolkit.sh"

BRUTE_USER_OPTS=()
BRUTE_PASS_OPTS=()
BRUTE_SELECTED_MODE=""
BRUTE_SELECTED_HOST=""
BRUTE_SELECTED_PORT=""
BRUTE_SELECTED_OUTFILE=""
BRUTE_SELECTED_WEB_SPEC=""
BRUTE_SELECTED_URL=""
BRUTE_WORKFLOW_MODE="brute-only"

set_brute_identity_option() {
    local kind="$1"
    local value="$2"

    if [[ "$kind" == "user" ]]; then
        if [[ -f "$value" ]]; then
            BRUTE_USER_OPTS=(-L "$value")
        else
            BRUTE_USER_OPTS=(-l "$value")
        fi
    else
        if [[ -f "$value" ]]; then
            BRUTE_PASS_OPTS=(-P "$value")
        else
            BRUTE_PASS_OPTS=(-p "$value")
        fi
    fi
}

init_brute_defaults() {
    BRUTE_USER_OPTS=()
    BRUTE_PASS_OPTS=()

    [[ -n "$WORDLIST_USERS" ]] && BRUTE_USER_OPTS=(-L "$WORDLIST_USERS")

    local default_pass="$WORDLIST_PASS"
    [[ -z "$default_pass" && -f "/usr/share/wordlists/rockyou.txt" ]] && default_pass="/usr/share/wordlists/rockyou.txt"
    [[ -n "$default_pass" ]] && BRUTE_PASS_OPTS=(-P "$default_pass")
}

validate_brute_inputs() {
    if [[ ${#BRUTE_USER_OPTS[@]} -eq 0 ]]; then
        log_warn "No username input configured."
        return 1
    fi

    if [[ ${#BRUTE_PASS_OPTS[@]} -eq 0 ]]; then
        log_warn "No password input configured."
        return 1
    fi

    if [[ "${BRUTE_USER_OPTS[0]}" == "-L" && ! -f "${BRUTE_USER_OPTS[1]}" ]]; then
        log_warn "User wordlist not found: ${BRUTE_USER_OPTS[1]}"
        return 1
    fi

    if [[ "${BRUTE_PASS_OPTS[0]}" == "-P" && ! -f "${BRUTE_PASS_OPTS[1]}" ]]; then
        log_warn "Password wordlist not found: ${BRUTE_PASS_OPTS[1]}"
        return 1
    fi

    return 0
}

service_ports_from_nmap() {
    local nmap_file="$1"
    local service_regex="$2"
    [[ ! -f "$nmap_file" ]] && return 0

    awk -v re="$service_regex" '
        /^[0-9]/ && $2 == "open" {
            svc=tolower($3)
            split($1, a, "/")
            if (svc ~ re) print a[1]
        }
    ' "$nmap_file" | sort -un | paste -sd, -
}

display_detected_service() {
    local label="$1"
    local ports="$2"
    if [[ -n "$ports" ]]; then
        echo "${label} ${DIM}(detected: ${ports})${NC}"
    else
        echo "${label} ${DIM}(not detected)${NC}"
    fi
}

choose_prompt_default() {
    local value="$1"
    local fallback="$2"
    [[ -n "$value" ]] && echo "$value" || echo "$fallback"
}

choose_service_port() {
    local label="$1"
    local detected_ports="$2"
    local fallback="$3"

    if [[ -n "$detected_ports" ]]; then
        IFS=',' read -r -a detected_array <<< "$detected_ports"

        if (( ${#detected_array[@]} == 1 )); then
            local only_port="${detected_array[0]}"
            echo -ne "  ${BOLD}${label} port [default: ${only_port}]:${NC} " >&2
            read -r port_input
            echo "${port_input:-$only_port}"
            return 0
        fi

        echo -e "  ${BOLD}${CYAN}  ${label} Port Selection${NC}" >&2
        local idx=1
        local port
        for port in "${detected_array[@]}"; do
            echo -e "  ${CYAN}[${idx}]${NC} ${port} ${DIM}(detected)${NC}" >&2
            idx=$((idx + 1))
        done
        echo -e "  ${CYAN}[0]${NC} Custom port" >&2
        echo -ne "  ${BOLD}Choose port [default: 1]:${NC} " >&2
        read -r port_choice

        if [[ -z "$port_choice" || "$port_choice" == "1" ]]; then
            echo "${detected_array[0]}"
        elif [[ "$port_choice" == "0" ]]; then
            echo -ne "  ${BOLD}Enter custom port [default: ${fallback}]:${NC} " >&2
            read -r custom_port
            echo "${custom_port:-$fallback}"
        elif [[ "$port_choice" =~ ^[0-9]+$ ]] && (( port_choice >= 1 && port_choice <= ${#detected_array[@]} )); then
            echo "${detected_array[$((port_choice - 1))]}"
        else
            echo "${detected_array[0]}"
        fi
        return 0
    fi

    echo -ne "  ${BOLD}${label} port [default: ${fallback}]:${NC} " >&2
    read -r port_input
    echo "${port_input:-$fallback}"
}

parse_url_components() {
    local url="$1"
    local proto=""
    local rest="$url"
    local host_port=""
    local host=""
    local port=""
    local path="/"

    if [[ "$url" == *"://"* ]]; then
        proto="${url%%://*}"
        rest="${url#*://}"
    fi

    host_port="${rest%%/*}"
    if [[ "$rest" != "$host_port" ]]; then
        path="/${rest#*/}"
    fi

    if [[ "$host_port" == *:* ]]; then
        host="${host_port%:*}"
        port="${host_port##*:}"
    else
        host="$host_port"
    fi

    echo "${proto}|${host}|${port}|${path}"
}

choose_web_target_url() {
    local result_dir="$1"
    local default_host="${2:-}"
    local -a urls=()
    local selected_url=""

    while read -r url; do
        [[ -n "$url" ]] && urls+=("$url")
    done < <(
        {
            [[ -f "${result_dir}/scans/web_ports.txt" ]] && cat "${result_dir}/scans/web_ports.txt"
            [[ -f "${result_dir}/web/subdomain_web_targets.txt" ]] && awk '{print $NF}' "${result_dir}/web/subdomain_web_targets.txt"
        } 2>/dev/null | awk 'NF' | sort -u
    )

    echo -e "  ${BOLD}${CYAN}  🌐 Web Target Selection${NC}"
    if [[ ${#urls[@]} -gt 0 ]]; then
        local idx=1
        local url
        for url in "${urls[@]}"; do
            echo -e "  ${CYAN}[${idx}]${NC} ${url}"
            idx=$((idx + 1))
        done
        echo -e "  ${CYAN}[0]${NC} Custom URL"
        echo -ne "  ${BOLD}Choose web target [default: 1]:${NC} "
        read -r url_choice

        if [[ -z "$url_choice" || "$url_choice" == "1" ]]; then
            selected_url="${urls[0]}"
        elif [[ "$url_choice" == "0" ]]; then
            echo -ne "  ${BOLD}Enter full URL:${NC} "
            read -r selected_url
        elif [[ "$url_choice" =~ ^[0-9]+$ ]] && (( url_choice >= 1 && url_choice <= ${#urls[@]} )); then
            selected_url="${urls[$((url_choice - 1))]}"
        fi
    fi

    if [[ -z "$selected_url" ]]; then
        local protocol_default="http"
        [[ -n "$default_host" ]] || default_host="${TARGET_DOMAIN:-$TARGET}"
        echo -ne "  ${BOLD}Protocol [http/https, default: ${protocol_default}]:${NC} "
        read -r custom_proto
        [[ -z "$custom_proto" ]] && custom_proto="$protocol_default"
        echo -ne "  ${BOLD}Host [default: ${default_host}]:${NC} "
        read -r custom_host
        [[ -z "$custom_host" ]] && custom_host="$default_host"
        echo -ne "  ${BOLD}Port [default: $([[ "$custom_proto" == "https" ]] && echo 443 || echo 80)]:${NC} "
        read -r custom_port
        [[ -z "$custom_port" ]] && custom_port="$([[ "$custom_proto" == "https" ]] && echo 443 || echo 80)"
        selected_url="${custom_proto}://${custom_host}:${custom_port}/"
    fi

    BRUTE_SELECTED_URL="$selected_url"
}

configure_web_form_target() {
    local ip="$1"
    local result_dir="$2"
    local default_host="${TARGET_DOMAIN:-$ip}"
    BRUTE_SELECTED_URL=""
    choose_web_target_url "$result_dir" "$default_host"
    local selected_url="$BRUTE_SELECTED_URL"
    [[ -z "$selected_url" ]] && return 1

    local parsed
    parsed=$(parse_url_components "$selected_url")
    local proto="${parsed%%|*}"
    local remainder="${parsed#*|}"
    local host="${remainder%%|*}"
    remainder="${remainder#*|}"
    local port="${remainder%%|*}"
    local path="${remainder#*|}"

    [[ -z "$proto" ]] && proto="http"
    [[ -z "$host" ]] && host="$default_host"
    [[ -z "$port" ]] && port="$([[ "$proto" == "https" ]] && echo 443 || echo 80)"
    [[ "$path" == "/" ]] && path="/login"

    echo -e "${BOLD}${YELLOW}  📝 Web Form Brute Force Configuration${NC}"
    echo -e "  ${DIM}Selected target: ${selected_url}${NC}"
    echo ""
    echo -e "  ${CYAN}[1]${NC} POST ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}[2]${NC} GET"
    echo -ne "  ${BOLD}Method [1/2, default: 1]:${NC} "
    read -r method_choice

    local method="post"
    [[ "$method_choice" == "2" ]] && method="get"

    local original_port="$port"
    echo -ne "  ${BOLD}Protocol [http/https, default: ${proto}]:${NC} "
    read -r input_proto
    [[ -n "$input_proto" ]] && proto="$input_proto"

    echo -ne "  ${BOLD}Host [default: ${host}]:${NC} "
    read -r input_host
    [[ -n "$input_host" ]] && host="$input_host"

    local default_port="$port"
    if [[ -n "$input_proto" ]]; then
        if [[ "$original_port" == "80" && "$proto" == "https" ]]; then
            default_port="443"
        elif [[ "$original_port" == "443" && "$proto" == "http" ]]; then
            default_port="80"
        fi
    fi
    [[ -z "$default_port" ]] && default_port="$([[ "$proto" == "https" ]] && echo 443 || echo 80)"
    echo -ne "  ${BOLD}Port [default: ${default_port}]:${NC} "
    read -r input_port
    [[ -n "$input_port" ]] && port="$input_port" || port="$default_port"

    echo -ne "  ${BOLD}Login path [default: ${path}]:${NC} "
    read -r input_path
    [[ -n "$input_path" ]] && path="$input_path"
    [[ "$path" != /* ]] && path="/${path}"

    local default_params="username=^USER^&password=^PASS^"
    echo -ne "  ${BOLD}Form parameters [default: ${default_params}]:${NC} "
    read -r form_params
    [[ -z "$form_params" ]] && form_params="$default_params"

    echo -e "  ${CYAN}[1]${NC} Failure string ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}[2]${NC} Success string"
    echo -ne "  ${BOLD}Matcher type [1/2, default: 1]:${NC} "
    read -r matcher_choice
    local matcher_prefix="F="
    [[ "$matcher_choice" == "2" ]] && matcher_prefix="S="

    echo -ne "  ${BOLD}Matcher text:${NC} "
    read -r matcher_text
    [[ -z "$matcher_text" ]] && {
        log_warn "Matcher text is required for web form brute force."
        return 1
    }

    echo -ne "  ${BOLD}Cookie string [optional]:${NC} "
    read -r cookie_string

    BRUTE_SELECTED_MODE="${proto}-${method}-form"
    BRUTE_SELECTED_HOST="$host"
    BRUTE_SELECTED_PORT="$port"
    BRUTE_SELECTED_OUTFILE="${result_dir}/loot/web_brute.txt"
    BRUTE_SELECTED_WEB_SPEC="${path}:${form_params}:${matcher_prefix}${matcher_text}"
    [[ -n "$cookie_string" ]] && BRUTE_SELECTED_WEB_SPEC="${BRUTE_SELECTED_WEB_SPEC}:C=${cookie_string}"
    return 0
}

choose_brute_target() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local ssh_ports=""
    local ftp_ports=""
    local smb_ports=""
    local mysql_ports=""
    local mssql_ports=""
    local rdp_ports=""
    local web_targets=0

    [[ -f "$nmap_file" ]] && {
        ssh_ports=$(service_ports_from_nmap "$nmap_file" '^(ssh)$')
        ftp_ports=$(service_ports_from_nmap "$nmap_file" '^(ftp)$')
        smb_ports=$(service_ports_from_nmap "$nmap_file" '^(microsoft-ds|netbios-ssn)$')
        mysql_ports=$(service_ports_from_nmap "$nmap_file" '^(mysql|mariadb)$')
        mssql_ports=$(service_ports_from_nmap "$nmap_file" '^(ms-sql.*|mssql)$')
        rdp_ports=$(service_ports_from_nmap "$nmap_file" '^(ms-wbt-server|rdp)$')
    }
    [[ -f "${result_dir}/scans/web_ports.txt" ]] && web_targets=$(wc -l < "${result_dir}/scans/web_ports.txt" 2>/dev/null || echo 0)

    echo -e "${BOLD}${CYAN}  🎯 Brute Force Target Selection${NC}"
    echo -e "  ${CYAN}[1]${NC} Auto-detect common services"
    echo -e "  ${CYAN}[2]${NC} $(display_detected_service "SSH" "$ssh_ports")"
    echo -e "  ${CYAN}[3]${NC} $(display_detected_service "FTP" "$ftp_ports")"
    echo -e "  ${CYAN}[4]${NC} $(display_detected_service "SMB" "$smb_ports")"
    echo -e "  ${CYAN}[5]${NC} $(display_detected_service "MySQL / MariaDB" "$mysql_ports")"
    echo -e "  ${CYAN}[6]${NC} $(display_detected_service "MSSQL" "$mssql_ports")"
    echo -e "  ${CYAN}[7]${NC} $(display_detected_service "RDP" "$rdp_ports")"
    echo -e "  ${CYAN}[8]${NC} Web Login Form ${DIM}(${web_targets} detected web target(s))${NC}"
    echo -e "  ${CYAN}[9]${NC} Custom Hydra Module"
    echo -e "  ${CYAN}[0]${NC} Cancel"
    echo -ne "  ${BOLD}Choose [0-9, default: 1]:${NC} "
    read -r choice

    BRUTE_SELECTED_MODE="auto"
    BRUTE_SELECTED_HOST="$ip"
    BRUTE_SELECTED_PORT=""
    BRUTE_SELECTED_OUTFILE=""
    BRUTE_SELECTED_WEB_SPEC=""

    case "$choice" in
        0|q|Q)
            return 1
            ;;
        2)
            BRUTE_SELECTED_MODE="ssh"
            BRUTE_SELECTED_PORT="$(choose_service_port "SSH" "$ssh_ports" "22")"
            ;;
        3)
            BRUTE_SELECTED_MODE="ftp"
            BRUTE_SELECTED_PORT="$(choose_service_port "FTP" "$ftp_ports" "21")"
            ;;
        4)
            BRUTE_SELECTED_MODE="smb"
            BRUTE_SELECTED_PORT="$(choose_service_port "SMB" "$smb_ports" "445")"
            ;;
        5)
            BRUTE_SELECTED_MODE="mysql"
            BRUTE_SELECTED_PORT="$(choose_service_port "MySQL / MariaDB" "$mysql_ports" "3306")"
            ;;
        6)
            BRUTE_SELECTED_MODE="mssql"
            BRUTE_SELECTED_PORT="$(choose_service_port "MSSQL" "$mssql_ports" "1433")"
            ;;
        7)
            BRUTE_SELECTED_MODE="rdp"
            BRUTE_SELECTED_PORT="$(choose_service_port "RDP" "$rdp_ports" "3389")"
            ;;
        8)
            configure_web_form_target "$ip" "$result_dir" || return 1
            ;;
        9)
            echo -ne "  ${BOLD}Hydra module name:${NC} "
            read -r custom_module
            [[ -z "$custom_module" ]] && return 1
            BRUTE_SELECTED_MODE="$custom_module"
            echo -ne "  ${BOLD}Host [default: ${ip}]:${NC} "
            read -r custom_host
            [[ -n "$custom_host" ]] && BRUTE_SELECTED_HOST="$custom_host"
            echo -ne "  ${BOLD}Port [optional]:${NC} "
            read -r custom_port
            BRUTE_SELECTED_PORT="$custom_port"
            BRUTE_SELECTED_OUTFILE="${result_dir}/loot/$(sanitize_filename_component "${custom_module}")_brute.txt"
            ;;
        1|"")
            ;;
        *)
            log_warn "Invalid selection"
            return 1
            ;;
    esac

    if [[ "$BRUTE_SELECTED_MODE" != "auto" && "$BRUTE_SELECTED_MODE" != *"-form" ]]; then
        BRUTE_SELECTED_OUTFILE="${result_dir}/loot/$(sanitize_filename_component "${BRUTE_SELECTED_MODE}")_brute.txt"
    fi

    return 0
}

choose_brute_workflow() {
    echo -e "${BOLD}${CYAN}  🧰 Phase 5 Workflow${NC}"
    echo -e "  ${CYAN}[1]${NC} Brute force only"
    echo -e "  ${CYAN}[2]${NC} Operator toolkit only ${DIM}(build reviewed commands, no execution)${NC}"
    echo -e "  ${CYAN}[3]${NC} Brute force, then operator toolkit"
    echo -e "  ${CYAN}[0]${NC} Cancel"
    echo -ne "  ${BOLD}Choose [0-3, default: 1]:${NC} "
    read -r workflow_choice

    case "$workflow_choice" in
        0|q|Q)
            return 1
            ;;
        2)
            BRUTE_WORKFLOW_MODE="toolkit-only"
            ;;
        3)
            BRUTE_WORKFLOW_MODE="brute-then-toolkit"
            ;;
        1|"")
            BRUTE_WORKFLOW_MODE="brute-only"
            ;;
        *)
            log_warn "Invalid selection"
            return 1
            ;;
    esac

    return 0
}

format_command_preview() {
    local preview=""
    printf -v preview '%q ' "$@"
    echo "${preview% }"
}

run_hydra_service() {
    local label="$1"
    local timeout_sec="$2"
    local host="$3"
    local port="$4"
    local module="$5"
    local out_file="$6"

    local -a cmd=(hydra "${BRUTE_USER_OPTS[@]}" "${BRUTE_PASS_OPTS[@]}")
    [[ -n "$port" ]] && cmd+=(-s "$port")
    cmd+=(-t 4 -f "$host" "$module" -o "$out_file")

    sub_header "${label}"
    log_scan "hydra ${module} brute force..."
    echo -e "  ${DIM}Command: $(format_command_preview "${cmd[@]}")${NC}"

    timeout "$timeout_sec" "${cmd[@]}" >/dev/null 2>&1

    if grep -q "login:" "$out_file" 2>/dev/null; then
        print_found "${label} credentials found!"
        cat "$out_file"
    fi
}

run_hydra_web_form() {
    local out_file="$1"
    local -a cmd=(hydra "${BRUTE_USER_OPTS[@]}" "${BRUTE_PASS_OPTS[@]}")
    [[ -n "$BRUTE_SELECTED_PORT" ]] && cmd+=(-s "$BRUTE_SELECTED_PORT")
    cmd+=(-t 4 -f "$BRUTE_SELECTED_HOST" "$BRUTE_SELECTED_MODE" "$BRUTE_SELECTED_WEB_SPEC" -o "$out_file")

    sub_header "Brute: Web Form (${BRUTE_SELECTED_HOST}:${BRUTE_SELECTED_PORT})"
    log_scan "hydra ${BRUTE_SELECTED_MODE} brute force..."
    echo -e "  ${DIM}Command: $(format_command_preview "${cmd[@]}")${NC}"

    timeout 600 "${cmd[@]}" >/dev/null 2>&1

    if grep -q "login:" "$out_file" 2>/dev/null; then
        print_found "Web credentials found!"
        cat "$out_file"
    fi
}

run_auto_bruteforce() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    [[ ! -f "$nmap_file" ]] && {
        log_warn "No nmap results found for auto brute force."
        return 1
    }

    while read -r line; do
        local port
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        local service
        service=$(echo "$line" | awk '{print $3}' | tr '[:upper:]' '[:lower:]')

        case "$service" in
            ssh)
                run_hydra_service "Brute: SSH (${ip}:${port})" 300 "$ip" "$port" "ssh" "${result_dir}/loot/ssh_${port}_brute.txt"
                ;;
            ftp)
                run_hydra_service "Brute: FTP (${ip}:${port})" 300 "$ip" "$port" "ftp" "${result_dir}/loot/ftp_${port}_brute.txt"
                ;;
            mysql|mariadb)
                run_hydra_service "Brute: MySQL (${ip}:${port})" 300 "$ip" "$port" "mysql" "${result_dir}/loot/mysql_${port}_brute.txt"
                ;;
            microsoft-ds|netbios-ssn)
                run_hydra_service "Brute: SMB (${ip}:${port})" 300 "$ip" "$port" "smb" "${result_dir}/loot/smb_${port}_brute.txt"
                ;;
            ms-sql*|mssql)
                run_hydra_service "Brute: MSSQL (${ip}:${port})" 300 "$ip" "$port" "mssql" "${result_dir}/loot/mssql_${port}_brute.txt"
                ;;
            ms-wbt-server|rdp)
                run_hydra_service "Brute: RDP (${ip}:${port})" 300 "$ip" "$port" "rdp" "${result_dir}/loot/rdp_${port}_brute.txt"
                ;;
        esac
    done < <(grep "^[0-9]" "$nmap_file" | grep "open")
}

run_brute_force() {
    local ip="$1"
    local result_dir="$2"
    
    if [[ "$AUTO_BRUTE" != "true" && "$AUTO_BRUTE" != "interactive" ]]; then
        log_info "Brute force disabled. Enable it from Settings or run option 6."
        return 0
    fi
    
    section_header "PHASE 5: BRUTE FORCE"
    local start
    start=$(timer_start)

    mkdir -p "${result_dir}/loot"
    BRUTE_WORKFLOW_MODE="brute-only"

    if [[ "$AUTO_BRUTE" == "interactive" ]]; then
        choose_brute_workflow || return 0

        if [[ "$BRUTE_WORKFLOW_MODE" == "toolkit-only" ]]; then
            if declare -F run_operator_toolkit >/dev/null; then
                run_operator_toolkit "$ip" "$result_dir"
            else
                log_warn "Operator toolkit module is unavailable."
            fi
            log_info "Time: $(timer_elapsed "$start")"
            return 0
        fi
    fi

    if ! command -v hydra &>/dev/null; then
        if [[ "$BRUTE_WORKFLOW_MODE" == "brute-then-toolkit" ]] && declare -F run_operator_toolkit >/dev/null; then
            log_warn "hydra not installed. Opening operator toolkit instead."
            run_operator_toolkit "$ip" "$result_dir"
            log_info "Time: $(timer_elapsed "$start")"
            return 0
        fi
        log_error "hydra not installed. Skipping brute force."
        return 1
    fi

    init_brute_defaults

    if [[ "$AUTO_BRUTE" == "interactive" ]]; then
        echo -e "${BOLD}${CYAN}  🔥 Interactive Brute Force Configuration${NC}"
        echo -e "${DIM}  Press Enter to keep defaults${NC}"

        local default_user_display="${WORDLIST_USERS:-none}"
        echo -ne "  ${CYAN}▶${NC} Username [Default: ${default_user_display}]: "
        read -r input_user
        if [[ -n "$input_user" ]]; then
            set_brute_identity_option "user" "$input_user"
        elif [[ ${#BRUTE_USER_OPTS[@]} -eq 0 ]]; then
            log_warn "No default username wordlist available. Enter a username or wordlist path."
            return 1
        fi

        local default_pass="${WORDLIST_PASS}"
        [[ -z "$default_pass" && -f "/usr/share/wordlists/rockyou.txt" ]] && default_pass="/usr/share/wordlists/rockyou.txt"
        echo -ne "  ${CYAN}▶${NC} Password [Default: ${default_pass:-none}]: "
        read -r input_pass
        if [[ -n "$input_pass" ]]; then
            set_brute_identity_option "pass" "$input_pass"
        elif [[ ${#BRUTE_PASS_OPTS[@]} -eq 0 ]]; then
            log_warn "No default password wordlist available. Enter a password or wordlist path."
            return 1
        fi

        echo ""
        choose_brute_target "$ip" "$result_dir" || return 0
    else
        BRUTE_SELECTED_MODE="auto"
    fi

    validate_brute_inputs || return 1

    case "$BRUTE_SELECTED_MODE" in
        auto)
            run_auto_bruteforce "$ip" "$result_dir"
            ;;
        http-post-form|http-get-form|https-post-form|https-get-form)
            run_hydra_web_form "$BRUTE_SELECTED_OUTFILE"
            ;;
        *)
            run_hydra_service \
                "Brute: ${BRUTE_SELECTED_MODE^^} (${BRUTE_SELECTED_HOST}:${BRUTE_SELECTED_PORT})" \
                600 \
                "$BRUTE_SELECTED_HOST" \
                "$BRUTE_SELECTED_PORT" \
                "$BRUTE_SELECTED_MODE" \
                "$BRUTE_SELECTED_OUTFILE"
            ;;
    esac

    if [[ "$BRUTE_WORKFLOW_MODE" == "brute-then-toolkit" ]] && declare -F run_operator_toolkit >/dev/null; then
        echo ""
        run_operator_toolkit "$ip" "$result_dir"
    fi

    if declare -F operator_toolkit_refresh_credentials >/dev/null; then
        operator_toolkit_refresh_credentials "$result_dir"
    fi
    if declare -F operator_toolkit_show_summary >/dev/null; then
        echo ""
        operator_toolkit_show_summary "$result_dir"
    fi

    log_info "Time: $(timer_elapsed "$start")"
}
