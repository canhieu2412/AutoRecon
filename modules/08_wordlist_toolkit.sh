#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 8: Wordlist Toolkit
# ============================================================================

wordlist_toolkit_dir() {
    local result_dir="$1"
    echo "${result_dir}/wordlists"
}

ensure_wordlist_toolkit_layout() {
    local result_dir="$1"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    mkdir -p "$wordlist_dir"
}

wordlist_prompt_value() {
    local label="$1"
    local default_value="${2:-}"
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

wordlist_extract_tokens_from_stream() {
    tr '[:upper:]' '[:lower:]' | \
        sed -E 's#https?://# #g; s#[/?=&,:;(){}\[\]<>\\|]# #g; s#[_\.-]# #g; s#[^a-z0-9@ ]# #g' | \
        tr ' ' '\n' | \
        awk 'length($0) >= 3 && length($0) <= 32'
}

wordlist_choose_web_target() {
    local result_dir="$1"
    local -a urls=()
    local selected_url=""

    while IFS= read -r url; do
        [[ -n "$url" ]] && urls+=("$url")
    done < <(
        {
            [[ -f "${result_dir}/scans/web_ports.txt" ]] && cat "${result_dir}/scans/web_ports.txt"
            [[ -f "${result_dir}/web/subdomain_web_targets.txt" ]] && awk '{print $NF}' "${result_dir}/web/subdomain_web_targets.txt"
        } 2>/dev/null | awk 'NF && !seen[$0]++'
    )

    if (( ${#urls[@]} == 0 )); then
        return 1
    fi

    echo -e "  ${BOLD}${CYAN}  Web Target Selection${NC}"
    local idx=1
    local url=""
    for url in "${urls[@]}"; do
        echo -e "  ${CYAN}[${idx}]${NC} ${url}"
        idx=$((idx + 1))
    done
    echo -e "  ${CYAN}[0]${NC} Custom URL"
    echo -ne "  ${BOLD}Choose target [default: 1]:${NC} "
    read -r target_choice

    if [[ -z "$target_choice" || "$target_choice" == "1" ]]; then
        selected_url="${urls[0]}"
    elif [[ "$target_choice" == "0" ]]; then
        echo -ne "  ${BOLD}Enter full URL:${NC} "
        read -r selected_url
    elif [[ "$target_choice" =~ ^[0-9]+$ ]] && (( target_choice >= 1 && target_choice <= ${#urls[@]} )); then
        selected_url="${urls[$((target_choice - 1))]}"
    fi

    [[ -n "$selected_url" ]] && printf '%s\n' "$selected_url"
}

wordlist_pick_auto_web_target() {
    local result_dir="$1"

    {
        [[ -f "${result_dir}/scans/web_ports.txt" ]] && cat "${result_dir}/scans/web_ports.txt"
        [[ -f "${result_dir}/web/subdomain_web_targets.txt" ]] && awk '{print $NF}' "${result_dir}/web/subdomain_web_targets.txt"
    } 2>/dev/null | awk 'NF && !seen[$0]++' | head -n 1
}

wordlist_append_file_tokens() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    wordlist_extract_tokens_from_stream < "$file"
}

wordlist_build_seed_lists() {
    local ip="$1"
    local result_dir="$2"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    local source_inventory="${wordlist_dir}/source_inventory.txt"
    local base_tokens="${wordlist_dir}/base_tokens.txt"
    local usernames="${wordlist_dir}/custom_usernames.txt"
    local password_seeds="${wordlist_dir}/password_seeds.txt"
    local content_words="${wordlist_dir}/custom_content.txt"
    local raw_tokens="${wordlist_dir}/.raw_tokens"
    local raw_usernames="${wordlist_dir}/.raw_usernames"
    local helper_file=""

    : > "$source_inventory"
    : > "$raw_tokens"
    : > "$raw_usernames"

    {
        printf '%s\n' "${TARGET_INPUT:-$ip}"
        printf '%s\n' "${TARGET_DOMAIN:-}"
        printf '%s\n' "${TARGET_DISPLAY:-$ip}"
    } | wordlist_extract_tokens_from_stream >> "$raw_tokens"

    local source_file=""
    for source_file in \
        "${result_dir}/web/discovered_hostnames.txt" \
        "${result_dir}/web/discovered_root_domains.txt" \
        "${result_dir}/web/subdomains.txt" \
        "${result_dir}/web/extra_paths.txt" \
        "${result_dir}/web/default_creds.txt" \
        "${result_dir}/scans/windows_auth_inventory.txt" \
        "${result_dir}/scans/linux_remote_access_inventory.txt" \
        "${result_dir}/scans/directory_services_inventory.txt" \
        "${result_dir}/scans/auth_surfaces.tsv" \
        "${result_dir}/toolkit/credential_cache.tsv" \
        "${result_dir}/loot/cewl_wordlist.txt" \
        "${result_dir}/wordlists/cewl_words.txt" \
        "${result_dir}/loot/cewl_emails.txt" \
        "${result_dir}/wordlists/cewl_emails.txt"; do
        [[ -f "$source_file" ]] || continue
        printf '%s\n' "${source_file#${result_dir}/}" >> "$source_inventory"
        wordlist_append_file_tokens "$source_file" >> "$raw_tokens"
    done

    local params_file=""
    for params_file in "${result_dir}/web/params_"*.txt; do
        [[ -f "$params_file" ]] || continue
        printf '%s\n' "${params_file#${result_dir}/}" >> "$source_inventory"
        wordlist_append_file_tokens "$params_file" >> "$raw_tokens"
    done

    local src_file=""
    for src_file in "${result_dir}/web/source_analysis_"*.txt "${result_dir}/js/js_analysis_report.txt"; do
        [[ -f "$src_file" ]] || continue
        printf '%s\n' "${src_file#${result_dir}/}" >> "$source_inventory"
        wordlist_append_file_tokens "$src_file" >> "$raw_tokens"
    done

    if [[ -f "${result_dir}/loot/cewl_emails.txt" ]]; then
        cut -d'@' -f1 "${result_dir}/loot/cewl_emails.txt" 2>/dev/null | wordlist_extract_tokens_from_stream >> "$raw_usernames"
    fi
    if [[ -f "${result_dir}/wordlists/cewl_emails.txt" ]]; then
        cut -d'@' -f1 "${result_dir}/wordlists/cewl_emails.txt" 2>/dev/null | wordlist_extract_tokens_from_stream >> "$raw_usernames"
    fi
    if [[ -f "${result_dir}/toolkit/credential_cache.tsv" ]]; then
        awk -F'\t' '{print $4}' "${result_dir}/toolkit/credential_cache.tsv" 2>/dev/null | wordlist_extract_tokens_from_stream >> "$raw_usernames"
    fi
    if [[ -f "${result_dir}/scans/windows_auth_inventory.txt" ]]; then
        grep -oE '[A-Za-z][A-Za-z0-9._-]{2,}' "${result_dir}/scans/windows_auth_inventory.txt" 2>/dev/null | tr '[:upper:]' '[:lower:]' >> "$raw_usernames"
    fi

    sort -u "$raw_tokens" > "$base_tokens"
    sort -u "$raw_usernames" > "$usernames"
    cat "$base_tokens" "$usernames" | awk 'NF && !seen[$0]++' > "$password_seeds"
    cp "$base_tokens" "$content_words"

    rm -f "$raw_tokens" "$raw_usernames"

    helper_file="${wordlist_dir}/summary.txt"
    {
        echo "=== Wordlist Toolkit Summary ==="
        echo "Generated: $(date)"
        echo "Target: ${TARGET_DISPLAY:-$ip}"
        echo "Base Tokens: $(wc -l < "$base_tokens" 2>/dev/null || echo 0)"
        echo "Usernames: $(wc -l < "$usernames" 2>/dev/null || echo 0)"
        echo "Password Seeds: $(wc -l < "$password_seeds" 2>/dev/null || echo 0)"
        echo "Content Words: $(wc -l < "$content_words" 2>/dev/null || echo 0)"
        echo ""
        echo "Source Inventory:"
        cat "$source_inventory" 2>/dev/null
    } > "$helper_file"

    log_success "Seed wordlists built → ${wordlist_dir}"
}

wordlist_run_cewl_toolkit() {
    local ip="$1"
    local result_dir="$2"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    if ! command -v cewl &>/dev/null; then
        log_warn "cewl not installed."
        return 1
    fi

    local selected_url=""
    selected_url=$(wordlist_choose_web_target "$result_dir") || {
        log_warn "No web target available for CeWL."
        return 1
    }

    local depth
    local min_len
    local include_numbers=""
    depth=$(wordlist_prompt_value "Depth" "2")
    min_len=$(wordlist_prompt_value "Minimum word length" "4")
    echo -ne "  ${BOLD}Include numbers? [y/N]:${NC} "
    read -r include_numbers

    local out_words="${wordlist_dir}/cewl_words.txt"
    local out_emails="${wordlist_dir}/cewl_emails.txt"
    local -a cewl_cmd=(timeout 180 cewl "$selected_url" -d "$depth" -m "$min_len" --lowercase -w "$out_words" --email_file "$out_emails")
    [[ "$include_numbers" =~ ^[Yy]$ ]] && cewl_cmd+=(--with-numbers)

    sub_header "Wordlist Toolkit: CeWL"
    log_scan "Crawling ${selected_url} for custom words..."
    log_command_preview "${cewl_cmd[@]}"
    "${cewl_cmd[@]}" 2>/dev/null

    if [[ -f "$out_words" ]]; then
        log_success "CeWL words → ${out_words}"
        [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]] || cp "$out_words" "${result_dir}/loot/cewl_wordlist.txt" 2>/dev/null || true
    fi
    if [[ -f "$out_emails" ]] && [[ -s "$out_emails" ]]; then
        log_success "CeWL emails → ${out_emails}"
        [[ -f "${result_dir}/loot/cewl_emails.txt" ]] || cp "$out_emails" "${result_dir}/loot/cewl_emails.txt" 2>/dev/null || true
    fi

    wordlist_build_seed_lists "$ip" "$result_dir"
}

wordlist_run_cewl_auto() {
    local ip="$1"
    local result_dir="$2"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    if ! command -v cewl &>/dev/null; then
        log_info "CeWL not installed; skipping auto web wordlist crawl."
        return 0
    fi

    local selected_url=""
    selected_url=$(wordlist_pick_auto_web_target "$result_dir")
    [[ -z "$selected_url" ]] && {
        log_info "No web target available for auto CeWL crawl."
        return 0
    }

    local out_words="${wordlist_dir}/cewl_words.txt"
    local out_emails="${wordlist_dir}/cewl_emails.txt"
    local -a cewl_cmd=(timeout 180 cewl "$selected_url" -d 2 -m 4 --lowercase --with-numbers -w "$out_words" --email_file "$out_emails")

    sub_header "Wordlist Toolkit: Auto CeWL"
    log_scan "Auto-crawling ${selected_url} for custom wordlist seeds..."
    log_command_preview "${cewl_cmd[@]}"
    "${cewl_cmd[@]}" 2>/dev/null || true

    if [[ -f "$out_words" ]]; then
        log_success "Auto CeWL words → ${out_words}"
        [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]] || cp "$out_words" "${result_dir}/loot/cewl_wordlist.txt" 2>/dev/null || true
    fi
    if [[ -f "$out_emails" ]] && [[ -s "$out_emails" ]]; then
        log_success "Auto CeWL emails → ${out_emails}"
        [[ -f "${result_dir}/loot/cewl_emails.txt" ]] || cp "$out_emails" "${result_dir}/loot/cewl_emails.txt" 2>/dev/null || true
    fi
}

wordlist_run_rsmangler_toolkit() {
    local result_dir="$1"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    if ! command -v rsmangler &>/dev/null; then
        log_warn "rsmangler not installed."
        return 1
    fi

    local default_seed="${wordlist_dir}/password_seeds.txt"
    local input_file
    input_file=$(wordlist_prompt_value "Seed file" "$default_seed")
    [[ -f "$input_file" ]] || {
        log_warn "Seed file not found: ${input_file}"
        return 1
    }

    local min_len
    local max_len
    min_len=$(wordlist_prompt_value "Minimum output length" "4")
    max_len=$(wordlist_prompt_value "Maximum output length" "24")

    local out_file="${wordlist_dir}/rsmangler_passwords.txt"
    local -a cmd=(rsmangler --file "$input_file" --output "$out_file" --min "$min_len" --max "$max_len")

    sub_header "Wordlist Toolkit: RSMangler"
    log_scan "Mangling ${input_file}..."
    log_command_preview "${cmd[@]}"
    "${cmd[@]}" 2>/dev/null

    if [[ -f "$out_file" ]]; then
        log_success "RSMangler output → ${out_file}"
    fi
}

wordlist_run_crunch_toolkit() {
    local result_dir="$1"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    if ! command -v crunch &>/dev/null; then
        log_warn "crunch not installed."
        return 1
    fi

    local min_len
    local max_len
    local charset
    local pattern
    min_len=$(wordlist_prompt_value "Minimum length" "4")
    max_len=$(wordlist_prompt_value "Maximum length" "6")
    charset=$(wordlist_prompt_value "Charset" "abcdefghijklmnopqrstuvwxyz0123456789")
    pattern=$(wordlist_prompt_value "Pattern (optional, example @@@%%%%)" "")

    local out_file="${wordlist_dir}/crunch_custom.txt"
    local -a cmd=(timeout 120 crunch "$min_len" "$max_len" "$charset")
    [[ -n "$pattern" ]] && cmd+=(-t "$pattern")
    cmd+=(-o "$out_file")

    sub_header "Wordlist Toolkit: Crunch"
    log_scan "Generating constrained crunch wordlist..."
    log_command_preview "${cmd[@]}"
    "${cmd[@]}" >/dev/null 2>&1

    if [[ -f "$out_file" ]]; then
        log_success "Crunch output → ${out_file}"
    fi
}

wordlist_build_merged_lists() {
    local ip="$1"
    local result_dir="$2"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")
    ensure_wordlist_toolkit_layout "$result_dir"

    [[ -f "${wordlist_dir}/base_tokens.txt" ]] || wordlist_build_seed_lists "$ip" "$result_dir"

    local merged_passwords="${wordlist_dir}/custom_passwords.txt"
    local merged_users="${wordlist_dir}/custom_usernames.txt"
    local merged_content="${wordlist_dir}/custom_content.txt"
    local merged_all="${wordlist_dir}/custom_all.txt"
    local source_file=""

    cat "${wordlist_dir}/custom_usernames.txt" \
        "${result_dir}/toolkit/credential_cache.tsv" 2>/dev/null | \
        wordlist_extract_tokens_from_stream | awk 'NF && !seen[$0]++' > "${wordlist_dir}/.merged_users"
    mv "${wordlist_dir}/.merged_users" "$merged_users"

    {
        [[ -f "${wordlist_dir}/password_seeds.txt" ]] && cat "${wordlist_dir}/password_seeds.txt"
        [[ -f "${wordlist_dir}/rsmangler_passwords.txt" ]] && cat "${wordlist_dir}/rsmangler_passwords.txt"
        [[ -f "${wordlist_dir}/crunch_custom.txt" ]] && cat "${wordlist_dir}/crunch_custom.txt"
        [[ -f "${wordlist_dir}/cewl_words.txt" ]] && cat "${wordlist_dir}/cewl_words.txt"
        [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]] && cat "${result_dir}/loot/cewl_wordlist.txt"
    } 2>/dev/null | awk 'NF && !seen[$0]++' > "$merged_passwords"

    {
        [[ -f "${wordlist_dir}/base_tokens.txt" ]] && cat "${wordlist_dir}/base_tokens.txt"
        [[ -f "${wordlist_dir}/cewl_words.txt" ]] && cat "${wordlist_dir}/cewl_words.txt"
        [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]] && cat "${result_dir}/loot/cewl_wordlist.txt"
    } 2>/dev/null | awk 'NF && !seen[$0]++' > "$merged_content"

    cat "$merged_users" "$merged_passwords" "$merged_content" 2>/dev/null | awk 'NF && !seen[$0]++' > "$merged_all"

    {
        echo "=== Wordlist Toolkit Summary ==="
        echo "Generated: $(date)"
        echo "Target: ${TARGET_DISPLAY:-$ip}"
        echo "Usernames: $(wc -l < "$merged_users" 2>/dev/null || echo 0)"
        echo "Passwords: $(wc -l < "$merged_passwords" 2>/dev/null || echo 0)"
        echo "Content Words: $(wc -l < "$merged_content" 2>/dev/null || echo 0)"
        echo "All-in-One: $(wc -l < "$merged_all" 2>/dev/null || echo 0)"
        echo ""
        echo "Generated Files:"
        for source_file in \
            "${merged_users}" \
            "${merged_passwords}" \
            "${merged_content}" \
            "${merged_all}" \
            "${wordlist_dir}/cewl_words.txt" \
            "${wordlist_dir}/rsmangler_passwords.txt" \
            "${wordlist_dir}/crunch_custom.txt"; do
            [[ -f "$source_file" ]] && printf '%s\n' "${source_file#${result_dir}/}"
        done
    } > "${wordlist_dir}/summary.txt"

    log_success "Merged custom wordlists → ${wordlist_dir}"
}

wordlist_promote_generated_lists() {
    local result_dir="$1"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")

    if [[ -f "${wordlist_dir}/custom_content.txt" ]]; then
        WORDLIST_WEB="${wordlist_dir}/custom_content.txt"
        log_success "Active web wordlist set → ${WORDLIST_WEB}"
    fi
    if [[ -f "${wordlist_dir}/custom_usernames.txt" ]]; then
        WORDLIST_USERS="${wordlist_dir}/custom_usernames.txt"
        log_success "Active username wordlist set → ${WORDLIST_USERS}"
    fi
    if [[ -f "${wordlist_dir}/custom_passwords.txt" ]]; then
        WORDLIST_PASS="${wordlist_dir}/custom_passwords.txt"
        log_success "Active password wordlist set → ${WORDLIST_PASS}"
    fi

    declare -F mark_profile_custom >/dev/null && mark_profile_custom
}

wordlist_show_summary() {
    local result_dir="$1"
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")

    if [[ -f "${wordlist_dir}/summary.txt" ]]; then
        cat "${wordlist_dir}/summary.txt"
    else
        log_info "No wordlist summary yet. Build seed lists or merged lists first."
    fi
}

run_wordlist_toolkit_auto() {
    local ip="$1"
    local result_dir="$2"

    section_header "PHASE 8: WORDLIST TOOLKIT"
    ensure_wordlist_toolkit_layout "$result_dir"

    wordlist_build_seed_lists "$ip" "$result_dir"
    wordlist_run_cewl_auto "$ip" "$result_dir"
    wordlist_build_seed_lists "$ip" "$result_dir"
    wordlist_build_merged_lists "$ip" "$result_dir"
    wordlist_promote_generated_lists "$result_dir"
    wordlist_show_summary "$result_dir"
}

run_wordlist_toolkit() {
    local ip="$1"
    local result_dir="$2"
    local choice=""
    local wordlist_dir
    wordlist_dir=$(wordlist_toolkit_dir "$result_dir")

    section_header "PHASE 8: WORDLIST TOOLKIT"
    ensure_wordlist_toolkit_layout "$result_dir"

    while true; do
        echo -e "  ${DIM}Outputs: ${wordlist_dir}${NC}"
        echo -e "  ${CYAN}[1]${NC} Build target-derived seed lists"
        echo -e "  ${CYAN}[2]${NC} Run CeWL custom crawl"
        echo -e "  ${CYAN}[3]${NC} Run RSMangler mutations"
        echo -e "  ${CYAN}[4]${NC} Run Crunch constrained generator"
        echo -e "  ${CYAN}[5]${NC} Build merged custom wordlists"
        echo -e "  ${CYAN}[6]${NC} Promote generated lists into current session"
        echo -e "  ${CYAN}[7]${NC} View wordlist summary"
        echo -e "  ${CYAN}[0]${NC} Return"
        echo -ne "  ${BOLD}Choose [0-7, default: 1]:${NC} "
        read -r choice
        [[ -z "$choice" ]] && choice=1

        case "$choice" in
            1)
                wordlist_build_seed_lists "$ip" "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            2)
                wordlist_run_cewl_toolkit "$ip" "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            3)
                wordlist_run_rsmangler_toolkit "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            4)
                wordlist_run_crunch_toolkit "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            5)
                wordlist_build_merged_lists "$ip" "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            6)
                wordlist_promote_generated_lists "$result_dir"
                wordlist_show_summary "$result_dir"
                ;;
            7) wordlist_show_summary "$result_dir" ;;
            0|q|Q) return 0 ;;
            *) log_warn "Invalid selection" ;;
        esac

        echo ""
    done
}
