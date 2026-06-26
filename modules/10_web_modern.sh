#!/bin/bash
# ============================================================================
# AUTO RECON - Modern Web Recon Helpers (called from modules/03_web_recon.sh)
# ----------------------------------------------------------------------------
# Layered on top of the existing web recon flow. Every tool here is optional
# and degrades to a curl/builtin fallback so the pipeline still runs on a
# minimal box. Aggressive/active tools (dalfox) are gated behind OffSec-safe.
# ============================================================================

# Reuse the vuln module's gate if present; otherwise read the config flag.
web_modern_safe_mode_on() {
    if declare -F offsec_oscp_safe_mode_enabled >/dev/null; then
        offsec_oscp_safe_mode_enabled
    else
        [[ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ]]
    fi
}

# Slug for per-target output filenames (matches the rest of web recon).
web_modern_slug() { echo "$1" | sed 's|[:/]|_|g'; }

# Resolve ProjectDiscovery httpx, working around the PyPI `httpx` CLI collision.
# On Kali the PD binary is `httpx-toolkit`; elsewhere it may be `httpx`, but a
# bare `httpx` is often the Python HTTP client — so we verify it's really PD.
resolve_pd_httpx() {
    local cand
    for cand in httpx-toolkit httpx; do
        have_tool "$cand" || continue
        if "$cand" -version 2>&1 | grep -qiE 'projectdiscovery|httpx version|v[0-9]+\.[0-9]+'; then
            echo "$cand"; return 0
        fi
    done
    return 1
}

# ── httpx: fast probe of every queued web target ──────────────────────────
run_httpx_probe() {
    local ip="$1" result_dir="$2"
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    [[ -s "$web_ports_file" ]] || return 0

    local httpx_bin
    if ! httpx_bin=$(resolve_pd_httpx); then
        log_info "ProjectDiscovery httpx not found (install httpx-toolkit) — using whatweb fingerprint instead"
        return 0
    fi

    sub_header "httpx — fast tech/title/status probe (${httpx_bin})"
    local out="${result_dir}/web/httpx.txt"
    record_tool_choice "$result_dir" web_probe "$httpx_bin"
    # -silent keeps it parseable; flags chosen to be widely compatible.
    run_timed "${TOOL_TIMEOUT:-420}" "$httpx_bin" -silent \
        -l "$web_ports_file" \
        -title -status-code -tech-detect -web-server -location -no-color \
        -o "$out" 2>/dev/null || true
    if [[ -s "$out" ]]; then
        log_success "httpx → ${out} ($(wc -l < "$out") live)"
        head -n 15 "$out" | while IFS= read -r l; do echo -e "    ${DIM}${l}${NC}"; done
    else
        log_info "httpx produced no live results"
    fi
}

# ── Common CTF / sensitive endpoint probe ─────────────────────────────────
run_ctf_endpoint_probe() {
    local url="$1" ip="$2" result_dir="$3"
    prepare_web_target_context "$url" "$ip" "$result_dir"
    local base curl_url
    base=$(web_modern_slug "$url")
    curl_url="${WEB_CTX_CURL_URL%/}"
    local out="${result_dir}/web/ctf_endpoints_${base}.txt"

    sub_header "CTF / sensitive endpoint probe: ${WEB_CTX_DISPLAY_URL}"

    local -a paths=(
        ".git/HEAD" ".git/config" ".svn/entries" ".hg/store" ".bzr/"
        ".env" ".env.local" ".env.bak" "config.php.bak" "config.php~"
        "wp-config.php.bak" "settings.py" "credentials" "secrets.json"
        "robots.txt" "sitemap.xml" "security.txt" ".well-known/security.txt"
        "flag" "flag.txt" "FLAG.txt" "flag.php" "backup.zip" "backup.tar.gz"
        "backup.sql" "db.sql" "dump.sql" "database.sql" "www.zip" "site.zip"
        "phpinfo.php" "info.php" "test.php" "adminer.php" "server-status"
        ".DS_Store" ".htaccess" ".htpasswd" "id_rsa" ".ssh/id_rsa"
        "swagger.json" "swagger-ui.html" "api/swagger.json" "openapi.json"
        ".dockerenv" "docker-compose.yml" "Dockerfile" ".aws/credentials"
    )

    : > "$out"
    local hit_count=0 git_exposed=false p code size
    for p in "${paths[@]}"; do
        # -s silent, -k insecure, follow nothing, cap time; reuse --resolve ctx.
        read -r code size < <(curl -sk -o /dev/null \
            -w '%{http_code} %{size_download}\n' \
            --max-time 8 "${WEB_CTX_CURL_ARGS[@]}" "${curl_url}/${p}" 2>/dev/null)
        [[ -z "$code" ]] && continue
        if [[ "$code" =~ ^(200|301|302|401|403)$ ]] && [[ "$code" != "404" ]]; then
            # 200 with real body, or auth-protected, is interesting.
            if [[ "$code" == "200" && "${size:-0}" -eq 0 ]]; then continue; fi
            printf '[%s] %4s  %s\n' "$code" "${size:-0}" "${WEB_CTX_DISPLAY_URL%/}/${p}" >> "$out"
            echo "${WEB_CTX_DISPLAY_URL%/}/${p}" >> "${result_dir}/web/extra_paths.txt"
            hit_count=$((hit_count+1))
            [[ "$p" == ".git/HEAD" && "$code" == "200" ]] && git_exposed=true
        fi
    done

    if (( hit_count > 0 )); then
        print_found "${hit_count} interesting endpoint(s) on ${WEB_CTX_DISPLAY_URL}"
        sort -u "$out" -o "$out"
        head -n 20 "$out" | while IFS= read -r l; do echo -e "    ${YELLOW}${l}${NC}"; done
        log_success "CTF endpoints → ${out}"
    else
        log_info "No exposed sensitive endpoints"
        rm -f "$out"
    fi

    [[ "$git_exposed" == "true" ]] && run_git_dumper "$WEB_CTX_DISPLAY_URL" "$result_dir"
}

# ── Exposed .git handoff / dump ───────────────────────────────────────────
run_git_dumper() {
    local url="$1" result_dir="$2"
    local base loot
    base=$(web_modern_slug "$url")
    loot="${result_dir}/loot/git_${base}"
    print_found "Exposed .git detected at ${url}.git/ — source disclosure likely!"
    local tool
    if tool=$(pick_tool git_dump git-dumper githack 2>/dev/null); then
        log_scan "Dumping repository with ${tool}..."
        mkdir -p "$loot"
        run_timed "${TOOL_TIMEOUT:-420}" "$tool" "${url%/}/.git/" "$loot" >/dev/null 2>&1 || true
        if [[ -d "$loot/.git" ]] || [[ -n "$(ls -A "$loot" 2>/dev/null)" ]]; then
            log_success "Git repo dumped → ${loot}  (run: git -C ${loot} log --all; git checkout .)"
        else
            log_info "git-dumper ran but produced nothing — try manually"
        fi
    else
        {
            echo "Exposed .git at: ${url}.git/"
            echo "Install git-dumper, then:"
            echo "  git-dumper ${url%/}/.git/ ${loot}"
            echo "  git -C ${loot} log --all --oneline && git -C ${loot} checkout ."
        } >> "${result_dir}/web/git_exposure.txt"
        log_warn "git-dumper not installed — handoff written to web/git_exposure.txt"
    fi
}

# ── Crawl + JS/endpoint secret mining (katana → gospider → hakrawler → curl) ─
mine_js_secrets() {
    local url="$1" ip="$2" result_dir="$3"
    prepare_web_target_context "$url" "$ip" "$result_dir"
    local base curl_url
    base=$(web_modern_slug "$url")
    curl_url="$WEB_CTX_CURL_URL"
    local endpoints="${result_dir}/web/crawl_endpoints_${base}.txt"
    local secrets="${result_dir}/web/js_secrets_${base}.txt"

    sub_header "Crawl + secret mining: ${WEB_CTX_DISPLAY_URL}"

    local crawler
    if crawler=$(pick_tool crawler katana gospider hakrawler 2>/dev/null); then
        record_tool_choice "$result_dir" crawler "$crawler"
        case "$crawler" in
            katana)
                run_timed 120 katana -u "$curl_url" -jc -silent -d 2 -kf all \
                    -o "$endpoints" 2>/dev/null || true ;;
            gospider)
                run_timed 120 gospider -s "$curl_url" -d 2 -q --js 2>/dev/null \
                    | grep -oE 'https?://[^ ]+' | sort -u > "$endpoints" || true ;;
            hakrawler)
                echo "$curl_url" | run_timed 120 hakrawler -d 2 -u 2>/dev/null \
                    | sort -u > "$endpoints" || true ;;
        esac
    else
        # Fallback: pull root page, extract .js and href/src links.
        curl -sk --max-time 15 "${WEB_CTX_CURL_ARGS[@]}" "$curl_url" 2>/dev/null \
            | grep -oE '(src|href)="[^"]+"' | cut -d'"' -f2 \
            | sed "s#^/#${curl_url%/}/#" | sort -u > "$endpoints" || true
    fi

    local ep_count=0
    [[ -s "$endpoints" ]] && ep_count=$(wc -l < "$endpoints")
    log_info "Crawled ${ep_count} endpoint(s) → ${endpoints##*/}"

    # Fetch JS files referenced and grep for secrets.
    local js_urls
    js_urls=$( { echo "$curl_url"; grep -iE '\.js(\?|$)' "$endpoints" 2>/dev/null; } | sort -u | head -40)
    : > "$secrets"
    local jurl
    while IFS= read -r jurl; do
        [[ -z "$jurl" ]] && continue
        curl -sk --max-time 10 "${WEB_CTX_CURL_ARGS[@]}" "$jurl" 2>/dev/null \
            | grep -aoiE '(api[_-]?key|secret|passwd|password|token|authorization|bearer [a-z0-9._-]+|aws_access_key_id|aws_secret|s3\.amazonaws|-----BEGIN [A-Z ]+PRIVATE KEY-----|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+|/api/[a-z0-9_/-]+)[":= ]*[^"'\'' <>]{0,60}' \
            | sed "s#^#${jurl##*/}: #" >> "$secrets" || true
    done <<< "$js_urls"

    if [[ -s "$secrets" ]]; then
        sort -u "$secrets" -o "$secrets"
        print_found "$(wc -l < "$secrets") potential secret/endpoint pattern(s) in JS"
        head -n 12 "$secrets" | while IFS= read -r l; do echo -e "    ${RED}${l:0:120}${NC}"; done
        log_success "JS secrets → ${secrets}"
    else
        log_info "No obvious secrets in crawled JS"
        rm -f "$secrets"
    fi
}

# ── arjun: dedicated parameter mining ─────────────────────────────────────
run_arjun_params() {
    local url="$1" ip="$2" result_dir="$3"
    have_tool arjun || return 0
    prepare_web_target_context "$url" "$ip" "$result_dir"
    local base out
    base=$(web_modern_slug "$url")
    out="${result_dir}/web/arjun_${base}.json"
    sub_header "arjun — parameter mining: ${WEB_CTX_DISPLAY_URL}"
    record_tool_choice "$result_dir" param_mine arjun
    run_timed 180 arjun -u "$WEB_CTX_CURL_URL" -oJ "$out" -t 20 2>/dev/null || true
    if [[ -s "$out" ]] && grep -q '"params"' "$out" 2>/dev/null; then
        local params
        params=$(grep -oE '"params": *\[[^]]*\]' "$out" | head -1)
        print_found "arjun parameters: ${params}"
        log_success "arjun → ${out}"
    else
        log_info "arjun found no extra parameters"
        rm -f "$out"
    fi
}

# ── dalfox: XSS scan on discovered GET-parameter URLs (active → gated) ─────
run_dalfox_xss() {
    local ip="$1" result_dir="$2"
    have_tool dalfox || return 0
    if web_modern_safe_mode_on; then
        log_info "OffSec-safe mode ON — skipping dalfox (active XSS)"
        return 0
    fi
    # Collect candidate URLs with parameters from param-discovery output.
    local cand="${result_dir}/web/.dalfox_targets.txt"
    grep -rhoE 'https?://[^ ]+\?[^ ]+=' "${result_dir}/web/params_"*.txt \
        "${result_dir}/web/crawl_endpoints_"*.txt 2>/dev/null | sort -u > "$cand"
    [[ -s "$cand" ]] || { rm -f "$cand"; return 0; }

    sub_header "dalfox — XSS scan ($(wc -l < "$cand") param URLs)"
    local out="${result_dir}/web/dalfox.txt"
    record_tool_choice "$result_dir" xss dalfox
    run_timed "${TOOL_TIMEOUT:-420}" dalfox file "$cand" --silence --no-color -o "$out" 2>/dev/null || true
    if [[ -s "$out" ]]; then
        print_found "dalfox findings → ${out}"
    else
        log_info "dalfox reported no XSS"
        rm -f "$out"
    fi
    rm -f "$cand"
}

# ── Screenshots of every web target (gowitness → aquatone) ────────────────
run_web_screenshots() {
    local ip="$1" result_dir="$2"
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    [[ -s "$web_ports_file" ]] || return 0
    local shotdir="${result_dir}/web/screenshots"

    local tool
    if ! tool=$(pick_tool screenshot gowitness aquatone 2>/dev/null); then
        log_info "No screenshot tool (gowitness/aquatone) — skipping web screenshots"
        return 0
    fi
    sub_header "Screenshots — ${tool}"
    mkdir -p "$shotdir"
    record_tool_choice "$result_dir" screenshot "$tool"
    case "$tool" in
        gowitness)
            # gowitness v2 (scan file) and v3 (file scan) differ; try both.
            run_timed "${TOOL_TIMEOUT:-420}" gowitness scan file -f "$web_ports_file" \
                -s "$shotdir" --write-none 2>/dev/null \
            || run_timed "${TOOL_TIMEOUT:-420}" gowitness file -f "$web_ports_file" \
                -P "$shotdir" 2>/dev/null || true ;;
        aquatone)
            run_timed "${TOOL_TIMEOUT:-420}" bash -c \
                "aquatone -out '$shotdir' < '$web_ports_file'" 2>/dev/null || true ;;
    esac
    local n
    n=$(find "$shotdir" -type f \( -name '*.png' -o -name '*.jpeg' -o -name '*.jpg' \) 2>/dev/null | wc -l)
    if (( n > 0 )); then
        log_success "${n} screenshot(s) → ${shotdir}"
    else
        log_info "No screenshots captured"
    fi
}
