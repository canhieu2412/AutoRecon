#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 3: Web Reconnaissance (Recursive Fuzzing)
# ============================================================================

NIKTO_PIDS=()

get_subdomain_wordlist() {
    local result_dir="$1"
    local base_wordlist="$WORDLIST_DNS"
    local tmp_wordlist="${result_dir}/web/.subdomains_wordlist"
    local limit=0

    [[ -z "$base_wordlist" || ! -f "$base_wordlist" ]] && return 0

    case "$SCAN_MODE" in
        quick)  limit=500 ;;
        normal) limit=3000 ;;
        full)   limit=0 ;;
        *)      limit=3000 ;;
    esac

    if (( limit > 0 )); then
        head -n "$limit" "$base_wordlist" > "$tmp_wordlist"
        echo "$tmp_wordlist"
    else
        echo "$base_wordlist"
    fi
}

resolve_host_ips() {
    local host="$1"
    getent ahosts "$host" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]' | sort -u
}

normalize_hostname_candidate() {
    local candidate="$1"
    candidate=$(echo "$candidate" | tr '[:upper:]' '[:lower:]' | \
        sed -E 's#^[a-z]+://##; s#[/?#].*$##; s#^\*\.##; s#\.$##; s#^[[]##; s#[]]$##')
    candidate="${candidate%%:*}"

    [[ -z "$candidate" ]] && return 1
    is_valid_ip "$candidate" && return 1
    [[ "$candidate" == *.* ]] || return 1
    is_valid_domain "$candidate" || return 1

    local suffix="${candidate##*.}"
    case "$suffix" in
        txt|xml|html|htm|xhtml|php|phtml|asp|aspx|jsp|js|css|json|map|ico|png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|eot|bak|old|log|conf|cfg|config|ini|sql|db|csv|md|yml|yaml|zip|tar|gz|dtd|url|min|bundle|chunk|lock)
            return 1
            ;;
    esac

    case "$candidate" in
        robots.txt|sitemap.xml|favicon.ico|index.html|index.htm|default.asp|default.aspx|login.php|wp-login.php)
            return 1
            ;;
    esac

    case "$candidate" in
        localhost|localhost.localdomain) return 1 ;;
    esac

    echo "$candidate"
}

extract_hostnames_from_stream() {
    grep -oE '([A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]{1,62}' 2>/dev/null | while read -r candidate; do
        normalize_hostname_candidate "$candidate"
    done | awk 'NF && !seen[$0]++'
}

extract_hostnames_from_text() {
    local text="$1"
    printf '%s\n' "$text" | extract_hostnames_from_stream
}

is_internal_domain_candidate() {
    local host="${1,,}"
    local suffix="${host##*.}"
    case "$suffix" in
        htb|local|lab|internal|corp|lan|home|test|localdomain|intra|intranet)
            return 0
            ;;
    esac
    return 1
}

apex_domain_from_host() {
    local host
    host=$(normalize_hostname_candidate "$1") || return 1

    local IFS='.'
    read -r -a labels <<< "$host"
    local count=${#labels[@]}
    (( count >= 2 )) || return 1

    echo "${labels[$((count - 2))]}.${labels[$((count - 1))]}"
}

pick_preferred_hostname() {
    local file="$1"
    [[ -s "$file" ]] || return 1

    awk -F'.' '{print NF, length($0), $0}' "$file" | sort -k1,1nr -k2,2n | head -1 | cut -d' ' -f3-
}

extract_hosts_from_http_endpoint() {
    local url="$1"
    shift
    local -a curl_args=("$@")
    local headers=""
    local body=""

    headers=$(curl -skIL -m 8 "${curl_args[@]}" "$url" 2>/dev/null)
    body=$(curl -sk -m 8 "${curl_args[@]}" "$url" 2>/dev/null | head -c 200000)

    {
        echo "$headers" | grep -iE '^(location|refresh):'
        echo "$body" | grep -oE 'https?://[^"'"'"'[:space:]<>]+' 2>/dev/null
    } | extract_hostnames_from_stream
}

extract_hosts_from_ssl_endpoint() {
    local connect_host="$1"
    local port="$2"
    local servername="${3:-}"

    if [[ -n "$servername" ]]; then
        echo | timeout 6 openssl s_client -connect "${connect_host}:${port}" -servername "$servername" -showcerts 2>/dev/null | \
            openssl x509 -noout -text 2>/dev/null | extract_hostnames_from_stream
    else
        echo | timeout 6 openssl s_client -connect "${connect_host}:${port}" -showcerts 2>/dev/null | \
            openssl x509 -noout -text 2>/dev/null | extract_hostnames_from_stream
    fi
}

hostname_matches_ip() {
    local host="$1"
    local ip="$2"
    resolve_host_ips "$host" | grep -qx "$ip"
}

host_mapping_ips() {
    local hosts_file="$1"
    local host="$2"

    [[ -f "$hosts_file" ]] || return 0

    awk -v host="$host" '
        /^[[:space:]]*#/ || NF < 2 { next }
        {
            for (i = 2; i <= NF; i++) {
                if ($i == host) {
                    print $1
                    break
                }
            }
        }
    ' "$hosts_file" | sort -u
}

upsert_hosts_mapping() {
    local hosts_file="$1"
    local ip="$2"
    local host="$3"
    local tmp
    tmp=$(mktemp /tmp/auto_recon_hosts.XXXXXX)

    awk -v host="$host" '
        /^[[:space:]]*#/ || NF == 0 {
            print
            next
        }
        {
            rebuilt = $1
            kept = 0
            for (i = 2; i <= NF; i++) {
                if ($i != host) {
                    rebuilt = rebuilt " " $i
                    kept = 1
                }
            }
            if (kept) {
                print rebuilt
            }
        }
    ' "$hosts_file" > "$tmp"

    printf '%s %s\n' "$ip" "$host" >> "$tmp"
    mv "$tmp" "$hosts_file"
}

emit_web_inventory_hosts() {
    local result_dir="$1"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local roots_file="${result_dir}/web/discovered_root_domains.txt"
    local subdomains_file="${result_dir}/web/subdomains.txt"
    local resolved_subdomains_file="${result_dir}/web/subdomains_resolved.txt"
    local vhosts_file="${result_dir}/web/vhosts.txt"

    {
        [[ -f "$hostnames_file" ]] && cat "$hostnames_file"
        [[ -f "$roots_file" ]] && cat "$roots_file"
        [[ -f "$subdomains_file" ]] && cat "$subdomains_file"
        [[ -f "$resolved_subdomains_file" ]] && awk '{print $1}' "$resolved_subdomains_file"
        [[ -f "$vhosts_file" ]] && cat "$vhosts_file"
    } 2>/dev/null | while read -r host; do
        [[ -z "$host" ]] && continue
        normalize_hostname_candidate "$host" 2>/dev/null || true
    done | awk 'NF && !seen[$0]++'
}

persist_discovered_web_inventory() {
    local ip="$1"
    local result_dir="$2"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local roots_file="${result_dir}/web/discovered_root_domains.txt"
    local source_file="${3:-}"

    [[ -n "$source_file" && -s "$source_file" ]] || return 0

    touch "$hostnames_file" "$roots_file"

    while read -r host; do
        [[ -z "$host" ]] && continue
        echo "$host" >> "$hostnames_file"
        local root_domain
        root_domain=$(apex_domain_from_host "$host" 2>/dev/null || true)
        [[ -n "$root_domain" ]] && echo "$root_domain" >> "$roots_file"
    done < <(
        while read -r candidate; do
            [[ -z "$candidate" ]] && continue
            normalize_hostname_candidate "$candidate" 2>/dev/null || true
        done < "$source_file" | awk 'NF && !seen[$0]++'
    )

    dedup_file "$hostnames_file"
    dedup_file "$roots_file"
    build_hosts_suggestions "$ip" "$result_dir"
    sync_discovered_hosts_into_system "$result_dir"
    queue_hostname_web_targets "$ip" "$result_dir"
    canonicalize_web_targets "$ip" "$result_dir"
}

build_hosts_suggestions() {
    local ip="$1"
    local result_dir="$2"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local vhosts_file="${result_dir}/web/vhosts.txt"
    local root_domains_file="${result_dir}/web/discovered_root_domains.txt"
    local out="${result_dir}/web/hosts_suggestions.txt"
    local import_script="${result_dir}/web/import_hosts.sh"

    : > "$out"

    while read -r host; do
        [[ -z "$host" ]] && continue

        local is_vhost_generated=false
        [[ -f "$vhosts_file" ]] && grep -Fxq "$host" "$vhosts_file" && is_vhost_generated=true

        if [[ "$is_vhost_generated" == "true" ]]; then
            # VHost fuzz can return a large wildcard set; keep it for manual review only.
            continue
        fi

        local resolved_ips
        resolved_ips=$(resolve_host_ips "$host" | paste -sd, -)

        if [[ -n "$resolved_ips" ]] && ! grep -Eq "(^|,)${ip}(,|$)" <<< "$resolved_ips"; then
            continue
        fi

        echo "${ip} ${host}" >> "$out"
    done < <(emit_web_inventory_hosts "$result_dir")

    dedup_file "$out"

    cat > "$import_script" <<EOF
#!/bin/bash
set -euo pipefail

upsert_host() {
    local ip="\$1"
    local host="\$2"
    local tmp
    tmp=\$(mktemp /tmp/auto_recon_hosts.XXXXXX)

    awk -v host="\$host" '
        /^[[:space:]]*#/ || NF == 0 {
            print
            next
        }
        {
            rebuilt = \$1
            kept = 0
            for (i = 2; i <= NF; i++) {
                if (\$i != host) {
                    rebuilt = rebuilt " " \$i
                    kept = 1
                }
            }
            if (kept) {
                print rebuilt
            }
        }
    ' /etc/hosts > "\$tmp"

    printf '%s %s\n' "\$ip" "\$host" >> "\$tmp"
    sudo cp "\$tmp" /etc/hosts
    rm -f "\$tmp"
}

while IFS= read -r line; do
    [[ -z "\$line" ]] && continue
    ip=\${line%% *}
    host=\${line#* }
    current_ips=\$(awk -v host="\$host" '
        /^[[:space:]]*#/ || NF < 2 { next }
        {
            for (i = 2; i <= NF; i++) {
                if (\$i == host) {
                    print \$1
                    break
                }
            }
        }
    ' /etc/hosts | sort -u)

    if grep -qx "\$ip" <<< "\$current_ips"; then
        continue
    fi

    upsert_host "\$ip" "\$host"
done < "${out}"
EOF
    chmod +x "$import_script"

    if [[ -s "$out" ]]; then
        log_info "Hosts suggestions → ${out}"
        log_info "Import helper → ${import_script}"
    fi
}

sync_discovered_hosts_into_system() {
    local result_dir="$1"
    local hosts_file="${result_dir}/web/hosts_suggestions.txt"
    [[ ! -s "$hosts_file" ]] && return 0
    [[ "$AUTO_UPDATE_ETC_HOSTS" != "true" ]] && return 0

    if ! check_root; then
        log_warn "Hosts auto-map is ON but current shell is not root. Skipping /etc/hosts update."
        return 0
    fi

    local appended=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local ip="${line%% *}"
        local host="${line#* }"
        local current_ips
        current_ips=$(host_mapping_ips /etc/hosts "$host")

        if grep -qx "$ip" <<< "$current_ips"; then
            continue
        fi

        upsert_hosts_mapping /etc/hosts "$ip" "$host"
        appended=$((appended + 1))
    done < "$hosts_file"

    if (( appended > 0 )); then
        log_success "Added ${appended} discovered host mapping(s) to /etc/hosts"
    else
        log_info "No new /etc/hosts entries needed"
    fi
}

queue_hostname_web_targets() {
    local ip="$1"
    local result_dir="$2"
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local vhosts_file="${result_dir}/web/vhosts.txt"
    local root_domains_file="${result_dir}/web/discovered_root_domains.txt"
    local can_queue_unresolved=false

    [[ ! -f "$web_ports_file" ]] && return 0
    [[ "$AUTO_UPDATE_ETC_HOSTS" == "true" ]] && check_root && can_queue_unresolved=true

    local current_targets="${result_dir}/web/.web_ports_current"
    cp "$web_ports_file" "$current_targets" 2>/dev/null || : > "$current_targets"

    while read -r url; do
        [[ -z "$url" ]] && continue

        local proto="${url%%://*}"
        local remainder="${url#*://}"
        local host_port="${remainder%%/*}"
        local host="${host_port%%:*}"
        local port=""

        if [[ "$host_port" == *:* ]]; then
            port="${host_port##*:}"
        else
            port=$([[ "$proto" == "https" ]] && echo 443 || echo 80)
        fi

        is_valid_ip "$host" || continue

        while read -r hostname; do
            [[ -z "$hostname" ]] && continue

            if [[ -f "$vhosts_file" ]] && grep -Fxq "$hostname" "$vhosts_file"; then
                continue
            fi

            local host_matches_target=false
            if hostname_matches_ip "$hostname" "$ip"; then
                host_matches_target=true
            fi

            if [[ "$host_matches_target" != "true" ]]; then
                if [[ "$can_queue_unresolved" != "true" ]]; then
                    continue
                fi
            fi

            local entry="${proto}://${hostname}"
            [[ "$port" != "80" && "$port" != "443" ]] && entry="${entry}:${port}"
            echo "$entry" >> "$web_ports_file"
    done < <(emit_web_inventory_hosts "$result_dir")
    done < "$current_targets"

    dedup_file "$web_ports_file"
    rm -f "$current_targets"
}

get_primary_web_hostname() {
    local result_dir="$1"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local vhosts_file="${result_dir}/web/vhosts.txt"
    local roots_file="${result_dir}/web/discovered_root_domains.txt"

    if [[ -n "$TARGET_DOMAIN" ]]; then
        normalize_hostname_candidate "$TARGET_DOMAIN" && return 0
    fi

    if [[ -s "$hostnames_file" ]]; then
        local preferred_candidates="${result_dir}/web/.preferred_host_candidates"
        : > "$preferred_candidates"

        while read -r host; do
            [[ -z "$host" ]] && continue

            if [[ -f "$vhosts_file" ]] && grep -Fxq "$host" "$vhosts_file"; then
                continue
            fi

            echo "$host" >> "$preferred_candidates"
        done < "$hostnames_file"

        dedup_file "$preferred_candidates"
        if [[ -s "$preferred_candidates" ]]; then
            pick_preferred_hostname "$preferred_candidates"
            rm -f "$preferred_candidates"
            return 0
        fi

        rm -f "$preferred_candidates"
    fi

    if [[ -s "$roots_file" ]]; then
        awk '{print length($0), $0}' "$roots_file" | sort -n | head -1 | cut -d' ' -f2-
        return 0
    fi
}

parse_web_url() {
    local url="$1"
    local proto="${url%%://*}"
    local remainder="${url#*://}"
    local host_port="${remainder%%/*}"
    local path="/"

    [[ "$remainder" != "$host_port" ]] && path="/${remainder#*/}"

    local host="$host_port"
    local port=""
    if [[ "$host_port" == *:* ]]; then
        host="${host_port%:*}"
        port="${host_port##*:}"
    else
        port=$([[ "$proto" == "https" ]] && echo 443 || echo 80)
    fi

    printf '%s|%s|%s|%s\n' "$proto" "$host" "$port" "$path"
}

build_web_url() {
    local proto="$1"
    local host="$2"
    local port="$3"
    local path="${4:-/}"
    local url="${proto}://${host}"

    if [[ "$proto" == "http" && "$port" != "80" ]] || [[ "$proto" == "https" && "$port" != "443" ]]; then
        url="${url}:${port}"
    fi

    [[ -n "$path" && "$path" != "/" ]] && url="${url%/}${path}"
    printf '%s\n' "$url"
}

prepare_web_target_context() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local parsed

    parsed=$(parse_web_url "$url")

    WEB_CTX_PROTO="${parsed%%|*}"
    local remainder="${parsed#*|}"
    WEB_CTX_ORIGINAL_HOST="${remainder%%|*}"
    remainder="${remainder#*|}"
    WEB_CTX_PORT="${remainder%%|*}"
    WEB_CTX_PATH="${remainder#*|}"

    WEB_CTX_ORIGINAL_URL="$url"
    WEB_CTX_DISPLAY_URL="$url"
    WEB_CTX_CURL_URL="$url"
    WEB_CTX_TOOL_URL="$url"
    WEB_CTX_REQUEST_HOST="$WEB_CTX_ORIGINAL_HOST"
    WEB_CTX_NEEDS_HOST_OVERRIDE=false

    declare -ga WEB_CTX_CURL_ARGS=()
    declare -ga WEB_CTX_FFUF_ARGS=()
    declare -ga WEB_CTX_GOBUSTER_ARGS=()
    declare -ga WEB_CTX_FEROX_ARGS=()

    if [[ "$WEB_CTX_PROTO" == "https" ]]; then
        WEB_CTX_FFUF_ARGS+=(-k)
        WEB_CTX_GOBUSTER_ARGS+=(-k)
        WEB_CTX_FEROX_ARGS+=(-k)
    fi

    is_valid_ip "$WEB_CTX_ORIGINAL_HOST" || return 0

    local preferred_host=""
    preferred_host=$(get_primary_web_hostname "$result_dir" 2>/dev/null || true)
    preferred_host=$(normalize_hostname_candidate "$preferred_host" 2>/dev/null || true)
    [[ -z "$preferred_host" ]] && return 0

    WEB_CTX_NEEDS_HOST_OVERRIDE=true
    WEB_CTX_REQUEST_HOST="$preferred_host"
    WEB_CTX_DISPLAY_URL=$(build_web_url "$WEB_CTX_PROTO" "$preferred_host" "$WEB_CTX_PORT" "$WEB_CTX_PATH")
    WEB_CTX_CURL_URL="$WEB_CTX_DISPLAY_URL"
    WEB_CTX_CURL_ARGS+=(--resolve "${preferred_host}:${WEB_CTX_PORT}:${WEB_CTX_ORIGINAL_HOST}")

    if hostname_matches_ip "$preferred_host" "$ip"; then
        WEB_CTX_TOOL_URL="$WEB_CTX_DISPLAY_URL"
        return 0
    fi

    WEB_CTX_FFUF_ARGS+=(-H "Host: ${preferred_host}")
    WEB_CTX_GOBUSTER_ARGS+=(-H "Host: ${preferred_host}")
    WEB_CTX_FEROX_ARGS+=(-H "Host: ${preferred_host}")
    [[ "$WEB_CTX_PROTO" == "https" ]] && WEB_CTX_FFUF_ARGS+=(-sni "$preferred_host")
}

canonicalize_web_targets() {
    local ip="$1"
    local result_dir="$2"
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    local preferred_host=""

    [[ ! -s "$web_ports_file" ]] && return 0
    preferred_host=$(get_primary_web_hostname "$result_dir" 2>/dev/null || true)
    [[ -z "$preferred_host" ]] && return 0

    local can_use_unresolved=false
    [[ "$AUTO_UPDATE_ETC_HOSTS" == "true" ]] && check_root && can_use_unresolved=true
    if [[ "$can_use_unresolved" != "true" ]] && ! hostname_matches_ip "$preferred_host" "$ip"; then
        return 0
    fi

    local tmp="${result_dir}/web/.web_ports_canonical"
    local migrated=0

    while read -r url; do
        [[ -z "$url" ]] && continue

        local proto="${url%%://*}"
        local remainder="${url#*://}"
        local host_port="${remainder%%/*}"
        local path="/"
        local host="${host_port%%:*}"
        local port=""

        [[ "$remainder" != "$host_port" ]] && path="/${remainder#*/}"

        if [[ "$host_port" == *:* ]]; then
            port="${host_port##*:}"
        else
            port=$([[ "$proto" == "https" ]] && echo 443 || echo 80)
        fi

        if is_valid_ip "$host"; then
            local canonical="${proto}://${preferred_host}"
            [[ "$port" != "80" && "$port" != "443" ]] && canonical="${canonical}:${port}"
            [[ -n "$path" && "$path" != "/" ]] && canonical="${canonical%/}${path}"
            echo "$canonical" >> "$tmp"
            [[ "$canonical" != "$url" ]] && migrated=$((migrated + 1))
        else
            echo "$url" >> "$tmp"
        fi
    done < "$web_ports_file"

    dedup_file "$tmp"
    mv "$tmp" "$web_ports_file"

    if (( migrated > 0 )); then
        log_info "Canonicalized ${migrated} web target(s) from IP to hostname ${preferred_host}"
    fi
}

discover_web_domain_context() {
    local ip="$1"
    local result_dir="$2"
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"
    local root_domains_file="${result_dir}/web/discovered_root_domains.txt"
    local raw_candidates="${result_dir}/web/.host_candidates_raw"
    local strong_candidates="${result_dir}/web/.host_candidates_strong"
    local new_hostnames="${result_dir}/web/.host_candidates_new_hostnames"
    local new_roots="${result_dir}/web/.host_candidates_new_roots"

    touch "$hostnames_file" "$root_domains_file"
    : > "$raw_candidates"
    : > "$strong_candidates"
    : > "$new_hostnames"
    : > "$new_roots"

    [[ -n "$TARGET_DOMAIN" ]] && echo "$TARGET_DOMAIN" >> "$strong_candidates"

    if [[ -f "${result_dir}/scans/nmap_targeted.nmap" ]]; then
        grep "^[0-9]" "${result_dir}/scans/nmap_targeted.nmap" | grep -Ei 'open.*(http|ssl|https|apache|nginx|tomcat|iis)' | \
            extract_hostnames_from_stream >> "$strong_candidates"
    fi

    for artifact in "${result_dir}/web/fingerprint_"*.txt "${result_dir}/web/ssl_"*.txt; do
        [[ -f "$artifact" ]] || continue
        extract_hostnames_from_stream < "$artifact" >> "$strong_candidates"
    done

    for artifact in "${result_dir}/web/source_analysis_"*.txt "${result_dir}/web/api_fuzz_"*.txt; do
        [[ -f "$artifact" ]] || continue
        extract_hostnames_from_stream < "$artifact" >> "$raw_candidates"
    done

    while read -r url; do
        [[ -z "$url" ]] && continue

        prepare_web_target_context "$url" "$ip" "$result_dir"
        extract_hosts_from_http_endpoint "$WEB_CTX_CURL_URL" "${WEB_CTX_CURL_ARGS[@]}" >> "$raw_candidates"
        if [[ "$WEB_CTX_PROTO" == "https" ]]; then
            extract_hosts_from_ssl_endpoint "$WEB_CTX_ORIGINAL_HOST" "$WEB_CTX_PORT" "$WEB_CTX_REQUEST_HOST" >> "$strong_candidates"
        fi
    done < "$web_ports_file"

    dedup_file "$raw_candidates"
    dedup_file "$strong_candidates"

    while read -r host; do
        [[ -z "$host" ]] && continue

        local resolved_ips
        resolved_ips=$(resolve_host_ips "$host" | paste -sd, -)

        if [[ -n "$resolved_ips" ]]; then
            grep -Eq "(^|,)${ip}(,|$)" <<< "$resolved_ips" && echo "$host" >> "$new_hostnames"
            continue
        fi

        if grep -Fxq "$host" "$strong_candidates" || is_internal_domain_candidate "$host"; then
            echo "$host" >> "$new_hostnames"
        fi
    done < <(cat "$hostnames_file" "$strong_candidates" "$raw_candidates" 2>/dev/null | awk 'NF && !seen[$0]++')

    dedup_file "$new_hostnames"
    cat "$new_hostnames" >> "$hostnames_file"
    dedup_file "$hostnames_file"

    while read -r host; do
        [[ -z "$host" ]] && continue
        local root_domain
        root_domain=$(apex_domain_from_host "$host" 2>/dev/null || true)
        [[ -n "$root_domain" ]] && echo "$root_domain" >> "$new_roots"
    done < <(emit_web_inventory_hosts "$result_dir")

    dedup_file "$new_roots"
    cat "$new_roots" >> "$root_domains_file"
    dedup_file "$root_domains_file"

    if [[ -z "$TARGET_DOMAIN" ]] && [[ -s "$hostnames_file" ]]; then
        TARGET_DOMAIN=$(pick_preferred_hostname "$hostnames_file")
        export TARGET_DOMAIN
        log_info "Primary web hostname candidate: ${TARGET_DOMAIN}"
    elif [[ -z "$TARGET_DOMAIN" ]] && [[ -s "$root_domains_file" ]]; then
        TARGET_DOMAIN=$(awk '{print length($0), $0}' "$root_domains_file" | sort -n | head -1 | cut -d' ' -f2-)
        export TARGET_DOMAIN
        log_info "Primary web domain candidate: ${TARGET_DOMAIN}"
    fi

    local host_count
    host_count=$(wc -l < "$hostnames_file" 2>/dev/null || echo 0)
    if (( host_count > 0 )); then
        log_success "Discovered ${host_count} hostname candidate(s) for web target ${ip}"
        head -10 "$hostnames_file" | while read -r host; do
            [[ -n "$host" ]] && print_found "HOSTNAME: ${host}"
        done
        build_hosts_suggestions "$ip" "$result_dir"
        sync_discovered_hosts_into_system "$result_dir"
        queue_hostname_web_targets "$ip" "$result_dir"
        canonicalize_web_targets "$ip" "$result_dir"
    elif [[ -z "$TARGET_DOMAIN" ]]; then
        log_info "No domain/vhost hints discovered from current web responses"
    fi

    rm -f "$raw_candidates" "$strong_candidates" "$new_hostnames" "$new_roots"
}

run_discovered_domain_enrichment() {
    local ip="$1"
    local result_dir="$2"
    local roots_file="${result_dir}/web/discovered_root_domains.txt"
    local processed_roots="${result_dir}/web/.processed_root_domains"

    touch "$processed_roots"

    if [[ "$WEB_DISCOVER_HOSTNAMES" == "true" ]]; then
        discover_web_domain_context "$ip" "$result_dir"
    fi

    [[ ! -s "$roots_file" ]] && return 0

    while read -r domain; do
        [[ -z "$domain" ]] && continue
        grep -Fxq "$domain" "$processed_roots" && continue
        run_subdomain_enum "$domain" "$result_dir"
        echo "$domain" >> "$processed_roots"
    done < "$roots_file"
}

probe_subdomain_web() {
    local subdomain="$1"
    local result_dir="$2"
    local ports_file="${result_dir}/scans/web_ports.txt"
    local out="${result_dir}/web/subdomain_web_targets.txt"
    local -a probes=("http:80" "https:443" "http:8080" "https:8443")

    local probe
    for probe in "${probes[@]}"; do
        local proto="${probe%%:*}"
        local port="${probe##*:}"
        local url="${proto}://${subdomain}"

        [[ "$port" != "80" && "$port" != "443" ]] && url="${url}:${port}"

        local status
        status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "$url" 2>/dev/null)
        if [[ -n "$status" && "$status" != "000" ]]; then
            echo "[${status}] ${url}" >> "$out"
            echo "$url" >> "$ports_file"
        fi
    done
}

run_subdomain_enum() {
    local domain="$1"
    local result_dir="$2"
    local out="${result_dir}/web/subdomains.txt"
    local resolved_out="${result_dir}/web/subdomains_resolved.txt"
    local web_out="${result_dir}/web/subdomain_web_targets.txt"
    local domain_label
    domain_label=$(sanitize_filename_component "$domain")
    local domain_out="${result_dir}/web/.subdomains_${domain_label}"
    local tmp_found="${result_dir}/web/.subdomains_found"
    local subfinder_out="${result_dir}/web/.subdomains_subfinder"
    local gobuster_out="${result_dir}/web/.subdomains_gobuster"
    local dnsrecon_out="${result_dir}/web/.subdomains_dnsrecon"
    local sub_wordlist
    sub_wordlist=$(get_subdomain_wordlist "$result_dir")
    local temp_wordlist="${result_dir}/web/.subdomains_wordlist"

    [[ -z "$domain" ]] && return 0

    sub_header "Subdomain Enumeration: ${domain}"

    : > "$tmp_found"
    : > "$subfinder_out"
    : > "$gobuster_out"
    : > "$dnsrecon_out"

    local -a enum_pids=()

    if command -v subfinder &>/dev/null; then
        log_scan "Passive discovery with subfinder..."
        local -a subfinder_cmd=(timeout "$TOOL_TIMEOUT" subfinder -d "$domain" -silent -all -recursive)
        log_command_preview "${subfinder_cmd[@]}"
        "${subfinder_cmd[@]}" \
            > "$subfinder_out" 2>/dev/null &
        enum_pids+=("$!")
    else
        log_info "subfinder not installed; skipping passive subdomain discovery"
    fi

    if [[ -n "$sub_wordlist" && -f "$sub_wordlist" ]]; then
        local wl_lines
        wl_lines=$(wc -l < "$sub_wordlist" 2>/dev/null || echo "?")
        log_scan "Active DNS brute force with $(basename "$sub_wordlist") (${wl_lines} entries)..."

        if command -v gobuster &>/dev/null; then
            local -a gobuster_dns_cmd=(timeout "$TOOL_TIMEOUT" gobuster dns -d "$domain" -w "$sub_wordlist" -q)
            log_command_preview "${gobuster_dns_cmd[@]}"
            "${gobuster_dns_cmd[@]}" \
                > "$gobuster_out" 2>/dev/null &
            enum_pids+=("$!")
        fi

        if command -v dnsrecon &>/dev/null && [[ "$SCAN_MODE" != "quick" ]]; then
            local -a dnsrecon_cmd=(timeout "$TOOL_TIMEOUT" dnsrecon -d "$domain" -D "$sub_wordlist" -t brt)
            log_command_preview "${dnsrecon_cmd[@]}"
            "${dnsrecon_cmd[@]}" \
                > "$dnsrecon_out" 2>/dev/null &
            enum_pids+=("$!")
        fi
    else
        log_info "SecLists DNS wordlist not found; skipping active brute force"
    fi

    if [[ ${#enum_pids[@]} -gt 0 ]]; then
        local pid
        for pid in "${enum_pids[@]}"; do
            wait "$pid" 2>/dev/null
        done
    else
        log_warn "No subdomain enumeration tool available"
    fi

    cat "$subfinder_out" >> "$tmp_found" 2>/dev/null
    local domain_regex="${domain//./\\.}"
    grep -h -oE "([A-Za-z0-9_-]+\\.)+${domain_regex}" "$gobuster_out" "$dnsrecon_out" 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | sed 's/\.$//' >> "$tmp_found"

    touch "$out" "$resolved_out" "$web_out"
    sort -u "$tmp_found" | grep -v "^${domain}$" > "$domain_out"
    rm -f "$tmp_found" "$subfinder_out" "$gobuster_out" "$dnsrecon_out"

    # Fast bulk resolution with dnsx (drops dead brute-force / wildcard noise).
    if command -v dnsx &>/dev/null && [[ -s "$domain_out" ]]; then
        local dnsx_live="${domain_out}.live"
        timeout "$TOOL_TIMEOUT" dnsx -silent -l "$domain_out" -o "$dnsx_live" 2>/dev/null
        if [[ -s "$dnsx_live" ]]; then
            sort -u "$dnsx_live" -o "$domain_out"
            log_info "dnsx confirmed $(wc -l < "$domain_out") resolvable subdomain(s)"
        fi
        rm -f "$dnsx_live"
    fi

    local sub_count
    sub_count=$(wc -l < "$domain_out" 2>/dev/null || echo 0)
    if [[ "$sub_count" -eq 0 ]]; then
        log_info "No subdomains discovered for ${domain}"
        rm -f "$domain_out"
        [[ "$sub_wordlist" == "$temp_wordlist" ]] && rm -f "$sub_wordlist" 2>/dev/null
        return 0
    fi

    log_success "Discovered ${sub_count} subdomain(s)"
    cat "$domain_out" >> "$out"
    dedup_file "$out"

    local -a probe_pids=()
    while read -r subdomain; do
        [[ -z "$subdomain" ]] && continue
        local ips
        ips=$(resolve_host_ips "$subdomain" | paste -sd, -)
        [[ -n "$ips" ]] && echo "${subdomain} ${ips}" >> "$resolved_out"

        throttle_jobs "$ENUM_MAX_JOBS"
        probe_subdomain_web "$subdomain" "$result_dir" &
        probe_pids+=("$!")
    done < "$domain_out"

    local pid
    for pid in "${probe_pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    dedup_file "$resolved_out"
    dedup_file "$web_out"
    dedup_file "${result_dir}/scans/web_ports.txt"

    persist_discovered_web_inventory "$ip" "$result_dir" "$domain_out"
    rm -f "$domain_out"
    [[ "$sub_wordlist" == "$temp_wordlist" ]] && rm -f "$sub_wordlist" 2>/dev/null

    if [[ -s "$web_out" ]]; then
        log_success "Subdomain web targets discovered:"
        head -20 "$web_out" | while read -r line; do
            [[ -n "$line" ]] && print_found "$line"
        done
    fi
}

# ── Technology Fingerprint ──
web_fingerprint() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/fingerprint_${base_name}.txt"
    local robots_tmp="${result_dir}/web/.robots_${base_name}"
    local sitemap_tmp="${result_dir}/web/.sitemap_${base_name}"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "Fingerprinting: ${WEB_CTX_DISPLAY_URL}"
    {
        echo "=== Web Fingerprint - ${WEB_CTX_DISPLAY_URL} ==="
        echo ""
        
        # HTTP Headers
        echo "--- HTTP Headers ---"
        curl -skIL -m 10 "${WEB_CTX_CURL_ARGS[@]}" "$WEB_CTX_CURL_URL" 2>/dev/null
        echo ""
        
        # WhatWeb
        if command -v whatweb &>/dev/null; then
            echo "--- WhatWeb ---"
            if [[ "$WEB_CTX_TOOL_URL" == "$WEB_CTX_DISPLAY_URL" ]]; then
                whatweb -a 3 "$WEB_CTX_DISPLAY_URL" 2>/dev/null
            else
                whatweb -a 3 "$WEB_CTX_ORIGINAL_URL" 2>/dev/null
            fi
            echo ""
        fi
        
        # robots.txt
        echo "--- robots.txt ---"
        local robots
        local robots_status
        robots_status=$(curl -sk -m 5 "${WEB_CTX_CURL_ARGS[@]}" -o "$robots_tmp" -w '%{http_code}' "${WEB_CTX_DISPLAY_URL%/}/robots.txt" 2>/dev/null)
        robots=$(cat "$robots_tmp" 2>/dev/null)
        if [[ "$robots_status" =~ ^20[0-9]$ ]] && [[ -n "$robots" ]]; then
            echo "$robots"
            # Extract paths from robots.txt for extra probing/fuzzing.
            extract_hint_paths_from_robots "$robots" >> "${result_dir}/web/extra_paths.txt"
            print_found "robots.txt found - paths extracted"
        else
            echo "Not found (HTTP ${robots_status:-000})"
        fi
        echo ""
        
        # sitemap.xml
        echo "--- sitemap.xml ---"
        curl -sk -m 5 "${WEB_CTX_CURL_ARGS[@]}" "${WEB_CTX_DISPLAY_URL%/}/sitemap.xml" 2>/dev/null | tee "$sitemap_tmp" | head -50
        echo ""

    } > "$out" 2>&1

    if [[ -s "$sitemap_tmp" ]]; then
        extract_hint_paths_from_sitemap "$(cat "$sitemap_tmp" 2>/dev/null)" >> "${result_dir}/web/extra_paths.txt"
        extract_hostnames_from_stream < "$sitemap_tmp" >> "${result_dir}/web/discovered_hostnames.txt"
        dedup_file "${result_dir}/web/discovered_hostnames.txt"
    fi
    
    # Detect technology for smart extension selection
    local tech=""
    local headers
    headers=$(curl -skI -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$WEB_CTX_CURL_URL" 2>/dev/null)
    
    if echo "$headers" | grep -qi "php\|x-powered-by.*php"; then
        tech="php"
    elif echo "$headers" | grep -qi "asp\.net\|asp"; then
        tech="asp"
    elif echo "$headers" | grep -qi "java\|tomcat\|jsp"; then
        tech="java"
    elif echo "$headers" | grep -qi "python\|django\|flask"; then
        tech="python"
    elif echo "$headers" | grep -qi "node\|express"; then
        tech="node"
    fi
    
    echo "$tech" > "${result_dir}/web/detected_tech.txt"
    [[ -n "$tech" ]] && log_info "Detected technology: ${tech}"
    rm -f "$robots_tmp" "$sitemap_tmp"
    log_success "Fingerprint → ${out}"
}

# ── Get smart extensions based on tech ──
get_extensions() {
    local tech_file="$1"
    local tech=""
    [[ -f "$tech_file" ]] && tech=$(cat "$tech_file")
    
    case "$tech" in
        php)    echo "php,phtml,php5,phps,inc,bak,txt,html,old,conf,zip,log,sql" ;;
        asp)    echo "asp,aspx,config,bak,html,txt,old,zip" ;;
        java)   echo "jsp,do,action,html,xml,properties,bak,txt,war,jar" ;;
        python) echo "py,html,txt,json,yaml,yml,bak,conf,cfg,db" ;;
        node)   echo "js,json,html,txt,bak,env,config" ;;
        *)      echo "$FUZZ_EXTENSIONS" ;;
    esac
}

is_static_asset_path() {
    local path="$1"
    [[ "$path" =~ \.(css|js|png|jpe?g|gif|ico|svg|woff2?|woff|ttf|eot|otf|map|mp4|mp3|webm|pdf|zip|tar|gz|bz2|7z)$ ]]
}

normalize_hint_path() {
    local raw="$1"
    raw=$(echo "$raw" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ -z "$raw" ]] && return 1

    raw="${raw#Allow: }"
    raw="${raw#Disallow: }"
    raw="${raw#allow: }"
    raw="${raw#disallow: }"
    raw="${raw%%#*}"
    raw="${raw%%\?*}"
    raw="${raw%\"}"
    raw="${raw#\"}"
    raw="${raw%\'}"
    raw="${raw#\'}"

    [[ -z "$raw" || "$raw" == "/" || "$raw" == "#" || "$raw" == "*" ]] && return 1
    [[ "$raw" =~ ^(mailto:|javascript:|tel:) ]] && return 1

    if [[ "$raw" =~ ^https?://[^/]+(/.*)$ ]]; then
        raw="${BASH_REMATCH[1]}"
    fi

    raw="${raw#./}"
    while [[ "$raw" == ../* ]]; do
        raw="${raw#../}"
    done
    raw="${raw#/}"

    [[ -z "$raw" ]] && return 1
    is_static_asset_path "$raw" && return 1

    echo "$raw"
}

extract_hint_paths_from_robots() {
    local robots_content="$1"
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '\r')
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        if [[ "$line" =~ ^[[:space:]]*(Allow|Disallow):[[:space:]]*(.+)$ ]]; then
            normalize_hint_path "${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^[[:space:]]*/[^[:space:]]* ]]; then
            normalize_hint_path "$(echo "$line" | awk '{print $1}')"
        fi
    done <<< "$robots_content"
}

extract_hint_paths_from_body() {
    local body="$1"
    echo "$body" | grep -oP '(?:href|src|action)=["'"'"']\K[^"'"'"']+' 2>/dev/null | while read -r path; do
        normalize_hint_path "$path"
    done
}

extract_hint_paths_from_sitemap() {
    local sitemap_content="$1"
    echo "$sitemap_content" | grep -oE 'https?://[^<"[:space:]]+' 2>/dev/null | while read -r path; do
        normalize_hint_path "$path"
    done
}

build_api_probe_wordlist() {
    local result_dir="$1"
    local out="${result_dir}/web/.api_probe_wordlist"
    local builtin_out="${result_dir}/web/.api_probe_builtin"
    local seclists_api="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"

    cat > "$builtin_out" <<'EOF'
api
api/
api/v1
api/v2
api/v3
api/docs
api/doc
api/swagger
api/swagger.json
api/openapi.json
api/openapi.yaml
api/graphql
api/graphiql
api/api-docs
rest
rest/v1
rest/v2
v1
v2
graphql
graphiql
swagger
swagger.json
swagger.yaml
swagger-ui
swagger-ui.html
api-docs
openapi.json
openapi.yaml
.well-known/openapi.json
.well-known/ai-plugin.json
EOF

    cp "$builtin_out" "$out"

    if [[ -f "$seclists_api" ]]; then
        cat "$seclists_api" >> "$out"
    fi

    if [[ -f "${result_dir}/web/extra_paths.txt" ]]; then
        grep -iE '(api|graphql|swagger|openapi|rest|v[0-9]+)' "${result_dir}/web/extra_paths.txt" 2>/dev/null >> "$out" || true
    fi

    sort -u "$out" -o "$out"
    printf '%s\n' "$out"
}

record_api_discovery() {
    local result_dir="$1"
    local full_url="$2"
    local status="$3"
    local out_file="$4"
    local api_inventory="${result_dir}/web/api_inventory.txt"
    local api_paths="${result_dir}/web/extra_paths.txt"
    local relative_path=""

    [[ -z "$full_url" || -z "$status" ]] && return 0
    printf '[%s] %s\n' "$status" "$full_url" >> "$out_file"
    printf '[%s] %s\n' "$status" "$full_url" >> "$api_inventory"

    relative_path=$(normalize_hint_path "$full_url" 2>/dev/null || true)
    [[ -n "$relative_path" ]] && printf '%s\n' "$relative_path" >> "$api_paths"
}

probe_hinted_paths() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name
    base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local hints_file="${result_dir}/web/extra_paths.txt"
    local out="${result_dir}/web/hinted_paths_${base_name}.txt"

    [[ ! -f "$hints_file" ]] && return 0

    prepare_web_target_context "$url" "$ip" "$result_dir"

    local origin
    origin=$(echo "$WEB_CTX_DISPLAY_URL" | sed -E 's#(https?://[^/]+).*#\1#')
    local base_dir="${WEB_CTX_DISPLAY_URL%/}"
    [[ "$base_dir" == "$origin" ]] || base_dir="${base_dir%/*}"

    : > "$out"
    while read -r rel_path; do
        [[ -z "$rel_path" ]] && continue

        local target_url=""
        if [[ "$rel_path" == /* ]]; then
            target_url="${origin}${rel_path}"
        else
            target_url="${base_dir}/${rel_path}"
        fi

        local status
        status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$target_url" 2>/dev/null)
        case "$status" in
            200|204|301|302|307|401|403|405)
                printf '[%s] %s\n' "$status" "$target_url" >> "$out"
                ;;
        esac
    done < <(sed '/^[[:space:]]*$/d' "$hints_file" | sort -u)

    local count
    count=$(awk 'NF' "$out" 2>/dev/null | wc -l)
    if [[ "$count" -gt 0 ]]; then
        log_success "Hinted paths discovered ${count} reachable path(s) → ${out}"
        head -10 "$out" | while read -r line; do
            print_found "$line"
        done
    else
        rm -f "$out"
    fi
}

run_quick_path_probe() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name
    base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/quick_hits_${base_name}.txt"
    local extra_paths="${result_dir}/web/extra_paths.txt"
    local -a candidates=(
        "admin"
        "login"
        "uploads"
        "upload"
        "secrets"
        "secret"
        "hidden"
        "private"
        "backup"
        "backups"
        "dev"
        "test"
        "old"
        "archive"
        "recovery.php"
        "recovery"
        ".git"
        ".env"
    )

    prepare_web_target_context "$url" "$ip" "$result_dir"

    : > "$out"
    for candidate in "${candidates[@]}"; do
        local target_url="${WEB_CTX_DISPLAY_URL%/}/${candidate}"
        local status
        status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$target_url" 2>/dev/null)
        case "$status" in
            200|204|301|302|307|401|403|405)
                printf '[%s] %s\n' "$status" "$target_url" >> "$out"
                printf '%s\n' "$candidate" >> "$extra_paths"
                if [[ "$status" =~ ^30[127]$ ]]; then
                    local redirect_url
                    redirect_url=$(curl -sk -o /dev/null -w '%{redirect_url}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$target_url" 2>/dev/null)
                    if [[ -n "$redirect_url" ]]; then
                        local redirect_status
                        redirect_status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$redirect_url" 2>/dev/null)
                        case "$redirect_status" in
                            200|204|301|302|307|401|403|405)
                                printf '[%s] %s\n' "$redirect_status" "$redirect_url" >> "$out"
                                local redirect_path
                                redirect_path=$(echo "$redirect_url" | sed -E 's#^[a-z]+://[^/]+/?##')
                                redirect_path="${redirect_path%%[\?#]*}"
                                [[ -n "$redirect_path" ]] && printf '%s\n' "$redirect_path" >> "$extra_paths"
                                ;;
                        esac
                    fi
                fi
                ;;
        esac
    done

    dedup_file "$out"
    dedup_file "$extra_paths"

    local count
    count=$(awk 'NF' "$out" 2>/dev/null | wc -l)
    if [[ "$count" -gt 0 ]]; then
        log_success "Quick path probe found ${count} hit(s) → ${out}"
        head -10 "$out" | while read -r line; do
            print_found "$line"
        done
    else
        rm -f "$out"
    fi
}

# ── Get wordlist for CMS-specific fuzzing ──
get_cms_wordlist() {
    local cms_name="$1"
    local cms_file="${CMS_WORDLIST_DIR}/${cms_name}-all-levels.txt"
    if [[ -f "$cms_file" ]]; then
        echo "$cms_file"
    else
        echo ""
    fi
}

# ── Run CMS-specific fuzz with dedicated wordlist ──
fuzz_cms() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local cms_name="$4"
    local base_name
    base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local cms_wl
    cms_wl=$(get_cms_wordlist "$cms_name")
    
    if [[ -n "$cms_wl" ]] && [[ -f "$cms_wl" ]]; then
        prepare_web_target_context "$url" "$ip" "$result_dir"
        local wl_lines=$(wc -l < "$cms_wl")
        local tool
        tool=$(resolve_web_fuzz_tool "$url" "$ip" "$result_dir") || {
            log_warn "No fuzzing tool available for CMS fuzz"
            return 0
        }
        log_scan "CMS fuzz (${tool}): ${cms_name} wordlist (${wl_lines} entries)"

        local out_txt="${result_dir}/web/cms_fuzz_${cms_name}_${base_name}.txt"
        local out_json="${result_dir}/web/cms_fuzz_${cms_name}_${base_name}.json"
        rm -f "$out_txt" "$out_json"

        case "$tool" in
            feroxbuster)
                local -a cms_cmd=(timeout -k 5 "$TOOL_TIMEOUT" feroxbuster
                    -u "$WEB_CTX_TOOL_URL" -w "$cms_wl"
                    --depth 2 --threads "$FUZZ_THREADS"
                    "${WEB_CTX_FEROX_ARGS[@]}"
                    --filter-status 404 --no-state --silent --quiet)
                log_command_preview "${cms_cmd[@]}"
                "${cms_cmd[@]}" \
                    > "$out_txt" 2>/dev/null
                ;;
            gobuster)
                local -a cms_cmd=(timeout -k 5 "$TOOL_TIMEOUT" gobuster dir
                    -u "$WEB_CTX_TOOL_URL" -w "$cms_wl" -t "$FUZZ_THREADS"
                    "${WEB_CTX_GOBUSTER_ARGS[@]}"
                    --no-error -e -q -o "$out_txt")
                log_command_preview "${cms_cmd[@]}"
                "${cms_cmd[@]}" 2>/dev/null
                ;;
            ffuf)
                local -a cms_cmd=(ffuf
                    -u "${WEB_CTX_TOOL_URL%/}/FUZZ"
                    -w "$cms_wl"
                    -mc 200,204,301,302,307,401,403,405
                    -fc 404
                    -ac
                    -ach
                    -t "$FUZZ_THREADS"
                    -maxtime "$TOOL_TIMEOUT"
                    -recursion
                    -recursion-depth 2
                    "${WEB_CTX_FFUF_ARGS[@]}"
                    -o "$out_json"
                    -of json)
                log_command_preview "${cms_cmd[@]}"
                "${cms_cmd[@]}" 2>/dev/null
                ;;
        esac

        local found=0
        local output_path=""
        if [[ -f "$out_txt" ]]; then
            found=$(awk 'NF' "$out_txt" 2>/dev/null | wc -l)
            output_path=$(basename "$out_txt")
        elif [[ -f "$out_json" ]]; then
            found=$(grep -c '"url"' "$out_json" 2>/dev/null || echo 0)
            output_path=$(basename "$out_json")
        fi

        if (( found > 0 )); then
            log_success "CMS fuzz found ${found} paths → ${output_path}"
        else
            log_info "CMS fuzz found no paths for ${cms_name}"
        fi
    else
        log_info "No CMS wordlist for ${cms_name}"
    fi
}

# ── CMS Detection & Auto Scan ──
detect_and_scan_cms() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name
    base_name=$(echo "$url" | sed 's|[:/]|_|g')

    prepare_web_target_context "$url" "$ip" "$result_dir"

    local body
    body=$(curl -sk -m 10 "${WEB_CTX_CURL_ARGS[@]}" "$WEB_CTX_CURL_URL" 2>/dev/null)
    
    # WordPress
    if echo "$body" | grep -qi "wp-content\|wp-includes\|wordpress"; then
        print_found "WordPress detected!"
        log_scan "Running WPScan..."
        local out="${result_dir}/web/wpscan_${base_name}.txt"
        if command -v wpscan &>/dev/null; then
            local -a wpscan_cmd=(timeout 300 wpscan --url "$url" --enumerate ap,at,u --no-banner --random-user-agent)
            log_command_preview "${wpscan_cmd[@]}"
            "${wpscan_cmd[@]}" 2>/dev/null > "$out"
            log_success "WPScan → ${out}"
        else
            log_warn "wpscan not installed"
        fi
        fuzz_cms "$url" "$ip" "$result_dir" "wordpress"
        return 0
    fi
    
    # Joomla
    if echo "$body" | grep -qi "joomla\|com_content"; then
        print_found "Joomla detected!"
        if command -v joomscan &>/dev/null; then
            log_scan "Running joomscan..."
            local -a joomscan_cmd=(timeout 300 joomscan --url "$url")
            log_command_preview "${joomscan_cmd[@]}"
            "${joomscan_cmd[@]}" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' > "${result_dir}/web/joomscan_${base_name}.txt"
            log_success "joomscan → ${result_dir}/web/joomscan_${base_name}.txt"
        fi
        local target_host
        local target_port
        target_host=$(echo "$url" | sed -E 's#https?://([^/:]+).*#\1#')
        target_port=$(echo "$url" | sed -nE 's#https?://[^/:]+:([0-9]+).*#\1#p')
        [[ -z "$target_port" ]] && target_port=$([[ "$url" == https://* ]] && echo 443 || echo 80)
        local -a joomla_cmd=(nmap -p "$target_port" --script http-joomla-brute -Pn "$target_host")
        log_command_preview "${joomla_cmd[@]}"
        "${joomla_cmd[@]}" > "${result_dir}/web/joomla_${base_name}.txt" 2>/dev/null
        fuzz_cms "$url" "$ip" "$result_dir" "joomla"
        return 0
    fi
    
    # Drupal
    if echo "$body" | grep -qi "drupal\|sites/default"; then
        print_found "Drupal detected!"
        if command -v droopescan &>/dev/null; then
            droopescan scan drupal -u "$url" > "${result_dir}/web/drupal_${base_name}.txt" 2>/dev/null
        fi
        fuzz_cms "$url" "$ip" "$result_dir" "drupal"
        return 0
    fi
    
    # Magento
    if echo "$body" | grep -qi "magento\|mage\|varien"; then
        print_found "Magento detected!"
        fuzz_cms "$url" "$ip" "$result_dir" "magento"
        return 0
    fi
    
    # Laravel
    if echo "$body" | grep -qi "laravel\|csrf-token"; then
        print_found "Laravel detected!"
        fuzz_cms "$url" "$ip" "$result_dir" "laravel"
        return 0
    fi
    
    # Tomcat
    if echo "$body" | grep -qi "tomcat\|apache-tomcat"; then
        print_found "Tomcat detected!"
        fuzz_cms "$url" "$ip" "$result_dir" "tomcat"
        return 0
    fi
    
    return 1
}

# ── Nikto Scan ──
run_nikto() {
    local url="$1"
    local result_dir="$2"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    
    if ! command -v nikto &>/dev/null; then return; fi
    
    sub_header "Nikto Scan: ${url}"
    log_scan "Running nikto (this may take a while)..."

    local -a nikto_cmd=(timeout -k 10 "$TOOL_TIMEOUT" nikto -host "$url" -Format txt -nointeractive -ask no -nocheck -output "${result_dir}/web/nikto_${base_name}")
    log_command_preview "${nikto_cmd[@]}"
    "${nikto_cmd[@]}" >/dev/null 2>&1 &
    
    local nikto_pid=$!
    NIKTO_PIDS+=("$nikto_pid")
    log_info "Nikto running in background (PID: ${nikto_pid})"
}

# ── Select wordlist based on scan mode ──
get_fuzz_wordlist() {
    case "$SCAN_MODE" in
        quick)  echo "$WORDLIST_WEB_SMALL" ;;  # ~4K lines
        full)   echo "$WORDLIST_WEB_BIG" ;;    # ~1.2M lines
        *)      echo "$WORDLIST_WEB" ;;        # ~220K lines (default)
    esac
}

resolve_web_fuzz_tool() {
    local url="${1:-}"
    local ip="${2:-}"
    local result_dir="${3:-}"
    local requested="${WEB_FUZZ_TOOL:-auto}"

    if [[ -n "$url" && -n "$ip" && -n "$result_dir" ]]; then
        prepare_web_target_context "$url" "$ip" "$result_dir"
        if [[ "$WEB_CTX_NEEDS_HOST_OVERRIDE" == "true" ]] && [[ "$WEB_CTX_TOOL_URL" == "$WEB_CTX_ORIGINAL_URL" ]]; then
            if command -v ffuf &>/dev/null; then
                if [[ "$requested" != "auto" && "$requested" != "ffuf" ]]; then
                    log_warn "Overriding web fuzz tool to ffuf for hostname-aware probing of ${WEB_CTX_DISPLAY_URL}" >&2
                fi
                echo "ffuf"
                return 0
            fi
            log_warn "Hostname-aware probing needed for ${WEB_CTX_DISPLAY_URL}, but ffuf is not installed; falling back to available tool" >&2
        fi
    fi

    if [[ "$requested" != "auto" ]]; then
        if command -v "$requested" &>/dev/null; then
            echo "$requested"
            return 0
        fi
        log_warn "Configured web fuzz tool '${requested}' is not installed, falling back to auto" >&2
    fi

    local tool
    for tool in feroxbuster gobuster ffuf; do
        if command -v "$tool" &>/dev/null; then
            echo "$tool"
            return 0
        fi
    done

    return 1
}

extract_urls_from_fuzz_artifact() {
    local artifact="$1"
    local base_url="${2:-}"

    [[ ! -f "$artifact" ]] && return 0

    if [[ "$artifact" == *.json ]]; then
        grep -oE 'https?://[^"]+' "$artifact" 2>/dev/null
        return 0
    fi

    grep -oE 'https?://[^[:space:]]+' "$artifact" 2>/dev/null

    if [[ -n "$base_url" ]]; then
        awk '
            match($0, /^\/[^[:space:]]+/) {
                print substr($0, RSTART, RLENGTH)
            }
        ' "$artifact" 2>/dev/null | while read -r path; do
            printf '%s/%s\n' "${base_url%/}" "${path#/}"
        done
    fi
}

get_primary_fuzz_artifact() {
    local result_dir="$1"
    local base_name="$2"
    local preferred_tool=""
    local marker_file="${result_dir}/web/fuzz_engine_${base_name}.txt"

    [[ -f "$marker_file" ]] && preferred_tool=$(head -1 "$marker_file" 2>/dev/null)

    case "$preferred_tool" in
        feroxbuster)
            [[ -f "${result_dir}/web/feroxbuster_${base_name}.txt" ]] && {
                echo "${result_dir}/web/feroxbuster_${base_name}.txt"
                return 0
            }
            ;;
        gobuster)
            [[ -f "${result_dir}/web/gobuster_d0_${base_name}.txt" ]] && {
                echo "${result_dir}/web/gobuster_d0_${base_name}.txt"
                return 0
            }
            ;;
        ffuf)
            [[ -f "${result_dir}/web/ffuf_${base_name}.json" ]] && {
                echo "${result_dir}/web/ffuf_${base_name}.json"
                return 0
            }
            ;;
    esac

    local candidate
    for candidate in \
        "${result_dir}/web/feroxbuster_${base_name}.txt" \
        "${result_dir}/web/gobuster_d0_${base_name}.txt" \
        "${result_dir}/web/ffuf_${base_name}.json"
    do
        [[ -f "$candidate" ]] && {
            echo "$candidate"
            return 0
        }
    done

    return 1
}

emit_ffuf_match_line() {
    local json_line="$1"
    local pretty
    pretty=$(echo "$json_line" | sed -nE 's/.*"status":([0-9]+).*"url":"([^"]+)".*/[\1] \2/p')
    [[ -n "$pretty" ]] && printf '%s\n' "$pretty"
}

resolve_gobuster_next_url() {
    local current_url="$1"
    local result_line
    # Strip ANSI escape codes
    result_line=$(echo "$2" | sed 's/\x1b\[[0-9;]*m//g')

    local first_field
    first_field=$(echo "$result_line" | awk '{print $1}')
    [[ -z "$first_field" ]] && return 1

    local redirect_target
    redirect_target=$(echo "$result_line" | sed -nE 's#.*\[--> ([^]]+)\].*#\1#p')

    local next_url=""
    if [[ -n "$redirect_target" ]]; then
        if [[ "$redirect_target" =~ ^https?:// ]]; then
            next_url="$redirect_target"
        elif [[ "$redirect_target" == /* ]]; then
            next_url="${current_url%/}${redirect_target}"
        else
            next_url="${current_url%/}/${redirect_target#/}"
        fi
    elif [[ "$first_field" =~ ^https?:// ]]; then
        next_url="$first_field"
    else
        next_url="${current_url%/}/${first_field#/}"
    fi

    # Security check: Ensure next_url is within the same host/domain to avoid out-of-scope fuzzing
    local current_host
    current_host=$(echo "$current_url" | sed -E 's#https?://([^/]+).*#\1#')
    local next_host
    next_host=$(echo "$next_url" | sed -E 's#https?://([^/]+).*#\1#')

    if [[ "$current_host" != "$next_host" ]]; then
        return 1
    fi

    printf '%s\n' "$next_url"
}

emit_live_fuzz_hit_once() {
    local seen_file="$1"
    local message="$2"

    [[ -z "$message" ]] && return 0
    touch "$seen_file"
    grep -Fxq -- "$message" "$seen_file" 2>/dev/null && return 0
    printf '%s\n' "$message" >> "$seen_file"
    print_found "$message"
}

# ── Directory Fuzzing (Core Recursive) ──
run_dir_fuzzing() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local live_seen="${result_dir}/web/.fuzz_live_${base_name}.seen"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "Directory Fuzzing: ${WEB_CTX_DISPLAY_URL}"
    if [[ "$WEB_CTX_DISPLAY_URL" != "$url" ]]; then
        log_info "Using hostname-aware probing via ${WEB_CTX_REQUEST_HOST} while connecting to ${WEB_CTX_ORIGINAL_HOST}"
    fi
    
    local extensions
    extensions=$(get_extensions "${result_dir}/web/detected_tech.txt")
    
    # Select wordlist by scan mode
    local wordlist
    wordlist=$(get_fuzz_wordlist)
    local wl_lines=$(wc -l < "$wordlist" 2>/dev/null || echo "?")
    find "${result_dir}/web" -maxdepth 1 -type f \
        \( -name "feroxbuster_${base_name}.txt" \
        -o -name "ffuf_${base_name}.json" \
        -o -name "gobuster_d*_${base_name}*.txt" \
        -o -name "fuzz_engine_${base_name}.txt" \
        -o -name ".fuzz_live_${base_name}.seen" \) -delete 2>/dev/null

    local tool
    tool=$(resolve_web_fuzz_tool "$url" "$ip" "$result_dir") || {
        log_error "No fuzzing tool found (install feroxbuster, gobuster, or ffuf)"
        return
    }
    printf '%s\n' "$tool" > "${result_dir}/web/fuzz_engine_${base_name}.txt"

    case "$tool" in
        feroxbuster)
            log_scan "feroxbuster (wordlist: $(basename "$wordlist") [${wl_lines} lines], depth: ${RECURSION_DEPTH})"

            local -a fuzz_cmd=(timeout -k 5 "$TOOL_TIMEOUT" feroxbuster
                -u "$WEB_CTX_TOOL_URL"
                -w "$wordlist"
                --depth "$RECURSION_DEPTH"
                --threads "$FUZZ_THREADS"
                --filter-status 404
                --no-state
                --extract-links
                --auto-tune
                --collect-extensions
                "${WEB_CTX_FEROX_ARGS[@]}"
                -x "$extensions"
                --silent)
            log_command_preview "${fuzz_cmd[@]}"
            "${fuzz_cmd[@]}" \
                2>/dev/null | tee "${result_dir}/web/feroxbuster_${base_name}.txt" | while read -r line; do
                    emit_live_fuzz_hit_once "$live_seen" "$line"
                done

            if [[ -f "${result_dir}/web/feroxbuster_${base_name}.txt" ]]; then
                local count
                count=$(awk 'NF' "${result_dir}/web/feroxbuster_${base_name}.txt" 2>/dev/null | wc -l)
                if [[ $count -gt 0 ]]; then
                    log_success "feroxbuster found ${count} results → ${result_dir}/web/feroxbuster_${base_name}.txt"
                else
                    log_info "feroxbuster found no results"
                fi
            fi
            ;;
        gobuster)
            log_scan "gobuster + recursive crawl (depth: ${RECURSION_DEPTH})"
            _gobuster_recursive "$url" "$ip" "$result_dir" "$base_name" "$wordlist" "$extensions" 0
            ;;
        ffuf)
            log_scan "ffuf directory scan (wordlist: $(basename "$wordlist") [${wl_lines} lines], depth: ${RECURSION_DEPTH})"

            local out_json="${result_dir}/web/ffuf_${base_name}.json"
            local -a fuzz_cmd=(ffuf
                -u "${WEB_CTX_TOOL_URL%/}/FUZZ"
                -w "$wordlist"
                -mc 200,204,301,302,307,401,403,405
                -fc 404
                -ac
                -ach
                -t "$FUZZ_THREADS"
                -maxtime "$TOOL_TIMEOUT"
                -recursion
                -recursion-depth "$RECURSION_DEPTH"
                -recursion-strategy greedy
                -v
                -noninteractive
                "${WEB_CTX_FFUF_ARGS[@]}"
                -e ".${extensions//,/,.}"
                -o "$out_json"
                -of json)
            log_command_preview "${fuzz_cmd[@]}"
            "${fuzz_cmd[@]}" 2>/dev/null | while read -r line; do
                # Parsing ffuf -v output: [Status: 200, ...] | http://target/path
                local pretty
                pretty=$(echo "$line" | grep -oE '\[Status: [0-9]+.*\] \| https?://[^[:space:]]+')
                if [[ -n "$pretty" ]]; then
                    emit_live_fuzz_hit_once "$live_seen" "$pretty"
                fi
            done
            if [[ -f "$out_json" ]]; then
                local count
                count=$(grep -c '"url"' "$out_json" 2>/dev/null || echo 0)
                if (( count > 0 )); then
                    log_success "ffuf found ${count} results → ${out_json}"
                else
                    log_info "ffuf found no results"
                fi
            fi
            ;;
    esac
}

# ── Gobuster Recursive Implementation ──
_gobuster_recursive() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name="$4"
    local wordlist="$5"
    local extensions="$6"
    local depth="$7"
    
    if (( depth >= RECURSION_DEPTH )); then
        return
    fi
    
    local indent=""
    for ((i=0; i<depth; i++)); do indent+="  "; done
    
    local out="${result_dir}/web/gobuster_d${depth}_${base_name}.txt"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    log_info "${indent}Depth ${depth}: Fuzzing ${WEB_CTX_DISPLAY_URL}"

    local -a gobuster_cmd=(timeout -k 5 "$TOOL_TIMEOUT" gobuster dir
        -u "$WEB_CTX_TOOL_URL"
        -w "$wordlist"
        -t "$FUZZ_THREADS"
        -x "$extensions"
        -s "200,204,301,302,307,401,403,405"
        -b ""
        "${WEB_CTX_GOBUSTER_ARGS[@]}"
        -e
        --no-error
        -q)
    log_command_preview "${gobuster_cmd[@]}"
    "${gobuster_cmd[@]}" \
        2>/dev/null | tee "$out" | while read -r line; do
            emit_live_fuzz_hit_once "${result_dir}/web/.fuzz_live_${base_name}.seen" "${indent}${line}"
        done
    
    if [[ ! -f "$out" ]]; then return; fi
    
    # Find directories to recurse into
    grep -E "Status: (200|301|302|307)" "$out" 2>/dev/null | while read -r line; do
        local status
        status=$(echo "$line" | grep -oP 'Status: \K\d+')

        # Recurse into directories (paths ending with / or 301 redirects)
        local next_url=""
        next_url=$(resolve_gobuster_next_url "$url" "$line")
        [[ -z "$next_url" ]] && continue

        local path_hint
        path_hint=$(echo "$line" | awk '{print $1}')
        if [[ "$path_hint" == */ ]] || [[ "$status" == "301" ]] || [[ "$status" == "302" ]] || [[ "$status" == "307" ]]; then
            local next_name=$(echo "$next_url" | sed 's|[:/]|_|g')
            _gobuster_recursive "$next_url" "$ip" "$result_dir" "$next_name" "$wordlist" "$extensions" $((depth + 1))
        fi
    done
}

# ── Source Code Analysis ──
analyze_source() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/source_analysis_${base_name}.txt"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "Source Analysis: ${WEB_CTX_DISPLAY_URL}"

    local body
    body=$(curl -sk -m 10 "${WEB_CTX_CURL_ARGS[@]}" "$WEB_CTX_CURL_URL" 2>/dev/null)
    
    {
        echo "=== Source Code Analysis - ${WEB_CTX_DISPLAY_URL} ==="
        echo ""
        
        # Extract comments
        echo "--- HTML Comments ---"
        echo "$body" | grep -oP '<!--.*?-->' 2>/dev/null
        echo ""
        
        # Extract URLs/paths
        echo "--- Extracted URLs/Paths ---"
        echo "$body" | grep -oP '(?:href|src|action)=["'"'"']\K[^"'"'"']+' 2>/dev/null | sort -u
        echo ""
        
        # Extract emails
        echo "--- Emails ---"
        echo "$body" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' 2>/dev/null | sort -u
        echo ""
        
        # Extract potential usernames/keywords
        echo "--- Interesting Keywords ---"
        echo "$body" | grep -oiP '(?:user|admin|pass|key|secret|token|api|flag|root|config)[a-zA-Z0-9_]*' 2>/dev/null | sort -u
        echo ""
        
        # JavaScript files
        echo "--- JavaScript Files ---"
        echo "$body" | grep -oP '(?:src)=["'"'"']\K[^"'"'"']*\.js[^"'"'"']*' 2>/dev/null | sort -u
        echo ""
        
    } > "$out" 2>&1
    
    # Extract and queue internal paths for additional probing.
    extract_hint_paths_from_body "$body" | sort -u >> "${result_dir}/web/extra_paths.txt"
    
    log_success "Source analysis → ${out}"
}

generate_random_dns_label() {
    tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c 12
}

collect_http_response_fingerprint() {
    local url="$1"
    shift
    local -a curl_args=("$@")
    local headers_tmp
    local body_tmp
    headers_tmp=$(mktemp /tmp/auto_recon_fp_headers.XXXXXX)
    body_tmp=$(mktemp /tmp/auto_recon_fp_body.XXXXXX)

    local metrics
    metrics=$(curl -sk -m 8 -D "$headers_tmp" -o "$body_tmp" \
        -w '%{http_code}|%{size_download}|%{redirect_url}|%{content_type}' \
        "${curl_args[@]}" "$url" 2>/dev/null || true)

    local status="${metrics%%|*}"
    local remainder="${metrics#*|}"
    local size="${remainder%%|*}"
    remainder="${remainder#*|}"
    local redirect="${remainder%%|*}"
    local content_type="${remainder#*|}"

    if [[ -z "$redirect" ]]; then
        redirect=$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {sub(/\r$/, "", $0); sub(/^[^:]+:[[:space:]]*/, "", $0); print; exit}' "$headers_tmp")
    fi

    local words
    local lines
    words=$(wc -w < "$body_tmp" 2>/dev/null | tr -d '[:space:]')
    lines=$(wc -l < "$body_tmp" 2>/dev/null | tr -d '[:space:]')

    rm -f "$headers_tmp" "$body_tmp"
    printf '%s|%s|%s|%s|%s\n' "${status:-000}" "${words:-0}" "${lines:-0}" "${content_type:-}" "${redirect:-}"
}

collect_vhost_baseline_fingerprints() {
    local url="$1"
    local base_domain="$2"
    local out_file="$3"
    local attempts="${4:-3}"

    : > "$out_file"

    local idx
    for ((idx = 0; idx < attempts; idx++)); do
        local random_label
        random_label="zz$(generate_random_dns_label)"
        local probe_host="${random_label}.${base_domain}"
        collect_http_response_fingerprint "$url" -H "Host: ${probe_host}" >> "$out_file"
    done

    dedup_file "$out_file"
}

get_vhost_base_domains() {
    local result_dir="$1"
    local url_host="$2"
    local roots_file="${result_dir}/web/discovered_root_domains.txt"
    local hostnames_file="${result_dir}/web/discovered_hostnames.txt"

    {
        [[ -n "$TARGET_DOMAIN" ]] && echo "$TARGET_DOMAIN"
        [[ -n "$TARGET_DOMAIN" ]] && apex_domain_from_host "$TARGET_DOMAIN" 2>/dev/null
        [[ ! -f "$roots_file" ]] || cat "$roots_file"
        if [[ -f "$hostnames_file" ]]; then
            while read -r host; do
                [[ -z "$host" ]] && continue
                apex_domain_from_host "$host" 2>/dev/null
            done < "$hostnames_file"
        fi
        if [[ -n "$url_host" ]] && ! is_valid_ip "$url_host"; then
            echo "$url_host"
            apex_domain_from_host "$url_host" 2>/dev/null
        fi
    } | while read -r candidate; do
        [[ -z "$candidate" ]] && continue
        normalize_hostname_candidate "$candidate" 2>/dev/null || true
    done | awk 'NF && !seen[$0]++'
}

# ── VHost Fuzzing ──
run_vhost_fuzzing() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local has_jq=false
    
    if ! command -v ffuf &>/dev/null; then return; fi
    command -v jq &>/dev/null && has_jq=true
    [[ -z "$WORDLIST_DNS" || ! -f "$WORDLIST_DNS" ]] && return
    [[ "$has_jq" != "true" ]] && log_warn "jq not installed; wildcard VHost filtering disabled"

    local url_host
    url_host=$(echo "$url" | sed -E 's#https?://([^/:]+).*#\1#')

    local -a base_domains=()
    while read -r base_domain; do
        [[ -n "$base_domain" ]] && base_domains+=("$base_domain")
    done < <(get_vhost_base_domains "$result_dir" "$url_host")

    [[ ${#base_domains[@]} -eq 0 ]] && {
        log_info "Skipping VHost fuzzing for ${url} (no domain name available)"
        return
    }
    
    sub_header "VHost Fuzzing: ${url}"
    
    local found_any=false
    local base_domain=""
    local vhosts_out="${result_dir}/web/vhosts.txt"
    local existing_vhosts="${result_dir}/web/.vhosts_existing_${base_name}"
    local tmp_new_vhosts="${result_dir}/web/.vhosts_new_${base_name}"
    touch "$vhosts_out"
    cp "$vhosts_out" "$existing_vhosts" 2>/dev/null || : > "$existing_vhosts"
    : > "$tmp_new_vhosts"

    for base_domain in "${base_domains[@]}"; do
        local domain_label
        domain_label=$(sanitize_filename_component "$base_domain")
        local baseline_fp_file="${result_dir}/web/.vhost_fuzz_${base_name}_${domain_label}.baseline"
        local baseline_json_file="${result_dir}/web/.vhost_fuzz_${base_name}_${domain_label}.baseline.json"
        local raw_json="${result_dir}/web/.vhost_fuzz_${base_name}_${domain_label}.raw.json"
        local json_out="${result_dir}/web/vhost_fuzz_${base_name}_${domain_label}.json"
        local raw_count=0
        local filtered_count=0

        if [[ "$has_jq" == "true" ]]; then
            collect_vhost_baseline_fingerprints "$url" "$base_domain" "$baseline_fp_file"
            jq -Rn '[inputs | select(length > 0)]' < "$baseline_fp_file" > "$baseline_json_file"
        fi

        ffuf \
            -u "$url" \
            -H "Host: FUZZ.${base_domain}" \
            -w "$WORDLIST_DNS" \
            -mc 200,301,302,307 \
            -ac \
            -ach \
            -s \
            -noninteractive \
            -t 20 \
            -maxtime 120 \
            -o "$raw_json" \
            -of json \
            2>/dev/null

        if [[ -f "$raw_json" ]]; then
            if [[ "$has_jq" == "true" ]]; then
                raw_count=$(jq '.results | length' "$raw_json" 2>/dev/null || echo 0)
                jq --slurpfile baselines "$baseline_json_file" '
                    .results |= map(
                        select(
                            (
                            [
                                (.status | tostring),
                                (.words | tostring),
                                (.lines | tostring),
                                (.["content-type"] // ""),
                                (.redirectlocation // "")
                                ] | join("|")
                            ) as $fp
                            | ($baselines[0] | index($fp) | not)
                        )
                    )
                ' "$raw_json" > "$json_out" 2>/dev/null || cp "$raw_json" "$json_out"
                filtered_count=$(jq '.results | length' "$json_out" 2>/dev/null || echo 0)

                if (( raw_count > filtered_count )); then
                    log_info "Filtered $((raw_count - filtered_count)) wildcard VHost match(es) for ${base_domain}"
                fi
            else
                cp "$raw_json" "$json_out"
            fi
        fi

        while read -r sub_label; do
            [[ -z "$sub_label" ]] && continue
            local vhost="${sub_label}.${base_domain}"
            echo "$vhost" >> "$vhosts_out"
            if ! grep -Fxq "$vhost" "$existing_vhosts" 2>/dev/null; then
                echo "$vhost" >> "$tmp_new_vhosts"
                found_any=true
            fi
        done < <(
            if [[ "$has_jq" == "true" ]]; then
                jq -r '.results[].input.FUZZ // empty' "$json_out" 2>/dev/null
            else
                grep -oP '"FUZZ"\s*:\s*"\K[^"]+' "$json_out" 2>/dev/null
            fi | awk 'NF && !seen[$0]++'
        )
    done

    if [[ -f "${result_dir}/web/discovered_hostnames.txt" ]]; then
        cat "$tmp_new_vhosts" >> "${result_dir}/web/discovered_hostnames.txt" 2>/dev/null
        dedup_file "${result_dir}/web/discovered_hostnames.txt"
    fi
    dedup_file "$vhosts_out"
    dedup_file "$tmp_new_vhosts"

    if [[ "$found_any" == "true" ]]; then
        while read -r host; do
            [[ -z "$host" ]] && continue
            local root_domain
            root_domain=$(apex_domain_from_host "$host" 2>/dev/null || true)
            [[ -n "$root_domain" ]] && echo "$root_domain" >> "${result_dir}/web/discovered_root_domains.txt"
        done < "$vhosts_out"

        dedup_file "${result_dir}/web/discovered_root_domains.txt"
        build_hosts_suggestions "$ip" "$result_dir"
        sync_discovered_hosts_into_system "$result_dir"
        queue_hostname_web_targets "$ip" "$result_dir"
        canonicalize_web_targets "$ip" "$result_dir"
        log_success "VHost fuzzing discovered $(wc -l < "$tmp_new_vhosts" 2>/dev/null || echo 0) hostname(s)"
    else
        log_info "VHost fuzzing complete (no new hostnames)"
    fi

    rm -f "$existing_vhosts" "$tmp_new_vhosts"
}

# ── SSL/TLS Scan ──
run_ssl_scan() {
    local url="$1"
    local result_dir="$2"
    
    # Only for HTTPS
    [[ "$url" != https://* ]] && return
    
    local host_port=$(echo "$url" | sed 's|https://||' | sed 's|/$||')
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/ssl_${base_name}.txt"
    
    sub_header "SSL/TLS Scan: ${host_port}"
    
    {
        echo "=== SSL/TLS Scan - ${host_port} ==="
        echo ""
        
        # sslscan
        if command -v sslscan &>/dev/null; then
            echo "--- sslscan ---"
            timeout 30 sslscan --no-colour "$host_port" 2>/dev/null
            echo ""
        fi
        
        # nmap ssl scripts (Heartbleed, POODLE, etc.)
        local port=$(echo "$host_port" | grep -oP ':\K\d+' || echo "443")
        local host=$(echo "$host_port" | cut -d: -f1)
        echo "--- Nmap SSL Scripts ---"
        nmap -p "$port" --script="ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-cert,ssl-enum-ciphers" -Pn "$host" 2>/dev/null
        
        # Extract cert info
        echo ""
        echo "--- Certificate Info ---"
        echo | timeout 5 openssl s_client -connect "$host_port" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null
        
    } > "$out" 2>&1
    
    # Check for vulns
    if grep -qi "heartbleed\|VULNERABLE\|poodle\|ccs-injection" "$out" 2>/dev/null; then
        print_found "SSL VULNERABILITY detected! Check ${out}"
    fi
    log_success "SSL scan → ${out}"
}

# ── WAF Detection ──
run_waf_detect() {
    local url="$1"
    local result_dir="$2"
    
    if ! command -v wafw00f &>/dev/null; then return; fi
    
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/waf_${base_name}.txt"
    
    sub_header "WAF Detection: ${url}"
    
    timeout 30 wafw00f "$url" 2>/dev/null | tee "$out"
    
    if grep -Eiq 'is behind|is protected|behind an? .*waf|behind .*waf' "$out" 2>/dev/null && \
       ! grep -Eiq 'no waf detected|no .* detected by the generic detection' "$out" 2>/dev/null; then
        print_found "⚠ WAF DETECTED! Fuzzing may be blocked/rate-limited"
        log_warn "Consider adjusting fuzz threads and adding delays"
    else
        log_info "No WAF detected"
    fi
}

# ── CeWL Custom Wordlist ──
run_cewl() {
    local ip="$1"
    local result_dir="$2"
    
    if ! command -v cewl &>/dev/null; then return; fi
    
    local web_file="${result_dir}/scans/web_ports.txt"
    [[ ! -f "$web_file" ]] && return
    
    sub_header "CeWL Custom Wordlist Generation"
    
    local url
    url=$(head -1 "$web_file")
    [[ -z "$url" ]] && return
    
    log_scan "Crawling ${url} for custom words..."
    
    timeout 120 cewl "$url" -d 2 -m 5 \
        -w "${result_dir}/loot/cewl_wordlist.txt" \
        --email_file "${result_dir}/loot/cewl_emails.txt" \
        2>/dev/null
    
    if [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]]; then
        local wc=$(wc -l < "${result_dir}/loot/cewl_wordlist.txt")
        log_success "CeWL generated ${wc} custom words → cewl_wordlist.txt"
        log_info "Use for brute force: hydra -P cewl_wordlist.txt ..."
    fi
    
    if [[ -f "${result_dir}/loot/cewl_emails.txt" ]] && [[ -s "${result_dir}/loot/cewl_emails.txt" ]]; then
        print_found "Emails found:"
        cat "${result_dir}/loot/cewl_emails.txt"
    fi
}

# ── Default Credential Check ──
check_default_creds() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local out="${result_dir}/web/default_creds.txt"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "Default Credential Check"
    
    {
        echo "=== Default Credential Check - ${WEB_CTX_DISPLAY_URL} ==="
        echo ""
        
        # Common admin paths + default creds
        local -a paths=("admin" "administrator" "manager/html" "phpmyadmin" "wp-login.php" "wp-admin" "login" "admin/login" "user/login" "panel")
        local -a creds=("admin:admin" "admin:password" "admin:123456" "root:root" "root:toor" "test:test" "guest:guest")
        
        for path in "${paths[@]}"; do
            local test_url="${WEB_CTX_DISPLAY_URL%/}/${path}"
            local status
            status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$test_url" 2>/dev/null)
            
            if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" ]]; then
                echo "[${status}] ${test_url}"
                
                # Try default creds on login forms
                if [[ "$status" == "200" ]]; then
                    for cred in "${creds[@]}"; do
                        local user="${cred%%:*}"
                        local pass="${cred##*:}"
                        local login_status
                        login_status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 \
                            "${WEB_CTX_CURL_ARGS[@]}" \
                            -d "username=${user}&password=${pass}&user=${user}&pass=${pass}&login=Login" \
                            "$test_url" 2>/dev/null)
                        if [[ "$login_status" == "302" || "$login_status" == "301" ]]; then
                            echo "  >>> POSSIBLE LOGIN: ${user}:${pass} (redirect ${login_status})"
                        fi
                    done
                fi
            fi
        done
        
        # Tomcat default
        local tomcat_status
        tomcat_status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" -u "tomcat:tomcat" "${WEB_CTX_DISPLAY_URL%/}/manager/html" 2>/dev/null)
        [[ "$tomcat_status" == "200" ]] && echo ">>> TOMCAT DEFAULT: tomcat:tomcat WORKS!"
        
        tomcat_status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" -u "admin:admin" "${WEB_CTX_DISPLAY_URL%/}/manager/html" 2>/dev/null)
        [[ "$tomcat_status" == "200" ]] && echo ">>> TOMCAT: admin:admin WORKS!"
        
        echo ""
    } >> "$out" 2>&1
    
    if grep -qi "POSSIBLE LOGIN\|WORKS" "$out" 2>/dev/null; then
        print_found "Default credentials may work! Check default_creds.txt"
    fi
    log_success "Default creds → ${out}"
}
# ── API Endpoint Discovery ──
run_api_fuzzing() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/api_fuzz_${base_name}.txt"
    local raw_out="${result_dir}/web/.api_fuzz_${base_name}.raw"
    local api_wordlist=""
    local builtin_api_wordlist="${result_dir}/web/.api_probe_builtin"
    local used_ffuf=false

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "API Endpoint Discovery: ${WEB_CTX_DISPLAY_URL}"
    log_scan "Probing API and documentation endpoints..."

    : > "$out"
    : > "$raw_out"
    api_wordlist=$(build_api_probe_wordlist "$result_dir")

    if command -v ffuf &>/dev/null && [[ -f "$api_wordlist" ]]; then
        used_ffuf=true
        local -a api_cmd=(ffuf
            -u "${WEB_CTX_TOOL_URL%/}/FUZZ"
            -w "$api_wordlist"
            -mc 200,204,301,302,307,401,403,405
            -fc 404
            -H "Accept: application/json"
            -ac
            -ach
            "${WEB_CTX_FFUF_ARGS[@]}"
            -t "$FUZZ_THREADS"
            -maxtime "$TOOL_TIMEOUT"
            -s)
        log_command_preview "${api_cmd[@]}"
        "${api_cmd[@]}" > "$raw_out" 2>/dev/null || true

        while read -r line; do
            [[ -z "$line" ]] && continue
            local candidate
            local full_url
            local status
            candidate=$(echo "$line" | awk '{print $1}')
            [[ -z "$candidate" ]] && continue
            if [[ "$candidate" =~ ^https?:// ]]; then
                full_url="$candidate"
            else
                full_url="${WEB_CTX_DISPLAY_URL%/}/${candidate#/}"
            fi
            status=$(echo "$line" | sed -nE 's/.*Status: ([0-9]+).*/\1/p')
            [[ -z "$status" ]] && status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "${WEB_CTX_CURL_ARGS[@]}" "$full_url" 2>/dev/null)
            [[ "$status" =~ ^(200|204|301|302|307|401|403|405)$ ]] || continue
            record_api_discovery "$result_dir" "$full_url" "$status" "$out"
        done < "$raw_out"
    else
        log_info "ffuf not available for API fuzzing; using built-in API path probes"
    fi

    local candidate
    while read -r candidate; do
        [[ -z "$candidate" ]] && continue
        local candidate_url="${WEB_CTX_DISPLAY_URL%/}/${candidate#/}"
        local status
        status=$(curl -sk -o /dev/null -w '%{http_code}' -m 5 \
            -H "Accept: application/json" \
            "${WEB_CTX_CURL_ARGS[@]}" "$candidate_url" 2>/dev/null)
        case "$status" in
            200|204|301|302|307|401|403|405)
                record_api_discovery "$result_dir" "$candidate_url" "$status" "$out"
                ;;
        esac
    done < "$builtin_api_wordlist"

    dedup_file "$out"
    dedup_file "${result_dir}/web/api_inventory.txt"
    dedup_file "${result_dir}/web/extra_paths.txt"
    rm -f "$raw_out"

    local count=$(wc -l < "$out" 2>/dev/null || echo 0)
    if [[ $count -gt 0 ]]; then
        log_success "Discovered ${count} API endpoints → ${out}"
        print_found "Found APIs:"
        head -10 "$out" | while read -r line; do
            echo -e "    ${RED}→ ${line}${NC}"
        done
    elif [[ "$used_ffuf" != "true" ]]; then
        log_info "No reachable API or documentation paths found with built-in probes"
    fi

    rm -f "$api_wordlist" "$builtin_api_wordlist"
}
# ── Parameter Discovery (ffuf/wfuzz based) ──
run_param_fuzz() {
    local url="$1"
    local ip="$2"
    local result_dir="$3"
    local base_name=$(echo "$url" | sed 's|[:/]|_|g')
    local out="${result_dir}/web/params_${base_name}.txt"

    prepare_web_target_context "$url" "$ip" "$result_dir"

    sub_header "Parameter Discovery: ${WEB_CTX_DISPLAY_URL}"
    
    # Built-in common parameters
    local param_wordlist="${result_dir}/web/.param_list.txt"
    cat > "$param_wordlist" << 'PARAMS'
id
page
file
url
path
dir
search
category
cmd
exec
command
ping
query
redirect
out
view
name
user
username
password
pass
email
type
action
callback
p
q
s
c
n
t
lang
list
order
column
table
from
to
template
mod
php_path
style
include
require
input
output
format
download
filename
preview
root
admin
access
login
token
key
api
apikey
config
db
debug
test
old
backup
src
dest
filter
result
data
val
var
do
option
load
read
fetch
get
set
show
log
panel
manage
control
PARAMS

    # Use SecLists param wordlist if available (bigger)
    local seclists_params="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if [[ -f "$seclists_params" ]]; then
        cat "$seclists_params" >> "$param_wordlist"
        sort -u "$param_wordlist" -o "$param_wordlist"
    fi

    local param_count=$(wc -l < "$param_wordlist")
    log_scan "Testing ${param_count} parameter names..."
    
    # Find pages to test params on (from fuzz results)
    local -a test_urls=("$url")
    
    # Add interesting pages found during fuzzing
    for fuzz_f in "${result_dir}/web/feroxbuster_"*.txt "${result_dir}/web/gobuster_"*.txt "${result_dir}/web/ffuf_"*.json; do
        [[ ! -f "$fuzz_f" ]] && continue
        while read -r found_url; do
            [[ -n "$found_url" ]] && test_urls+=("$found_url")
        done < <(extract_urls_from_fuzz_artifact "$fuzz_f" "$url" | grep -iE '\.(php|asp|aspx|jsp|cgi|pl|py)' | head -10)
    done
    
    {
        echo "=== Parameter Discovery ==="
        echo "Tested URLs: ${#test_urls[@]}"
        echo "Wordlist: ${param_count} params"
        echo ""
        
        for test_url in "${test_urls[@]}"; do
            prepare_web_target_context "$test_url" "$ip" "$result_dir"
            local display_test_url="$WEB_CTX_DISPLAY_URL"
            local ffuf_test_url="$WEB_CTX_TOOL_URL"

            echo "--- ${display_test_url} ---"
            
            if command -v ffuf &>/dev/null; then
                # GET params
                local get_tmp="${result_dir}/web/.param_get_${base_name}_$$.tmp"
                ffuf -u "${ffuf_test_url}?FUZZ=test" \
                    -w "$param_wordlist" \
                    -mc 200,301,302,403 \
                    -fc 404 \
                    -fs 0 \
                    -ac \
                    -ach \
                    "${WEB_CTX_FFUF_ARGS[@]}" \
                    -t 30 \
                    -timeout 5 \
                    -maxtime 60 \
                    -s > "$get_tmp" 2>/dev/null || true
                while read -r result; do
                    local param
                    param=$(echo "$result" | awk '{print $1}')
                    [[ "$param" =~ ^[A-Za-z0-9_.-]+$ ]] && echo "  [GET] ${display_test_url}?${param}=FUZZ"
                done < "$get_tmp"
                rm -f "$get_tmp"
                
                # POST params
                local post_tmp="${result_dir}/web/.param_post_${base_name}_$$.tmp"
                ffuf -u "${ffuf_test_url}" \
                    -w "$param_wordlist" \
                    -X POST \
                    -d "FUZZ=test" \
                    -mc 200,301,302,403 \
                    -fc 404 \
                    -fs 0 \
                    -ac \
                    -ach \
                    "${WEB_CTX_FFUF_ARGS[@]}" \
                    -t 30 \
                    -timeout 5 \
                    -maxtime 60 \
                    -s > "$post_tmp" 2>/dev/null || true
                while read -r result; do
                    local param
                    param=$(echo "$result" | awk '{print $1}')
                    [[ "$param" =~ ^[A-Za-z0-9_.-]+$ ]] && echo "  [POST] ${display_test_url} → ${param}=FUZZ"
                done < "$post_tmp"
                rm -f "$post_tmp"
            elif command -v wfuzz &>/dev/null; then
                local wfuzz_tmp="${result_dir}/web/.param_wfuzz_${base_name}_$$.tmp"
                (
                    timeout -k 5 60 wfuzz -z file,"$param_wordlist" \
                        --hc 404 --hl 0 \
                        -t 30 \
                        "${ffuf_test_url}?FUZZ=test" > "$wfuzz_tmp" 2>/dev/null
                ) 2>/dev/null || true
                grep -v "^$\|Total" "$wfuzz_tmp" 2>/dev/null | while read -r line; do
                    local param
                    param=$(echo "$line" | awk '{print $NF}')
                    [[ "$param" =~ ^[A-Za-z0-9_.-]+$ ]] && echo "  [GET] ${display_test_url}?${param}=FUZZ"
                done
                rm -f "$wfuzz_tmp"
            fi
            echo ""
        done
    } > "$out" 2>&1
    
    rm -f "$param_wordlist"
    
    local found
    found=$(grep -cE '^  \[(GET|POST)\]' "$out" 2>/dev/null || true)
    [[ "$found" =~ ^[0-9]+$ ]] || found=0
    if [[ $found -gt 0 ]]; then
        print_found "${found} parameters discovered!"
        grep -E '^  \[(GET|POST)\]' "$out" | while read -r line; do
            print_found "$line"
        done
    else
        log_info "No hidden parameters found"
    fi
    log_success "Params → ${out}"
}

# ── JavaScript Analysis & Deobfuscation ──
run_js_analysis() {
    local url="$1"
    local result_dir="$2"
    
    local analyzer="${SCRIPT_DIR}/scripts/js_analyzer.js"
    
    if [[ ! -f "$analyzer" ]]; then
        log_info "JS analyzer script not found (skipping)"
        return
    fi
    
    if ! command -v node &>/dev/null; then
        log_warn "Node.js not installed (skipping JS analysis)"
        return
    fi
    
    sub_header "JavaScript Analysis & Deobfuscation"
    log_scan "Analyzing JS files from ${url}..."
    
    timeout 120 node "$analyzer" "$url" "$result_dir" 2>&1
    
    # Show findings summary
    local js_report="${result_dir}/js/js_analysis_report.txt"
    if [[ -f "$js_report" ]]; then
        local finding_count
        finding_count=$(grep -c "^  Value:" "$js_report" 2>/dev/null || true)
        [[ "$finding_count" =~ ^[0-9]+$ ]] || finding_count=0
        
        if [[ $finding_count -gt 0 ]]; then
            print_found "JS Analysis: ${finding_count} secrets/patterns found!"
            
            # Show critical findings
            grep -B1 "Value:" "$js_report" | grep -A1 "API Key\|Secret\|Password\|JWT\|Credential\|AWS" | head -20 | while read -r line; do
                [[ -n "$line" ]] && echo -e "    ${RED}→ ${line}${NC}"
            done
        else
            log_info "No secrets found in JS files"
        fi
        
        # List deobfuscated files
        local clean_count
        clean_count=$(ls "${result_dir}/js/clean_"* 2>/dev/null | wc -l)
        if [[ $clean_count -gt 0 ]]; then
            log_success "${clean_count} JS files deobfuscated → ${result_dir}/js/"
        fi
        
        log_success "JS report → ${js_report}"
    fi
}

# ── Main Web Recon Orchestrator ──
run_web_recon() {
    local ip="$1"
    local result_dir="$2"
    
    section_header "PHASE 3: WEB RECONNAISSANCE" "$ICON_FOUND"
    local start=$(timer_start)
    
    local web_ports_file="${result_dir}/scans/web_ports.txt"
    mkdir -p "${result_dir}/web"
    mkdir -p "${result_dir}/loot"
    touch "$web_ports_file"
    
    if [[ ! -f "$web_ports_file" ]] || [[ ! -s "$web_ports_file" ]]; then
        log_warn "No web services found. Skipping web recon."
        return 0
    fi
    
    touch "${result_dir}/web/extra_paths.txt"
    touch "${result_dir}/web/default_creds.txt"
    touch "${result_dir}/web/cms_discovered_paths.txt"
    touch "${result_dir}/web/subdomains.txt"
    touch "${result_dir}/web/subdomains_resolved.txt"
    touch "${result_dir}/web/subdomain_web_targets.txt"
    touch "${result_dir}/web/discovered_hostnames.txt"
    touch "${result_dir}/web/discovered_root_domains.txt"
    touch "${result_dir}/web/hosts_suggestions.txt"
    touch "${result_dir}/web/vhosts.txt"
    touch "${result_dir}/web/api_inventory.txt"
    touch "${result_dir}/web/.processed_root_domains"
    NIKTO_PIDS=()

    dedup_file "${result_dir}/web/extra_paths.txt"
    dedup_file "${result_dir}/web/cms_discovered_paths.txt"
    dedup_file "${result_dir}/web/subdomains.txt"
    dedup_file "${result_dir}/web/subdomains_resolved.txt"
    dedup_file "${result_dir}/web/subdomain_web_targets.txt"
    dedup_file "${result_dir}/web/discovered_hostnames.txt"
    dedup_file "${result_dir}/web/discovered_root_domains.txt"
    dedup_file "${result_dir}/web/vhosts.txt"
    dedup_file "${result_dir}/web/api_inventory.txt"

    run_discovered_domain_enrichment "$ip" "$result_dir"
    dedup_file "$web_ports_file"

    # Modern fast probe across all queued targets (httpx) before per-target dives.
    if declare -F run_httpx_probe >/dev/null; then
        run_httpx_probe "$ip" "$result_dir"
    fi

    local processed_targets="${result_dir}/web/.processed_web_targets"
    : > "$processed_targets"
    
    while true; do
        local url
        url=$(grep -vxFf "$processed_targets" "$web_ports_file" 2>/dev/null | head -1)
        [[ -z "$url" ]] && break
        local current_url="$url"
        echo "$url" >> "$processed_targets"
        
        echo -e "\n${BOLD}${MAGENTA}  ═══ Web Target: ${current_url} ═══${NC}"
        
        # ── WAVE 1: Quick recon (parallel, ~5s each) ──
        echo -e "  ${CYAN}▸ Wave 1: Fingerprint + SSL + WAF${NC}"
        web_fingerprint "$current_url" "$ip" "$result_dir" &
        local pid_fp=$!
        run_ssl_scan "$current_url" "$result_dir" &
        local pid_ssl=$!
        run_waf_detect "$current_url" "$result_dir" &
        local pid_waf=$!
        
        wait $pid_fp $pid_ssl $pid_waf 2>/dev/null

        run_discovered_domain_enrichment "$ip" "$result_dir"
        dedup_file "$web_ports_file"

        if ! grep -Fxq "$current_url" "$web_ports_file" 2>/dev/null; then
            log_info "Switching subsequent web recon from ${current_url} to discovered hostname target"
            continue
        fi
        
        # ── WAVE 2: CMS detection (feeds into wave 3) ──
        echo -e "  ${CYAN}▸ Wave 2: CMS Detection${NC}"
        detect_and_scan_cms "$current_url" "$ip" "$result_dir"
        
        # ── WAVE 3: Heavy jobs (ALL parallel!) ──
        echo -e "  ${CYAN}▸ Wave 3: Fuzz + Param + JS + Nikto (parallel)${NC}"
        
        run_nikto "$current_url" "$result_dir"   # Already runs in background
        
        run_dir_fuzzing "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ Dir fuzzing (bg PID: $!)${NC}"
        local pid_fuzz=$!
        
        run_param_fuzz "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ Param discovery (bg PID: $!)${NC}"
        local pid_param=$!
        
        analyze_source "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ Source analysis (bg PID: $!)${NC}"
        local pid_src=$!
        
        run_js_analysis "$current_url" "$result_dir" &
        echo -e "    ${DIM}→ JS analysis (bg PID: $!)${NC}"
        local pid_js=$!
        
        run_vhost_fuzzing "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ VHost fuzzing (bg PID: $!)${NC}"
        local pid_vhost=$!
        
        check_default_creds "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ Default creds (bg PID: $!)${NC}"
        local pid_creds=$!
        
        run_api_fuzzing "$current_url" "$ip" "$result_dir" &
        echo -e "    ${DIM}→ API Discovery (bg PID: $!)${NC}"
        local pid_api=$!

        local pid_ctf="" pid_jsmine="" pid_arjun=""
        if declare -F run_ctf_endpoint_probe >/dev/null; then
            run_ctf_endpoint_probe "$current_url" "$ip" "$result_dir" &
            echo -e "    ${DIM}→ CTF/sensitive endpoints (bg PID: $!)${NC}"
            pid_ctf=$!
        fi
        if declare -F mine_js_secrets >/dev/null; then
            mine_js_secrets "$current_url" "$ip" "$result_dir" &
            echo -e "    ${DIM}→ Crawl + JS secret mining (bg PID: $!)${NC}"
            pid_jsmine=$!
        fi
        if declare -F run_arjun_params >/dev/null; then
            run_arjun_params "$current_url" "$ip" "$result_dir" &
            echo -e "    ${DIM}→ arjun param mining (bg PID: $!)${NC}"
            pid_arjun=$!
        fi

        # Wait for all wave 3 jobs
        echo ""
        log_info "Waiting for wave 3 jobs..."
        wait $pid_fuzz $pid_param $pid_src $pid_js $pid_vhost $pid_creds $pid_api \
             $pid_ctf $pid_jsmine $pid_arjun 2>/dev/null

        run_discovered_domain_enrichment "$ip" "$result_dir"
        dedup_file "$web_ports_file"

        run_quick_path_probe "$current_url" "$ip" "$result_dir"
        probe_hinted_paths "$current_url" "$ip" "$result_dir"
        
        # ── WAVE 4: Post-Fuzzing Sub-directory CMS Check ──
        echo -e "  ${CYAN}▸ Wave 4: Sub-directory Tech & CMS Check${NC}"
        local base_name=$(echo "$current_url" | sed 's|[:/]|_|g')
        local fuzz_out
        fuzz_out=$(get_primary_fuzz_artifact "$result_dir" "$base_name")
        
        if [[ -n "$fuzz_out" ]] && [[ -f "$fuzz_out" ]]; then
            extract_urls_from_fuzz_artifact "$fuzz_out" "$current_url" | grep -v '\.\w{2,4}$' | sort -u | head -5 | while read -r sub_url; do
                [[ "$sub_url" == "$current_url" ]] && continue
                [[ "$sub_url" == "${current_url}/" ]] && continue
                log_scan "Checking CMS on new sub-directory: ${sub_url}"
                detect_and_scan_cms "$sub_url" "$ip" "$result_dir"
                echo "$sub_url" >> "${result_dir}/web/cms_discovered_paths.txt"
            done
        fi
        
        log_success "All web recon for ${current_url} complete!"
        dedup_file "$web_ports_file"
        local next_url
        next_url=$(grep -vxFf "$processed_targets" "$web_ports_file" 2>/dev/null | head -1)
        [[ -z "$next_url" ]] && break
    done
    
    # CeWL (runs after all URLs processed)
    run_cewl "$ip" "$result_dir"

    # Active XSS scan on discovered param URLs (gated by OffSec-safe mode).
    if declare -F run_dalfox_xss >/dev/null; then
        run_dalfox_xss "$ip" "$result_dir"
    fi

    # Screenshots of every live web target for the report gallery.
    if declare -F run_web_screenshots >/dev/null; then
        run_web_screenshots "$ip" "$result_dir"
    fi
    
    # Wait for all background nikto jobs
    if [[ ${#NIKTO_PIDS[@]} -gt 0 ]]; then
        log_info "Waiting for ${#NIKTO_PIDS[@]} Nikto job(s) to finish..."
        local nikto_pid
        for nikto_pid in "${NIKTO_PIDS[@]}"; do
            wait "$nikto_pid" 2>/dev/null
        done
    fi
    
    # Dedup extra paths
    dedup_file "${result_dir}/web/extra_paths.txt"
    dedup_file "${result_dir}/web/cms_discovered_paths.txt"
    
    local extra_count=$(wc -l < "${result_dir}/web/extra_paths.txt" 2>/dev/null || echo 0)
    if [[ $extra_count -gt 0 ]]; then
        log_info "Extra paths discovered from source/robots: ${extra_count}"
    fi

    rm -f "$processed_targets"
    
    log_info "Time: $(timer_elapsed $start)"
    
    # Show all web output files
    echo ""
    for f in "${result_dir}/web/"*.txt; do
        [[ ! -f "$f" ]] && continue
        [[ "$(basename "$f")" == "extra_paths.txt" ]] && continue
        [[ "$(basename "$f")" == "detected_tech.txt" ]] && continue
        echo -e "  ${DIM}── $(basename "$f") ──${NC}"
        cat "$f"
        echo ""
    done
    
    pause_if_interactive
}
