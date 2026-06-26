#!/bin/bash
# ============================================================================
# AUTO RECON - Network / URL Parsing Helpers
# ----------------------------------------------------------------------------
# Centralizes the URL + host parsing and ANSI handling that was previously
# copy-pasted across modules (web recon, vuln scan, operator toolkit). Keeping
# it in one place avoids subtle regex drift between callers.
# ============================================================================

# Strip ANSI / color escape codes from a stream (stdin -> stdout).
strip_ansi() {
    sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g'
}

# Strip ANSI from a single argument string.
strip_ansi_str() {
    printf '%s' "$1" | strip_ansi
}

# Scheme of a URL (http / https). Defaults to http when absent.
url_scheme() {
    local url="$1"
    case "$url" in
        https://*) echo "https" ;;
        http://*)  echo "http" ;;
        *)         echo "http" ;;
    esac
}

# Host[:port] component of a URL.
url_authority() {
    local url="$1"
    echo "$url" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##'
}

# Hostname without port.
url_hostname() {
    url_authority "$1" | sed -E 's#:[0-9]+$##'
}

# Port of a URL (explicit, else scheme default).
url_port() {
    local url="$1"
    local authority
    authority=$(url_authority "$url")
    if [[ "$authority" == *:* ]]; then
        echo "${authority##*:}"
    elif [[ "$(url_scheme "$url")" == "https" ]]; then
        echo "443"
    else
        echo "80"
    fi
}

# True when two URLs share the same authority (host[:port]) — used to keep
# recursive fuzzing in-scope.
same_authority() {
    [[ "$(url_authority "$1")" == "$(url_authority "$2")" ]]
}

# True when two URLs share the same hostname (ignoring port).
same_hostname() {
    [[ "$(url_hostname "$1")" == "$(url_hostname "$2")" ]]
}

# Build a base URL from scheme/host/port, omitting default ports.
build_url() {
    local scheme="$1" host="$2" port="${3:-}"
    if [[ -z "$port" ]] \
       || { [[ "$scheme" == "http" && "$port" == "80" ]]; } \
       || { [[ "$scheme" == "https" && "$port" == "443" ]]; }; then
        printf '%s://%s' "$scheme" "$host"
    else
        printf '%s://%s:%s' "$scheme" "$host" "$port"
    fi
}
