# Changelog

## v4.0.0

### Refactor foundation
- Added `lib/tools.sh`: a central tool registry + execution wrappers (`have_tool`, `pick_tool` fallback selection, `run_timed`, tool-choice recording). `config/tool_check.sh` now renders the dependency report directly from this registry so it can no longer drift from the tools the modules use.
- Added `lib/net.sh`: shared URL/host parsing and ANSI-strip helpers, replacing copy-pasted `sed` regexes across modules.

### Modern tooling (all optional, with graceful fallbacks)
- Web: `httpx` fast probe, `katana`/`gospider`/`hakrawler` crawling, `gowitness`/`aquatone` screenshots, `arjun` parameter mining, `dalfox` XSS (gated by OffSec-safe mode), `joomscan` for Joomla.
- Discovery: `naabu` added to the port-scan engine rotation; `dnsx` bulk-resolves brute-forced subdomains to drop dead/wildcard noise.

### Web-CTF depth
- Common CTF / sensitive-endpoint probe (`.git`, `.env`, `flag`, backups, swagger, key files).
- Automatic `.git` exposure detection with `git-dumper` handoff/dump.
- JS + endpoint secret mining (API keys, JWTs, private keys, AWS creds) over the crawl output.

### Privilege escalation handoff (new Phase 9, `modules/09_privesc.sh`)
- Maps discovered service banners to known boot2root/OSCP CVEs (vsftpd 2.3.4, Samba usermap, ProFTPD mod_copy, Apache path traversal, EternalBlue, etc.).
- OS-family detection and ready-to-paste linpeas/winpeas/pspy/PrivescCheck fetch+run cheatsheets (no bundled binaries).
- GTFOBins / LOLBAS quick reference for SUID/sudo/capabilities and living-off-the-land abuse.

### Reporting
- New report sections: web screenshot gallery (with `<img>` rendering in HTML), privilege-escalation handoff, CTF endpoints, crawled endpoints, JS secrets, httpx/dalfox/git-exposure artifacts.

### TUI (gum-backed, `lib/tui.sh`)
- Optional terminal UI built on charmbracelet `gum`: **full-screen** main menu (alternate screen buffer), target input, confirms, a fuzzy-filter + pager results browser, and a live pipeline dashboard that refreshes after each phase during Full Auto.
- Full-screen launcher model: the menu takes the whole screen, then drops back to the normal terminal while a scan streams (scrollback preserved), then pops back. The EXIT/INT trap always restores the screen.
- Fully optional and auto-detected via the controlling terminal (`/dev/tty`), so it works even when menu helpers run inside `$(...)`. Falls back to the classic text menu when gum is absent. Toggle `USE_TUI=auto|on|off` or `--tui` / `--no-tui`.
- Install: `sudo apt install gum` (or `go install github.com/charmbracelet/gum@latest`).

### Shell Handler & File Transfer (new, `modules/11_shell_handler.sh`, menu `[h]`)
- Reverse-shell payload cheatsheet generator (bash/python/nc/perl/php/socat + base64 + Windows PowerShell) auto-filled with LHOST/LPORT.
- Listener to catch reverse shells: prefers `pwncat-cs` (auto-stabilise + up/download), falls back to `ncat`, `rlwrap nc`, or plain `nc`.
- Serve files **to** target over HTTP (python/php) with ready wget/curl/certutil/powershell fetch commands.
- Receive files **from** target: python `uploadserver` (HTTP POST) when available, else an `nc`/`ncat` receiver. Loot saved under `<results>/shells/loot/`.

## v3.7.0

- Added interactive menu workflow for full reconnaissance runs.
- Added engagement profiles for balanced, OffSec lab, HTB, THM, Boot2Root, and custom workflows.
- Added multi-engine port scanning with fallback behavior.
- Added deeper web recon for fingerprints, fuzzing, hostnames, vhosts, APIs, parameters, CMS checks, WAF, SSL/TLS, and JavaScript analysis.
- Added SQLMap workflows, operator toolkit, wordlist toolkit, and HTML/Markdown reporting.
- Redesigned report generation with executive dashboard, normalized key findings, attack surface inventory, evidence sections, coverage gaps, redaction, and artifact appendix.
- Prepared public GitHub documentation, ignore rules, license, and security policy.
