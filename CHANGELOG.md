# Changelog

## v5.0.0

### Web GUI — run as CLI **or** GUI (`web/`, `auto_recon.sh --gui`)
A localhost web interface on `http://127.0.0.1:2412` that drives the *same* bash
engine — no scan logic is duplicated. FastAPI + WebSockets backend, server-rendered
Jinja2 + vanilla-JS frontend (no build step), sharing the report design system.
- **Full parity**: dashboard (target + profile/engine/safe-mode + Full-Auto or any phase),
  live scan view (streaming terminal + accurate pipeline tracker from `state/*.env`),
  results browser (KPIs + severity bar parsed from the report, inline report, file search),
  per-phase launch pages, and a **reverse-shell console** (catch a shell + base64
  upload/download, reusing `ReverseShellEngine`).
- **Editable, persistent config**: Settings page writes `config/user_config.sh`
  (validated, schema-driven) which `config.sh` sources — so changes apply to CLI **and** GUI.
- **Flexible launches**: per-scan advanced overrides (engine/depth/threads/fuzzer),
  target history, toast notifications, running-jobs badge, browser notifications.
- **Security**: binds `127.0.0.1` only, random session token on every request/WebSocket,
  file API confined to `results/` (path-traversal rejected), scans spawned via argv arrays,
  and inherited `BASH_FUNC_*` shell-function shadows stripped from scan subprocesses.

### Headless CLI (also powers the GUI)
`--full-auto`, `--headless --phase <name>`, `--result-dir`, `--gui`/`--port`/`--unsafe-bind`,
`--dry-run`. Interactive prompts can be pre-seeded via `AR_ANS_<slug>` env (GUI uses this).

### New phases & modules
- `modules/13_next_steps.sh` — per-service manual "Try Harder" cheatsheet (menu `[n]`).
- `modules/14_pivot.sh` — chisel/ligolo-ng/sshuttle/proxychains generator (menu `[v]`).
- `modules/shell_tui.py` — two-panel Textual reverse-shell + file-transfer console (Shell Handler `[5]`).

### Priv-esc, AD, reporting, OSCP
- Priv-esc: GTFOBins one-liner resolver + auto-staging of linpeas/winpeas/pspy into the serve dir.
- AD: lockout-aware spray cap parsed from pass-pol; BloodHound shortest-path hint; auto-spray gated by OSCP-safe.
- Reporting: OSCP submission template + flag/proof capture (`[x]`); redesigned HTML report.
- Compliance: startup restricted-tool banner; central OSCP-safe gating.

### Quality
- `scripts/lint.sh`, `scripts/test_phases.sh`, `scripts/test_web.py`, `Makefile` (`make lint|test`).
- Bug fixes incl. AD wordlist stdout leak and pivot cheatsheet heredoc under `set -u`.

## v4.1.0

### Active Directory Attack Path (new, `modules/12_ad_enum.sh`, menu `[a]`)
OSCP-oriented AD workflow; auto-runs in Full Auto when a host looks like a DC
(Kerberos + LDAP + SMB), interactive sub-menu (TUI/text) for the rest:
- **Unauth enum**: netexec/crackmapexec null+guest sessions (users, RID brute, shares, pass-pol), enum4linux-ng, rpcclient, anonymous LDAP; consolidates a domain `users.txt`.
- **AS-REP roasting** (no creds) → hashcat -m 18200.
- **Authenticated enum**: shares/users/groups/pass-pol/loggedon, share spidering, WinRM/MSSQL access (Pwn3d! detection), **Kerberoasting** (-m 13100), **BloodHound** ingest (`-c All`), **secretsdump** (DCSync when privileged).
- **ADCS** via certipy (ESC1–ESC8 vulnerable templates).
- **NTLM relay / coercion** handoff (ntlmrelayx/PetitPotam/coercer/mitm6/responder) — command-only, gated by OffSec-safe.
- Crack hints + a summary with concrete next steps (evil-winrm / PtH / golden ticket / BloodHound path).

### Reporting / PoC
- Every executed command is now collected per target into `commands_poc.txt` (copy-paste-ready) and rendered in a new report section **Commands Executed (PoC)** — for exam write-ups.
- New report section **Active Directory** (summary, hashes, ADCS, secretsdump, enum artifacts).

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
