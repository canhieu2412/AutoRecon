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
- Optional terminal UI built on charmbracelet `gum`: styled main menu, target input, confirms, and a live pipeline dashboard that refreshes after each phase during Full Auto.
- Fully optional and auto-detected: falls back to the classic text menu when gum is absent or output is not a TTY. Toggle with `USE_TUI=auto|on|off` or `--tui` / `--no-tui`. The text pipeline overview also shows in classic mode.
- Install: `sudo apt install gum` (or `go install github.com/charmbracelet/gum@latest`).

## v3.7.0

- Added interactive menu workflow for full reconnaissance runs.
- Added engagement profiles for balanced, OffSec lab, HTB, THM, Boot2Root, and custom workflows.
- Added multi-engine port scanning with fallback behavior.
- Added deeper web recon for fingerprints, fuzzing, hostnames, vhosts, APIs, parameters, CMS checks, WAF, SSL/TLS, and JavaScript analysis.
- Added SQLMap workflows, operator toolkit, wordlist toolkit, and HTML/Markdown reporting.
- Redesigned report generation with executive dashboard, normalized key findings, attack surface inventory, evidence sections, coverage gaps, redaction, and artifact appendix.
- Prepared public GitHub documentation, ignore rules, license, and security policy.
