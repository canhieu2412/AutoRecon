# Auto Recon v3.7

**Author:** Canhieu  
**Type:** Bash-based reconnaissance automation framework  
**Target use:** Lab, CTF, Boot2Root, HTB/THM, OffSec-style practice and authorized internal pentest recon

Auto Recon là framework reconnaissance tự động viết bằng Bash, tối ưu cho việc enum một hoặc nhiều target trong môi trường được phép kiểm thử. Tool gom các bước thường phải làm thủ công như port scanning, service enumeration, web recon, vuln correlation, wordlist generation và report vào một menu duy nhất.

> Chỉ sử dụng công cụ này trên hệ thống bạn sở hữu hoặc có ủy quyền kiểm thử rõ ràng. Tác giả không chịu trách nhiệm cho việc sử dụng sai mục đích.

Công cụ này tập trung vào:

- Quét cổng nhanh với nhiều engine và fallback hợp lý
- Enum service song song nhưng có giới hạn để tránh tự quá tải
- Web recon nhiều lớp: subdomain, fingerprint, fuzzing, JS, params, SSL/WAF, CMS
- Có thể suy ra domain/vhost từ target IP và tạo mapping `/etc/hosts`
- Có submenu SQLi riêng để chạy SQLMap batch hoặc operator workflow từ inventory params đã tìm được
- Gom finding thành report Markdown/HTML và thư mục kết quả dễ duyệt

README này mô tả đúng implementation hiện tại trong repo.

## Mục lục nhanh

- [0. Quick Start cho người mới](#0-quick-start-cho-người-mới)
- [1. Tính năng chính](#1-tính-năng-chính)
- [2. Cấu trúc dự án](#2-cấu-trúc-dự-án)
- [3. Cài đặt](#3-cài-đặt)
- [4. Dependencies](#4-dependencies)
- [5. Cách chạy](#5-cách-chạy)
- [6. Menu](#6-menu)
- [7. Giao diện khi sử dụng](#7-giao-diện-khi-sử-dụng)
- [8. Test mẫu trước khi scan thật](#8-test-mẫu-trước-khi-scan-thật)
- [13. Kết quả đầu ra](#13-kết-quả-đầu-ra)
- [18. Troubleshooting](#18-troubleshooting)
- [20. Tác giả và mục tiêu sử dụng](#20-tác-giả-và-mục-tiêu-sử-dụng)

## 0. Quick Start cho người mới

### 0.1 Lần đầu dùng nên làm gì

Nếu bạn mới dùng tool này, đi theo đúng flow sau:

1. Clone hoặc mở thư mục project:

```bash
git clone https://github.com/canhieu2412/AutoRecon.git
cd AutoRecon
chmod +x auto_recon.sh
```

2. Chạy tool:

```bash
./auto_recon.sh
```

3. Trong menu chính, bấm:

```text
[c] Check Tools
```

Đây là bước nên làm đầu tiên để biết máy đang thiếu tool nào.

4. Quay lại menu chính, bấm:

```text
[t] Change Target
```

Sau đó nhập một trong các loại target:

- IP đơn: `10.10.10.10`
- CIDR: `10.10.10.0/24`
- File host: `targets.txt`
- Domain: `example.com`

5. Nếu chưa biết chỉnh gì trong Settings thì cứ giữ mặc định:

- `Scan Engine = auto`
- `Scan Mode = normal`
- `Port Chunks = 10`
- `Brute Force = OFF`

6. Chạy full pipeline:

```text
[1] Full Auto Scan
```

7. Khi scan xong:

- xem report bằng option `[7] Generate Report`
- duyệt file output bằng option `[8] View Results`
- nếu web recon đã tìm được GET params, mở `[s] SQLi Workflows` để chạy SQLMap All-in-One hoặc operator workflow

Nếu bạn scan bằng `IP` và target dùng virtual host:

- nên chạy bằng `sudo`
- giữ `Hosts Auto-Map = ON`
- kiểm tra thêm `web/discovered_hostnames.txt` và `web/hosts_suggestions.txt`

### 0.2 Khi nào nên dùng từng kiểu target

- Dùng `IP` khi bạn đã biết host đích cụ thể.
- Với `IP`, tool vẫn cố suy ra domain/vhost từ redirect, TLS cert và banner web nếu có.
- Dùng `Domain` khi muốn recon web đúng virtual host và bật subdomain enumeration.
- Dùng `CIDR` khi quét một dải lab hoặc subnet nội bộ.
- Dùng `File` khi bạn đã có danh sách nhiều host và muốn pipeline chạy lần lượt từng IP.

## 1. Tính năng chính

### 1.1 Port scanning

Các engine hiện được route thực tế trong phase port scan:

- `auto`
- `rustscan`
- `masscan`
- `nmap`
- `nmap-single`
- `nc`
- `nc-quick`

Hành vi:

- `quick` mode ưu tiên top ports để lấy kết quả sớm
- `normal` và `full` quét rộng hơn
- `auto` tự fallback từ nhanh sang chậm hơn
- UDP top 50 chạy nền song song với deep scan
- Sau khi tìm thấy cổng mở, tool chạy `nmap -sC -sV -O -A` trên đúng danh sách port đó

### 1.2 Host discovery

Hỗ trợ các loại target:

- IP đơn
- CIDR
- File chứa danh sách IP
- Domain

Với:

- IP: kiểm tra sống/chết nhanh rồi vẫn tiếp tục scan nếu không có ICMP
- CIDR: ping sweep bằng `nmap -sn`
- File: đọc từng host trong file
- Domain: resolve sang IP và lưu cả domain gốc để dùng cho web recon

### 1.3 Service enumeration

Enum service chạy theo port/service phát hiện từ `nmap_targeted.nmap`.

Các nhóm enum chính:

- FTP
- SSH
- SMTP
- DNS
- SMB / AD
- SNMP
- LDAP
- MySQL / MariaDB
- MSSQL
- RDP
- NFS
- Redis
- Generic banner + `nmap --script=default`

Điểm đáng chú ý:

- Các job enum chạy nền theo PID thật và được `wait` đúng cách
- Có throttle qua `ENUM_MAX_JOBS` để giữ hiệu năng ổn định
- Web service được tự đẩy vào danh sách cho phase web recon

### 1.4 Web reconnaissance

Phase web là phần lớn nhất của tool, gồm các lớp sau:

- Subdomain enumeration cho target domain
- Fingerprint HTTP headers / WhatWeb / robots / sitemap
- SSL/TLS checks
- WAF detection
- CMS detection
- Directory fuzzing
- Parameter discovery
- Source analysis
- JavaScript analysis và deobfuscation
- VHost fuzzing
- Default credential checks
- API endpoint discovery
- Nikto
- CeWL custom wordlist

### 1.5 Subdomain enumeration

Phần subdomain/vhost hoạt động theo 2 kiểu:

- Nếu target ban đầu là `domain`, tool chạy subdomain enum như bình thường.
- Nếu target ban đầu là `IP`, tool sẽ cố suy ra domain/vhost trước rồi mới mở tiếp flow subdomain/vhost.

Luồng hiện tại:

1. Nếu đã biết domain, hoặc suy ra được root domain từ web target:
   - `subfinder` làm passive discovery
2. Nếu có SecLists DNS wordlist, chạy thêm active brute-force bằng:
   - `gobuster dns`
   - `dnsrecon -t brt` trong mode không phải `quick`
3. Với IP targets, tool còn cố phát hiện hostname từ:
   - HTTP redirect
   - absolute URL trong response
   - TLS certificate CN/SAN
   - banner `nmap` của web service
4. Từ hostname/vhost phát hiện được, tool:
   - sinh `hosts_suggestions.txt`
   - có thể tự append vào `/etc/hosts` nếu đang chạy bằng root
   - rewrite `web_ports.txt` để ưu tiên hostname/domain thay cho IP
   - queue lại hostname đó vào web recon trong cùng run
5. Resolve IP cho subdomain tìm được
6. Probe nhanh web trên:
   - `http://subdomain`
   - `https://subdomain`
   - `http://subdomain:8080`
   - `https://subdomain:8443`
7. Các URL sống được tự merge vào `scans/web_ports.txt` để phase web recon xử lý tiếp

Output chính:

- `web/subdomains.txt`
- `web/subdomains_resolved.txt`
- `web/subdomain_web_targets.txt`
- `web/discovered_hostnames.txt`
- `web/discovered_root_domains.txt`
- `web/vhosts.txt`
- `web/hosts_suggestions.txt`

### 1.6 Vulnerability scanning

Phase vuln hiện có:

- `nmap --script vuln`
- `searchsploit --nmap` với kết quả được làm sạch và xếp hạng
- SearchSploit thủ công theo service/version với nhiều query fallback
- `nuclei` cho:
  - Web targets
  - Network templates
- `sqlmap` verify các GET params tìm được
- Submenu `SQLi Workflows` để:
  - chạy `SQLMap All-in-One` theo profile đang chọn
  - chạy `SQLMap Operator Workflow` theo từng target, lưu command repro và per-target logs
- LFI verification bằng `ffuf` + wordlist LFI
- Mapping CVE sang module Metasploit nếu có `msfconsole`

### 1.7 Brute force

Brute force là phase tùy chọn.

Hiện hỗ trợ:

- SSH
- FTP
- SMB
- MySQL
- MSSQL
- RDP
- Web login form qua Hydra

Interactive mode đã được nâng cấp để dễ dùng hơn:

- Không cần tự nhớ tên module Hydra
- Có menu chọn service brute-force theo số
- Hiển thị service nào đã được detect từ `nmap`
- Tự ưu tiên port detect từ `nmap` thay vì chỉ dựa vào port mặc định
- Nếu một service xuất hiện trên nhiều port, tool sẽ cho chọn trực tiếp từ danh sách port detect được
- Web form có wizard riêng để chọn:
  - target URL
  - protocol `http/https`
  - method `GET/POST`
  - port
  - login path
  - params template `^USER^` / `^PASS^`
- matcher kiểu fail/success string

Trong auto mode:

- Tool brute theo từng port detect được cho các service hỗ trợ
- Ví dụ nếu `ssh` mở ở `22` và `2222`, tool sẽ xử lý cả hai thay vì chỉ một port đầu tiên

Brute force không tự bật mặc định. Bật qua menu Settings hoặc option `6`.

### 1.8 Report

Tool sinh cả `report.md` và `report.html` trong thư mục kết quả với:

- Executive dashboard với counters chính và severity mix
- Scope, methodology và pipeline health
- Key findings đã normalize theo severity, asset, evidence, source và next action
- Attack surface inventory cho TCP/UDP, auth surfaces, web targets, vhosts, API và params
- Service evidence và web application details theo từng target
- Vulnerability evidence trong `<details>` để report không quá dài
- Loot, wordlists và operator notes với redaction cho secret/password/token/path nhạy cảm
- Coverage gaps, recommended next steps và appendix artifact index

## 2. Cấu trúc dự án

```text
auto_recon/
├── auto_recon.sh
├── config/
│   ├── config.sh
│   └── tool_check.sh
├── lib/
│   ├── colors.sh
│   ├── logger.sh
│   ├── net.sh            # URL/host parsing + ANSI helpers (v4.0)
│   ├── tools.sh          # tool registry + run wrappers + fallbacks (v4.0)
│   ├── tui.sh            # gum-backed TUI + classic fallback (v4.0)
│   └── utils.sh
├── modules/
│   ├── 00_host_discovery.sh
│   ├── 01_port_scan.sh
│   ├── 02_service_enum.sh
│   ├── 03_web_recon.sh
│   ├── 04_vuln_scan.sh
│   ├── 05_brute_force.sh
│   ├── 06_report.sh
│   ├── 07_operator_toolkit.sh
│   ├── 08_wordlist_toolkit.sh
│   ├── 09_privesc.sh     # priv-esc handoff: CVE hints + peas + GTFOBins (v4.0)
│   └── 10_web_modern.sh  # httpx/katana/gowitness/arjun/dalfox/ctf/git (v4.0)
├── scripts/
│   └── js_analyzer.js
├── wordlists/
│   └── builtin.txt
└── results/
```

## 3. Cài đặt

### 3.1 Clone project

```bash
git clone https://github.com/canhieu2412/AutoRecon.git
cd AutoRecon
chmod +x auto_recon.sh
```

Nếu bạn tải file zip từ GitHub:

```bash
unzip auto_recon-main.zip
cd auto_recon-main
chmod +x auto_recon.sh
```

### 3.2 Chạy kiểm tra tool

```bash
./auto_recon.sh
```

Trong menu, chọn:

```text
[c] Check Tools
```

Nếu muốn chạy nhanh bằng CLI sau khi clone:

```bash
./auto_recon.sh --profile balanced 10.10.10.10
```

Script sẽ preload target rồi mở menu để bạn chọn phase cần chạy.

### 3.3 Cài shortcut toàn cục tùy chọn

Nếu muốn gọi tool từ mọi thư mục:

```bash
sudo ln -s "$(pwd)/auto_recon.sh" /usr/local/bin/auto-recon
auto-recon
```

Nếu sau này đổi vị trí thư mục project, hãy tạo lại symlink.

### 3.4 Hệ điều hành khuyến nghị

- Kali Linux là môi trường phù hợp nhất
- Bash, `nmap`, `curl`, `nc` là nền tảng tối thiểu
- Node.js chỉ cần cho module JavaScript analyzer
- Một số tool như `masscan`, SYN scan và auto-map `/etc/hosts` hoạt động tốt hơn khi chạy bằng `sudo`

### 3.5 Lưu ý trước khi upload GitHub

Không nên commit các file sinh ra khi chạy tool:

- `results/`
- `hydra.restore`
- log, cache, report hoặc output scan thật

Repo public nên chỉ chứa source code, README, wordlist builtin nhỏ và tài liệu hướng dẫn.

## 4. Dependencies

### 4.1 Gần như bắt buộc

- `nmap`
- `nc`
- `curl`

### 4.2 Khuyến nghị mạnh

- `rustscan`
- `masscan`
- `gobuster`
- `feroxbuster`
- `ffuf`
- `nikto`
- `whatweb`
- `wafw00f`
- `cewl`
- `node`
- `subfinder`
- `searchsploit`
- `nuclei`
- `sslscan`
- `sqlmap`
- `hydra`

### 4.3 Tool enum theo service

- `enum4linux`
- `smbclient`
- `rpcclient`
- `netexec`
- `snmp-check`
- `dnsrecon`
- `dnsenum`
- `ldapsearch`
- `redis-cli`
- `showmount`
- `impacket-*`

### 4.4 Modern tooling (tùy chọn, v4.0 — có thì dùng, không có thì fallback)

Tất cả tool dưới đây đều **optional**: nếu chưa cài, tool tự dùng phương án thay thế (whatweb, gobuster, curl…) nên pipeline vẫn chạy.

- `httpx` — fast probe (title/status/tech/server) cho mọi web target
- `katana` / `gospider` / `hakrawler` — crawl endpoint + JS
- `gowitness` / `aquatone` — chụp screenshot web cho report
- `naabu` — engine port-scan nhanh (vào vòng auto rotation)
- `dnsx` — bulk-resolve subdomain, loại bỏ wildcard/dead host
- `arjun` — đào tham số ẩn (GET/POST)
- `dalfox` — quét XSS (tự skip khi bật OffSec-safe mode)
- `joomscan` — quét Joomla
- `git-dumper` — tự dump khi phát hiện `.git/` lộ

Cài nhanh (ProjectDiscovery + Go tools):

```bash
# ProjectDiscovery
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# Screenshots / XSS / git
go install github.com/sensepost/gowitness@latest
go install github.com/hahwul/dalfox/v2@latest
pipx install arjun
pipx install git-dumper

# TUI (tùy chọn — giao diện gum)
sudo apt install gum         # hoặc: go install github.com/charmbracelet/gum@latest
```

### 4.5 Giao diện TUI (gum)

`auto_recon` tự bật **TUI** (menu + nhập target + dashboard tiến độ trực tiếp) khi có `gum` và đang chạy trên terminal thật. Nếu chưa cài gum, tool tự dùng menu text như cũ — không lỗi.

```bash
./auto_recon.sh --tui      # ép dùng TUI (cần gum)
./auto_recon.sh --no-tui   # ép dùng menu text cổ điển
# mặc định: auto (có gum thì dùng TUI)
```

Đặt cố định trong `config/config.sh`: `USE_TUI="auto" | "on" | "off"`.

## 5. Cách chạy

### 5.1 Mở menu

```bash
./auto_recon.sh
```

### 5.2 Preload target rồi vào menu

```bash
./auto_recon.sh 10.10.10.10
./auto_recon.sh 10.10.10.0/24
./auto_recon.sh targets.txt
./auto_recon.sh example.com
```

Lưu ý:

- Script hiện dùng menu là luồng chính
- Truyền target ở CLI chỉ để preload target trước khi vào menu

### 5.3 Khi nào nên chạy bằng root

Nên dùng `sudo` nếu muốn:

- `masscan`
- `nmap -sS`
- một số low-level scan cho hiệu năng tốt hơn

Ví dụ:

```bash
sudo ./auto_recon.sh example.com
```

### 5.4 Workflow khuyến nghị cho người mới

Đây là luồng dùng thực tế ít lỗi nhất:

1. `Check Tools`
2. `Change Target`
3. `Settings` nếu cần chỉnh mode/engine
4. `Full Auto Scan`
5. `Generate Report`
6. `View Results`

Với bài lab scan bằng IP nhưng nghi có virtual host:

1. chạy bằng `sudo`
2. giữ `Hosts Auto-Map = ON`
3. chạy `Full Auto Scan`
4. xem thêm `web/discovered_hostnames.txt`, `web/vhosts.txt`, `web/hosts_suggestions.txt`

Nếu bạn chạy từng phase bằng tay, thứ tự nên là:

1. `Port Scan`
2. `Service Enumeration`
3. `Web Recon`
4. `Wordlist Toolkit`
5. `Vulnerability Scan`
6. `Brute / Toolkit`
7. `Generate Report`

### 5.5 Chạy từng phase khi nào hợp lý

- Chọn `Port Scan` khi mới bắt đầu hoặc khi bạn muốn đổi engine/mode rồi quét lại.
- Chọn `Service Enumeration` sau khi đã có `nmap_targeted.nmap`.
- Chọn `Web Recon` khi đã có web service hoặc bạn đang làm web target.
- Chọn `Wordlist Toolkit` khi muốn sinh user/pass/content list theo target để tái dùng cho Hydra, web fuzz và operator work.
- Chọn `Vulnerability Scan` sau khi đã có thông tin service/web tương đối đầy đủ.
- Chọn `Brute / Toolkit` khi bạn muốn thử credential attacks hoặc muốn build command khai thác Windows/Linux từ credential đã có.
- Chọn `Generate Report` bất cứ lúc nào sau khi đã có một phần output.

## 6. Menu

```text
[1] Full Auto Scan
[2] Port Scan
[3] Service Enumeration
[4] Web Recon
[5] Vulnerability Scan
[6] Brute / Toolkit
[s] SQLi Workflows
[w] Wordlist Toolkit
[7] Generate Report
[8] View Results
[9] Settings
[t] Change Target
[c] Check Tools
[0] Exit
```

Giải thích nhanh từng option:

- `[1] Full Auto Scan`: chạy toàn bộ pipeline theo thứ tự phase, tự bỏ qua các prompt tương tác giữa chừng, đồng thời tự build wordlists theo target và in digest ngay trên terminal sau từng phase quan trọng.
- `[2] Port Scan`: phase bắt đầu gần như mọi workflow.
- `[3] Service Enumeration`: đọc từ kết quả `nmap_targeted.nmap`; nếu chưa có thì nên chạy port scan trước.
- `[4] Web Recon`: chạy fingerprint, fuzzing, JS analysis, SSL/WAF, CMS, API discovery và các web checks khác.
- `[5] Vulnerability Scan`: chạy `nmap --script vuln`, `searchsploit`, `nuclei`, `sqlmap`, LFI verify và mapping sang Metasploit nếu có.
- `[6] Brute / Toolkit`: mở workflow phase 5:
  - brute force only
  - operator toolkit only
  - brute force rồi handoff sang operator toolkit
- `[s] SQLi Workflows`: mở submenu SQLMap với 2 flow:
  - `SQLMap All-in-One`: batch run trên toàn bộ GET params đã discover, tự tune theo profile hiện tại
  - `SQLMap Operator Workflow`: chạy từng target, lưu command repro và session artifacts trong `vulns/sqlmap_operator*`
- `[w] Wordlist Toolkit`: mở workflow custom wordlists:
  - build target-derived seed lists
  - crawl web target bằng CeWL
  - mutate bằng RSMangler
  - generate pattern list bằng Crunch
  - merge và promote các list này vào session hiện tại
- `[7] Generate Report`: tổng hợp lại output hiện có thành `report.md` và `report.html`.
- `[8] View Results`: duyệt file output trong `results/<target>/`.
- `[9] Settings`: đổi engine, mode, threads, timeout, wordlist, brute-force flag và `Hosts Auto-Map`.
- `[t] Change Target`: đổi sang IP/CIDR/file/domain khác.
- `[c] Check Tools`: kiểm tra nhanh dependency trong môi trường hiện tại.

### 6.1 Terminal digest

Tool giờ sẽ cố in kết quả tóm tắt ngay ra terminal sau các phase chính thay vì chỉ ghi rải ra file:

- port scan: open ports và engine đã dùng
- service enum: bảng service/port chính và web targets
- web recon: hostnames, web inventory, vhost/web target nổi bật
- wordlist toolkit: số lượng usernames/passwords/content words đã sinh
- vuln/SQLi: summary findings
- brute/toolkit: credential cache và command history mới nhất
- report: executive summary + pipeline health

Nếu chỉ muốn xem nhanh mà lười mở file, thường chỉ cần nhìn digest sau phase hoặc chạy `[7] Generate Report`.

## 7. Giao diện khi sử dụng

Khi mở tool bằng `./auto_recon.sh`, bạn sẽ thấy banner và menu chính dạng như sau:

```text
     ___        __         ____
    /   | __  _/ /_____   / __ \___  _________  ____
   / /| |/ / / / __/ __ \ / /_/ / _ \/ ___/ __ \/ __ \
  / ___ / /_/ / /_/ /_/ // _, _/  __/ /__/ /_/ / / / /
 /_/  |_\__,_/\__/\____//_/ |_|\___/\___/\____/_/ /_/

        Auto Recon v3.7  |  Author: Canhieu
        One-click recon for authorized labs, CTFs and pentest workflows
```

Nếu chưa set target:

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  No target set
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

─── SCAN ─────────────────────────────────────────
[1] Full Auto Scan       (all phases, 1 click)
[2] Port Scan            (auto, 8 chunks)
[3] Service Enumeration  (auto-detect services)
[4] Web Recon            (fuzz depth: 4)
[5] Vulnerability Scan   (nmap + searchsploit)
[6] Brute / Toolkit      (hydra + operator toolkit, OFF)
[s] SQLi Workflows       (SQLMap all-in-one + operator)
[w] Wordlist Toolkit     (CeWL + target seeds + crunch + rsmangler)

─── OUTPUT ───────────────────────────────────────
[7] Generate Report
[8] View Results         (browse output files)

─── CONFIG ───────────────────────────────────────
[9] Settings
[t] Change Target
[c] Check Tools

[0] Exit
Choose [0-9/s/w/t/c]:
```

Sau khi set target, thanh trạng thái sẽ hiển thị target, output folder, profile và các phase đã hoàn thành:

```text
Target:  10.10.10.10  (ip)
Output:  results/10.10.10.10
Profile: Balanced | OffSec-safe: OFF
Done:    Ports Services Web Vulns Words Report
```

Các phím hay dùng nhất:

- `[c]`: kiểm tra dependency trước khi scan.
- `[t]`: nhập target mới.
- `[9]`: chỉnh profile, scan mode, engine, threads, timeout.
- `[1]`: chạy full pipeline.
- `[7]`: tạo `report.md` và `report.html`.
- `[8]`: xem nhanh output theo file.

## 8. Test mẫu trước khi scan thật

Trước khi dùng với target thật, nên chạy vài bước test nhẹ để chắc tool hoạt động đúng trên máy của bạn.

### 8.1 Test cú pháp và help

```bash
bash -n auto_recon.sh modules/*.sh lib/*.sh config/*.sh
node --check scripts/js_analyzer.js
./auto_recon.sh --help
```

Kỳ vọng:

```text
bash syntax OK
node syntax OK
Usage:
  ./auto_recon.sh [--profile PROFILE] [--offsec-safe|--no-offsec-safe] [target]
```

### 8.2 Test mở menu và kiểm tool

```bash
./auto_recon.sh
```

Trong menu chọn:

```text
[c] Check Tools
```

Kỳ vọng:

- `nmap`, `nc`, `curl` nên có.
- Các tool như `rustscan`, `feroxbuster`, `ffuf`, `sqlmap`, `nuclei`, `hydra` là optional nhưng nên cài nếu muốn full workflow.

### 8.3 Test local an toàn

Nếu chỉ muốn kiểm tra flow cơ bản mà chưa scan lab thật, dùng localhost:

```bash
./auto_recon.sh 127.0.0.1
```

Trong menu:

```text
[2] Port Scan
[7] Generate Report
[8] View Results
```

Kỳ vọng output:

```text
results/127.0.0.1/
├── report.md
├── report.html
├── scans/
├── web/
├── vulns/
└── state/
```

Localhost có thể không mở port nào; điều đó vẫn bình thường. Mục tiêu của test này là kiểm tra tool tạo thư mục kết quả, chạy phase và sinh report được.

### 8.4 Test lab/CTF mẫu

Khi đã có một target lab được phép, ví dụ `10.10.10.10`:

```bash
sudo ./auto_recon.sh --profile htb 10.10.10.10
```

Trong menu chọn:

```text
[1] Full Auto Scan
```

Sau khi hoàn tất:

```bash
ls results/10.10.10.10
less results/10.10.10.10/report.md
xdg-open results/10.10.10.10/report.html
```

Report mới sẽ có:

- `Executive Dashboard`
- `Key Findings`
- `Attack Surface Inventory`
- `Web Application Details`
- `Vulnerability Evidence`
- `Coverage Gaps & Limitations`
- `Appendix: Artifact Index`

## 9. Full Auto hoạt động như thế nào

Khi chọn `Full Auto Scan`:

1. Tool tự chuyển sang non-interactive trong suốt pipeline
2. Nếu target là CIDR hoặc file IP, tool chạy host discovery trước
3. Mỗi host sau đó đi qua:
   - Port scan
   - Service enum
   - Web recon
   - Wordlist toolkit auto-build
   - Vuln scan
   - Brute force nếu bật
   - Report

Điểm quan trọng:

- Các prompt "Press Enter to continue" được bỏ qua trong full auto
- Nếu đã có kết quả port scan từ trước, tool có thể reuse kết quả đó
- Nếu target là IP nhưng web service tiết lộ domain/vhost, tool sẽ cố map hostname đó rồi tiếp tục recon theo hostname

Full auto phù hợp nhất khi:

- bạn muốn scan trọn một host hoặc một domain
- bạn muốn quét danh sách host từ file
- bạn không muốn bấm Enter sau từng phase

Full auto sẽ không làm được mọi thứ trong mọi hoàn cảnh. Ví dụ:

- nếu không có open ports thì các phase sau sẽ bị dừng
- nếu target là IP và không có tín hiệu hostname/domain nào lộ ra thì phần subdomain/vhost sẽ bị giới hạn
- nếu thiếu tool tương ứng thì phase đó sẽ tự skip hoặc giảm tính năng

Lưu ý thêm:

- `Full Auto Scan` vẫn giữ `sqlmap` auto-check bên trong phase `Vulnerability Scan`
- `Full Auto Scan` tự build và merge custom wordlists từ inventory hiện có, rồi promote sang session để các phase brute/toolkit tái dùng
- `SQLMap All-in-One` và `SQLMap Operator Workflow` là flow bổ sung trong submenu `[s]`
- Hai flow này chỉ chạy khi:
  - `OffSec Safe Mode = OFF`
  - web recon đã tạo được inventory GET params

## 10. Settings

Settings chính trong `config/config.sh` và menu:

### 8.1 Scan mode

- `quick`
  - Port scan nhanh hơn
  - Wordlist web nhỏ hơn
  - DNS brute-force wordlist nhỏ hơn
- `normal`
  - Mặc định
- `full`
  - Wordlist web lớn hơn
  - DNS brute-force giữ danh sách lớn hơn nếu có

### 8.2 Hiệu năng

Các biến quan trọng:

- `SCAN_TIMEOUT`
- `NMAP_DEEP_TIMEOUT`
- `PORT_CHUNKS`
- `NC_PARALLEL`
- `FUZZ_THREADS`
- `WEB_FUZZ_TOOL`
- `ENUM_MAX_JOBS`
- `AUTO_UPDATE_ETC_HOSTS`
- `SQLMAP_ALL_IN_ONE_TIMEOUT`
- `SQLMAP_OPERATOR_TIMEOUT`
- `SQLMAP_OPERATOR_MAX_TARGETS`

`WEB_FUZZ_TOOL` hỗ trợ:

- `auto`: tự ưu tiên `feroxbuster -> gobuster -> ffuf`
- `feroxbuster`: ép dir fuzz/CMS fuzz dùng `feroxbuster`
- `gobuster`: ép dir fuzz/CMS fuzz dùng `gobuster`
- `ffuf`: ép dir fuzz/CMS fuzz dùng `ffuf`

Trong menu `Settings`, option này nằm ở mục `[a] Web Fuzz Tool`.

### 8.3 Profile-aware SQLi workflow

Hai option trong `[s] SQLi Workflows` đọc `ENGAGEMENT_PROFILE` hiện tại để tự chỉnh độ sâu:

- `balanced` và `thm`: nhẹ hơn, timeout vừa phải, ưu tiên batch verify nhanh
- `htb`: tăng `level/risk`, timeout dài hơn và operator queue sâu hơn
- `boot2root`: aggressive nhất cho SQLMap batch và operator runs
- `offsec-lab`: mặc định bị chặn vì `OffSec Safe Mode = ON`

Bạn có thể đổi thêm qua `config/config.sh` bằng các biến:

- `SQLMAP_ALL_IN_ONE_TIMEOUT`
- `SQLMAP_OPERATOR_TIMEOUT`
- `SQLMAP_OPERATOR_MAX_TARGETS`

### 8.4 Gợi ý tuning

Máy yếu hoặc lab chậm:

- giảm `FUZZ_THREADS`
- giảm `PORT_CHUNKS`
- pin `WEB_FUZZ_TOOL=ffuf` hoặc `gobuster` nếu muốn nhẹ hơn `feroxbuster`
- giữ `SCAN_MODE=quick`

Máy mạnh hoặc muốn đào sâu:

- tăng `PORT_CHUNKS`
- giữ `WEB_FUZZ_TOOL=auto` hoặc `feroxbuster`
- giữ `SCAN_MODE=normal` hoặc `full`
- dùng `sudo` để `masscan` và SYN scan hoạt động tốt hơn

## 11. Wordlists

### 9.1 Web wordlists

Tool tự ưu tiên:

1. SecLists
2. Dirb
3. `wordlists/builtin.txt`

### 9.2 DNS wordlists

Subdomain brute-force hiện chỉ dùng SecLists nếu có:

- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt`

Nếu không có SecLists DNS wordlist:

- Passive discovery qua `subfinder` vẫn chạy
- Active brute-force DNS sẽ bị bỏ qua

## 12. JavaScript analysis

Script [`scripts/js_analyzer.js`](scripts/js_analyzer.js) làm các việc sau:

- Tìm external JS và inline script
- Deobfuscate các pattern đơn giản:
  - hex
  - unicode
  - octal
  - `String.fromCharCode`
  - `atob`
  - string concatenation
- Beautify code
- Trích xuất dấu hiệu nhạy cảm:
  - API keys
  - AWS keys
  - secrets/passwords
  - JWT
  - private keys
  - internal URLs
  - hidden paths
  - XSS sinks
  - hardcoded credentials

Output:

- `js/original_*`
- `js/clean_*`
- `js/js_analysis_report.txt`

## 13. Kết quả đầu ra

Ví dụ với target domain:

```text
results/
└── example.com_93.184.216.34/
    ├── auto_recon.log
    ├── report.md
    ├── report.html
    ├── scans/
    ├── web/
    ├── vulns/
    └── loot/
```

Ví dụ với CIDR:

```text
results/network_10.10.10.0_24/
```

Ví dụ với file IP:

```text
results/targets_targets.txt/
```

### 13.1 `scans/`

Chứa:

- `open_ports.txt`
- `scan_method.txt`
- `nmap_targeted.nmap`
- `nmap_targeted.xml`
- `nmap_targeted.gnmap`
- `udp_scan.*`
- file enum theo service

### 13.2 `web/`

Chứa:

- fingerprint
- params
- dir fuzz outputs
- SSL/WAF
- subdomains
- discovered hostnames / root domains / vhosts
- JS analysis
- CMS outputs
- default creds
- API discovery
- Nikto

### 13.3 `vulns/`

Chứa:

- `nmap_vuln.txt`
- `searchsploit_auto.txt`
- `searchsploit_manual.txt`
- `report.md` sẽ hiển thị cả auto correlation và manual ranked queries
- `nuclei_web.txt`
- `nuclei_network.txt`
- `sqlmap_auto.txt`
- `sqlmap_all_in_one_targets.txt`
- `sqlmap_all_in_one.txt`
- `sqlmap_all_in_one_summary.txt`
- `sqlmap_operator_targets.txt`
- `sqlmap_operator_commands.txt`
- `sqlmap_operator_summary.txt`
- `sqlmap_operator/`
- `sqlmap_operator_data/`
- `lfi_auto.txt`
- `msf_mapping.txt`
- `summary.txt`

### 13.4 `loot/`

Chứa:

- CeWL wordlist
- emails
- brute-force outputs

### 13.5 `toolkit/`

Chứa:

- `summary.txt`
- `credential_cache.tsv`
- `sessions/generated_commands.txt`
- `helpers/*.txt`
- command builder outputs cho Windows/Linux operator workflows

### 13.6 `wordlists/`

Chứa:

- `source_inventory.txt`
- `base_tokens.txt`
- `custom_usernames.txt`
- `password_seeds.txt`
- `custom_content.txt`
- `cewl_words.txt`
- `cewl_emails.txt`
- `rsmangler_passwords.txt`
- `crunch_custom.txt`
- `custom_passwords.txt`
- `custom_all.txt`
- `summary.txt`

### 13.7 Nên mở file nào trước

Nếu bạn muốn đọc kết quả nhanh mà không mất thời gian, ưu tiên theo thứ tự này:

0. đọc digest hiện ra ngay trên terminal trước
1. `report.md`
2. `scans/open_ports.txt`
3. `scans/nmap_targeted.nmap`
4. `web/discovered_hostnames.txt` nếu target bắt đầu từ IP
5. `web/subdomains.txt` nếu target là domain hoặc đã suy ra được domain
6. `web/hosts_suggestions.txt`
7. `vulns/summary.txt`
8. `vulns/searchsploit_auto.txt`
9. `vulns/searchsploit_manual.txt`
10. `vulns/sqlmap_all_in_one_summary.txt`
11. `vulns/sqlmap_operator_summary.txt`
12. các file `nuclei_*.txt`
13. `toolkit/summary.txt`
14. `wordlists/summary.txt`
15. `loot/` nếu bạn đã chạy brute force hoặc CeWL

## 14. Hành vi theo loại target

### 14.1 IP

- Tool sẽ cố suy ra domain/vhost từ redirect, TLS cert hoặc banner web
- Nếu phát hiện được hostname phù hợp, tool sẽ sinh mapping `/etc/hosts`
- Web recon chạy trên web service phát hiện từ port/service enum, rồi mở rộng sang hostname/vhost nếu tìm thấy

### 14.2 Domain

- Resolve sang IP
- Subdomain enum được bật
- Web URL ưu tiên domain thay vì IP để tránh lệch virtual host

### 14.3 CIDR

- Chạy host discovery trước
- Mỗi IP sống được scan riêng và có thư mục kết quả riêng

### 14.4 File IPs

- Đọc danh sách host từ file
- Mỗi IP trong file được scan riêng

## 15. Hiệu năng và kiến trúc chạy song song

### 15.1 Port scan

- TCP scan trước
- UDP chạy nền song song với deep scan

### 15.2 Service enum

- Mỗi service enum chạy background
- `ENUM_MAX_JOBS` giữ cho số lượng process cùng lúc không vượt ngưỡng hợp lý

### 15.3 Web recon

Web recon chạy theo wave:

1. Fingerprint + SSL + WAF
2. CMS detection
3. Heavy jobs song song:
   - Dir fuzz
   - Param discovery
   - Source analysis
   - JS analysis
   - VHost fuzz
   - Default creds
   - API discovery
   - Nikto chạy nền riêng
4. Post-fuzz CMS checks

### 15.4 Nuclei

- Web targets được gom vào một file và scan batch bằng `nuclei -l`
- Tránh chuyện ghi đè output khi có nhiều URL

## 16. Những điểm cần biết

- `Full Auto Scan` hiện hoạt động tốt nhất khi chạy từ menu
- Tool chưa có bộ CLI flags đầy đủ kiểu `--full-auto`, `--json`, `--quiet`
- Một vài setting lịch sử vẫn còn trong config/comment nhưng không phải giá trị nào cũng đang được orchestration route trực tiếp
- `subfinder` là khuyến nghị mạnh cho domain targets
- Với IP targets, VHost fuzzing chỉ mạnh khi tool suy ra được domain gốc hoặc cert/redirect để lộ hostname

## 17. Ví dụ workflow thực tế

### 17.1 Domain

```bash
sudo ./auto_recon.sh example.com
```

Trong menu:

```text
[1] Full Auto Scan
```

Tool sẽ:

- resolve domain
- tìm subdomain
- probe web subdomain sống
- scan cổng IP đích
- enum service
- recon web
- scan vuln
- tạo report

### 17.2 Danh sách nhiều host

`targets.txt`

```text
10.10.10.10
10.10.10.11
10.10.10.12
```

Chạy:

```bash
sudo ./auto_recon.sh targets.txt
```

Sau đó chọn `Full Auto Scan`.

### 17.2.1 IP target có virtual host

Ví dụ:

```bash
sudo ./auto_recon.sh 10.10.10.10
```

Trong menu:

1. kiểm tra `Settings` và giữ `Hosts Auto-Map = ON`
2. chọn `[1] Full Auto Scan`

Sau phase web recon, nên mở các file sau:

- `web/discovered_hostnames.txt`
- `web/vhosts.txt`
- `web/hosts_suggestions.txt`

Nếu target thực sự dùng virtual host, đây là nơi bạn sẽ thấy domain/vhost mà tool suy ra được.

### 17.3 Chạy từng phase bằng tay

Trường hợp bạn không muốn full auto, đây là luồng thủ công điển hình:

1. Chạy `./auto_recon.sh 10.10.10.10`
2. Chọn `[2] Port Scan`
3. Chọn `[3] Service Enumeration`
4. Nếu có web service, chọn `[4] Web Recon`
5. Chọn `[5] Vulnerability Scan`
6. Nếu cần credential attack hoặc command builder cho operator workflow, chọn `[6] Brute / Toolkit`
7. Cuối cùng chọn `[7] Generate Report`

Flow này phù hợp khi:

- bạn muốn chỉnh từng phase
- bạn chỉ quan tâm một nhóm service cụ thể
- bạn muốn dừng lại xem output trước khi phase tiếp theo chạy

### 17.4 SQLi workflows sau web recon

Nếu web recon đã tạo ra các file `web/params_*.txt`, bạn có thể đi tiếp:

1. Chọn `[s] SQLi Workflows`
2. Chọn `[1] SQLMap All-in-One` khi muốn verify nhanh toàn bộ inventory params theo profile hiện tại
3. Chọn `[2] SQLMap Operator Workflow` khi muốn per-target logs và command repro cụ thể

Kết quả chính sẽ nằm ở:

- `vulns/sqlmap_all_in_one_summary.txt`
- `vulns/sqlmap_operator_summary.txt`
- `vulns/sqlmap_operator_commands.txt`

Flow này hợp lý khi:

- bạn muốn chạy lại SQLi checks mà không rerun toàn bộ vuln phase
- bạn đang dùng profile `htb` hoặc `boot2root` và muốn đào sâu hơn inventory params hiện có
- bạn muốn report hiển thị rõ SQLMap batch findings và operator artifacts riêng

Nếu `OffSec Safe Mode = ON`, menu này sẽ tự skip và ghi trạng thái phase tương ứng.

### 17.5 Wordlist workflow sau web recon / brute

Nếu muốn tăng chất lượng credential attack theo đúng target:

1. Chọn `[w] Wordlist Toolkit`
2. Chạy `Build target-derived seed lists`
3. Nếu có web app, chạy thêm `Run CeWL custom crawl`
4. Có thể mutate bằng `RSMangler` hoặc sinh pattern bằng `Crunch`
5. Chạy `Build merged custom wordlists`
6. Chạy `Promote generated lists into current session`
7. Quay lại `[6] Brute / Toolkit` hoặc rerun các web checks cần custom list

Các file chính:

- `wordlists/custom_usernames.txt`
- `wordlists/custom_passwords.txt`
- `wordlists/custom_content.txt`
- `wordlists/custom_all.txt`
- `wordlists/summary.txt`

### 17.6 Brute force web form

Khi vào option `[6] Brute / Toolkit`, với `Web Login Form` bạn nên chuẩn bị trước:

- URL login hoặc base URL
- path đăng nhập
- params template
- chuỗi báo thất bại hoặc thành công

Ví dụ params template:

```text
username=^USER^&password=^PASS^&Login=Login
```

Ví dụ failure string:

```text
Invalid username or password
```

Nếu `nmap` hoặc web recon đã phát hiện nhiều web targets, wizard sẽ cho bạn chọn trực tiếp thay vì nhập tay toàn bộ URL.

## 18. Troubleshooting

### Không thấy subdomain

Kiểm tra:

- có chạy bằng domain hay không
- nếu chạy bằng IP, target có thực sự lộ hostname/domain qua redirect hoặc TLS cert hay không
- `subfinder` có được cài không
- SecLists DNS wordlist có tồn tại không
- DNS lab có resolve public/passive data hay không

Nếu bài dùng virtual host nhưng không có DNS public:

- xem `web/discovered_hostnames.txt`
- xem `web/hosts_suggestions.txt`
- bật `Hosts Auto-Map`
- chạy lại `Web Recon` nếu bạn vừa thêm mapping thủ công

### Không có web recon

Kiểm tra:

- `scans/web_ports.txt`
- service scan có detect được `http` / `https` không
- target có dùng virtual host không

### Kết quả scan chậm

Thử:

- `SCAN_MODE=quick`
- giảm `FUZZ_THREADS`
- giảm `PORT_CHUNKS`
- chạy riêng từng phase thay vì full auto

### `masscan` không chạy

- chạy bằng `sudo`
- kiểm tra rule mạng lab

## 19. Hướng nâng cấp tiếp theo

Những thứ nên làm tiếp:

- thêm `httpx` để probe web trên subdomain nhanh và chuẩn hơn `curl`
- thêm CLI flags đầy đủ
- thêm JSON summary ngoài Markdown report
- thêm test suite `bats` + `shellcheck`
- thay brute-force command construction sang Bash arrays hoàn toàn, bỏ `eval`

## 20. Tác giả và mục tiêu sử dụng

**Author:** Canhieu

Đây là công cụ hỗ trợ recon tự động cho môi trường được phép kiểm thử. Mục tiêu của Auto Recon là giúp tiết kiệm thời gian ở phase reconnaissance, chuẩn hóa output và tạo report dễ đọc sau mỗi lần scan.

Chỉ sử dụng với:

- lab
- CTF
- môi trường pentest có ủy quyền
- hệ thống bạn được phép kiểm tra

Không sử dụng tool để quét hoặc brute-force hệ thống không thuộc phạm vi được phép. Nếu public lên GitHub, nên đi kèm license, `.gitignore`, và security/disclaimer rõ ràng để người dùng hiểu đúng phạm vi.
