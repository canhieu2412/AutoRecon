# Auto Recon All-in-One Quick Guide

## Muc tieu

Ban nay dung de chay nhanh cho:

- OffSec labs
- HTB
- THM
- Boot2Root

No uu tien 3 dieu:

- recon sau hon theo target
- ket qua tom tat in ngay tren terminal
- custom wordlists + operator workflows nam trong cung mot tool

## Chay nhanh

```bash
./auto_recon.sh --profile offsec-lab 10.10.10.10
./auto_recon.sh --profile htb 10.10.11.10
./auto_recon.sh --profile thm room.local
./auto_recon.sh --profile boot2root 192.168.56.101
```

## Profile nen dung

- `offsec-lab`: an toan hon cho phong cach OffSec, co the bat kem `--offsec-safe`
- `htb`: dao sau hon cho single target
- `thm`: vua phai, hop room co huong dan
- `boot2root`: aggressive nhat
- `balanced`: default cho moi truong hon hop

## Menu nhanh

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
```

## Thu tu de dung hang ngay

Neu muon nhanh:

1. set target
2. chay `[1] Full Auto Scan`
3. xem digest tren terminal sau moi phase
4. neu can dao sau SQLi, vao `[s]`
5. neu can target-specific wordlists, vao `[w]`
6. neu can credential attack hoac build command cho Windows/Linux, vao `[6]`
7. chay `[7] Generate Report` de co tong hop cuoi

## Terminal digest

Tool se tu in ket qua tom tat ngay sau cac phase chinh:

- open ports
- service table
- web targets / hostnames
- wordlist counts
- vuln summary
- SQLi summary
- credential cache / generated operator commands
- report executive summary

Muc tieu la de ban khong can mo tung file le te moi thay thong tin chinh.

## Wordlist workflow

Menu `[w]` dung de tao list theo target:

1. build seed lists tu hostnames, params, inventories, creds
2. crawl CeWL neu co web target
3. mutate bang RSMangler
4. sinh pattern bang Crunch
5. merge thanh:
   - `wordlists/custom_usernames.txt`
   - `wordlists/custom_passwords.txt`
   - `wordlists/custom_content.txt`
   - `wordlists/custom_all.txt`
6. promote cac list nay vao session hien tai de brute/web fuzz tai su dung ngay

Trong `Full Auto`, tool cung tu build va merge wordlists co ban sau service/web recon.

## Operator workflow

Menu `[6] Brute / Toolkit` gom:

- brute force only
- toolkit only
- brute force roi handoff sang toolkit

Toolkit build command cho:

- Windows: `evil-winrm`, `netexec`, `impacket-*`, `xfreerdp`, `smbclient`, `rpcclient`
- Linux: `ssh`, `scp`, helper notes cho priv-esc

## File can doc nhat

Neu van muon mo file, uu tien:

1. `results/<target>/report.md`
2. `results/<target>/vulns/summary.txt`
3. `results/<target>/toolkit/summary.txt`
4. `results/<target>/wordlists/summary.txt`

## Ghi chu

- `OffSec Safe Mode` se skip cac helper khong muon dung trong bai OffSec-safe.
- `SQLMap All-in-One` va `SQLMap Operator Workflow` chi chay khi safe mode tat.
- README chi tiet hon van nam o `README.md`.
