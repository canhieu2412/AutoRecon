# Auto Recon — Web GUI

A localhost web interface over the same bash engine. Two ways to run the tool:

| Mode | Command | Notes |
|------|---------|-------|
| **CLI** | `./auto_recon.sh` | the classic interactive menu (unchanged) |
| **GUI** | `./auto_recon.sh --gui` | web app on `http://127.0.0.1:2412` |

The GUI does **not** reimplement any scan logic — it shells out to
`auto_recon.sh --headless --phase <name> <target>` and streams the output over a
WebSocket. Every artifact still lands in `results/<target>/`.

## Install & run

```bash
pip install --user -r web/requirements.txt      # fastapi, uvicorn, jinja2, python-multipart
./auto_recon.sh --gui                            # or:  make gui
#   → prints:  Open: http://127.0.0.1:2412/?token=XXXX
```

Open the printed URL (it carries a one-time session **token**, then sets a cookie).
Other options:

```bash
./auto_recon.sh --gui --port 8000        # different port
./auto_recon.sh --gui --unsafe-bind      # bind 0.0.0.0 (exposes the tool — avoid)
python3 web/server.py --check            # verify deps are installed
```

## What's in it (full parity)

- **Dashboard** — set a target, pick profile / engine / OSCP-safe, launch Full Auto or any phase.
- **Live scan view** — streaming terminal + pipeline tracker + Stop.
- **Results** — browse `results/<target>/` files and open the rendered `report.html`.
- **Phase pages** — every phase (port/service/web/vuln/next-steps/priv-esc/AD/pivot/wordlist/brute/report),
  with an *Advanced → pre-seed answers* box that answers interactive prompts (`prompt = value`).
- **Shell Console** — catch a reverse shell and upload/download files (base64 through the shell).
- **Settings** — view `config.sh` defaults; set per-session overrides (sent with each scan, file untouched).

## Headless CLI (also used by the GUI)

```bash
./auto_recon.sh --full-auto --profile htb 10.10.11.10
./auto_recon.sh --headless --phase next_steps 10.10.10.99
./auto_recon.sh --headless --phase pivot --result-dir /tmp/out 10.10.10.5
```

## Security

This app runs offensive tooling. It **binds `127.0.0.1` only** and requires the
session token on every request/WebSocket. The file API is confined to `results/`
(path-traversal rejected), and scans are spawned via argv arrays (no shell
injection). **Do not expose this port.** Authorized lab / CTF / OSCP use only.

## Tests

```bash
make test-web      # launches the real server, runs a no-network phase + shell bridge
make test          # everything: lint + phase tests + web tests + TUI self-test
```
