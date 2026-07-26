#!/usr/bin/env python3
# ============================================================================
# AUTO RECON - Web GUI backend (FastAPI)
# ----------------------------------------------------------------------------
# A thin driver over the existing bash engine. It shells out to
#   auto_recon.sh --headless --phase <name> <target>
# streams the output over WebSockets, and browses the results/ tree. No scan
# logic is reimplemented here.
#
# SECURITY: binds 127.0.0.1 by default and requires a session token printed to
# the console at startup. This app runs offensive tooling — do NOT expose it.
# Authorized lab / CTF / OSCP-style pentest use only.
# ============================================================================
import argparse
import asyncio
import ipaddress
import os
import re
import secrets
import signal
import sys
import time
from collections import deque
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent          # repo root
RESULTS_DIR = BASE_DIR / "results"
AUTO_RECON = BASE_DIR / "auto_recon.sh"
WEB_DIR = BASE_DIR / "web"


def _load_shell_engine():
    """Reuse the UI-agnostic ReverseShellEngine from the Textual TUI module."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("shell_tui", BASE_DIR / "modules" / "shell_tui.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ReverseShellEngine

VALID_PHASES = [
    "full-auto", "port_scan", "service_enum", "web_recon", "vuln_scan",
    "next_steps", "privesc", "ad_enum", "pivot", "wordlist", "brute", "report",
]
VALID_PROFILES = ["balanced", "offsec-lab", "htb", "thm", "boot2root", "custom"]
MAX_CONCURRENT_JOBS = 4
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# ── target validation (mirrors lib/utils.sh detect_target_type) ─────────────
def detect_target_type(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return "unknown"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        if "/" in target:
            return "cidr"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+", target):
        return "domain"
    return "unknown"


def result_label_for(target: str) -> str:
    """Best-effort mirror of get_result_label for IP/CIDR (domains resolve at runtime)."""
    ttype = detect_target_type(target)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    if ttype == "cidr":
        return f"network_{safe}"
    return safe


# ── job manager ─────────────────────────────────────────────────────────────
class Job:
    def __init__(self, job_id, target, action, argv, env):
        self.id = job_id
        self.target = target
        self.action = action
        self.argv = argv
        self.env = env
        self.proc = None
        self.status = "queued"          # queued|running|done|failed|stopped
        self.returncode = None
        self.started = None
        self.ended = None
        self.lines = deque(maxlen=5000)  # ring buffer for reconnects
        self.subscribers = set()         # set[asyncio.Queue]
        self.logfile = None

    def as_dict(self):
        return {
            "id": self.id, "target": self.target, "action": self.action,
            "status": self.status, "returncode": self.returncode,
            "started": self.started, "ended": self.ended,
            "lines": len(self.lines),
            "result_label": result_label_for(self.target),
        }

    def _emit(self, line):
        self.lines.append(line)
        for q in list(self.subscribers):
            try:
                q.put_nowait(line)
            except asyncio.QueueFull:
                pass
        if self.logfile:
            try:
                self.logfile.write(line + "\n")
                self.logfile.flush()
            except Exception:
                pass


class JobManager:
    def __init__(self):
        self.jobs = {}
        self._running = 0

    def list(self):
        return [j.as_dict() for j in sorted(self.jobs.values(), key=lambda x: x.started or 0, reverse=True)]

    def get(self, jid):
        return self.jobs.get(jid)

    async def start(self, target, action, profile, safe_mode, engine, answers, config):
        if self._running >= MAX_CONCURRENT_JOBS:
            raise RuntimeError(f"too many concurrent jobs (max {MAX_CONCURRENT_JOBS})")
        if detect_target_type(target) == "unknown":
            raise ValueError("invalid target (expected IP / CIDR / domain)")
        if action not in VALID_PHASES:
            raise ValueError(f"invalid action '{action}'")
        if profile not in VALID_PROFILES:
            profile = "balanced"

        jid = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        argv = ["bash", str(AUTO_RECON), "--no-tui", "--profile", profile]
        argv += ["--offsec-safe"] if safe_mode else ["--no-offsec-safe"]
        if action == "full-auto":
            argv += ["--full-auto"]
        else:
            argv += ["--phase", action]
        # target is positional; guarded by validation above (argv array = no shell injection)
        argv += ["--", target]

        # Drop inherited exported shell functions (e.g. a shell that wraps grep/
        # sed): the scan must use the real binaries, not a caller's shadows.
        env = {k: v for k, v in os.environ.items() if not k.startswith("BASH_FUNC_")}
        env["USE_TUI"] = "off"
        env["INTERACTIVE"] = "false"
        if engine:
            env["SCAN_METHOD"] = str(engine)
        for k, v in (answers or {}).items():
            slug = re.sub(r"[^a-z0-9]+", "_", str(k).lower()).strip("_")[:48]
            env[f"AR_ANS_{slug}"] = str(v)
        for k, v in (config or {}).items():
            if re.fullmatch(r"[A-Z][A-Z0-9_]{1,40}", str(k)):
                env[str(k)] = str(v)

        job = Job(jid, target, action, argv, env)
        self.jobs[jid] = job
        asyncio.create_task(self._run(job))
        return job

    async def _run(self, job):
        self._running += 1
        job.status = "running"
        job.started = time.time()
        # per-run log under the target's result dir
        try:
            runs = RESULTS_DIR / result_label_for(job.target) / "web_runs"
            runs.mkdir(parents=True, exist_ok=True)
            job.logfile = open(runs / f"{job.id}.log", "w")
        except Exception:
            job.logfile = None
        try:
            job.proc = await asyncio.create_subprocess_exec(
                *job.argv, cwd=str(BASE_DIR),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.DEVNULL, env=job.env, start_new_session=True,
            )
            job._emit(f"$ auto_recon.sh --headless {'--full-auto' if job.action=='full-auto' else '--phase '+job.action} {job.target}")
            async for raw in job.proc.stdout:
                job._emit(strip_ansi(raw.decode("utf-8", "replace").rstrip("\n")))
            job.returncode = await job.proc.wait()
            job.status = "done" if job.returncode == 0 else "failed"
        except Exception as e:  # noqa: BLE001
            job.status = "failed"
            job._emit(f"[server error] {e}")
        finally:
            job.ended = time.time()
            self._running -= 1
            job._emit(f"__JOB_END__ status={job.status} rc={job.returncode}")
            if job.logfile:
                job.logfile.close()

    def stop(self, jid):
        job = self.jobs.get(jid)
        if not job or not job.proc or job.status != "running":
            return False
        try:
            os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
            job.status = "stopped"
            return True
        except ProcessLookupError:
            return False


# ── reverse-shell bridge (web port of the Textual console) ──────────────────
class ShellBridge:
    def __init__(self):
        self.engine = None
        self.subs = set()                    # set[asyncio.Queue]
        self.history = deque(maxlen=3000)
        self.peer = None
        self.port = None
        self.loot = RESULTS_DIR / "_shell" / "loot"

    def _log(self, text):
        for q in list(self.subs):
            try:
                q.put_nowait(text)
            except asyncio.QueueFull:
                pass
        self.history.append(text)

    def status(self):
        return {
            "listening": self.engine is not None,
            "connected": bool(self.engine and self.engine.is_connected()),
            "peer": self.peer, "port": self.port,
        }

    async def listen(self, host, port):
        Engine = _load_shell_engine()
        if self.engine is not None:
            raise RuntimeError("a listener is already active")
        eng = Engine(host, int(port), log_cb=self._log)
        eng.on_connect_cb = self._on_connect
        await eng.start()
        self.engine = eng
        self.port = int(port)
        self._log(f"[*] listening on {host}:{port} — run a reverse-shell payload on the target")

    def _on_connect(self, peer):
        self.peer = peer
        self._log(f"[+] shell from {peer}")

    async def send(self, cmd):
        if not (self.engine and self.engine.is_connected()):
            raise RuntimeError("no shell connected")
        self._log(f"$ {cmd}")
        await self.engine.send_command(cmd)

    async def upload(self, local_path, remote_path):
        if not (self.engine and self.engine.is_connected()):
            raise RuntimeError("no shell connected")
        return await self.engine.upload(local_path, remote_path)

    async def download(self, remote_path):
        if not (self.engine and self.engine.is_connected()):
            raise RuntimeError("no shell connected")
        self.loot.mkdir(parents=True, exist_ok=True)
        name = os.path.basename(remote_path.rstrip("/")) or "loot.bin"
        local = str(self.loot / name)
        return await self.engine.download(remote_path, local), local


# ── FastAPI app ─────────────────────────────────────────────────────────────
def build_app(token: str):
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Depends, UploadFile, Form
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates

    app = FastAPI(title="Auto Recon", docs_url=None, redoc_url=None)
    app.state.token = token
    app.state.jobs = JobManager()
    app.state.shell = ShellBridge()
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    if (WEB_DIR / "static").is_dir():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    def token_ok(request: Request) -> bool:
        supplied = (request.cookies.get("ar_token")
                    or request.headers.get("x-ar-token")
                    or request.query_params.get("token"))
        return bool(supplied) and secrets.compare_digest(supplied, token)

    def require(request: Request):
        if not token_ok(request):
            raise HTTPException(status_code=401, detail="invalid or missing token")
        return True

    def safe_target_dir(target: str) -> Path:
        # confine to results/ — reject traversal
        candidate = (RESULTS_DIR / target).resolve()
        if not str(candidate).startswith(str(RESULTS_DIR.resolve()) + os.sep) and candidate != RESULTS_DIR.resolve():
            raise HTTPException(status_code=400, detail="path outside results/")
        return candidate

    # ---- page routes (token via ?token= sets a cookie, then redirects clean) --
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        q = request.query_params.get("token")
        if q and secrets.compare_digest(q, token):
            resp = RedirectResponse(url="/")
            resp.set_cookie("ar_token", token, httponly=True, samesite="strict")
            return resp
        if not token_ok(request):
            return HTMLResponse(LOGIN_HTML, status_code=401)
        return templates.TemplateResponse("dashboard.html", {"request": request, "profiles": VALID_PROFILES})

    @app.get("/scan/{job_id}", response_class=HTMLResponse)
    async def scan_view(request: Request, job_id: str):
        require(request)
        job = app.state.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "no such job")
        return templates.TemplateResponse("scan.html", {"request": request, "job": job.as_dict()})

    @app.get("/results", response_class=HTMLResponse)
    async def results_index(request: Request):
        require(request)
        return templates.TemplateResponse("results.html", {"request": request, "targets": _list_targets(), "preselect": ""})

    @app.get("/results/{target}", response_class=HTMLResponse)
    async def results_target(request: Request, target: str):
        require(request)
        safe_target_dir(target)  # validate/confine
        return templates.TemplateResponse("results.html", {"request": request, "targets": _list_targets(), "preselect": target})

    @app.get("/shell", response_class=HTMLResponse)
    async def shell_page(request: Request):
        require(request)
        return templates.TemplateResponse("shell.html", {"request": request})

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        require(request)
        return templates.TemplateResponse("settings.html", {"request": request})

    @app.get("/phase/{name}", response_class=HTMLResponse)
    async def phase_page(request: Request, name: str):
        require(request)
        if name not in VALID_PHASES:
            raise HTTPException(404, "unknown phase")
        return templates.TemplateResponse("phase.html", {"request": request, "phase": name, "profiles": VALID_PROFILES})

    # ---- REST API ------------------------------------------------------------
    @app.post("/api/scan")
    async def api_scan(request: Request, _=Depends(require)):
        body = await request.json()
        try:
            job = await app.state.jobs.start(
                target=body.get("target", "").strip(),
                action=body.get("action", "full-auto"),
                profile=body.get("profile", "balanced"),
                safe_mode=bool(body.get("safe_mode", False)),
                engine=body.get("engine") or None,
                answers=body.get("answers") or {},
                config=body.get("config") or {},
            )
        except (ValueError, RuntimeError) as e:
            raise HTTPException(400, str(e))
        return {"job_id": job.id, "job": job.as_dict()}

    @app.get("/api/jobs")
    async def api_jobs(_=Depends(require)):
        return {"jobs": app.state.jobs.list()}

    @app.get("/api/jobs/{job_id}")
    async def api_job(job_id: str, _=Depends(require)):
        job = app.state.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "no such job")
        return {"job": job.as_dict(), "tail": list(job.lines)[-200:]}

    @app.post("/api/jobs/{job_id}/stop")
    async def api_job_stop(job_id: str, _=Depends(require)):
        return {"stopped": app.state.jobs.stop(job_id)}

    @app.get("/api/targets")
    async def api_targets(_=Depends(require)):
        return {"targets": _list_targets()}

    @app.get("/api/targets/{target}/files")
    async def api_files(target: str, _=Depends(require)):
        base = safe_target_dir(target)
        if not base.is_dir():
            raise HTTPException(404, "no such target")
        files = []
        for p in sorted(base.rglob("*")):
            if p.is_file():
                files.append({"path": str(p.relative_to(base)), "size": p.stat().st_size})
        return {"target": target, "files": files}

    @app.get("/api/targets/{target}/file")
    async def api_file(target: str, path: str, _=Depends(require)):
        base = safe_target_dir(target)
        fp = (base / path).resolve()
        if not str(fp).startswith(str(base) + os.sep) or not fp.is_file():
            raise HTTPException(400, "path outside target or not a file")
        if fp.stat().st_size > 3_000_000:
            return PlainTextResponse(f"[file too large: {fp.stat().st_size} bytes]")
        return PlainTextResponse(fp.read_text("utf-8", "replace"))

    @app.get("/api/targets/{target}/report", response_class=HTMLResponse)
    async def api_report(target: str, _=Depends(require)):
        base = safe_target_dir(target)
        rep = base / "report.html"
        if not rep.is_file():
            raise HTTPException(404, "no report.html — run the report phase")
        return FileResponse(str(rep))

    @app.get("/api/config")
    async def api_config_get(_=Depends(require)):
        values, overrides = _read_config()
        return {"schema": CONFIG_SCHEMA, "values": values, "overridden": list(overrides)}

    @app.post("/api/config")
    async def api_config_set(request: Request, _=Depends(require)):
        body = await request.json()
        clean, errors = _validate_config(body or {})
        if errors:
            raise HTTPException(400, "; ".join(errors))
        _write_user_config(clean)
        values, overrides = _read_config()
        return {"saved": list(clean), "values": values, "overridden": list(overrides)}

    @app.post("/api/config/reset")
    async def api_config_reset(_=Depends(require)):
        removed = _reset_user_config()
        values, overrides = _read_config()
        return {"reset": removed, "values": values, "overridden": list(overrides)}

    @app.get("/api/targets/{target}/phases")
    async def api_phases(target: str, _=Depends(require)):
        safe_target_dir(target)
        return {"phases": _read_phase_states(target)}

    @app.get("/api/targets/{target}/summary")
    async def api_summary(target: str, _=Depends(require)):
        safe_target_dir(target)
        return _read_summary(target)

    @app.get("/api/health")
    async def api_health():
        return {"ok": True, "targets": len(_list_targets()), "jobs": len(app.state.jobs.jobs)}

    # ---- WebSocket: live job output -----------------------------------------
    @app.websocket("/ws/jobs/{job_id}")
    async def ws_job(ws: WebSocket, job_id: str):
        supplied = ws.query_params.get("token") or ws.cookies.get("ar_token")
        if not supplied or not secrets.compare_digest(supplied, token):
            await ws.close(code=1008)
            return
        job = app.state.jobs.get(job_id)
        if not job:
            await ws.close(code=1008)
            return
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=10000)
        job.subscribers.add(q)
        try:
            for line in list(job.lines):          # replay history on connect
                await ws.send_text(line)
            if job.status not in ("running", "queued"):
                await ws.send_text(f"__JOB_END__ status={job.status} rc={job.returncode}")
            while True:
                line = await q.get()
                await ws.send_text(line)
                if line.startswith("__JOB_END__"):
                    break
        except WebSocketDisconnect:
            pass
        finally:
            job.subscribers.discard(q)

    # ---- reverse-shell console -----------------------------------------------
    @app.get("/api/shell/status")
    async def shell_status(_=Depends(require)):
        return app.state.shell.status()

    @app.post("/api/shell/listen")
    async def shell_listen(request: Request, _=Depends(require)):
        body = await request.json()
        port = body.get("port", 4444)
        if not (isinstance(port, int) or str(port).isdigit()):
            raise HTTPException(400, "invalid port")
        try:
            await app.state.shell.listen("0.0.0.0", int(port))
        except (RuntimeError, OSError) as e:
            raise HTTPException(400, str(e))
        return app.state.shell.status()

    @app.post("/api/shell/upload")
    async def shell_upload(_=Depends(require), file: UploadFile = None, remote_path: str = Form(...)):
        if file is None:
            raise HTTPException(400, "no file")
        tmp = RESULTS_DIR / "_shell" / "upload_tmp"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as fh:
            fh.write(await file.read())
        try:
            ok, msg = await app.state.shell.upload(str(tmp), remote_path)
        except RuntimeError as e:
            raise HTTPException(400, str(e))
        finally:
            try: os.remove(tmp)
            except OSError: pass
        return {"ok": ok, "message": msg}

    @app.post("/api/shell/download")
    async def shell_download(request: Request, _=Depends(require)):
        body = await request.json()
        remote = (body.get("remote_path") or "").strip()
        if not remote:
            raise HTTPException(400, "remote_path required")
        try:
            (ok, msg), local = await app.state.shell.download(remote)
        except RuntimeError as e:
            raise HTTPException(400, str(e))
        return {"ok": ok, "message": msg, "local": local}

    @app.websocket("/ws/shell")
    async def ws_shell(ws: WebSocket):
        supplied = ws.query_params.get("token") or ws.cookies.get("ar_token")
        if not supplied or not secrets.compare_digest(supplied, token):
            await ws.close(code=1008)
            return
        await ws.accept()
        bridge = app.state.shell
        q: asyncio.Queue = asyncio.Queue(maxsize=10000)
        bridge.subs.add(q)

        async def pump():
            try:
                while True:
                    await ws.send_text(await q.get())
            except Exception:
                pass

        pump_task = asyncio.create_task(pump())
        try:
            for line in list(bridge.history):
                await ws.send_text(line)
            while True:
                cmd = await ws.receive_text()
                try:
                    await bridge.send(cmd)
                except RuntimeError as e:
                    await ws.send_text(f"[!] {e}")
        except WebSocketDisconnect:
            pass
        finally:
            pump_task.cancel()
            bridge.subs.discard(q)

    return app


def _list_targets():
    if not RESULTS_DIR.is_dir():
        return []
    out = []
    for d in sorted(RESULTS_DIR.iterdir()):
        if d.is_dir():
            out.append({
                "name": d.name,
                "has_report": (d / "report.html").is_file(),
                "mtime": int(d.stat().st_mtime),
            })
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


USER_CONFIG = BASE_DIR / "config" / "user_config.sh"

# Editable settings schema — drives validation AND the Settings form widgets.
CONFIG_SCHEMA = [
    {"key": "SCAN_METHOD", "label": "Port scan engine", "type": "enum", "group": "Scanning",
     "options": ["auto", "rustscan", "naabu", "masscan", "nmap", "nmap-single", "nc", "nc-quick"]},
    {"key": "SCAN_MODE", "label": "Scan depth", "type": "enum", "group": "Scanning",
     "options": ["quick", "normal", "full"]},
    {"key": "PORT_CHUNKS", "label": "Port scan chunks", "type": "int", "group": "Scanning"},
    {"key": "THREADS", "label": "Default threads", "type": "int", "group": "Scanning"},
    {"key": "ENUM_MAX_JOBS", "label": "Max parallel enum jobs", "type": "int", "group": "Scanning"},
    {"key": "SCAN_TIMEOUT", "label": "Engine switch timeout (s)", "type": "int", "group": "Scanning"},
    {"key": "WEB_FUZZ_TOOL", "label": "Web fuzzer", "type": "enum", "group": "Web",
     "options": ["auto", "feroxbuster", "gobuster", "ffuf"]},
    {"key": "RECURSION_DEPTH", "label": "Fuzz recursion depth", "type": "int", "group": "Web"},
    {"key": "FUZZ_THREADS", "label": "Fuzzing threads", "type": "int", "group": "Web"},
    {"key": "ENGAGEMENT_PROFILE", "label": "Default profile", "type": "enum", "group": "Engagement",
     "options": VALID_PROFILES},
    {"key": "OFFSEC_OSCP_SAFE_MODE", "label": "OSCP-safe mode", "type": "bool", "group": "Engagement"},
    {"key": "AUTO_BRUTE", "label": "Auto brute-force", "type": "bool", "group": "Engagement"},
    {"key": "AD_SPRAY_MAX", "label": "AD spray cap", "type": "int", "group": "Active Directory"},
    {"key": "DRY_RUN", "label": "Dry-run (print, don't execute)", "type": "bool", "group": "Execution"},
]
CONFIG_BY_KEY = {c["key"]: c for c in CONFIG_SCHEMA}


def _parse_sh_assignments(text, keys):
    out = {}
    for key in keys:
        for m in re.finditer(rf'^{key}=(?:"([^"]*)"|\'([^\']*)\'|([^\s#]+))', text, re.MULTILINE):
            out[key] = next(g for g in m.groups() if g is not None)
    return out


def _read_config():
    """Defaults from config.sh, overlaid with persisted user_config.sh."""
    keys = list(CONFIG_BY_KEY)
    cfg = {}
    cfgfile = BASE_DIR / "config" / "config.sh"
    if cfgfile.is_file():
        cfg.update(_parse_sh_assignments(cfgfile.read_text("utf-8", "replace"), keys))
    overrides = {}
    if USER_CONFIG.is_file():
        overrides = _parse_sh_assignments(USER_CONFIG.read_text("utf-8", "replace"), keys)
    cfg.update(overrides)
    return cfg, overrides


def _validate_config(updates):
    """Return (clean_dict, errors[]) validated against the schema."""
    clean, errors = {}, []
    for k, v in updates.items():
        spec = CONFIG_BY_KEY.get(k)
        if not spec:
            errors.append(f"unknown setting: {k}")
            continue
        v = str(v).strip()
        t = spec["type"]
        if t == "bool":
            if v.lower() not in ("true", "false"):
                errors.append(f"{k}: expected true/false"); continue
            clean[k] = v.lower()
        elif t == "int":
            if not re.fullmatch(r"-?\d+", v):
                errors.append(f"{k}: expected an integer"); continue
            clean[k] = v
        elif t == "enum":
            if v not in spec["options"]:
                errors.append(f"{k}: must be one of {spec['options']}"); continue
            clean[k] = v
        else:
            if not re.fullmatch(r"[\w./:\-]{0,120}", v):
                errors.append(f"{k}: invalid characters"); continue
            clean[k] = v
    return clean, errors


def _write_user_config(updates):
    """Merge validated updates into user_config.sh (atomic, safely quoted)."""
    _, existing = _read_config()
    merged = dict(existing)
    merged.update(updates)
    lines = ["#!/bin/bash",
             "# Auto Recon user overrides — edited via the GUI Settings page.",
             "# Sourced last by config/config.sh; applies to CLI and GUI. Delete to reset.",
             ""]
    for k in sorted(merged):
        spec = CONFIG_BY_KEY.get(k)
        v = merged[k]
        if spec and spec["type"] in ("bool", "int"):
            lines.append(f"{k}={v}")
        else:
            lines.append(f'{k}="{v}"')
    tmp = USER_CONFIG.with_suffix(".sh.tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.replace(tmp, USER_CONFIG)


def _reset_user_config():
    try:
        USER_CONFIG.unlink()
        return True
    except FileNotFoundError:
        return False


PHASE_ORDER = ["host_discovery", "port_scan", "service_enum", "web_recon", "wordlist_toolkit",
               "vuln_scan", "next_steps", "privesc", "ad_enum", "pivot", "brute_force", "report"]


def _read_phase_states(target):
    base = (RESULTS_DIR / target / "state")
    states = []
    if base.is_dir():
        found = {}
        for f in base.glob("*.env"):
            kv = {}
            for line in f.read_text("utf-8", "replace").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip().strip('"').replace("\\", "")
            if "status" not in kv:      # skip non-phase files (e.g. target_context.env)
                continue
            found[f.stem] = {
                "phase": f.stem, "status": kv.get("status", "unknown"),
                "duration": kv.get("duration_seconds", ""), "detail": kv.get("detail", ""),
            }
        for p in PHASE_ORDER:
            if p in found:
                states.append(found.pop(p))
        states.extend(found.values())
    return states


def _read_summary(target):
    base = RESULTS_DIR / target
    md = base / "report.md"
    kpis, sev = [], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if md.is_file():
        text = md.read_text("utf-8", "replace")
        for m in re.finditer(r"^- \*\*([^*]+)\*\*:\s*(.+)$", text, re.MULTILINE):
            kpis.append({"label": m.group(1).strip(), "value": m.group(2).strip()})
            if len(kpis) >= 14:
                break
        for level in sev:
            sev[level] = len(re.findall(rf"\[{level}\]", text))
    return {"kpis": kpis, "severity": sev, "has_report": (base / "report.html").is_file()}


LOGIN_HTML = """<!doctype html><meta charset=utf-8><title>Auto Recon — token required</title>
<style>body{font-family:ui-monospace,monospace;background:#0b0f16;color:#e7eef8;display:grid;place-items:center;height:100vh;margin:0}
.b{border:1px solid #1e2a3d;border-radius:12px;padding:28px 32px;max-width:460px}
h1{color:#35c2b8;font-size:1.1rem}code{color:#ffc34d}</style>
<div class=b><h1>Auto Recon Web GUI</h1>
<p>A session token is required. Open the URL printed in your terminal, e.g.:</p>
<p><code>http://127.0.0.1:2412/?token=YOUR_TOKEN</code></p>
<p style="color:#8494aa">The token is shown when the server starts. This app runs offensive tooling — keep it on localhost.</p></div>"""


def deps_available():
    try:
        import fastapi, uvicorn, jinja2  # noqa: F401
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="Auto Recon web GUI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2412)
    ap.add_argument("--check", action="store_true", help="report whether web deps are installed")
    ap.add_argument("--token", default=None, help="override the session token (default: random)")
    args = ap.parse_args()

    if args.check:
        if deps_available():
            print("web deps: available (fastapi, uvicorn, jinja2)")
            return 0
        print("web deps: MISSING — pip install --user -r web/requirements.txt")
        return 2

    if not deps_available():
        sys.stderr.write("Missing deps. Install: pip install --user -r web/requirements.txt\n")
        return 2

    import uvicorn
    token = args.token or secrets.token_urlsafe(18)
    app = build_app(token)
    url = f"http://{args.host}:{args.port}/?token={token}"
    print("\n" + "=" * 68)
    print("  AUTO RECON — Web GUI")
    print("  Open:  " + url)
    print("  Token: " + token)
    if args.host != "127.0.0.1":
        print("  !! WARNING: bound to a non-localhost address — offensive tooling exposed")
    print("  Authorized lab / CTF / pentest use only. Ctrl-C to stop.")
    print("=" * 68 + "\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
