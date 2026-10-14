#!/usr/bin/env python3
"""agyhub — phone/browser page for the Antigravity CLI (agy).

The browser talks only to this process. Login is scrypt plus RFC 6238 TOTP.
agy has no localhost agent socket, so a chat turn is one long-running
`agy --input-format stream-json` process. Google sign-in is a separate pty
session that shows the OAuth link and accepts the code once.
"""

import argparse
import asyncio
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import pty
import re
import secrets
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import uuid
from pathlib import Path

from aiohttp import WSMsgType, web

CODE = Path(__file__).resolve().parent
PAGE = CODE / "static" / "index.html"
COOKIE = "agyhub"
SESSION_TTL = 12 * 3600
LOCK_AFTER = 5
LOCK_SECS = 15 * 60
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
DEFAULT_CWD = "/var/lib/agyhub/work"
MAX_IMAGES = 4
MAX_IMAGE_BYTES = 3_500_000
MAX_TEXT = 32_000
REPLAY_LIMIT = 400
IMAGE_MAGIC = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/gif": b"GIF8",
    "image/webp": b"RIFF",
}
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
CODE_RE = re.compile(r"[A-Za-z0-9_\-./+=]{8,512}")

_fails = {}
_sessions = {}


def hub_root():
    raw = os.environ.get("AGYHUB_ROOT", "").strip()
    return Path(raw).resolve() if raw else CODE


def hub_label():
    raw = os.environ.get("AGYHUB_NAME", "").strip() or hub_root().name or "agyhub"
    clean = "".join(ch for ch in raw if ch.isalnum() or ch in "-_")
    return clean or "agyhub"


def secrets_path():
    return hub_root() / "secrets.json"


def _b32decode(text):
    raw = text.strip().upper().rstrip("=")
    raw += "=" * ((8 - len(raw) % 8) % 8)
    return base64.b32decode(raw, casefold=True)


def totp_code(secret, when):
    counter = int(when) // 30
    digest = hmac.new(_b32decode(secret), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{binary % 1000000:06d}"


def totp_step(secret, code, now=None):
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6:
        return None
    now = time.time() if now is None else now
    for shift in (-30, 0, 30):
        when = now + shift
        if hmac.compare_digest(totp_code(secret, when), code):
            return int(when) // 30
    return None


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex(), "hash": digest.hex()}


def password_ok(record, password):
    digest = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(record["salt"]),
        n=record["n"], r=record["r"], p=record["p"], dklen=32,
    )
    return hmac.compare_digest(digest, bytes.fromhex(record["hash"]))


def load_secrets():
    data = json.loads(secrets_path().read_text())
    if not isinstance(data.get("password"), dict) or not data.get("totp_secret"):
        raise SystemExit("secrets.json is missing password or totp_secret")
    return data


def write_secrets(data):
    path = secrets_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
        fh.write("\n")
    os.chmod(path, 0o600)


def setup(force):
    path = secrets_path()
    if path.exists() and not force:
        raise SystemExit(f"{path} already exists (pass --force to replace it)")
    password = os.environ.get("AGYHUB_PASSWORD")
    if not password:
        import getpass
        password = getpass.getpass("Password: ")
        again = getpass.getpass("Again: ")
        if not hmac.compare_digest(password, again):
            raise SystemExit("passwords did not match")
    if len(password) < 8 or len(password) > 256:
        raise SystemExit("password must be 8 to 256 characters")
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    write_secrets({"password": hash_password(password), "totp_secret": secret})
    print("TOTP secret (shown once):", secret)
    print("Wrote", path, "mode 600")


def parse_bind(spec):
    if spec.startswith("["):
        host, _, port = spec[1:].rpartition("]:")
    else:
        host, _, port = spec.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("bind must be host:port")
    if host in {"0.0.0.0", "::", "::0"}:
        raise SystemExit(f"refusing wildcard bind {host}")
    return host, int(port)


def client_ip(request):
    peer = request.remote or "?"
    trusted = request.app.get("trusted_proxy") or ""
    if not trusted or peer != trusted:
        return peer
    parts = [part.strip() for part in request.headers.get("X-Forwarded-For", "").split(",") if part.strip()]
    return parts[-1] if parts else peer


def cookie_secure(request):
    """Secure on HTTPS. Plain HTTP, and HTTP via a trusted proxy, stays unsigned so the browser keeps the cookie."""
    if not request.app.get("secure_cookie"):
        return False
    peer = request.remote or ""
    trusted = request.app.get("trusted_proxy") or ""
    if peer == trusted:
        proto = request.headers.get("X-Forwarded-Proto", "")
        if proto:
            return proto.split(",")[0].strip().lower() == "https"
    return request.scheme == "https"


def origin_ok(request):
    origin = request.headers.get("Origin", "")
    if "://" not in origin:
        return False
    return origin.split("://", 1)[1] == request.host


def locked(ip):
    rec = _fails.get(ip)
    if not rec or not rec[1]:
        return False
    if time.time() >= rec[1]:
        _fails.pop(ip, None)
        return False
    return True


def note_failure(ip):
    rec = _fails.setdefault(ip, [0, 0.0])
    rec[0] += 1
    if rec[0] >= LOCK_AFTER:
        rec[1] = time.time() + LOCK_SECS


def note_success(ip):
    _fails.pop(ip, None)


def cookie_token(request):
    token = request.cookies.get(COOKIE, "")
    exp = _sessions.get(token)
    if not token or not exp or exp < time.time():
        _sessions.pop(token, None)
        return ""
    return token


def authed(request):
    return bool(cookie_token(request))


def image_blobs(images):
    if images is None:
        return []
    if not isinstance(images, list):
        raise ValueError("bad images")
    if len(images) > MAX_IMAGES:
        raise ValueError("too many images")
    out = []
    for item in images:
        if not isinstance(item, dict):
            raise ValueError("bad image")
        mime = str(item.get("mime") or "")
        raw = item.get("data") or ""
        if mime not in IMAGE_MAGIC or not isinstance(raw, str):
            raise ValueError("unsupported image")
        try:
            blob = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("bad image")
        if not (32 <= len(blob) <= MAX_IMAGE_BYTES):
            raise ValueError("image too large")
        if mime == "image/webp":
            if not (blob.startswith(b"RIFF") and blob[8:12] == b"WEBP"):
                raise ValueError("not an image")
        elif not blob.startswith(IMAGE_MAGIC[mime]):
            raise ValueError("not an image")
        out.append((mime, blob, raw))
    return out


_URL_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%"
)


def _osc_urls(raw):
    # agy uses OSC 8 with a nonempty param: ESC ] 8 ; params ; url BEL
    # The visible URL is wrapped, with a blank line between each piece.
    urls = []
    needle = b"\x1b]8;"
    i = 0
    while True:
        start = raw.find(needle, i)
        if start < 0:
            break
        body_at = start + len(needle)
        bel = raw.find(b"\x07", body_at)
        st = raw.find(b"\x1b\\", body_at)
        ends = [n for n in (bel, st) if n >= 0]
        if not ends:
            break
        end = min(ends)
        body = raw[body_at:end]
        semi = body.find(b";")
        if semi >= 0:
            url = body[semi + 1:].decode("utf-8", "replace").strip()
            if url.startswith("https://"):
                urls.append(url)
        i = end + 1
    return urls


def _urlish(stripped):
    if len(stripped) < 8:
        return False
    good = sum(ch in _URL_CHARS for ch in stripped)
    return good >= int(len(stripped) * 0.9)


def _oauth_stop(stripped):
    lower = stripped.lower()
    return (
        "─" in stripped
        or lower.startswith("copy ")
        or "authorization code" in lower
        or stripped.startswith("→")
    )


def _usable_oauth(url):
    if not url or any(ch.isspace() for ch in url) or "…" in url or "..." in url:
        return False
    if not url.startswith("https://accounts.google.com/"):
        return False
    return "response_type=" in url and "client_id=" in url and "state=" in url


def _join_oauth(text):
    mark = "https://accounts.google.com"
    idx = text.find(mark)
    if idx < 0:
        return ""
    lines = []
    pending_blank = False
    stopped = False
    for line in text[idx:].splitlines():
        stripped = line.strip().strip("│|")
        if not stripped:
            if lines:
                pending_blank = True
            continue
        if _oauth_stop(stripped):
            stopped = True
            break
        if pending_blank and not _urlish(stripped):
            stopped = True
            break
        pending_blank = False
        lines.append(stripped)
    if not stopped or not lines:
        return ""
    url = "".join(lines).split()[0]
    if url.startswith(mark):
        return url
    return ""


def extract_oauth_url(raw):
    """Pull the Google OAuth link out of an agy login screen.

    Do not return a wrapped first line. That slice ends before response_type,
    and Google answers 400 invalid_request.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    osc = [url for url in _osc_urls(raw) if _usable_oauth(url)]
    if osc:
        return max(osc, key=len)
    text = ANSI_RE.sub("", raw.decode("utf-8", "replace")).replace("\r", "\n")
    joined = _join_oauth(text)
    if _usable_oauth(joined):
        return joined
    return ""


def map_step(step):
    """One stream-json step_update, as hub updates. Empty if nothing to show."""
    stype = str(step.get("step_type") or "")
    state = str(step.get("state") or "").upper()
    delta = step.get("text_delta") or ""
    if stype == "agent_response" and delta:
        return [{"kind": "agent_message_chunk", "text": str(delta)}]
    if "think" in stype and delta:
        return [{"kind": "agent_thought_chunk", "text": str(delta)}]
    if stype == "tool" or step.get("tool_info"):
        info = step.get("tool_info") or {}
        name = str(step.get("tool_name") or info.get("name") or "tool")
        params = info.get("parameters") or {}
        parts = []
        if params:
            parts.append(json.dumps(params, ensure_ascii=False)[:4000])
        if info.get("output"):
            parts.append(str(info.get("output"))[:8000])
        err = info.get("error")
        status = "done" if state == "DONE" else "running"
        if err:
            status = "error"
            parts.append(json.dumps(err, ensure_ascii=False)[:2000])
        return [{
            "kind": "tool_call",
            "tool": str(step.get("step_index") if step.get("step_index") is not None else name),
            "title": name,
            "status": status,
            "body": "\n".join(parts),
            "text": name,
        }]
    sub = step.get("subagent_info")
    if sub:
        return [{
            "kind": "tool_call",
            "tool": "sub-" + str(step.get("step_index") or ""),
            "title": "subagent",
            "status": "done" if state == "DONE" else "running",
            "body": json.dumps(sub, ensure_ascii=False)[:4000],
            "text": "subagent",
        }]
    return []


def turn_stop(result):
    status = str((result or {}).get("status") or "").upper()
    if status == "SUCCESS":
        return "end_turn", ""
    if status in {"CANCELED", "CANCELLED", "INTERRUPTED"}:
        return "cancelled", ""
    return "error", str((result or {}).get("error") or status or "agy error")[:500]


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "sessions.json"
        self._lock = threading.Lock()

    def _read(self):
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        rows = data.get("sessions") if isinstance(data, dict) else None
        return rows if isinstance(rows, list) else []

    def _write(self, rows):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"sessions": rows}, fh)
            fh.write("\n")
        os.chmod(self.path, 0o600)

    def list(self):
        with self._lock:
            return list(self._read())

    def get(self, sid):
        with self._lock:
            for row in self._read():
                if row.get("id") == sid:
                    return dict(row)
        return None

    def upsert(self, row):
        with self._lock:
            rows = self._read()
            rows = [item for item in rows if item.get("id") != row.get("id")]
            rows.append(row)
            self._write(rows)
        return row

    def transcript_path(self, sid):
        safe = "".join(ch for ch in sid if ch.isalnum() or ch in "-_")
        folder = self.root / "transcripts"
        folder.mkdir(parents=True, exist_ok=True)
        return folder / (safe + ".jsonl")

    def append(self, sid, update):
        path = self.transcript_path(sid)
        line = json.dumps(update, ensure_ascii=False) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(line)

    def tail(self, sid, limit=REPLAY_LIMIT):
        path = self.transcript_path(sid)
        if not path.exists():
            return []
        lines = path.read_text(errors="replace").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                out.append(item)
        return out


def token_present(path):
    try:
        return Path(path).is_file() and Path(path).stat().st_size > 0
    except OSError:
        return False


class GoogleLogin:
    """One interactive `agy` on a pty. Enter once to pick Google OAuth, then one code."""

    def __init__(self, agy, token_file):
        self.agy = agy
        self.token_file = Path(token_file)
        self.lock = threading.Lock()
        self.proc = None
        self.master = None
        self.url = ""
        self.sent = False
        self.buf = bytearray()
        self.stop_drain = threading.Event()
        self.drain = None

    def _alive(self):
        return self.proc is not None and self.proc.poll() is None

    def pending(self):
        return bool(self.url) and self._alive() and not self.sent

    def close(self):
        self.stop_drain.set()
        proc = self.proc
        master = self.master
        drain = self.drain
        self.proc = None
        self.master = None
        self.drain = None
        self.url = ""
        self.sent = False
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait(timeout=2)
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        if drain is not None and drain.is_alive() and drain is not threading.current_thread():
            drain.join(timeout=1)
        self.stop_drain = threading.Event()
        self.buf = bytearray()

    def _read_available(self):
        master = self.master
        if master is None:
            return
        while True:
            ready, _, _ = select.select([master], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.buf.extend(chunk)

    def _drain_loop(self):
        while not self.stop_drain.is_set():
            master = self.master
            if master is None:
                return
            try:
                ready, _, _ = select.select([master], [], [], 0.2)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.buf.extend(chunk)

    def start(self):
        with self.lock:
            if self.url and self._alive() and not self.sent:
                return self.url
            self.close()
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            # A fake SSH session makes agy print the URL instead of opening a browser.
            env["SSH_CONNECTION"] = "127.0.0.1 1 127.0.0.1 22"
            env["SSH_CLIENT"] = "127.0.0.1 1 22"
            env.pop("DISPLAY", None)
            env.pop("BROWSER", None)
            try:
                self.proc = subprocess.Popen(
                    [self.agy], stdin=slave, stdout=slave, stderr=slave,
                    env=env, start_new_session=True, close_fds=True,
                )
            finally:
                os.close(slave)
            self.master = master
            self.buf = bytearray()
            deadline = time.time() + 25
            while time.time() < deadline and self._alive():
                self._read_available()
                if b"Select login method" in self.buf:
                    break
                time.sleep(0.1)
            if b"Select login method" not in self.buf:
                self.close()
                raise RuntimeError("agy did not offer Google sign-in")
            os.write(master, b"\r")
            deadline = time.time() + 20
            while time.time() < deadline and self._alive():
                self._read_available()
                url = extract_oauth_url(bytes(self.buf))
                if url:
                    self.url = url
                    self.sent = False
                    self.stop_drain.clear()
                    self.drain = threading.Thread(target=self._drain_loop, daemon=True)
                    self.drain.start()
                    return url
                time.sleep(0.1)
            self.close()
            raise RuntimeError("agy did not show a Google sign-in link")

    def submit(self, code):
        with self.lock:
            if self.sent:
                raise RuntimeError("that code was already sent; get a new link")
            if not self.url or not self._alive() or self.master is None:
                raise RuntimeError("get a sign-in link first")
            code = re.sub(r"\s+", "", code or "")
            if not CODE_RE.fullmatch(code):
                raise RuntimeError("that does not look like an authorization code")
            self.sent = True
            os.write(self.master, code.encode() + b"\r")
            deadline = time.time() + 60
            while time.time() < deadline:
                if token_present(self.token_file):
                    self.close()
                    return
                if self.proc is not None and self.proc.poll() is not None:
                    break
                time.sleep(0.2)
            blob = bytes(self.buf).lower()
            self.close()
            if b"invalid" in blob or b"error" in blob or b"denied" in blob:
                raise RuntimeError("Google did not accept that code. Get a new link.")
            raise RuntimeError("sign-in did not finish. Get a new link.")


class Agent:
    def __init__(self, agy, cwd, token_file, store, yolo, sandbox, print_timeout):
        self.agy = agy
        self.cwd = str(cwd)
        self.token_file = Path(token_file)
        self.store = store
        self.yolo = yolo
        self.sandbox = sandbox
        self.print_timeout = print_timeout
        self.proc = None
        self.hub_id = ""
        self.conversation_id = ""
        self.busy = False
        self.browsers = set()
        self.stderr_task = None
        Path(self.cwd).mkdir(parents=True, exist_ok=True)

    def signed_in(self):
        return token_present(self.token_file)

    async def broadcast(self, obj):
        dead = []
        for browser in self.browsers:
            try:
                await browser.send_json(obj)
            except Exception:
                dead.append(browser)
        for browser in dead:
            self.browsers.discard(browser)

    async def close(self):
        await self._stop_proc()

    async def _stop_proc(self):
        proc = self.proc
        self.proc = None
        self.hub_id = ""
        task = self.stderr_task
        self.stderr_task = None
        if proc is not None and proc.returncode is None:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                await proc.wait()
        if task is not None:
            task.cancel()

    async def _read_stderr(self, proc):
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    return
                text = line.decode("utf-8", "replace").strip()
                lower = text.lower()
                if not text:
                    continue
                if any(word in lower for word in ("denied", "authentication", "sign in", "error")):
                    await self.broadcast({"op": "update", "id": self.hub_id, "kind": "err", "text": text[:300]})
        except asyncio.CancelledError:
            return
        except Exception:
            return

    async def _read_event(self):
        proc = self.proc
        if proc is None:
            raise RuntimeError("agy is not running")
        for _ in range(80):
            line = await proc.stdout.readline()
            if not line:
                raise RuntimeError("agy closed")
            raw = line.strip()
            if not raw:
                continue
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                text = raw.decode("utf-8", "replace")[:300]
                lower = text.lower()
                if "auth" in lower or "sign in" in lower:
                    raise RuntimeError(text)
                continue
        raise RuntimeError("agy sent no json")

    async def _ensure(self, row):
        conv = row.get("conversation_id") or ""
        if (
            self.proc is not None
            and self.proc.returncode is None
            and self.hub_id == row["id"]
        ):
            return
        await self._stop_proc()
        cmd = [
            self.agy,
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--print-timeout", self.print_timeout,
            "--disable-slash-commands",
        ]
        if self.yolo:
            cmd.append("--dangerously-skip-permissions")
        if self.sandbox:
            cmd.append("--sandbox")
        if conv:
            cmd.extend(["--conversation", conv])
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.cwd,
            start_new_session=True,
        )
        self.hub_id = row["id"]
        self.stderr_task = asyncio.create_task(self._read_stderr(self.proc))
        try:
            init = await asyncio.wait_for(self._read_event(), 45)
        except asyncio.TimeoutError:
            await self._stop_proc()
            raise RuntimeError("agy did not start")
        if init.get("event") != "init":
            await self._stop_proc()
            raise RuntimeError("agy did not start")
        self.conversation_id = init.get("conversation_id") or conv
        if self.conversation_id and self.conversation_id != conv:
            row["conversation_id"] = self.conversation_id
            self.store.upsert(row)

    def _remember(self, sid, update):
        update = dict(update)
        update["op"] = "update"
        update["id"] = sid
        self.store.append(sid, update)
        return update

    async def prompt(self, sid, text, images):
        if self.busy:
            raise RuntimeError("busy")
        row = self.store.get(sid)
        if row is None:
            raise RuntimeError("no such chat")
        if not self.signed_in():
            raise RuntimeError("agy is not signed in")
        blobs = image_blobs(images)
        text = (text or "").strip()
        if len(text) > MAX_TEXT:
            raise ValueError("message too long")
        if not text and not blobs:
            raise ValueError("empty prompt")
        self.busy = True
        try:
            paths = self._save_images(sid, blobs)
            content = text
            if paths:
                content = (content + "\n\n" if content else "") + "Attached files:\n" + "\n".join(paths)
            user = self._remember(sid, {"kind": "user_message_chunk", "text": text or "(image)"})
            for mime, _blob, b64 in blobs:
                self._remember(sid, {"kind": "user_image", "mime": mime, "data": b64})
            await self.broadcast(user)
            if row.get("title") in {"", "New chat"} and text:
                row["title"] = text.replace("\n", " ")[:48]
            row["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.store.upsert(row)
            await self._ensure(row)
            payload = json.dumps({"event": "user", "message": {"content": content}}) + "\n"
            self.proc.stdin.write(payload.encode())
            await self.proc.stdin.drain()
            while True:
                event = await self._read_event()
                if event.get("event") == "result":
                    stop, err = turn_stop(event.get("result") or {})
                    if err:
                        noted = self._remember(sid, {"kind": "err", "text": err})
                        await self.broadcast(noted)
                    return stop
                step = event.get("step_update") or {}
                for update in map_step(step):
                    saved = self._remember(sid, update)
                    await self.broadcast(saved)
        finally:
            self.busy = False

    def _save_images(self, sid, blobs):
        paths = []
        folder = Path(self.cwd) / "attachments" / "".join(ch for ch in sid if ch.isalnum())
        if blobs:
            folder.mkdir(parents=True, exist_ok=True)
        ext = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
        for mime, blob, _b64 in blobs:
            name = uuid.uuid4().hex + ext.get(mime, ".bin")
            path = folder / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            paths.append(str(path))
        return paths

    async def cancel(self):
        proc = self.proc
        if proc is not None and proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass


LOGIN_HTML = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#101011">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="__HUB__">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" href="/icon-192.png" type="image/png">
<title>__HUB__</title>
<style>
html{color-scheme:dark}
body{font:17px/1.4 system-ui,sans-serif;margin:0;background:#101011;color:#ececec;min-height:100dvh}
main{max-width:24rem;margin:0 auto;padding:max(28px,env(safe-area-inset-top)) 20px max(24px,env(safe-area-inset-bottom))}
h1{font-size:22px;font-weight:650;margin:12px 0 4px}
.sub{color:#8b919a;margin:0 0 22px;font-size:14px}
form{display:flex;flex-direction:column;gap:10px}
input,button{font:17px system-ui,sans-serif;padding:14px;border-radius:12px;border:0}
input{background:#1c1d21;color:#ececec}
button{background:#2f6f4e;color:#fff;min-height:48px}
p{color:#8b919a;font-size:14px;margin:18px 0 0}
</style>
<main>
<h1>__HUB__</h1>
<p class="sub">Password, then the 6 digit code.</p>
<form id="login" method="post" action="/login">
<input name="password" type="password" autocomplete="current-password" placeholder="Password" required>
<input name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="6 digit code" required>
<button>Sign in</button>
</form>
<p>On your phone: browser menu, then Add to Home Screen.</p>
</main>
<script>if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js")</script>
"""


def login_page(_request):
    html = LOGIN_HTML.replace("__HUB__", hub_label())
    return web.Response(text=html, content_type="text/html", headers={"Cache-Control": "no-cache"})


async def index(request):
    if not authed(request):
        raise web.HTTPFound("/login")
    html = PAGE.read_text().replace("__HUB__", hub_label())
    return web.Response(text=html, content_type="text/html", headers={"Cache-Control": "no-cache"})


async def manifest(_request):
    path = CODE / "static" / "manifest.webmanifest"
    data = json.loads(path.read_text())
    name = hub_label()
    data["name"] = name
    data["short_name"] = name
    data["description"] = "Chat with " + name
    return web.Response(
        text=json.dumps(data),
        content_type="application/manifest+json",
        headers={"Cache-Control": "no-cache"},
    )


def public_asset(path, content_type, cache):
    async def handler(_request):
        return web.Response(
            body=path.read_bytes(), content_type=content_type,
            headers={"Cache-Control": cache},
        )
    return handler


async def login(request):
    ip = client_ip(request)
    if locked(ip):
        return web.Response(status=429, text="locked\n")
    form = await request.post()
    password = str(form.get("password", ""))[:256]
    code = str(form.get("totp", ""))[:16]
    secrets_data = request.app["secrets"]
    step = totp_step(secrets_data["totp_secret"], code)
    ok = password_ok(secrets_data["password"], password) and step is not None and step > request.app["totp_last"]
    if not ok:
        note_failure(ip)
        return web.Response(status=401, text="unauthorized\n")
    request.app["totp_last"] = step
    note_success(ip)
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + SESSION_TTL
    resp = web.HTTPFound("/")
    resp.set_cookie(
        COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="Strict", path="/",
        secure=cookie_secure(request),
    )
    raise resp


async def logout(request):
    token = cookie_token(request)
    if token:
        _sessions.pop(token, None)
    resp = web.HTTPFound("/login")
    resp.set_cookie(
        COOKIE, "", max_age=0, httponly=True, samesite="Strict", path="/",
        secure=cookie_secure(request),
    )
    raise resp


def new_row(cwd):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "id": uuid.uuid4().hex,
        "title": "New chat",
        "conversation_id": "",
        "cwd": cwd,
        "updated": now,
    }


async def browser_ws(request):
    if not authed(request):
        raise web.HTTPUnauthorized(text="unauthorized\n")
    if not origin_ok(request):
        raise web.HTTPForbidden(text="bad origin\n")
    agent = request.app["agent"]
    login_flow = request.app["google"]
    ws = web.WebSocketResponse(max_msg_size=12 * 1024 * 1024)
    await ws.prepare(request)
    agent.browsers.add(ws)
    inflight = set()
    await ws.send_json({"op": "auth", "signed_in": agent.signed_in()})

    def spawn_prompt(sid, text, images):
        async def run():
            try:
                stop = await agent.prompt(sid, text, images)
                if not ws.closed:
                    await ws.send_json({"op": "done", "id": sid, "stop": stop})
                    await ws.send_json({"op": "sessions", "sessions": agent.store.list()})
            except Exception as exc:
                if not ws.closed:
                    await ws.send_json({"op": "error", "id": sid, "message": str(exc)[:300]})
        task = asyncio.create_task(run())
        inflight.add(task)
        task.add_done_callback(inflight.discard)

    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
                op = data.get("op")
                if op == "list":
                    await ws.send_json({"op": "sessions", "sessions": agent.store.list()})
                elif op == "new":
                    row = new_row(agent.cwd)
                    agent.store.upsert(row)
                    await ws.send_json({"op": "opened", "id": row["id"], "title": "new"})
                elif op == "open":
                    sid = str(data.get("id") or "")
                    row = agent.store.get(sid)
                    if row is None:
                        raise RuntimeError("no such chat")
                    for update in agent.store.tail(sid):
                        await ws.send_json(update)
                    await ws.send_json({"op": "opened", "id": sid, "title": row.get("title") or ""})
                elif op == "prompt":
                    if login_flow.pending():
                        raise RuntimeError("finish Google sign-in first")
                    spawn_prompt(str(data.get("id") or ""), str(data.get("text") or ""), data.get("images"))
                elif op == "cancel":
                    await agent.cancel()
                    await ws.send_json({"op": "cancelled", "id": data.get("id") or ""})
                elif op == "login_start":
                    if agent.busy:
                        raise RuntimeError("wait for the current turn to finish")
                    url = await asyncio.to_thread(login_flow.start)
                    await ws.send_json({"op": "login", "phase": "code", "url": url})
                elif op == "login_code":
                    await asyncio.to_thread(login_flow.submit, str(data.get("code") or ""))
                    await ws.send_json({"op": "login", "phase": "done"})
                    await ws.send_json({"op": "auth", "signed_in": agent.signed_in()})
                else:
                    await ws.send_json({"op": "error", "message": "unknown op"})
            except Exception as exc:
                await ws.send_json({"op": "error", "message": str(exc)[:300]})
    finally:
        agent.browsers.discard(ws)
        for task in inflight:
            task.cancel()
    return ws


def build_app(secrets_data, agent, google, secure_cookie, trusted_proxy):
    app = web.Application()
    app["secrets"] = secrets_data
    app["agent"] = agent
    app["google"] = google
    app["secure_cookie"] = secure_cookie
    app["trusted_proxy"] = trusted_proxy
    app["totp_last"] = 0
    public = {
        "/sw.js": (CODE / "static" / "sw.js", "application/javascript", "no-cache"),
        "/icon-192.png": (CODE / "static" / "icon-192.png", "image/png", "public, max-age=86400"),
        "/icon-512.png": (CODE / "static" / "icon-512.png", "image/png", "public, max-age=86400"),
        "/apple-touch-icon.png": (CODE / "static" / "apple-touch-icon.png", "image/png", "public, max-age=86400"),
        "/favicon.ico": (CODE / "static" / "icon-192.png", "image/png", "public, max-age=86400"),
    }
    for path, (file_path, content_type, cache) in public.items():
        app.router.add_get(path, public_asset(file_path, content_type, cache))
    app.add_routes([
        web.get("/", index),
        web.get("/manifest.webmanifest", manifest),
        web.get("/login", login_page),
        web.post("/login", login),
        web.get("/logout", logout),
        web.get("/ws", browser_ws),
    ])
    return app


async def serve(args):
    host, port = parse_bind(args.bind)
    root = hub_root()
    data = Path(args.data) if args.data else root / "data"
    cwd = Path(args.cwd)
    store = Store(data)
    agent = Agent(args.agy, cwd, args.token_file, store, args.yolo, args.sandbox, args.print_timeout)
    google = GoogleLogin(args.agy, args.token_file)
    app = build_app(load_secrets(), agent, google, args.secure_cookie, args.trusted_proxy or "")
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    print(f"agyhub listening on {host}:{port}", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await agent.close()
        await asyncio.to_thread(google.close)


def main(argv):
    parser = argparse.ArgumentParser(description="agyhub")
    sub = parser.add_subparsers(dest="cmd", required=True)
    setup_p = sub.add_parser("setup")
    setup_p.add_argument("--force", action="store_true")
    serve_p = sub.add_parser("serve")
    serve_p.add_argument("--bind", required=True, help="host:port, not 0.0.0.0 or ::")
    serve_p.add_argument("--agy", default="agy", help="agy binary")
    serve_p.add_argument("--cwd", default=DEFAULT_CWD, help="workspace agy may read and write")
    serve_p.add_argument("--token-file", default=str(Path.home() / ".gemini/antigravity-cli/antigravity-oauth-token"))
    serve_p.add_argument("--data", default="", help="session store; default is <root>/data")
    serve_p.add_argument("--print-timeout", default="15m")
    serve_p.add_argument("--yolo", action="store_true", help="pass --dangerously-skip-permissions to agy")
    serve_p.add_argument("--sandbox", action="store_true", help="pass --sandbox to agy")
    serve_p.add_argument("--secure-cookie", action="store_true")
    serve_p.add_argument("--trusted-proxy", default="")
    args = parser.parse_args(argv)
    if args.cmd == "setup":
        setup(args.force)
        return
    asyncio.run(serve(args))


if __name__ == "__main__":
    main(sys.argv[1:])
