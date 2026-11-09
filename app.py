"""Admin Ubuntu web app. Privileged commands are fixed and passed as argv."""
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque
import hashlib
import hmac
import json
import os
import platform
import socket
import subprocess
import time
import asyncio
from urllib.parse import urlsplit

import pam
import psutil
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent
SECRET = os.environ.get("ADMIN_UBUNTU_SECRET", "")
COOKIE = "admin_ubuntu_session"
SESSION_TTL = 8 * 60 * 60
LOGIN_FAILS = defaultdict(deque)
app = FastAPI(title="Admin Ubuntu", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and origin:
        if urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            return Response("Origine de requête refusée.", status_code=403)
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=32, pattern=r"^[a-z_][a-z0-9_-]*[$]?$" )
    password: str = Field(min_length=1, max_length=256)


class PackageAction(BaseModel):
    package: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.+:_-]*$")


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=32, pattern=r"^[a-z_][a-z0-9_-]*$")
    password: str = Field(min_length=12, max_length=128)
    admin: bool = False


def require_secret():
    if len(SECRET) < 32:
        raise HTTPException(503, "Configurez ADMIN_UBUNTU_SECRET avec au moins 32 caractères.")


def token_for(username: str, expires: int) -> str:
    payload = f"{username}:{expires}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def session_user(request: Request, websocket: bool = False) -> str:
    require_secret()
    value = request.cookies.get(COOKIE)
    try:
        username, exp, sig = value.rsplit(":", 2)
        payload = f"{username}:{exp}"
        valid = hmac.compare_digest(sig, hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest())
        if valid and int(exp) > time.time():
            return username
    except (AttributeError, ValueError):
        pass
    if websocket:
        raise WebSocketDisconnect(code=4401)
    raise HTTPException(401, "Session expirée ou absente.")


def is_admin(username: str) -> bool:
    try:
        result = subprocess.run(["/usr/bin/id", "-nG", username], capture_output=True, text=True, timeout=3, check=True)
        return bool(set(result.stdout.split()) & {"sudo", "admin"})
    except (subprocess.SubprocessError, OSError):
        return False


def admin_user(request: Request) -> str:
    username = session_user(request)
    if not is_admin(username):
        raise HTTPException(403, "Cette fonction est réservée aux membres du groupe sudo.")
    return username


def helper(action: str, **data):
    try:
        p = subprocess.run(["/usr/bin/sudo", "-n", "/usr/local/sbin/admin-ubuntu-helper"],
                           input=json.dumps({"action": action, **data}), text=True,
                           capture_output=True, timeout=900, check=False,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    except subprocess.TimeoutExpired:
        raise HTTPException(503, "Le helper système a dépassé le délai autorisé.")
    except OSError:
        raise HTTPException(503, "Le helper système est indisponible.")
    if p.returncode:
        detail = (p.stderr or p.stdout or "Commande refusée par sudo.").strip()[-1200:]
        raise HTTPException(500, detail)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, "Réponse invalide du helper système.")


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/session")
def current_session(request: Request):
    user = session_user(request)
    return {"username": user, "admin": is_admin(user)}


@app.post("/api/login")
def login(data: Login, request: Request, response: Response):
    require_secret()
    now = time.time()
    while LOGIN_FAILS[data.username] and LOGIN_FAILS[data.username][0] < now - 300:
        LOGIN_FAILS[data.username].popleft()
    if len(LOGIN_FAILS[data.username]) >= 6:
        raise HTTPException(429, "Trop de tentatives. Réessayez dans quelques minutes.")
    try:
        valid = pam.pam().authenticate(data.username, data.password, service="login")
    except Exception:
        valid = False
    if not valid:
        LOGIN_FAILS[data.username].append(now)
        raise HTTPException(401, "Identifiants Linux incorrects.")
    LOGIN_FAILS.pop(data.username, None)
    expiry = int(now + SESSION_TTL)
    response.set_cookie(COOKIE, token_for(data.username, expiry), max_age=SESSION_TTL, httponly=True,
                        secure=True, samesite="strict", path="/")
    return {"username": data.username, "admin": is_admin(data.username)}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"ok": True}


@app.get("/api/status")
def status(request: Request):
    session_user(request)
    mem, swap = psutil.virtual_memory(), psutil.swap_memory()
    disk, freq = psutil.disk_usage("/"), psutil.cpu_freq()
    boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
    counters = psutil.net_io_counters()
    return {"hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "platform": platform.platform(), "cpu_count": psutil.cpu_count(logical=False) or psutil.cpu_count(),
            "threads": psutil.cpu_count(logical=True), "cpu_percent": psutil.cpu_percent(interval=0.15),
            "cpu_frequency_mhz": round(freq.current) if freq else None,
            "memory": {"total": mem.total, "used": mem.used, "available": mem.available, "percent": mem.percent},
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
            "disk": {"total": disk.total, "used": disk.used, "free": disk.free, "percent": disk.percent},
            "uptime_seconds": max(0, int(datetime.now(timezone.utc).timestamp() - boot.timestamp())),
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [], "processes": len(psutil.pids()),
            "network": {"sent": counters.bytes_sent, "received": counters.bytes_recv},
            "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/storage")
def storage(request: Request):
    session_user(request)
    out = []
    for part in psutil.disk_partitions(all=False):
        if not part.mountpoint or part.fstype in {"squashfs", "tmpfs", "devtmpfs"}:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            out.append({"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype,
                        "total": usage.total, "used": usage.used, "free": usage.free, "percent": usage.percent})
        except (PermissionError, OSError):
            continue
    return out


@app.get("/api/packages")
def packages(request: Request, q: str = ""):
    admin_user(request)
    q = q[:80]
    try:
        rows = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n"],
                              capture_output=True, text=True, timeout=20, check=True).stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(503, f"dpkg-query indisponible: {exc}")
    result = []
    for row in rows:
        cols = row.split("\t")
        if len(cols) < 3 or cols[2] != "installed":
            continue
        if not q or q.casefold() in cols[0].casefold():
            result.append({"name": cols[0], "version": cols[1]})
    return {"packages": result[:500], "truncated": len(result) > 500}


@app.post("/api/packages/install")
def package_install(data: PackageAction, request: Request):
    admin_user(request)
    return helper("package-install", package=data.package)


@app.post("/api/packages/remove")
def package_remove(data: PackageAction, request: Request):
    admin_user(request)
    return helper("package-remove", package=data.package)


@app.get("/api/users")
def users(request: Request):
    admin_user(request)
    return helper("user-list")


@app.post("/api/users")
def user_create(data: UserCreate, request: Request):
    admin_user(request)
    return helper("user-create", username=data.username, password=data.password, admin=data.admin)


@app.delete("/api/users/{username}")
def user_delete(username: str, request: Request):
    admin_user(request)
    if not username or not __import__("re").fullmatch(r"[a-z_][a-z0-9_-]{1,31}", username):
        raise HTTPException(422, "Nom de compte invalide.")
    if username == session_user(request):
        raise HTTPException(400, "Vous ne pouvez pas supprimer votre propre compte connecté.")
    return helper("user-delete", username=username, actor=session_user(request))


@app.websocket("/api/terminal")
async def terminal(ws: WebSocket):
    origin = ws.headers.get("origin", "")
    if not origin or urlsplit(origin).netloc.lower() != ws.headers.get("host", "").lower():
        await ws.close(code=4403)
        return
    username = session_user(ws, websocket=True)
    if not is_admin(username):
        await ws.close(code=4403)
        return
    await ws.accept()
    try:
        proc = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/local/sbin/admin-ubuntu-helper"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        proc.stdin.write((json.dumps({"action": "shell", "username": username}) + "\n").encode())

        async def output_to_browser():
            while True:
                chunk = await asyncio.to_thread(os.read, proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                await ws.send_text(chunk.decode("utf-8", errors="replace"))

        output_task = asyncio.create_task(output_to_browser())
        receive_task = None
        try:
            while not output_task.done():
                receive_task = asyncio.create_task(ws.receive_text())
                done, _ = await asyncio.wait({output_task, receive_task}, return_when=asyncio.FIRST_COMPLETED)
                if output_task in done:
                    receive_task.cancel()
                    break
                msg = receive_task.result()
                if len(msg) <= 4096:
                    proc.stdin.write(msg.encode("utf-8", errors="replace"))
                    proc.stdin.flush()
            await output_task
        finally:
            if receive_task and not receive_task.done():
                receive_task.cancel()
            try:
                proc.stdin.close()
            except OSError:
                pass
            if proc.poll() is None:
                proc.terminate()
            try:
                await asyncio.to_thread(proc.wait, 2)
            except subprocess.TimeoutExpired:
                proc.kill()
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.send_text("\r\nTerminal indisponible. Vérifiez la configuration du helper sudo.\r\n")
        except Exception:
            pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass
