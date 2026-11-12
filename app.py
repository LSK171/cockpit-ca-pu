"""Docker web front end; host operations are delegated to a Unix-socket agent."""
from pathlib import Path
from collections import defaultdict, deque
import hashlib
import hmac
import json
import os
import socket
import time
import asyncio
import codecs
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent
SECRET = os.environ.get("ADMIN_UBUNTU_SECRET", "")
AGENT_SOCKET = os.environ.get("ADMIN_UBUNTU_AGENT_SOCKET", "/run/admin-ubuntu/agent.sock")
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
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
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
        return host_call({"action": "admin-check", "username": username}) is True
    except HTTPException:
        return False


def admin_user(request: Request) -> str:
    username = session_user(request)
    if not is_admin(username):
        raise HTTPException(403, "Cette fonction est réservée aux membres du groupe sudo.")
    return username


def host_call(payload: dict, timeout: int = 30):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(AGENT_SOCKET)
        conn.sendall((json.dumps(payload) + "\n").encode())
        chunks = bytearray()
        while len(chunks) <= 4_000_000:
            part = conn.recv(65536)
            if not part:
                break
            chunks.extend(part)
            if b"\n" in part:
                break
    except (OSError, TimeoutError):
        raise HTTPException(503, "L’agent Ubuntu sur l’hôte est indisponible. Vérifiez le service admin-ubuntu-agent.")
    finally:
        conn.close()
    if not chunks or b"\n" not in chunks:
        raise HTTPException(503, "Réponse incomplète de l’agent Ubuntu.")
    try:
        response = json.loads(bytes(chunks).split(b"\n", 1)[0])
    except json.JSONDecodeError:
        raise HTTPException(503, "Réponse invalide de l’agent Ubuntu.")
    if isinstance(response, dict) and "error" in response:
        raise HTTPException(int(response.get("status", 500)), response["error"])
    return response


def helper(action: str, timeout: int = 900, **data):
    return host_call({"action": action, **data}, timeout=timeout)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html", headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


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
        auth_result = helper("auth-check", username=data.username, password=data.password)
        valid = auth_result.get("authenticated") is True
    except HTTPException as exc:
        if exc.status_code != 500:
            raise
        raise HTTPException(503, "Le vérificateur PAM privilégié n’est pas installé. Relancez l’installation.")
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
    return host_call({"action": "status"})


@app.get("/api/storage")
def storage(request: Request):
    session_user(request)
    return host_call({"action": "storage"})


@app.get("/api/packages")
def packages(request: Request, q: str = ""):
    admin_user(request)
    return host_call({"action": "packages", "query": q[:80]})


@app.post("/api/packages/install")
def package_install(data: PackageAction, request: Request):
    admin_user(request)
    return helper("package-install", timeout=900, package=data.package)


@app.post("/api/packages/remove")
def package_remove(data: PackageAction, request: Request):
    admin_user(request)
    return helper("package-remove", timeout=900, package=data.package)


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
    agent_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        agent_conn.connect(AGENT_SOCKET)
        agent_conn.sendall((json.dumps({"action": "shell", "username": username}) + "\n").encode())

        async def output_to_browser():
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            while True:
                chunk = await asyncio.to_thread(agent_conn.recv, 4096)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                if text:
                    await ws.send_text(text)
            tail = decoder.decode(b"", final=True)
            if tail:
                await ws.send_text(tail)

        output_task = asyncio.create_task(output_to_browser())
        receive_task = None
        try:
            while not output_task.done():
                receive_task = asyncio.create_task(ws.receive())
                done, _ = await asyncio.wait({output_task, receive_task}, return_when=asyncio.FIRST_COMPLETED)
                if output_task in done:
                    receive_task.cancel()
                    break
                frame = receive_task.result()
                if frame.get("type") == "websocket.disconnect":
                    raise WebSocketDisconnect(code=frame.get("code", 1000))
                data = frame.get("bytes")
                text = frame.get("text")
                if text is not None:
                    try:
                        control = json.loads(text)
                    except json.JSONDecodeError:
                        control = None
                    if isinstance(control, dict) and control.get("type") == "resize":
                        try:
                            cols = max(40, min(300, int(control.get("cols", 100))))
                            rows = max(12, min(100, int(control.get("rows", 30))))
                            data = f"\x00ADMIN_RESIZE:{cols}:{rows}\n".encode()
                        except (TypeError, ValueError):
                            data = None
                    else:
                        data = text.encode("utf-8", errors="replace")
                if data and len(data) <= 4096:
                    agent_conn.sendall(data)
            await output_task
        finally:
            if receive_task and not receive_task.done():
                receive_task.cancel()
            try:
                agent_conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
        agent_conn.close()
