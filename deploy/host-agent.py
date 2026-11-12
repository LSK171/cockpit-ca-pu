#!/opt/admin-ubuntu/.venv/bin/python
"""Root-only host agent exposed to the Docker web app through a Unix socket."""
from datetime import datetime, timezone
from pathlib import Path
import grp
import json
import os
import platform
import pwd
import re
import runpy
import select
import socket
import socketserver
import subprocess
import psutil

APP_USER = "adminubuntu"
SOCKET_PATH = Path("/run/admin-ubuntu/agent.sock")
HELPER_PATH = Path("/usr/local/sbin/admin-ubuntu-helper")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{1,31}$")
HELPER = runpy.run_path(str(HELPER_PATH), run_name="admin_ubuntu_helper_module")
helper_handle = HELPER["handle"]


def admin_check(username):
    if not isinstance(username, str) or not USER_RE.fullmatch(username):
        return False
    try:
        pwd.getpwnam(username)
        groups = subprocess.run(["/usr/bin/id", "-nG", username], capture_output=True,
                                text=True, timeout=3, check=True).stdout.split()
        return bool(set(groups) & {"sudo", "admin"})
    except (KeyError, OSError, subprocess.SubprocessError):
        return False


def system_status():
    mem, swap = psutil.virtual_memory(), psutil.swap_memory()
    disk, freq = psutil.disk_usage("/"), psutil.cpu_freq()
    boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
    net = psutil.net_io_counters()
    return {
        "hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
        "platform": platform.platform(), "cpu_count": psutil.cpu_count(logical=False) or psutil.cpu_count(),
        "threads": psutil.cpu_count(logical=True), "cpu_percent": psutil.cpu_percent(interval=0.15),
        "cpu_frequency_mhz": round(freq.current) if freq else None,
        "memory": {"total": mem.total, "used": mem.used, "available": mem.available, "percent": mem.percent},
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free, "percent": disk.percent},
        "uptime_seconds": max(0, int(datetime.now(timezone.utc).timestamp() - boot.timestamp())),
        "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [],
        "processes": len(psutil.pids()),
        "network": {"sent": net.bytes_sent, "received": net.bytes_recv},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def storage_status():
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


def packages(query=""):
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\\n"],
                            capture_output=True, text=True, timeout=25, check=True).stdout.splitlines()
    rows = []
    for row in result:
        cols = row.split("\t")
        if len(cols) >= 3 and cols[2] == "installed" and (not query or query.casefold() in cols[0].casefold()):
            rows.append({"name": cols[0], "version": cols[1]})
    return {"packages": rows[:500], "truncated": len(rows) > 500}


def dispatch(request):
    action = request.get("action")
    if action == "status":
        return system_status()
    if action == "storage":
        return storage_status()
    if action == "packages":
        query = request.get("query", "")
        return packages(query[:80] if isinstance(query, str) else "")
    if action == "admin-check":
        return admin_check(request.get("username"))
    return helper_handle(request)


def shell_proxy(client, username):
    HELPER["user_lookup"](username)
    if not admin_check(username):
        raise PermissionError("Le terminal est réservé aux membres du groupe sudo.")
    child = subprocess.Popen([str(HELPER_PATH)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
    child.stdin.write((json.dumps({"action": "shell", "username": username}) + "\n").encode())
    try:
        while True:
            ready, _, _ = select.select([client, child.stdout], [], [])
            if client in ready:
                incoming = client.recv(4096)
                if not incoming:
                    break
                child.stdin.write(incoming)
            if child.stdout in ready:
                outgoing = os.read(child.stdout.fileno(), 4096)
                if not outgoing:
                    break
                client.sendall(outgoing)
    finally:
        try:
            child.stdin.close()
        except OSError:
            pass
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)


def read_request(conn):
    line = bytearray()
    while len(line) <= 16384:
        char = conn.recv(1)
        if not char:
            raise ValueError("Requête incomplète.")
        if char == b"\n":
            return json.loads(line.decode("utf-8"))
        line.extend(char)
    raise ValueError("Requête trop longue.")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            request = read_request(self.request)
            if not isinstance(request, dict):
                raise ValueError("Format de requête invalide.")
            if request.get("action") == "shell":
                shell_proxy(self.request, request.get("username", ""))
                return
            result = dispatch(request)
            self.request.sendall((json.dumps(result, ensure_ascii=False) + "\n").encode())
        except Exception as exc:
            try:
                response = {"error": str(exc)[:1200], "status": 500}
                self.request.sendall((json.dumps(response, ensure_ascii=False) + "\n").encode())
            except OSError:
                pass


class AgentServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        if SOCKET_PATH.is_socket():
            SOCKET_PATH.unlink()
        elif SOCKET_PATH.exists():
            raise RuntimeError(f"Refus de remplacer un fichier non-socket: {SOCKET_PATH}")
    except FileNotFoundError:
        pass
    server = AgentServer(str(SOCKET_PATH), Handler, bind_and_activate=False)
    server.server_bind()
    gid = grp.getgrnam(APP_USER).gr_gid
    os.chown(SOCKET_PATH, 0, gid)
    os.chmod(SOCKET_PATH, 0o660)
    server.server_activate()
    print(f"Agent Ubuntu prêt sur {SOCKET_PATH}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("L’agent Ubuntu doit tourner en root.")
    main()
