#!/usr/bin/env python3
"""
honeypot.py — SSH Honeypot v2
Full stateful shell, tarpit delays, malware capture, WebSocket broadcasts.
"""

import socket
import threading
import paramiko
import time
import random
import hashlib
import logging
import re
import asyncio
from datetime import datetime, timezone
from pathlib import Path

import database as db
import threat_intel as ti
from fake_fs import FakeFS, STATIC_RESPONSES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("honeypot")

HOST       = "0.0.0.0"
PORT       = 2222
MALWARE_DIR = Path("malware_captures")
MALWARE_DIR.mkdir(exist_ok=True)

KEY_FILE = Path("logs/host_rsa.key")
if KEY_FILE.exists():
    HOST_KEY = paramiko.RSAKey(filename=str(KEY_FILE))
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(str(KEY_FILE))

# WebSocket broadcaster (set by ws_server if running)
_ws_broadcast = None

def set_broadcaster(fn):
    global _ws_broadcast
    _ws_broadcast = fn

def broadcast(event: dict):
    if _ws_broadcast:
        try:
            _ws_broadcast(event)
        except Exception:
            pass

def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ── Fake Shell ────────────────────────────────────────────────────────────────
class FakeShell:
    PROMPT = b"root@ubuntu-server:~# "

    SUSPICIOUS_PATTERNS = {
        r"wget\s+https?://":         ("file_download",         "high"),
        r"curl\s+.*-o\s":            ("file_download",         "high"),
        r"curl\s+https?://\S+\s*\|": ("pipe_execution",        "critical"),
        r"chmod\s+\+x":              ("make_executable",       "medium"),
        r"\.\/\w":                   ("execute_local",         "high"),
        r"python[23]?\s+-c":         ("interpreter_execution", "high"),
        r"perl\s+-e":                ("interpreter_execution", "high"),
        r"bash\s+-[ic]":             ("interpreter_execution", "high"),
        r"crontab":                  ("persistence",           "critical"),
        r"\/etc\/rc\.local":         ("persistence",           "critical"),
        r"systemctl\s+enable":       ("persistence",           "high"),
        r"ssh\s+\S+@\S+":            ("lateral_movement",      "critical"),
        r"scp\s+":                   ("data_exfiltration",     "critical"),
        r"rsync\s+":                 ("data_exfiltration",     "high"),
        r"nc\s+.*\d+\.\d+":         ("reverse_shell",         "critical"),
        r"\/dev\/tcp\/":             ("reverse_shell",         "critical"),
        r"base64\s+-d":              ("obfuscation",           "high"),
        r"dd\s+if=":                 ("disk_access",           "medium"),
        r"mkfs":                     ("disk_wipe",             "critical"),
        r"rm\s+-rf\s+\/":            ("destructive",           "critical"),
    }

    def __init__(self, channel, session_id, peer_ip):
        self.channel    = channel
        self.session_id = session_id
        self.peer_ip    = peer_ip
        self.fs         = FakeFS()
        self.cmd_count  = 0

    # ── input/output ─────────────────────────────────────────────────────────
    def _send(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        self.channel.send(data)

    def _tarpit(self):
        """Random delay to waste attacker's time."""
        time.sleep(random.uniform(0.2, 0.8))

    # ── suspicious detection ──────────────────────────────────────────────────
    def _check_suspicious(self, cmd: str):
        for pattern, (stype, severity) in self.SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, cmd, re.IGNORECASE):
                detail = {"command": cmd, "pattern": pattern}
                db.insert_suspicious({
                    "timestamp":      now_iso(),
                    "session_id":     self.session_id,
                    "peer_ip":        self.peer_ip,
                    "suspicious_type": stype,
                    "detail":         str(detail),
                    "severity":       severity,
                })
                broadcast({"type": "suspicious", "ip": self.peer_ip,
                           "stype": stype, "severity": severity, "cmd": cmd})
                if severity in ("high", "critical"):
                    ti.alert(f"[{severity.upper()}] {stype} from {self.peer_ip}: {cmd[:120]}", severity)
                log.warning("🚨 %s [%s] from %s: %s", stype, severity, self.peer_ip, cmd[:80])

    # ── wget/curl simulation with malware capture ─────────────────────────────
    def _handle_download(self, cmd: str, tool: str) -> str:
        parts  = cmd.split()
        url    = next((p for p in parts if p.startswith("http")), None)
        if not url:
            return f"{tool}: missing URL\n"

        # Parse output filename
        out_file = None
        if "-O" in parts:
            idx = parts.index("-O")
            if idx + 1 < len(parts):
                out_file = parts[idx + 1]
        elif "-o" in parts:
            idx = parts.index("-o")
            if idx + 1 < len(parts):
                out_file = parts[idx + 1]
        if not out_file:
            out_file = url.split("/")[-1] or "index.html"

        # Try to actually fetch for malware capture (sandboxed)
        file_hash, file_size, saved_path = None, 0, None
        try:
            import requests
            r = requests.get(url, timeout=5, stream=True,
                             headers={"User-Agent": "Wget/1.21.2"})
            content = r.content[:5_000_000]   # cap at 5 MB
            file_size = len(content)
            file_hash = hashlib.sha256(content).hexdigest()
            fname = f"{file_hash[:16]}_{Path(out_file).name}"
            saved_path = str(MALWARE_DIR / fname)
            Path(saved_path).write_bytes(content)
            log.warning("💾 Captured potential malware: %s → %s", url, saved_path)
            ti.alert(f"Malware downloaded from {url} (sha256:{file_hash[:16]}…)", "critical")
        except Exception:
            pass

        db.get_conn().execute("""
            INSERT INTO malware_captures
            (timestamp,session_id,peer_ip,url,tool,filename,file_hash,file_size,saved_path)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (now_iso(), self.session_id, self.peer_ip, url, tool,
              out_file, file_hash, file_size, saved_path))
        db.get_conn().commit()

        # Update fake filesystem
        self.fs.write_file(out_file, f"[binary content {file_size} bytes]")

        sz_str = f"{file_size/1024:.1f}K" if file_size else "51.2K"
        return (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
                f"Resolving {url.split('/')[2]}... 104.21.{random.randint(1,254)}.{random.randint(1,254)}\n"
                f"Connecting to {url.split('/')[2]}|...|:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {file_size or 52428} ({sz_str}) [application/octet-stream]\n"
                f"Saving to: '{out_file}'\n\n"
                f"{out_file}           100%[===================>] {sz_str}  1.23MB/s    in 0.04s\n\n"
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} (1.23 MB/s) - '{out_file}' saved [{file_size or 52428}/{file_size or 52428}]\n")

    # ── main command dispatcher ───────────────────────────────────────────────
    def _exec(self, raw: str) -> str:
        cmd = raw.strip()
        if not cmd or cmd.startswith("#"):
            return ""

        self._tarpit()
        self._check_suspicious(cmd)

        # Handle pipelines superficially (log but respond to first token)
        base_cmd = cmd.split("|")[0].strip()
        tokens   = base_cmd.split()
        verb     = tokens[0] if tokens else ""
        args     = tokens[1:]

        # Handle redirects: echo "x" >> /tmp/file
        redirect_append = re.search(r">>\s*(\S+)", cmd)
        redirect_write  = re.search(r"(?<!>)>\s*(\S+)", cmd)
        redirect_target = None
        if redirect_append:
            redirect_target = redirect_append.group(1)
            args = [a for a in args if not a.startswith(">") and a != redirect_target]
        elif redirect_write:
            redirect_target = redirect_write.group(1)
            args = [a for a in args if not a.startswith(">") and a != redirect_target]

        # Exact static match first
        if cmd in STATIC_RESPONSES:
            return STATIC_RESPONSES[cmd]
        for key, val in STATIC_RESPONSES.items():
            if cmd == key or cmd.startswith(key + " "):
                return val

        # Verb dispatch
        if verb == "cd":
            return self.fs.cd(args)
        if verb in ("ls", "ll", "dir"):
            return self.fs.ls(args if args else [self.fs.cwd])
        if verb == "pwd":
            return self.fs.pwd(args)
        if verb == "cat":
            return self.fs.cat(args)
        if verb == "echo":
            return self.fs.echo(args, redirect=redirect_target)
        if verb == "mkdir":
            return self.fs.mkdir(args)
        if verb == "touch":
            return self.fs.touch(args)
        if verb in ("rm", "rmdir"):
            return self.fs.rm(args)
        if verb in ("cp", "mv"):
            return ""
        if verb in ("chmod", "chown", "chgrp"):
            return ""
        if verb == "ps":
            return self.fs.ps(args)
        if verb == "uptime":
            return self.fs.uptime(args)

        if verb == "wget":
            return self._handle_download(cmd, "wget")
        if verb == "curl":
            if any(p.startswith("http") for p in args):
                return self._handle_download(cmd, "curl")
            return ""

        if verb in ("python", "python3", "perl", "ruby", "php"):
            return ""    # silent — already flagged by suspicious checker

        if verb in ("bash", "sh", "dash"):
            script = next((a for a in args if not a.startswith("-")), None)
            if script and self.fs.file_exists(script):
                return f"[executing {script}]\n"
            return ""

        if verb == "apt-get" or verb == "apt":
            pkg = args[-1] if args else "package"
            return (f"Reading package lists... Done\nBuilding dependency tree... Done\n"
                    f"The following NEW packages will be installed: {pkg}\n"
                    f"0 upgraded, 1 newly installed, 0 to remove and 12 not upgraded.\n"
                    f"Fetched 1,234 kB in 1s\nSetting up {pkg}...\n")

        if verb == "nmap":
            target = next((a for a in args if not a.startswith("-")), "10.0.0.1")
            return (f"Starting Nmap 7.80 ( https://nmap.org )\n"
                    f"Nmap scan report for {target}\n"
                    f"Host is up (0.00015s latency).\n"
                    f"PORT     STATE  SERVICE\n22/tcp   open   ssh\n80/tcp   open   http\n"
                    f"443/tcp  open   https\n3306/tcp open   mysql\n"
                    f"Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds\n")

        if verb in ("ssh", "scp", "sftp"):
            return f"ssh: connect to host {args[0] if args else 'host'} port 22: Connection refused\n"

        if verb in ("su", "sudo"):
            return ""   # already root

        if verb == "passwd":
            return "passwd: Authentication token manipulation error\n"

        if verb == "crontab":
            if "-l" in args:
                return "no crontab for root"
            if "-e" in args:
                return ""
            return ""

        if verb in ("systemctl", "service"):
            return "Failed to connect to bus: No such file or directory\n"

        if verb == "find":
            path = next((a for a in args if not a.startswith("-")), "/")
            return f"/etc/passwd\n/etc/shadow\n/root/.bash_history\n/root/.aws/credentials\n"

        if verb == "grep":
            return ""

        if verb in ("tar", "gzip", "gunzip", "zip", "unzip"):
            return ""

        if verb in ("nc", "netcat"):
            return ""   # flag already triggered

        if verb == "kill" or verb == "killall":
            return ""

        if verb in ("top", "htop"):
            return ("top - 14:22:31 up 42 days,  1 user,  load average: 0.08\n"
                    "Tasks:  87 total,   1 running,  86 sleeping,   0 stopped\n"
                    "%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.5 id\n"
                    "MiB Mem :   3987.0 total,   2145.3 free,    512.4 used\n")

        if verb == "clear" or verb == "reset":
            return "\033[2J\033[H"

        if verb in ("exit", "logout", "quit"):
            return "__EXIT__"

        # Unknown command
        return f"-bash: {verb}: command not found\n"

    # ── main shell loop ───────────────────────────────────────────────────────
    def run(self):
        self._send(
            b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            b"\r\n * Documentation:  https://help.ubuntu.com\r\n"
            b" * Management:     https://landscape.canonical.com\r\n"
            b" * Support:        https://ubuntu.com/advantage\r\n\r\n"
            b"Last login: Mon Apr  8 09:12:44 2024 from 10.0.1.55\r\n\r\n"
        )
        self._send(self.PROMPT)
        buf = b""
        try:
            while True:
                data = self.channel.recv(1024)
                if not data:
                    break
                self._send(data)
                buf += data
                if b"\r" in buf or b"\n" in buf:
                    line = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    cmd  = line.decode("utf-8", errors="replace").strip()
                    buf  = b""
                    if not cmd:
                        self._send(b"\r\n" + self.PROMPT)
                        continue

                    output = self._exec(cmd)

                    # Log every command
                    rec = {
                        "timestamp":      now_iso(),
                        "session_id":     self.session_id,
                        "peer_ip":        self.peer_ip,
                        "command":        cmd,
                        "command_base":   cmd.split()[0],
                        "output_preview": output[:200] if output else "",
                    }
                    db.insert_command(rec)
                    broadcast({"type": "command", "ip": self.peer_ip, "cmd": cmd})
                    self.cmd_count += 1

                    if output == "__EXIT__":
                        self._send(b"\r\nlogout\r\n")
                        break

                    if output:
                        out_bytes = ("\r\n" + output.rstrip("\n") + "\r\n").encode("utf-8", errors="replace")
                        self._send(out_bytes)
                    self._send(self.PROMPT)
        except Exception as e:
            log.debug("Shell error [%s]: %s", self.peer_ip, e)
        finally:
            self.channel.close()


# ── Paramiko server interface ─────────────────────────────────────────────────
class HoneypotServer(paramiko.ServerInterface):
    LURE_CREDS = {
        ("root","root"), ("admin","admin"), ("root","toor"),
        ("admin","password"), ("root","password123"), ("root","123456"),
        ("ubuntu","ubuntu"), ("pi","raspberry"),
    }

    def __init__(self, peer_ip, session_id):
        self.peer_ip    = peer_ip
        self.session_id = session_id
        self.event      = threading.Event()
        self.accepted   = False

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else \
               paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Tarpit: slow down brute-force tools
        time.sleep(random.uniform(0.5, 2.0))

        attack_type = ti.record_attempt(self.peer_ip, username, password)
        result      = "accepted" if (
            (username, password) in self.LURE_CREDS or random.random() < 0.10
        ) else "rejected"

        rec = {
            "timestamp":   now_iso(),
            "session_id":  self.session_id,
            "peer_ip":     self.peer_ip,
            "username":    username,
            "password":    password,
            "auth_method": "password",
            "result":      result,
        }
        db.insert_auth(rec)
        broadcast({"type": "auth", "ip": self.peer_ip,
                   "user": username, "pass": password, "result": result,
                   "attack_type": attack_type})
        log.info("[%s] AUTH %s  user=%-12s pass=%s  [%s]",
                 self.peer_ip, result.upper(), username, password, attack_type)

        if result == "accepted":
            self.accepted = True
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        db.insert_auth({
            "timestamp":   now_iso(),
            "session_id":  self.session_id,
            "peer_ip":     self.peer_ip,
            "username":    username,
            "password":    f"[pubkey:{key.get_fingerprint().hex()[:16]}]",
            "auth_method": "publickey",
            "result":      "rejected",
        })
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set(); return True
    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        return True
    def check_channel_exec_request(self, channel, command):
        self.event.set(); return True
    def get_allowed_auths(self, username):
        return "password,publickey"


# ── Connection handler ────────────────────────────────────────────────────────
def handle_connection(client_sock, addr):
    peer_ip    = addr[0]
    session_id = f"{peer_ip}-{int(time.time()*1000)}-{random.randint(100,999)}"
    log.info("⟶  Connection from %s [%s]", peer_ip, session_id)

    db.insert_session({
        "session_id":   session_id,
        "peer_ip":      peer_ip,
        "peer_port":    addr[1],
        "connected_at": now_iso(),
        "login_success": 0,
    })
    ti.enqueue_enrich(peer_ip)
    broadcast({"type": "connection", "ip": peer_ip, "session_id": session_id})

    transport = None
    cmd_count = 0
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

        server = HoneypotServer(peer_ip, session_id)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        db.update_session(session_id, login_success=1 if server.accepted else 0)

        if server.accepted:
            shell = FakeShell(channel, session_id, peer_ip)
            shell.run()
            cmd_count = shell.cmd_count
        else:
            channel.close()

    except Exception as e:
        log.debug("[%s] Transport error: %s", peer_ip, e)
    finally:
        if transport:
            transport.close()
        client_sock.close()
        db.update_session(session_id,
                          disconnected_at=now_iso(),
                          commands_count=cmd_count)
        log.info("⟵  Disconnected %s", peer_ip)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    db.init_db()
    ti.start_enrichment_worker()

    log.info("🍯 SSH Honeypot v2 starting on %s:%d", HOST, PORT)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(100)
    log.info("Listening… (Ctrl+C to stop)")

    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_connection,
                             args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
