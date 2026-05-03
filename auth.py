import os
import json
import time
import secrets
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import bcrypt
try:
    import jwt
except ImportError:
    raise SystemExit("ERROR: PyJWT not found. Fix: pip uninstall jwt PyJWT -y && pip install PyJWT")

log = logging.getLogger("honeypot.auth")

AUTH_FILE   = Path("logs/auth_config.json")
SECRET_KEY  = os.environ.get("HONEYWATCH_SECRET", secrets.token_hex(32))
TOKEN_TTL   = int(os.environ.get("HONEYWATCH_TOKEN_TTL", 3600 * 8))   # 8 hours
MAX_FAILS   = 5          # lockout after N bad attempts
LOCKOUT_SEC = 300        # 5 min lockout

DEFAULT_USER     = "admin"
DEFAULT_PASSWORD = "honeywatch"

# In-memory failed attempt tracking  {ip: [timestamp, ...]}
_fail_tracker: dict[str, list[float]] = {}


# ── Setup ─────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if AUTH_FILE.exists():
        return json.loads(AUTH_FILE.read_text())
    # First-time setup — create default admin account
    hashed = bcrypt.hashpw(DEFAULT_PASSWORD.encode(), bcrypt.gensalt(12)).decode()
    config = {
        "users": {DEFAULT_USER: {"password_hash": hashed, "role": "admin"}},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    AUTH_FILE.parent.mkdir(exist_ok=True)
    AUTH_FILE.write_text(json.dumps(config, indent=2))
    log.warning("🔐 Default admin created — user: %s  pass: %s  — CHANGE THIS!",
                DEFAULT_USER, DEFAULT_PASSWORD)
    return config


def _save_config(config: dict):
    AUTH_FILE.write_text(json.dumps(config, indent=2))


# ── Password management ───────────────────────────────────────────────────────

def verify_password(username: str, password: str) -> bool:
    config = _load_config()
    user = config.get("users", {}).get(username)
    if not user:
        return False
    return bcrypt.checkpw(password.encode(), user["password_hash"].encode())


def change_password(username: str, new_password: str) -> bool:
    if len(new_password) < 8:
        return False
    config = _load_config()
    if username not in config.get("users", {}):
        return False
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(12)).decode()
    config["users"][username]["password_hash"] = hashed
    _save_config(config)
    log.info("Password changed for user: %s", username)
    return True


def add_user(username: str, password: str, role: str = "viewer") -> bool:
    if len(password) < 8 or not username:
        return False
    config = _load_config()
    if username in config.get("users", {}):
        return False
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    config["users"][username] = {"password_hash": hashed, "role": role}
    _save_config(config)
    log.info("User created: %s (%s)", username, role)
    return True


# ── JWT tokens ────────────────────────────────────────────────────────────────

def create_token(username: str) -> str:
    config = _load_config()
    role = config["users"][username]["role"]
    payload = {
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + TOKEN_TTL,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    """Returns payload dict or None if invalid/expired."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        log.debug("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        log.debug("Invalid token: %s", e)
        return None


# ── Rate limiting / brute-force protection ────────────────────────────────────

def _is_locked(ip: str) -> bool:
    now = time.time()
    fails = [t for t in _fail_tracker.get(ip, []) if now - t < LOCKOUT_SEC]
    _fail_tracker[ip] = fails
    return len(fails) >= MAX_FAILS


def record_fail(ip: str):
    _fail_tracker.setdefault(ip, []).append(time.time())
    count = len([t for t in _fail_tracker[ip] if time.time() - t < LOCKOUT_SEC])
    if count >= MAX_FAILS:
        log.warning("🔒 IP %s locked out after %d failed login attempts", ip, count)


def clear_fails(ip: str):
    _fail_tracker.pop(ip, None)


# ── aiohttp middleware ────────────────────────────────────────────────────────

from aiohttp import web

def token_from_request(request: web.Request) -> str | None:
    # Check Authorization: Bearer <token> header
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    # Check cookie
    return request.cookies.get("hw_token")


def require_auth(handler):
    """Decorator: protects an aiohttp route handler with JWT auth."""
    async def wrapper(request: web.Request):
        # WebSocket upgrade — check token in query string too
        token = token_from_request(request) or request.rel_url.query.get("token")
        payload = verify_token(token) if token else None
        if not payload:
            if request.headers.get("Upgrade") == "websocket":
                raise web.HTTPUnauthorized()
            return web.Response(
                status=401,
                content_type="application/json",
                text=json.dumps({"error": "Unauthorized", "code": 401}),
                headers={"Access-Control-Allow-Origin": "*"},
            )
        request["user"] = payload
        return await handler(request)
    return wrapper


async def handle_login(request: web.Request) -> web.Response:
    """POST /api/login  { username, password }"""
    ip = request.remote

    if _is_locked(ip):
        return web.Response(
            status=429,
            content_type="application/json",
            text=json.dumps({"error": "Too many failed attempts. Try again in 5 minutes."}),
            headers={"Access-Control-Allow-Origin": "*"},
        )

    try:
        body = await request.json()
    except Exception:
        return web.Response(status=400, text='{"error":"Invalid JSON"}',
                            content_type="application/json")

    username = body.get("username", "").strip()
    password = body.get("password", "")

    if verify_password(username, password):
        clear_fails(ip)
        token = create_token(username)
        config = _load_config()
        role = config["users"][username]["role"]
        log.info("✅ Admin login: %s from %s", username, ip)
        resp = web.Response(
            text=json.dumps({"token": token, "username": username, "role": role,
                             "expires_in": TOKEN_TTL}),
            content_type="application/json",
            headers={"Access-Control-Allow-Origin": "*"},
        )
        resp.set_cookie("hw_token", token, max_age=TOKEN_TTL,
                        httponly=True, samesite="Strict")
        return resp
    else:
        record_fail(ip)
        remaining = max(0, MAX_FAILS - len(_fail_tracker.get(ip, [])))
        log.warning("❌ Failed login: %s from %s (%d attempts remaining)",
                    username, ip, remaining)
        return web.Response(
            status=401,
            content_type="application/json",
            text=json.dumps({"error": "Invalid credentials",
                             "attempts_remaining": remaining}),
            headers={"Access-Control-Allow-Origin": "*"},
        )


async def handle_logout(request: web.Request) -> web.Response:
    resp = web.Response(text='{"ok":true}', content_type="application/json",
                        headers={"Access-Control-Allow-Origin": "*"})
    resp.del_cookie("hw_token")
    return resp


async def handle_change_password(request: web.Request) -> web.Response:
    token = token_from_request(request)
    payload = verify_token(token) if token else None
    if not payload:
        return web.Response(status=401, text='{"error":"Unauthorized"}',
                            content_type="application/json")
    body = await request.json()
    username = payload["sub"]
    new_pass = body.get("new_password", "")
    if change_password(username, new_pass):
        return web.Response(text='{"ok":true,"message":"Password changed successfully"}',
                            content_type="application/json",
                            headers={"Access-Control-Allow-Origin": "*"})
    return web.Response(status=400,
                        text='{"error":"Password must be at least 8 characters"}',
                        content_type="application/json")


# ── CLI helper ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4 and sys.argv[1] == "adduser":
        ok = add_user(sys.argv[2], sys.argv[3])
        print("User created." if ok else "Failed (user exists or password too short).")
    elif len(sys.argv) == 4 and sys.argv[1] == "passwd":
        ok = change_password(sys.argv[2], sys.argv[3])
        print("Password changed." if ok else "Failed.")
    else:
        print("Usage:")
        print("  python auth.py adduser <username> <password>")
        print("  python auth.py passwd  <username> <newpassword>")
