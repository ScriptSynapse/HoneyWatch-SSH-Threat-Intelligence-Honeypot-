#!/usr/bin/env python3
"""
ws_server.py — WebSocket broadcaster + HTTP API server (combined).
Serves /api/stats JSON and pushes live events to connected dashboards.
"""

import asyncio
import json
import socket
import threading
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from aiohttp import web
import aiohttp

import database as db

log = logging.getLogger("honeypot.ws")

# ── Port discovery ─────────────────────────────────────────────────────────────
PREFERRED_PORTS = [8080, 8081, 8082, 8083, 8888, 9000, 9090, 7070]

def find_free_port() -> int:
    for port in PREFERRED_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return port
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]

HTTP_PORT = find_free_port()
PORT_FILE = Path("logs/server.port")

# ── Connected WebSocket clients ───────────────────────────────────────────────
_ws_clients: set[web.WebSocketResponse] = set()
_event_loop: asyncio.AbstractEventLoop | None = None
_pending_events: list[dict] = []
_pending_lock = threading.Lock()


def broadcast_event(event: dict):
    """Thread-safe broadcast called from the honeypot threads."""
    msg = json.dumps(event)
    with _pending_lock:
        _pending_events.append(msg)


# ── Stats builder ─────────────────────────────────────────────────────────────

def build_stats() -> dict:
    now = datetime.now(timezone.utc)

    # Summary
    total_attempts  = db.scalar("SELECT COUNT(*) FROM auth_attempts")
    total_successes = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE result='accepted'")
    unique_ips      = db.scalar("SELECT COUNT(DISTINCT peer_ip) FROM auth_attempts")
    total_commands  = db.scalar("SELECT COUNT(*) FROM commands")
    suspicious_cnt  = db.scalar("SELECT COUNT(*) FROM suspicious_events")
    malware_cnt     = db.scalar("SELECT COUNT(*) FROM malware_captures")
    active_sessions = db.scalar("SELECT COUNT(*) FROM sessions WHERE disconnected_at IS NULL")

    # 14-day timeline
    timeline = []
    for i in range(13, -1, -1):
        d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        attempts  = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp LIKE ?", (d + "%",))
        successes = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp LIKE ? AND result='accepted'", (d + "%",))
        cmds      = db.scalar("SELECT COUNT(*) FROM commands WHERE timestamp LIKE ?", (d + "%",))
        timeline.append({"date": d, "attempts": attempts, "successes": successes, "commands": cmds})

    # Top credentials
    top_users = db.query("""
        SELECT username as value, COUNT(*) as count
        FROM auth_attempts GROUP BY username ORDER BY count DESC LIMIT 15
    """)
    top_pass = db.query("""
        SELECT password as value, COUNT(*) as count
        FROM auth_attempts GROUP BY password ORDER BY count DESC LIMIT 15
    """)

    # Top IPs with geo
    top_ips_raw = db.query("""
        SELECT a.peer_ip as ip, COUNT(*) as count,
               r.country, r.country_code, r.city, r.isp, r.lat, r.lon, r.abuse_score
        FROM auth_attempts a
        LEFT JOIN ip_reputation r ON a.peer_ip = r.ip
        GROUP BY a.peer_ip ORDER BY count DESC LIMIT 15
    """)

    # Attack types breakdown
    attack_types = db.query("""
        SELECT attack_type as type, COUNT(*) as count
        FROM auth_attempts WHERE attack_type IS NOT NULL
        GROUP BY attack_type ORDER BY count DESC
    """)

    # Top commands
    top_cmds = db.query("""
        SELECT command_base as cmd, COUNT(*) as count
        FROM commands WHERE command_base != ''
        GROUP BY command_base ORDER BY count DESC LIMIT 15
    """)

    # Recent commands
    recent_cmds = db.query("""
        SELECT timestamp, peer_ip, command
        FROM commands ORDER BY timestamp DESC LIMIT 40
    """)

    # Suspicious events
    susp_types = db.query("""
        SELECT suspicious_type as type, COUNT(*) as count
        FROM suspicious_events GROUP BY suspicious_type ORDER BY count DESC
    """)
    recent_susp = db.query("""
        SELECT s.timestamp, s.peer_ip, s.suspicious_type, s.detail, s.severity,
               r.country, r.country_code
        FROM suspicious_events s
        LEFT JOIN ip_reputation r ON s.peer_ip = r.ip
        ORDER BY s.timestamp DESC LIMIT 25
    """)

    # Malware captures
    recent_malware = db.query("""
        SELECT timestamp, peer_ip, url, tool, filename, file_hash, file_size
        FROM malware_captures ORDER BY timestamp DESC LIMIT 10
    """)

    # GeoIP map data (all unique IPs with coords)
    map_points = db.query("""
        SELECT r.ip, r.lat, r.lon, r.country, r.country_code, r.city, r.isp,
               r.abuse_score, COUNT(a.id) as attempts
        FROM ip_reputation r
        JOIN auth_attempts a ON r.ip = a.peer_ip
        WHERE r.lat IS NOT NULL AND r.lon IS NOT NULL
        GROUP BY r.ip
    """)

    # Hourly heatmap (last 7 days)
    hourly = db.query("""
        SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
        FROM auth_attempts
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY hour ORDER BY hour
    """)
    hourly_map = {r["hour"]: r["count"] for r in hourly}
    hourly_full = [{"hour": h, "count": hourly_map.get(h, 0)} for h in range(24)]

    # Sessions today
    today = now.strftime("%Y-%m-%d")
    sessions_today = db.scalar("SELECT COUNT(*) FROM sessions WHERE connected_at LIKE ?", (today + "%",))

    return {
        "summary": {
            "total_attempts":    total_attempts,
            "total_successes":   total_successes,
            "unique_ips":        unique_ips,
            "total_commands":    total_commands,
            "suspicious_events": suspicious_cnt,
            "malware_captures":  malware_cnt,
            "active_sessions":   active_sessions,
            "sessions_today":    sessions_today,
            "success_rate":      round(total_successes / max(total_attempts, 1) * 100, 1),
        },
        "timeline":        timeline,
        "top_usernames":   top_users,
        "top_passwords":   top_pass,
        "top_ips":         top_ips_raw,
        "attack_types":    attack_types,
        "top_commands":    top_cmds,
        "recent_commands": recent_cmds,
        "suspicious_types":    susp_types,
        "recent_suspicious":   recent_susp,
        "recent_malware":      recent_malware,
        "map_points":          map_points,
        "hourly_heatmap":      hourly_full,
    }


# ── aiohttp handlers ──────────────────────────────────────────────────────────

async def handle_stats(request):
    data = await asyncio.get_event_loop().run_in_executor(None, build_stats)
    return web.Response(
        text=json.dumps(data, default=str),
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "*"},
    )


async def handle_ws(request):
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    _ws_clients.add(ws)
    log.info("WS client connected (total: %d)", len(_ws_clients))
    try:
        # Send initial snapshot
        data = await asyncio.get_event_loop().run_in_executor(None, build_stats)
        await ws.send_str(json.dumps({"type": "snapshot", "data": data}))

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                pass   # no client→server messages needed
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break
    finally:
        _ws_clients.discard(ws)
        log.info("WS client disconnected (total: %d)", len(_ws_clients))
    return ws


async def _broadcast_loop():
    """Pick up pending events from honeypot threads and push to WS clients."""
    while True:
        await asyncio.sleep(0.1)
        with _pending_lock:
            events, _pending_events[:] = list(_pending_events), []
        if events and _ws_clients:
            dead = set()
            for ws in list(_ws_clients):
                try:
                    for e in events:
                        await ws.send_str(e)
                except Exception:
                    dead.add(ws)
            _ws_clients -= dead


async def run_server():
    global _event_loop
    _event_loop = asyncio.get_event_loop()

    app = web.Application()
    app.router.add_get("/api/stats", handle_stats)
    app.router.add_get("/ws",        handle_ws)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()

    # Write port to file so dashboard.html can discover it
    PORT_FILE.parent.mkdir(exist_ok=True)
    PORT_FILE.write_text(str(HTTP_PORT))

    print("")
    print("  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║  HoneyWatch API running on port {HTTP_PORT:<5}               ║")
    print(f"  ║  API  →  http://localhost:{HTTP_PORT}/api/stats          ║")
    print(f"  ║  WS   →  ws://localhost:{HTTP_PORT}/ws                   ║")
    print("  ║                                                      ║")
    print("  ║  Open dashboard.html in your browser                ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print("")

    await _broadcast_loop()


def start_server_thread():
    """Start the aiohttp server in a background thread."""
    def _run():
        asyncio.run(run_server())
    t = threading.Thread(target=_run, daemon=True, name="ws-server")
    t.start()
    log.info("API + WebSocket server thread started on :%d", HTTP_PORT)
    return broadcast_event


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    db.init_db()
    asyncio.run(run_server())