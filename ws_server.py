#!/usr/bin/env python3
"""
ws_server.py v3 - API + WebSocket server with auth, alerts, PDF reports, auto port.
"""

import asyncio
import json
import socket
import threading
import logging
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

from aiohttp import web
import aiohttp

import database as db
import auth as auth_mod
import alerts as alert_mod

log = logging.getLogger("honeypot.ws")

PREFERRED_PORTS = [8080, 8081, 8082, 8083, 8888, 9000, 9090, 7070]

def find_free_port():
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

_ws_clients = set()
_pending_events = []
_pending_lock = threading.Lock()

def broadcast_event(event):
    with _pending_lock:
        _pending_events.append(json.dumps(event))

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
}

def json_resp(data, status=200):
    return web.Response(
        text=json.dumps(data, default=str),
        status=status,
        content_type="application/json",
        headers=CORS,
    )

def build_stats():
    now = datetime.now(timezone.utc)
    total_attempts  = db.scalar("SELECT COUNT(*) FROM auth_attempts")
    total_successes = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE result='accepted'")
    unique_ips      = db.scalar("SELECT COUNT(DISTINCT peer_ip) FROM auth_attempts")
    total_commands  = db.scalar("SELECT COUNT(*) FROM commands")
    suspicious_cnt  = db.scalar("SELECT COUNT(*) FROM suspicious_events")
    malware_cnt     = db.scalar("SELECT COUNT(*) FROM malware_captures")
    active_sessions = db.scalar("SELECT COUNT(*) FROM sessions WHERE disconnected_at IS NULL")
    today           = now.strftime("%Y-%m-%d")
    sessions_today  = db.scalar("SELECT COUNT(*) FROM sessions WHERE connected_at LIKE ?", (today+"%",))
    try:
        unacked_alerts = db.scalar("SELECT COUNT(*) FROM alerts WHERE acknowledged=0")
    except Exception:
        unacked_alerts = 0

    timeline = []
    for i in range(13, -1, -1):
        d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        attempts  = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp LIKE ?", (d+"%",))
        successes = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp LIKE ? AND result='accepted'", (d+"%",))
        cmds      = db.scalar("SELECT COUNT(*) FROM commands WHERE timestamp LIKE ?", (d+"%",))
        timeline.append({"date": d, "attempts": attempts, "successes": successes, "commands": cmds})

    top_users    = db.query("SELECT username as value, COUNT(*) as count FROM auth_attempts GROUP BY username ORDER BY count DESC LIMIT 15")
    top_pass     = db.query("SELECT password as value, COUNT(*) as count FROM auth_attempts GROUP BY password ORDER BY count DESC LIMIT 15")
    top_ips_raw  = db.query("""SELECT a.peer_ip as ip, COUNT(*) as count, r.country, r.country_code, r.city, r.isp, r.lat, r.lon, r.abuse_score FROM auth_attempts a LEFT JOIN ip_reputation r ON a.peer_ip=r.ip GROUP BY a.peer_ip ORDER BY count DESC LIMIT 15""")
    attack_types = db.query("SELECT attack_type as type, COUNT(*) as count FROM auth_attempts WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY count DESC")
    top_cmds     = db.query("SELECT command_base as cmd, COUNT(*) as count FROM commands WHERE command_base!='' GROUP BY command_base ORDER BY count DESC LIMIT 15")
    recent_cmds  = db.query("SELECT timestamp, peer_ip, command FROM commands ORDER BY timestamp DESC LIMIT 40")
    susp_types   = db.query("SELECT suspicious_type as type, COUNT(*) as count FROM suspicious_events GROUP BY suspicious_type ORDER BY count DESC")
    recent_susp  = db.query("""SELECT s.timestamp, s.peer_ip, s.suspicious_type, s.detail, s.severity, r.country, r.country_code FROM suspicious_events s LEFT JOIN ip_reputation r ON s.peer_ip=r.ip ORDER BY s.timestamp DESC LIMIT 25""")
    recent_malware = db.query("SELECT timestamp, peer_ip, url, tool, filename, file_hash, file_size FROM malware_captures ORDER BY timestamp DESC LIMIT 10")
    map_points   = db.query("""SELECT r.ip, r.lat, r.lon, r.country, r.country_code, r.city, r.isp, r.abuse_score, COUNT(a.id) as attempts FROM ip_reputation r JOIN auth_attempts a ON r.ip=a.peer_ip WHERE r.lat IS NOT NULL AND r.lon IS NOT NULL GROUP BY r.ip""")
    hourly = db.query("""SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count FROM auth_attempts WHERE timestamp >= datetime('now', '-7 days') GROUP BY hour ORDER BY hour""")
    hourly_map  = {r["hour"]: r["count"] for r in hourly}
    hourly_full = [{"hour": h, "count": hourly_map.get(h, 0)} for h in range(24)]
    try:
        recent_alerts = db.query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20")
    except Exception:
        recent_alerts = []

    return {
        "summary": {
            "total_attempts": total_attempts, "total_successes": total_successes,
            "unique_ips": unique_ips, "total_commands": total_commands,
            "suspicious_events": suspicious_cnt, "malware_captures": malware_cnt,
            "active_sessions": active_sessions, "sessions_today": sessions_today,
            "success_rate": round(total_successes / max(total_attempts, 1) * 100, 1),
            "unacked_alerts": unacked_alerts,
        },
        "timeline": timeline, "top_usernames": top_users, "top_passwords": top_pass,
        "top_ips": top_ips_raw, "attack_types": attack_types, "top_commands": top_cmds,
        "recent_commands": recent_cmds, "suspicious_types": susp_types,
        "recent_suspicious": recent_susp, "recent_malware": recent_malware,
        "map_points": map_points, "hourly_heatmap": hourly_full,
        "recent_alerts": recent_alerts,
    }

async def handle_options(request):
    return web.Response(headers=CORS)

async def handle_dashboard(request):
    """Serve dashboard.html so it runs on http://localhost — avoids file:// CORS block."""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if not dashboard_path.exists():
        return web.Response(status=404, text="dashboard.html not found next to ws_server.py")
    html = dashboard_path.read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html",
                        headers={"Cache-Control": "no-cache"})

async def handle_stats(request):
    data = await asyncio.get_event_loop().run_in_executor(None, build_stats)
    return json_resp(data)

async def handle_ws(request):
    token = auth_mod.token_from_request(request) or request.rel_url.query.get("token")
    payload = auth_mod.verify_token(token) if token else None
    if not payload:
        raise web.HTTPUnauthorized()
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    _ws_clients.add(ws)
    try:
        data = await asyncio.get_event_loop().run_in_executor(None, build_stats)
        await ws.send_str(json.dumps({"type": "snapshot", "data": data}))
        async for msg in ws:
            if msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break
    finally:
        _ws_clients.discard(ws)
    return ws

async def handle_report(request):
    token = auth_mod.token_from_request(request) or request.rel_url.query.get("token")
    if not auth_mod.verify_token(token):
        return json_resp({"error": "Unauthorized"}, 401)
    days = int(request.rel_url.query.get("days", 14))
    days = max(1, min(days, 90))
    try:
        import report_gen
        tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
        tmp.close()
        path = await asyncio.get_event_loop().run_in_executor(
            None, lambda: report_gen.generate_report(tmp.name, days))
        pdf_bytes = Path(path).read_bytes()
        filename = f"honeywatch_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        return web.Response(
            body=pdf_bytes, content_type="application/pdf",
            headers={**CORS,
                     "Content-Disposition": f'attachment; filename="{filename}"',
                     "Content-Length": str(len(pdf_bytes))},
        )
    except Exception as e:
        log.error("PDF error: %s", e)
        return json_resp({"error": str(e)}, 500)

async def handle_alerts_list(request):
    token = auth_mod.token_from_request(request) or request.rel_url.query.get("token")
    if not auth_mod.verify_token(token):
        return json_resp({"error": "Unauthorized"}, 401)
    try:
        rows = db.query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50")
    except Exception:
        rows = []
    return json_resp({"alerts": rows})

async def handle_alert_ack(request):
    token = auth_mod.token_from_request(request) or request.rel_url.query.get("token")
    if not auth_mod.verify_token(token):
        return json_resp({"error": "Unauthorized"}, 401)
    alert_id = request.match_info.get("id")
    try:
        db.get_conn().execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        db.get_conn().commit()
        return json_resp({"ok": True})
    except Exception as e:
        return json_resp({"error": str(e)}, 500)

async def handle_alert_config(request):
    token = auth_mod.token_from_request(request) or request.rel_url.query.get("token")
    if not auth_mod.verify_token(token):
        return json_resp({"error": "Unauthorized"}, 401)
    if request.method == "GET":
        safe = {k: v for k, v in alert_mod.CONFIG.items()
                if "pass" not in k.lower() and "key" not in k.lower()}
        return json_resp(safe)
    body = await request.json()
    alert_mod.CONFIG.update({k: v for k, v in body.items() if k in alert_mod.CONFIG})
    return json_resp({"ok": True})

async def _broadcast_loop():
    try:
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
    except asyncio.CancelledError:
        pass  # Normal shutdown — suppress traceback

async def run_server():
    app = web.Application()
    app.router.add_route("OPTIONS", "/{path_info:.*}", handle_options)
    app.router.add_get( "/",                    handle_dashboard)
    app.router.add_get( "/dashboard",           handle_dashboard)
    app.router.add_post("/api/login",           auth_mod.handle_login)
    app.router.add_post("/api/logout",          auth_mod.handle_logout)
    app.router.add_post("/api/passwd",          auth_mod.handle_change_password)
    app.router.add_get( "/api/stats",           handle_stats)
    app.router.add_get( "/ws",                  handle_ws)
    app.router.add_get( "/api/report",          handle_report)
    app.router.add_get( "/api/alerts",          handle_alerts_list)
    app.router.add_post("/api/alerts/{id}/ack", handle_alert_ack)
    app.router.add_get( "/api/alert-config",    handle_alert_config)
    app.router.add_post("/api/alert-config",    handle_alert_config)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    PORT_FILE.parent.mkdir(exist_ok=True)
    PORT_FILE.write_text(str(HTTP_PORT))

    print("")
    print("  ╔══════════════════════════════════════════════════════╗")
    print(f" ║  HoneyWatch v3  —  Port {HTTP_PORT:<5}               ║")
    print(f" ║                                                      ║")
    print(f" ║  >>> Open in browser:                                ║")
    print(f" ║      http://localhost:{HTTP_PORT}                    ║")
    print(f" ║                                                      ║")
    print(f" ║  Login :  admin / honeywatch                         ║")
    print(f" ║  API   :  http://localhost:{HTTP_PORT}/api/stats     ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print("")
    try:
        await _broadcast_loop()
    except asyncio.CancelledError:
        pass  # Normal Ctrl+C shutdown

def start_server_thread():
    def _run():
        asyncio.run(run_server())
    t = threading.Thread(target=_run, daemon=True, name="ws-server")
    t.start()
    return broadcast_event

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    db.init_db()
    alert_mod.init_alerts_table()
    alert_mod.start_spike_monitor()
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\n  HoneyWatch stopped.")
    except SystemExit:
        pass
