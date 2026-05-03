import json
import smtplib
import logging
import threading
import time
import os
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests

import database as db

log = logging.getLogger("honeypot.alerts")

# ── Config — edit here or set environment variables ───────────────────────────
CONFIG = {
    # ── Email ──────────────────────────────────────────────────────────────────
    "email_enabled":   os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true",
    "smtp_host":       os.environ.get("SMTP_HOST",     "smtp.gmail.com"),
    "smtp_port":       int(os.environ.get("SMTP_PORT", "587")),
    "smtp_user":       os.environ.get("SMTP_USER",     ""),
    "smtp_pass":       os.environ.get("SMTP_PASS",     ""),
    "alert_from":      os.environ.get("ALERT_FROM",    ""),
    "alert_to":        os.environ.get("ALERT_TO",      "").split(","),   # comma-separated

    # ── Discord ────────────────────────────────────────────────────────────────
    "discord_enabled": os.environ.get("DISCORD_ENABLED", "false").lower() == "true",
    "discord_webhook": os.environ.get("DISCORD_WEBHOOK", ""),

    # ── Slack ──────────────────────────────────────────────────────────────────
    "slack_enabled":   os.environ.get("SLACK_ENABLED", "false").lower() == "true",
    "slack_webhook":   os.environ.get("SLACK_WEBHOOK", ""),

    # ── Generic webhook ────────────────────────────────────────────────────────
    "webhook_enabled": os.environ.get("WEBHOOK_ENABLED", "false").lower() == "true",
    "webhook_url":     os.environ.get("WEBHOOK_URL", ""),

    # ── Thresholds ─────────────────────────────────────────────────────────────
    "spike_window_min":      10,     # minutes to watch for spikes
    "spike_threshold":       50,     # alert if >N attempts in window
    "new_ip_alert":          True,   # alert on first-seen IPs with high abuse score
    "new_ip_abuse_min":      75,     # minimum abuse score to alert
    "critical_always_alert": True,   # always alert on critical severity events
}

# Alert cooldowns — prevent flooding {alert_key: last_sent_ts}
_cooldowns: dict[str, float] = {}
COOLDOWN_SEC = 300   # 5 minutes between same alert type

# Sliding window for spike detection {minute_bucket: count}
_attempt_window: deque = deque(maxlen=60)
_window_lock = threading.Lock()

# Track seen IPs to detect new ones
_seen_ips: set = set()


# ── Core send ─────────────────────────────────────────────────────────────────

class Alert:
    def __init__(self, title: str, message: str, severity: str = "medium",
                 details: dict = None):
        self.title    = title
        self.message  = message
        self.severity = severity   # low / medium / high / critical
        self.details  = details or {}
        self.ts       = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {"title": self.title, "message": self.message,
                "severity": self.severity, "timestamp": self.ts,
                "details": self.details}

    @property
    def emoji(self):
        return {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}.get(self.severity, "⚠️")

    @property
    def color(self):
        return {"low": 0x00ff9d, "medium": 0xffcc00,
                "high": 0xff6600, "critical": 0xff2d55}.get(self.severity, 0xffcc00)


def _cooldown_ok(key: str) -> bool:
    now = time.time()
    last = _cooldowns.get(key, 0)
    if now - last > COOLDOWN_SEC:
        _cooldowns[key] = now
        return True
    return False


def send_alert(alert: Alert):
    """Dispatch alert to all enabled channels."""
    log.warning("🔔 ALERT [%s] %s — %s", alert.severity.upper(), alert.title, alert.message)
    threads = []
    if CONFIG["email_enabled"]:
        threads.append(threading.Thread(target=_send_email, args=(alert,), daemon=True))
    if CONFIG["discord_enabled"] and CONFIG["discord_webhook"]:
        threads.append(threading.Thread(target=_send_discord, args=(alert,), daemon=True))
    if CONFIG["slack_enabled"] and CONFIG["slack_webhook"]:
        threads.append(threading.Thread(target=_send_slack, args=(alert,), daemon=True))
    if CONFIG["webhook_enabled"] and CONFIG["webhook_url"]:
        threads.append(threading.Thread(target=_send_webhook, args=(alert,), daemon=True))
    for t in threads:
        t.start()
    # Store in DB for dashboard alert feed
    _store_alert(alert)


def _store_alert(alert: Alert):
    try:
        db.get_conn().execute("""
            INSERT OR IGNORE INTO alerts
            (timestamp, title, message, severity, details, acknowledged)
            VALUES (?,?,?,?,?,0)
        """, (alert.ts, alert.title, alert.message, alert.severity,
              json.dumps(alert.details)))
        db.get_conn().commit()
    except Exception as e:
        log.debug("Alert DB store error: %s", e)


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email(alert: Alert):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[HoneyWatch {alert.severity.upper()}] {alert.title}"
        msg["From"]    = CONFIG["alert_from"] or CONFIG["smtp_user"]
        msg["To"]      = ", ".join(CONFIG["alert_to"])

        html = f"""
        <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
        <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
          <div style="background:{'#ff2d55' if alert.severity=='critical' else '#ff6600' if alert.severity=='high' else '#ffcc00' if alert.severity=='medium' else '#00ffa3'};padding:20px">
            <h1 style="margin:0;color:{'#fff' if alert.severity in ('critical','high') else '#000'};font-size:18px">
              {alert.emoji} HoneyWatch Alert — {alert.severity.upper()}
            </h1>
          </div>
          <div style="padding:24px">
            <h2 style="margin-top:0;color:#1a1a2e">{alert.title}</h2>
            <p style="color:#444;line-height:1.6">{alert.message}</p>
            {''.join(f'<p><strong>{k}:</strong> {v}</p>' for k, v in alert.details.items())}
            <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
            <p style="color:#888;font-size:12px">
              Timestamp: {alert.ts}<br>
              HoneyWatch SSH Threat Intelligence Platform
            </p>
          </div>
        </div>
        </body></html>"""

        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(CONFIG["smtp_host"], CONFIG["smtp_port"]) as s:
            s.ehlo(); s.starttls(); s.ehlo()
            s.login(CONFIG["smtp_user"], CONFIG["smtp_pass"])
            s.sendmail(msg["From"], CONFIG["alert_to"], msg.as_string())
        log.info("📧 Email alert sent: %s", alert.title)
    except Exception as e:
        log.error("Email alert failed: %s", e)


# ── Discord ───────────────────────────────────────────────────────────────────

def _send_discord(alert: Alert):
    try:
        fields = [{"name": k, "value": str(v), "inline": True}
                  for k, v in alert.details.items()]
        payload = {
            "embeds": [{
                "title":       f"{alert.emoji} {alert.title}",
                "description": alert.message,
                "color":       alert.color,
                "fields":      fields,
                "footer":      {"text": "HoneyWatch • SSH Threat Intelligence"},
                "timestamp":   alert.ts,
            }]
        }
        r = requests.post(CONFIG["discord_webhook"], json=payload, timeout=5)
        if r.status_code in (200, 204):
            log.info("🎮 Discord alert sent: %s", alert.title)
        else:
            log.error("Discord alert failed: %s %s", r.status_code, r.text[:100])
    except Exception as e:
        log.error("Discord alert error: %s", e)


# ── Slack ─────────────────────────────────────────────────────────────────────

def _send_slack(alert: Alert):
    try:
        color_map = {"low":"#00ffa3","medium":"#ffcc00","high":"#ff6600","critical":"#ff2d55"}
        fields = [{"title": k, "value": str(v), "short": True}
                  for k, v in alert.details.items()]
        payload = {
            "attachments": [{
                "color":      color_map.get(alert.severity, "#ffcc00"),
                "title":      f"{alert.emoji} {alert.title}",
                "text":       alert.message,
                "fields":     fields,
                "footer":     "HoneyWatch SSH Threat Intelligence",
                "ts":         int(time.time()),
            }]
        }
        r = requests.post(CONFIG["slack_webhook"], json=payload, timeout=5)
        log.info("💬 Slack alert sent: %s", alert.title) if r.ok else \
        log.error("Slack alert failed: %s", r.text[:100])
    except Exception as e:
        log.error("Slack alert error: %s", e)


# ── Generic webhook ───────────────────────────────────────────────────────────

def _send_webhook(alert: Alert):
    try:
        r = requests.post(CONFIG["webhook_url"],
                          json=alert.to_dict(),
                          headers={"Content-Type": "application/json"},
                          timeout=5)
        log.info("🪝 Webhook alert sent: %d", r.status_code)
    except Exception as e:
        log.error("Webhook alert error: %s", e)


# ── Trigger functions (called from honeypot/ws_server) ───────────────────────

def trigger_suspicious(ip: str, stype: str, severity: str, cmd: str, country: str = ""):
    """Called when a suspicious event is flagged."""
    if severity not in ("high", "critical"):
        return
    if not CONFIG["critical_always_alert"]:
        return
    key = f"susp:{ip}:{stype}"
    if not _cooldown_ok(key):
        return
    send_alert(Alert(
        title   = f"Suspicious Activity: {stype.replace('_', ' ').title()}",
        message = f"High-risk behaviour detected from {ip}" +
                  (f" ({country})" if country else ""),
        severity = severity,
        details = {"IP": ip, "Type": stype, "Command": cmd[:120],
                   "Country": country or "Unknown"},
    ))


def trigger_new_attacker(ip: str, country: str, abuse_score: int, isp: str):
    """Called when a new high-reputation-score IP is seen."""
    if not CONFIG["new_ip_alert"]:
        return
    if abuse_score < CONFIG["new_ip_abuse_min"]:
        return
    key = f"newip:{ip}"
    if not _cooldown_ok(key):
        return
    send_alert(Alert(
        title    = f"High-Risk Attacker Detected: {ip}",
        message  = f"New connection from known-malicious IP (abuse score {abuse_score}/100)",
        severity = "high" if abuse_score < 90 else "critical",
        details  = {"IP": ip, "Country": country, "ISP": isp,
                    "Abuse Score": f"{abuse_score}/100"},
    ))


def trigger_malware_download(ip: str, url: str, tool: str, country: str = ""):
    """Called when an attacker downloads a file."""
    key = f"malware:{ip}:{url}"
    if not _cooldown_ok(key):
        return
    send_alert(Alert(
        title    = "Malware Download Attempt",
        message  = f"Attacker from {ip} downloaded payload via {tool}",
        severity = "critical",
        details  = {"Attacker IP": ip, "Tool": tool, "URL": url[:120],
                    "Country": country or "Unknown"},
    ))


def trigger_brute_force_spike(ip: str, count: int, window_min: int):
    """Called when a single IP exceeds attempt threshold."""
    key = f"spike:{ip}"
    if not _cooldown_ok(key):
        return
    send_alert(Alert(
        title    = f"Brute Force Spike: {ip}",
        message  = f"{count} login attempts in {window_min} minutes from single IP",
        severity = "high",
        details  = {"IP": ip, "Attempts": count, "Window": f"{window_min} min"},
    ))


def trigger_login_success(ip: str, username: str, country: str = ""):
    """Called when attacker successfully logs in."""
    key = f"success:{ip}"
    if not _cooldown_ok(key):
        return
    send_alert(Alert(
        title    = "⚠️ Honeypot Login Successful",
        message  = f"Attacker from {ip} authenticated successfully — monitoring session",
        severity = "high",
        details  = {"IP": ip, "Username": username, "Country": country or "Unknown"},
    ))


# ── Background spike monitor ──────────────────────────────────────────────────

def _spike_monitor():
    """Periodically check for single-IP brute-force spikes."""
    while True:
        time.sleep(60)
        try:
            window = CONFIG["spike_window_min"]
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window)).isoformat()
            rows = db.query("""
                SELECT peer_ip, COUNT(*) as cnt FROM auth_attempts
                WHERE timestamp > ? GROUP BY peer_ip
                HAVING cnt > ?
            """, (cutoff, CONFIG["spike_threshold"]))
            for row in rows:
                trigger_brute_force_spike(row["peer_ip"], row["cnt"], window)
        except Exception as e:
            log.debug("Spike monitor error: %s", e)


def start_spike_monitor():
    t = threading.Thread(target=_spike_monitor, daemon=True, name="spike-monitor")
    t.start()
    log.info("📈 Spike monitor started (threshold: %d/%.0f min)",
             CONFIG["spike_threshold"], CONFIG["spike_window_min"])


# ── Ensure alerts table exists ────────────────────────────────────────────────

def init_alerts_table():
    db.get_conn().executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            title        TEXT NOT NULL,
            message      TEXT NOT NULL,
            severity     TEXT NOT NULL,
            details      TEXT,
            acknowledged INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
    """)
    db.get_conn().commit()
