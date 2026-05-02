"""
threat_intel.py — GeoIP enrichment, AbuseIPDB checks, attack pattern detection.
All lookups are cached in SQLite to avoid hammering APIs.
"""

import json
import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque

import requests

import database as db

log = logging.getLogger("honeypot.intel")

# ── Config (set env vars or edit here) ───────────────────────────────────────
ABUSEIPDB_KEY  = ""   # https://www.abuseipdb.com/api  (free tier: 1000/day)
SHODAN_KEY     = ""   # https://developer.shodan.io    (optional)
GEO_CACHE_TTL  = 86400       # 24 hours
ABUSE_CACHE_TTL = 3600 * 6   # 6 hours

# ── In-memory sliding window for pattern detection ────────────────────────────
# {ip: deque of (timestamp, username, password)}
_ip_attempts: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
# {username: set of IPs that tried it}
_user_ips: dict[str, set] = defaultdict(set)
# {(ip,username): set of passwords tried}
_ip_user_passes: dict[tuple, set] = defaultdict(set)

_lock = threading.Lock()

DISCORD_WEBHOOK = ""  # paste your webhook URL for alerts


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def get_geo(ip: str) -> dict:
    """Return GeoIP dict for ip, using DB cache."""
    if _is_private(ip):
        return {"country": "Private", "countryCode": "XX", "city": "Local",
                "isp": "Private Network", "lat": 0, "lon": 0}

    row = db.query("SELECT * FROM ip_reputation WHERE ip=?", (ip,))
    if row and row[0].get("raw_geo"):
        cached_at = row[0].get("last_checked", "")
        age = (datetime.now(timezone.utc) - _parse_ts(cached_at)).total_seconds()
        if age < GEO_CACHE_TTL:
            return json.loads(row[0]["raw_geo"])

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,as,lat,lon",
                         timeout=4)
        geo = r.json() if r.status_code == 200 else {}
    except Exception as e:
        log.debug("GeoIP lookup failed for %s: %s", ip, e)
        geo = {}

    db.upsert_ip_reputation(ip, geo=geo)
    return geo


def get_abuse(ip: str) -> dict:
    """Check AbuseIPDB for ip reputation (if key configured)."""
    if not ABUSEIPDB_KEY or _is_private(ip):
        return {}

    row = db.query("SELECT * FROM ip_reputation WHERE ip=?", (ip,))
    if row and row[0].get("raw_abuse"):
        cached_at = row[0].get("last_checked", "")
        age = (datetime.now(timezone.utc) - _parse_ts(cached_at)).total_seconds()
        if age < ABUSE_CACHE_TTL:
            return json.loads(row[0]["raw_abuse"])

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        data = r.json().get("data", {}) if r.status_code == 200 else {}
    except Exception as e:
        log.debug("AbuseIPDB lookup failed: %s", e)
        data = {}

    db.upsert_ip_reputation(ip, abuse=data)
    return data


# ── Attack pattern detection ──────────────────────────────────────────────────

def record_attempt(ip: str, username: str, password: str) -> str:
    """
    Record a credential attempt and return detected attack type:
    bruteforce | credential_stuffing | dictionary | targeted | unknown
    """
    now = time.time()
    with _lock:
        dq = _ip_attempts[ip]
        dq.append((now, username, password))
        _user_ips[username].add(ip)
        _ip_user_passes[(ip, username)].add(password)

        # Prune old entries (> 10 min window)
        while dq and now - dq[0][0] > 600:
            dq.popleft()

        return _classify(ip, username, password, dq)


def _classify(ip, username, password, dq) -> str:
    recent = list(dq)
    if len(recent) < 3:
        return "unknown"

    usernames_seen   = {r[1] for r in recent}
    passwords_seen   = {r[2] for r in recent}
    ips_for_user     = _user_ips.get(username, set())
    passes_for_combo = _ip_user_passes.get((ip, username), set())

    # Same password across many usernames → credential stuffing
    if len(usernames_seen) > 5 and len(passwords_seen) <= 2:
        return "credential_stuffing"

    # Many IPs using same credentials → botnet sweep
    if len(ips_for_user) > 8 and len(passes_for_combo) == 1:
        return "botnet_sweep"

    # One username, many passwords → targeted brute-force
    if len(usernames_seen) == 1 and len(passes_for_combo) > 5:
        return "targeted_bruteforce"

    # Many passwords in short time → dictionary attack
    rate = len(recent) / max((recent[-1][0] - recent[0][0]) / 60, 0.1)  # per min
    if rate > 10 and len(passwords_seen) > 5:
        return "dictionary_attack"

    return "bruteforce"


# ── Alerting ──────────────────────────────────────────────────────────────────

def alert(message: str, severity: str = "medium"):
    """Send Discord/Slack webhook alert."""
    log.warning("ALERT [%s]: %s", severity.upper(), message)
    if not DISCORD_WEBHOOK:
        return
    icons = {"low": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
    icon  = icons.get(severity, "⚠️")
    try:
        requests.post(DISCORD_WEBHOOK,
                      json={"content": f"{icon} **[{severity.upper()}]** {message}"},
                      timeout=5)
    except Exception:
        pass


def severity_for_type(suspicious_type: str) -> str:
    return {
        "file_download":         "high",
        "interpreter_execution": "high",
        "persistence":           "critical",
        "privilege_escalation":  "high",
        "lateral_movement":      "critical",
        "data_exfiltration":     "critical",
    }.get(suspicious_type, "medium")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except ValueError:
        return False


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


# ── Background enrichment thread ──────────────────────────────────────────────

_enrich_queue: list[str] = []
_enrich_lock  = threading.Lock()


def enqueue_enrich(ip: str):
    """Queue an IP for background GeoIP + abuse lookup."""
    with _enrich_lock:
        if ip not in _enrich_queue:
            _enrich_queue.append(ip)


def _enrich_worker():
    while True:
        time.sleep(2)
        with _enrich_lock:
            if not _enrich_queue:
                continue
            ip = _enrich_queue.pop(0)
        try:
            geo   = get_geo(ip)
            abuse = get_abuse(ip)
            score = abuse.get("abuseConfidenceScore", 0)
            if score and score > 50:
                alert(f"High-risk IP {ip} connected (abuse score {score})", "high")
            # Update session geo fields
            db.get_conn().execute("""
                UPDATE sessions SET
                    country=?, country_code=?, city=?, isp=?, lat=?, lon=?,
                    abuse_score=?, is_known_bad=?
                WHERE peer_ip=? AND disconnected_at IS NULL
            """, (
                geo.get("country"), geo.get("countryCode"), geo.get("city"),
                geo.get("isp"), geo.get("lat"), geo.get("lon"),
                score, 1 if score > 50 else 0,
                ip,
            ))
            db.get_conn().commit()
        except Exception as e:
            log.debug("Enrich error for %s: %s", ip, e)


def start_enrichment_worker():
    t = threading.Thread(target=_enrich_worker, daemon=True)
    t.start()
    log.info("🌍 GeoIP enrichment worker started")
