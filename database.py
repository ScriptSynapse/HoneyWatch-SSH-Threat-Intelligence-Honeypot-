"""
database.py — SQLite backend for the honeypot.
Replaces flat JSONL files with indexed, queryable storage.
"""

import sqlite3
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path("logs/honeypot.db")
DB_PATH.parent.mkdir(exist_ok=True)

_local = threading.local()


def get_conn():
    """Return a thread-local connection (SQLite is not thread-safe across threads)."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Create all tables and indexes."""
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT UNIQUE NOT NULL,
            peer_ip         TEXT NOT NULL,
            peer_port       INTEGER,
            connected_at    TEXT NOT NULL,
            disconnected_at TEXT,
            login_success   INTEGER DEFAULT 0,
            commands_count  INTEGER DEFAULT 0,
            -- GeoIP fields
            country         TEXT,
            country_code    TEXT,
            city            TEXT,
            region          TEXT,
            isp             TEXT,
            asn             TEXT,
            lat             REAL,
            lon             REAL,
            -- Threat intel
            abuse_score     INTEGER,
            is_known_bad    INTEGER DEFAULT 0,
            threat_tags     TEXT    -- JSON array
        );

        CREATE TABLE IF NOT EXISTS auth_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            session_id  TEXT NOT NULL,
            peer_ip     TEXT NOT NULL,
            username    TEXT NOT NULL,
            password    TEXT NOT NULL,
            auth_method TEXT DEFAULT 'password',
            result      TEXT NOT NULL,   -- accepted / rejected
            -- Pattern detection
            attack_type TEXT             -- bruteforce / credential_stuffing / dictionary / targeted
        );

        CREATE TABLE IF NOT EXISTS commands (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT NOT NULL,
            session_id     TEXT NOT NULL,
            peer_ip        TEXT NOT NULL,
            command        TEXT NOT NULL,
            command_base   TEXT,         -- first token (ls, cat, wget…)
            output_preview TEXT
        );

        CREATE TABLE IF NOT EXISTS suspicious_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            peer_ip         TEXT NOT NULL,
            suspicious_type TEXT NOT NULL,
            detail          TEXT,        -- JSON blob
            severity        TEXT DEFAULT 'medium'  -- low/medium/high/critical
        );

        CREATE TABLE IF NOT EXISTS malware_captures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            session_id  TEXT NOT NULL,
            peer_ip     TEXT NOT NULL,
            url         TEXT,
            tool        TEXT,
            filename    TEXT,
            file_hash   TEXT,
            file_size   INTEGER,
            saved_path  TEXT
        );

        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip              TEXT PRIMARY KEY,
            last_checked    TEXT,
            abuse_score     INTEGER,
            is_tor          INTEGER DEFAULT 0,
            is_vpn          INTEGER DEFAULT 0,
            country_code    TEXT,
            isp             TEXT,
            asn             TEXT,
            lat             REAL,
            lon             REAL,
            city            TEXT,
            country         TEXT,
            raw_geo         TEXT,   -- full JSON from ip-api
            raw_abuse       TEXT    -- full JSON from AbuseIPDB
        );

        -- Indexes for common queries
        CREATE INDEX IF NOT EXISTS idx_auth_ip        ON auth_attempts(peer_ip);
        CREATE INDEX IF NOT EXISTS idx_auth_ts        ON auth_attempts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_auth_user      ON auth_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_auth_pass      ON auth_attempts(password);
        CREATE INDEX IF NOT EXISTS idx_cmd_ts         ON commands(timestamp);
        CREATE INDEX IF NOT EXISTS idx_cmd_ip         ON commands(peer_ip);
        CREATE INDEX IF NOT EXISTS idx_susp_ts        ON suspicious_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_sessions_ip    ON sessions(peer_ip);
    """)
    conn.commit()


# ── Write helpers ─────────────────────────────────────────────────────────────

def insert_session(data: dict):
    with tx() as c:
        c.execute("""
            INSERT OR REPLACE INTO sessions
            (session_id, peer_ip, peer_port, connected_at, login_success)
            VALUES (:session_id, :peer_ip, :peer_port, :connected_at, :login_success)
        """, data)


def update_session(session_id: str, **kwargs):
    if not kwargs:
        return
    cols = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [session_id]
    with tx() as c:
        c.execute(f"UPDATE sessions SET {cols} WHERE session_id=?", vals)


def insert_auth(data: dict):
    with tx() as c:
        c.execute("""
            INSERT INTO auth_attempts
            (timestamp, session_id, peer_ip, username, password, auth_method, result)
            VALUES (:timestamp, :session_id, :peer_ip, :username, :password, :auth_method, :result)
        """, data)


def insert_command(data: dict):
    base = data.get("command", "").split()[0] if data.get("command") else ""
    with tx() as c:
        c.execute("""
            INSERT INTO commands
            (timestamp, session_id, peer_ip, command, command_base, output_preview)
            VALUES (:timestamp, :session_id, :peer_ip, :command, :command_base, :output_preview)
        """, {**data, "command_base": base})


def insert_suspicious(data: dict):
    with tx() as c:
        c.execute("""
            INSERT INTO suspicious_events
            (timestamp, session_id, peer_ip, suspicious_type, detail, severity)
            VALUES (:timestamp, :session_id, :peer_ip, :suspicious_type, :detail, :severity)
        """, data)


def upsert_ip_reputation(ip: str, geo: dict = None, abuse: dict = None):
    with tx() as c:
        existing = c.execute("SELECT * FROM ip_reputation WHERE ip=?", (ip,)).fetchone()
        if not existing:
            c.execute("INSERT INTO ip_reputation (ip, last_checked) VALUES (?,?)",
                      (ip, datetime.now(timezone.utc).isoformat()))

        updates = {"last_checked": datetime.now(timezone.utc).isoformat()}
        if geo:
            updates.update({
                "country_code": geo.get("countryCode"),
                "country":      geo.get("country"),
                "city":         geo.get("city"),
                "isp":          geo.get("isp"),
                "asn":          geo.get("as"),
                "lat":          geo.get("lat"),
                "lon":          geo.get("lon"),
                "raw_geo":      json.dumps(geo),
            })
        if abuse:
            updates.update({
                "abuse_score": abuse.get("abuseConfidenceScore", 0),
                "is_tor":      1 if abuse.get("isTor") else 0,
                "raw_abuse":   json.dumps(abuse),
            })
        cols = ", ".join(f"{k}=?" for k in updates)
        c.execute(f"UPDATE ip_reputation SET {cols} WHERE ip=?",
                  list(updates.values()) + [ip])


# ── Read helpers ──────────────────────────────────────────────────────────────

def query(sql: str, params=()):
    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def scalar(sql: str, params=()):
    conn = get_conn()
    row = conn.execute(sql, params).fetchone()
    return row[0] if row else 0
