# 🍯 HoneyWatch v2 — SSH Honeypot + Threat Intelligence Platform

A production-grade SSH honeypot with stateful shell emulation, GeoIP enrichment,
attack pattern detection, malware capture, real-time WebSocket dashboard, and a
world-map visualization of attacker origins.

---

## File Overview

```
honeypot_v2/
├── honeypot.py          # SSH server — fake shell, tarpit, malware capture
├── fake_fs.py           # Stateful virtual filesystem + canary credentials
├── threat_intel.py      # GeoIP, AbuseIPDB, attack pattern detection, alerting
├── database.py          # SQLite backend (replaces JSONL flat files)
├── ws_server.py         # aiohttp API + WebSocket server (real-time push)
├── seed_logs.py         # Generate 14 days of realistic demo data
├── dashboard.html       # Full-featured browser dashboard (6 pages)
├── setup_and_run_v2.ps1 # Windows PowerShell launcher
├── setup_and_run_v2.bat # Windows Batch launcher
└── logs/
    └── honeypot.db      # SQLite database (auto-created)
```

---

## Quick Start

### Windows (recommended)
```
Double-click setup_and_run_v2.bat
```
Or in PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File setup_and_run_v2.ps1
```

### Linux / macOS
```bash
pip install paramiko requests aiohttp
python seed_logs.py          # populate DB with 14 days of demo data
python ws_server.py          # start API + WS on :8080
# open dashboard.html in browser

# In a second terminal:
python honeypot.py           # SSH honeypot on port 2222
```

> The dashboard works **without** the server — it falls back to embedded demo data automatically.

---

## What's New in v2

### 🗄️ SQLite Database
All events stored in `logs/honeypot.db` with full indexing:
- `sessions` — connection metadata + GeoIP columns
- `auth_attempts` — credentials + attack type classification
- `commands` — every post-auth command with base token
- `suspicious_events` — flagged high-risk actions with severity
- `malware_captures` — downloaded file metadata + sha256
- `ip_reputation` — GeoIP + AbuseIPDB cache

### 🌍 GeoIP Enrichment
Every attacker IP is automatically resolved via ip-api.com:
- Country, city, ISP, ASN
- Latitude/longitude for the world map
- Results cached in DB for 24 hours

### 🛡️ AbuseIPDB Integration
Set `ABUSEIPDB_KEY` in `threat_intel.py` for automatic reputation scoring:
- Abuse confidence score (0–100)
- Tor exit node detection
- 6-hour cache to stay within free tier limits

### 🔍 Attack Pattern Detection
Every auth attempt is classified:
- **dictionary_attack** — high rate, many passwords
- **targeted_bruteforce** — one username, many passwords
- **credential_stuffing** — one password across many usernames
- **botnet_sweep** — many IPs with same credentials
- **bruteforce** — general

### 🎣 Canary / Deception Credentials
The fake filesystem contains planted "valuable" secrets:
- `/root/.aws/credentials` — fake AWS keys
- `/root/.ssh/id_rsa` — fake private key
- `/root/.bash_history` — history showing interesting prior commands
- `/root/.env` — fake DB URLs + Django secret
- `/var/www/html/wp-config.php` — fake MySQL credentials

### 🐌 Tarpit Delays
Each auth attempt waits 0.5–2.0 seconds before responding, wasting attacker
brute-force tool threads and significantly slowing dictionary attacks.

### 💾 Real Malware Capture
When an attacker runs `wget`/`curl` against a real URL, the honeypot actually
fetches the payload and saves it to `malware_captures/` with sha256 hash.

### ⚡ WebSocket Live Feed
The dashboard connects to `ws://localhost:8080/ws` and receives push events
for every connection, auth attempt, command, and suspicious event — no polling.

### 📊 Dashboard Pages
| Page | Content |
|---|---|
| **Overview** | Stat strip, 14-day timeline, attack types donut, top credentials/commands, hourly heatmap, live event feed |
| **World Map** | Leaflet.js map with sized+colored markers per attacker, GeoIP + abuse score table |
| **Credentials** | Full username/password rankings, attack pattern bar + donut charts |
| **Activity** | Recent command log with country flags |
| **Threats** | Suspicious event table, severity distribution, type breakdown |
| **Malware** | Capture log with URLs, filenames, sha256 hashes |

---

## Configuration

### Enable AbuseIPDB (free: 1000 checks/day)
```python
# threat_intel.py
ABUSEIPDB_KEY = "your_key_here"
```

### Enable Discord/Slack Alerts
```python
# threat_intel.py
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/..."
```

### Change SSH port (production: port 22)
```python
# honeypot.py
PORT = 22   # requires root or authbind
```

### Run on port 22 without root (Linux)
```bash
sudo apt install authbind
sudo touch /etc/authbind/byport/22
sudo chmod 500 /etc/authbind/byport/22
sudo chown $USER /etc/authbind/byport/22
authbind --deep python honeypot.py
```

---

## Production Deployment (systemd)

```ini
# /etc/systemd/system/honeywatch.service
[Unit]
Description=HoneyWatch SSH Honeypot
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/honeywatch
ExecStart=/usr/bin/python3 honeypot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable honeywatch
sudo systemctl start honeywatch
```

---

## Security Hardening

```bash
# Isolate the honeypot host — block all outbound except your logging server
ufw default deny outgoing
ufw default allow incoming
ufw allow in 22/tcp
ufw allow in 2222/tcp
ufw allow out to <LOG_SERVER_IP> port 9200

# Never run on a machine with real data or services
# Use a dedicated VPS or isolated VM
```

---

## Log Schema (SQLite)

```sql
-- Every credential attempt
SELECT timestamp, peer_ip, username, password, result, attack_type
FROM auth_attempts ORDER BY timestamp DESC LIMIT 100;

-- Most common passwords
SELECT password, COUNT(*) as n FROM auth_attempts
GROUP BY password ORDER BY n DESC LIMIT 20;

-- Attackers by country
SELECT r.country, COUNT(DISTINCT a.peer_ip) as ips, COUNT(*) as attempts
FROM auth_attempts a JOIN ip_reputation r ON a.peer_ip=r.ip
GROUP BY r.country ORDER BY attempts DESC;

-- Critical suspicious events
SELECT timestamp, peer_ip, suspicious_type, detail
FROM suspicious_events WHERE severity='critical'
ORDER BY timestamp DESC;

-- Malware download URLs
SELECT url, COUNT(*) as times, COUNT(DISTINCT peer_ip) as attackers
FROM malware_captures GROUP BY url ORDER BY times DESC;
```

---

## Legal Notice

Deploy only on infrastructure you own or have explicit authorization to use for
security research. Honeypot traffic is legitimate to collect; ensure compliance
with local laws regarding network monitoring and data retention.
