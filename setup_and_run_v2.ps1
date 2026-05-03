# setup_and_run_v2.ps1 — HoneyWatch v2 Windows Setup
# Run: powershell -ExecutionPolicy Bypass -File setup_and_run_v2.ps1

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  HoneyWatch v2 — Windows Setup & Launcher" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ── Find Python ──────────────────────────────────────────────────────────────
$py = $null
foreach ($cmd in @("python","py","python3")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") { $py = $cmd; Write-Host "[OK] $ver  (command: '$cmd')" -ForegroundColor Green; break }
    } catch {}
}
if (-not $py) {
    Write-Host "[ERROR] Python 3 not found. Download from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "        Check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 1
}

# ── Install packages ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/4] Installing Python packages..." -ForegroundColor Cyan

# Remove conflicting 'jwt' package if present (correct one is PyJWT)
Write-Host "      Removing conflicting jwt package if present..." -ForegroundColor Gray
& $py -m pip uninstall jwt -y 2>$null | Out-Null

# Install all required packages
& $py -m pip install paramiko requests aiohttp bcrypt PyJWT reportlab --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] pip install failed. Try running as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}

# Verify PyJWT works
$jwtCheck = & $py -c "import jwt; print(jwt.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FIX] Reinstalling PyJWT cleanly..." -ForegroundColor Yellow
    & $py -m pip uninstall jwt PyJWT -y --quiet
    & $py -m pip install PyJWT --quiet
    Write-Host "[OK] PyJWT reinstalled." -ForegroundColor Green
}
Write-Host "[OK] All packages ready." -ForegroundColor Green

# ── Seed database ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Seeding SQLite database with 14 days of realistic data..." -ForegroundColor Cyan
& $py seed_logs.py
Write-Host "[OK] Database ready at logs\honeypot.db" -ForegroundColor Green

# ── Start dashboard server ────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Starting dashboard API + WebSocket server on :8080..." -ForegroundColor Cyan
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  Open  dashboard.html  in your browser NOW          │" -ForegroundColor Yellow
Write-Host "  │  API:  http://localhost:8080/api/stats               │" -ForegroundColor Yellow
Write-Host "  │  WS:   ws://localhost:8080/ws                        │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""
Write-Host "  (In a second terminal, run:  $py honeypot.py  to start the SSH server on port 2222)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

Write-Host ''
Write-Host '  IMPORTANT: Open this URL in your browser (NOT dashboard.html as a file):' -ForegroundColor Yellow
Write-Host '     http://localhost:8080' -ForegroundColor Green  
Write-Host '  Login: admin / honeywatch' -ForegroundColor Cyan
Write-Host ''
Start-Sleep -Seconds 3
Start-Process 'http://localhost:8080'
& $py ws_server.py
