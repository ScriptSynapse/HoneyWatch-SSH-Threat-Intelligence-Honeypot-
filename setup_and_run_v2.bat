@echo off
title HoneyWatch v2 - Setup
color 0A
echo.
echo  =====================================================
echo   HoneyWatch v2 -- SSH Honeypot Threat Intelligence
echo  =====================================================
echo.

REM ── Find Python ─────────────────────────────────────────────────────────────
set PY=
python --version >nul 2>&1
if %errorlevel%==0 ( set PY=python & goto :found )
py --version >nul 2>&1
if %errorlevel%==0 ( set PY=py & goto :found )

echo [ERROR] Python not found. Install from https://www.python.org/downloads/
echo         Make sure to check "Add Python to PATH"
pause & exit /b 1

:found
for /f "tokens=*" %%v in ('%PY% --version 2^>^&1') do echo [OK] %%v  (using '%PY%')

REM ── Install dependencies ─────────────────────────────────────────────────────
echo.
echo [1/4] Installing packages...
%PY% -m pip install paramiko requests aiohttp --quiet
if %errorlevel% neq 0 (
    echo [ERROR] pip failed. Try running as Administrator.
    pause & exit /b 1
)
echo [OK] Packages ready.

REM ── Seed database ────────────────────────────────────────────────────────────
echo.
echo [2/4] Seeding database with demo data...
%PY% seed_logs.py
echo [OK] logs\honeypot.db ready.

REM ── Instructions ─────────────────────────────────────────────────────────────
echo.
echo [3/4] Open dashboard.html in your browser NOW
echo.
echo        API  -^>  http://localhost:8080/api/stats
echo        WS   -^>  ws://localhost:8080/ws
echo.
echo [4/4] Starting API + WebSocket server...
echo       (In a new terminal: %PY% honeypot.py  to start SSH honeypot on port 2222)
echo.
echo       Press Ctrl+C to stop.
echo.
%PY% ws_server.py
pause
