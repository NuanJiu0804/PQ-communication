@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
title Post-Quantum Hybrid E2EE IM - Extra Client

rem =================================================================
rem  Launch an ADDITIONAL desktop client window.
rem
rem  Why this exists:
rem    "npm run tauri dev" starts its own Vite dev server on :5173.
rem    Running it a second time fails ("Port 5173 already in use").
rem    Instead, this script runs the already-built dev binary, which
rem    loads its UI from the FIRST instance's Vite server (:5173) and
rem    opens a second independent window.
rem
rem  Prerequisite:
rem    Run "npm run tauri dev" once first (the first instance must be
rem    running, and it builds target\debug\pqchat.exe).
rem
rem  Each instance can log in as a DIFFERENT user (Alice / Bob / Carol):
rem    the local encrypted store is per-user (pqchat-<userId>.db), so
rem    they do not collide.
rem =================================================================

set "EXE=%~dp0apps\client\src-tauri\target\debug\pqchat.exe"

rem ---- ensure first instance's dev server is up ----
netstat -an | find ":5173 " | find "LISTENING" >nul
if errorlevel 1 (
  echo [WARN] Dev server :5173 not detected.
  echo        Start the FIRST instance first:
  echo            cd apps\client  ^&^&  npm run tauri dev
  echo.
)

if not exist "%EXE%" (
  echo [ERROR] %EXE%
  echo         not found. Run "npm run tauri dev" once to build it.
  echo.
  pause
  exit /b 1
)

echo Launching an additional client window...
echo Log in as a different user, e.g. bob@pqchat.local / Pqchat123456
start "E2EE-IM Client 2" "%EXE%"
exit /b 0
