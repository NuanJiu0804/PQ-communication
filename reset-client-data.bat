@echo off
chcp 65001 >nul 2>&1
title Post-Quantum Hybrid E2EE IM - Reset Client Data

rem =================================================================
rem  Deletes the local encrypted session stores of the desktop client.
rem  Use this to recover from a broken/colliding session state.
rem  After running, log in again - the client regenerates its keys
rem  and re-uploads prekeys, starting a clean session.
rem
rem  IMPORTANT: close all client windows first (the .db files
rem  are locked while the app is running).
rem =================================================================

set "DIR=%APPDATA%\com.pqchat.desktop"

echo This will delete local client session stores in:
echo     %DIR%
echo.
if exist "%DIR%\pqchat-*.db" (
  dir /b "%DIR%\pqchat-*.db"
) else (
  echo (no store files found - nothing to reset)
  echo.
  pause
  exit /b 0
)
echo.
choice /c YN /m "Delete these files"
if errorlevel 2 ( echo Cancelled. & pause & exit /b 0 )

rem Close any running client first (otherwise the .db files are locked and
rem cannot be deleted - this was the cause of "delete had no effect").
echo Closing running client windows...
taskkill /f /im pqchat.exe >nul 2>&1
timeout /t 2 /nobreak >nul

del /q "%DIR%\pqchat-*.db" 2>nul
if exist "%DIR%\pqchat-*.db" (
  echo [WARN] Some files could not be deleted - make sure all client
  echo        client windows are closed, then run this again.
) else (
  echo Done. Start the clients again and log in for a fresh session.
)
echo.
pause
exit /b 0
