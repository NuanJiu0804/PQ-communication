@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Post-Quantum Hybrid E2EE IM Launcher

echo ==================================================
echo      Post-Quantum Hybrid E2EE IM - One-Click Launcher
echo ==================================================
echo.

rem ---- put Go on PATH (winget install is not on PATH by default) ----
if exist "C:\Program Files\Go\bin\go.exe" set "PATH=C:\Program Files\Go\bin;%PATH%"

rem =================================================================
rem  1) PostgreSQL (:5432)
rem =================================================================
set PG=0
netstat -an | find ":5432 " | find "LISTENING" >nul && set PG=1
if "%PG%"=="1" ( echo [ OK ]  PostgreSQL  :5432  running & goto after_pg )
echo [START] trying to start PostgreSQL service...
for %%v in (17 16 15 14 13 12) do net start postgresql-x64-%%v >nul 2>&1
netstat -an | find ":5432 " | find "LISTENING" >nul && set PG=1
if "%PG%"=="1" ( echo [ OK ]  PostgreSQL started ) else ( echo [WARN]  PostgreSQL :5432 not running - please start it manually )
:after_pg

rem =================================================================
rem  2) Redis (:6379)
rem =================================================================
set RD=0
netstat -an | find ":6379 " | find "LISTENING" >nul && set RD=1
if "%RD%"=="1" ( echo [ OK ]  Redis       :6379  running & goto after_redis )
echo [START] trying to start Redis / Memurai service...
net start Memurai >nul 2>&1
net start Redis >nul 2>&1
netstat -an | find ":6379 " | find "LISTENING" >nul && set RD=1
if "%RD%"=="1" ( echo [ OK ]  Redis started ) else ( echo [WARN]  Redis :6379 not running - please start it manually )
:after_redis

rem =================================================================
rem  3) MinIO (:9000)  - object storage for encrypted media
rem =================================================================
set MO=0
netstat -an | find ":9000 " | find "LISTENING" >nul && set MO=1
if "%MO%"=="1" ( echo [ OK ]  MinIO       :9000  running & goto after_minio )
if not exist "C:\minio\minio.exe" ( echo [WARN]  C:\minio\minio.exe not found - media features disabled & goto after_minio )
echo [START] starting MinIO...
start "E2EE-IM MinIO" cmd /k "set MINIO_ROOT_USER=pqchat&&set MINIO_ROOT_PASSWORD=pqchat_dev_password&&C:\minio\minio.exe server C:\minio\data --console-address :9001"
for /l %%i in (1,1,15) do (
  if "!MO!"=="0" (
    timeout /t 1 /nobreak >nul
    netstat -an | find ":9000 " | find "LISTENING" >nul && set MO=1
  )
)
if "%MO%"=="1" ( echo [ OK ]  MinIO started - console http://localhost:9001 ) else ( echo [WARN]  MinIO slow to start, continuing )
:after_minio

echo.
rem =================================================================
rem  4) dependencies (install only if missing)
rem =================================================================
if not exist "apps\admin\node_modules" (
  echo [DEPS]  installing admin dependencies...
  pushd apps\admin & call npm install & popd
)
if not exist "apps\client\node_modules" (
  echo [DEPS]  installing client dependencies...
  pushd apps\client & call npm install & popd
)

echo.
rem =================================================================
rem  5) launch services (each in its own window)
rem =================================================================
echo [RUN ]  backend        -^> http://localhost:8080
start "E2EE-IM Backend :8080" cmd /k "cd /d %~dp0apps\server&&go run ./cmd/server"

echo [RUN ]  admin console  -^> http://localhost:5174
start "E2EE-IM Admin :5174" cmd /k "cd /d %~dp0apps\admin&&npm run dev"

set CLIENTMODE=tauri
if /i "%~1"=="-browser"  set CLIENTMODE=browser
if /i "%~1"=="/browser"  set CLIENTMODE=browser
if /i "%~1"=="browser"   set CLIENTMODE=browser
if /i "%~1"=="-noclient" set CLIENTMODE=none
if /i "%~1"=="/noclient" set CLIENTMODE=none

if "%CLIENTMODE%"=="tauri" (
  echo [RUN ]  desktop client  ^(Tauri - first Rust build is slow^)
  start "E2EE-IM Client (Tauri)" cmd /k "cd /d %~dp0apps\client&&echo Building Rust core, please wait for the desktop window...&&npm run tauri dev"
)
if "%CLIENTMODE%"=="browser" (
  echo [RUN ]  client preview  -^> http://localhost:5173  ^(no E2EE chat in browser^)
  start "E2EE-IM Client :5173" cmd /k "cd /d %~dp0apps\client&&npm run dev"
)
if "%CLIENTMODE%"=="none" (
  echo [SKIP]  client not started ^(-noclient^)
)

echo.
echo ================== TEST ACCOUNTS ==================
echo  Admin console  http://localhost:5174
echo      username: admin     password: admin123456
echo.
echo  Users ^(login in the desktop client; password: Pqchat123456^)
echo      alice@pqchat.local    ^(Alice^)
echo      bob@pqchat.local      ^(Bob^)
echo      carol@pqchat.local    ^(Carol^)
echo ==================================================
echo.
echo  Tip: for E2EE chat, open a SECOND client instance and log in as
echo       another user ^(run "npm run tauri dev" again in apps\client^).
echo  Each opened window is one service - close it to stop that service.
echo.
echo  Usage:  start-all.bat             full desktop client
echo          start-all.bat -browser    client in browser ^(no E2EE^)
echo          start-all.bat -noclient   backend + admin only
echo.
pause
exit /b 0
