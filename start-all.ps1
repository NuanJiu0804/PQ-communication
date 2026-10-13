# =============================================================================
# 基于后量子混合密码的端到端加密即时通讯系统 —— 一键启动脚本(Windows / PowerShell)
#
# 用法:在仓库根目录右键「使用 PowerShell 运行」,或在 PowerShell 中执行:
#   powershell -ExecutionPolicy Bypass -File .\start-all.ps1
#
# 依次:确保 PostgreSQL / Redis / MinIO 在运行 → 启动后端 → 管理后台 → 桌面客户端。
# 每个服务在独立窗口中运行,关闭对应窗口或按 Ctrl+C 即可停止该服务。
#
# 可选参数:
#   -Browser   客户端以浏览器预览方式启动(npm run dev,无需 Rust;但浏览器下不支持端到端聊天)
#   -NoClient  不启动客户端(只起后端 + 管理后台 + 基础设施)
# =============================================================================
param(
  [switch]$Browser,
  [switch]$NoClient
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $root

# 定位 Go(winget 安装默认不在 PATH)
$go = "C:\Program Files\Go\bin\go.exe"
if (-not (Test-Path $go)) { $go = "go" }

function Test-Port([int]$p) {
  (Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded
}
function New-Window([string]$title, [string]$cmd) {
  Start-Process powershell -ArgumentList '-NoExit', '-Command',
    "`$Host.UI.RawUI.WindowTitle = '$title'; $cmd"
}
function Try-StartService([string]$pattern, [string]$label) {
  try {
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pattern -or $_.DisplayName -match $pattern } | Select-Object -First 1
    if ($svc) {
      if ($svc.Status -ne 'Running') { Start-Service $svc.Name; Start-Sleep -Seconds 2 }
      Write-Host "[启动] $label 服务:$($svc.Name)" -ForegroundColor Green
      return $true
    }
  } catch { }
  return $false
}

Write-Host "======== 基于后量子混合密码的端到端加密即时通讯系统 · 一键启动 ========" -ForegroundColor Cyan

# ---- 1. PostgreSQL ----
if (Test-Port 5432) { Write-Host "[OK]   PostgreSQL :5432 已运行" -ForegroundColor Green }
elseif (-not (Try-StartService 'postgres' 'PostgreSQL')) {
  Write-Host "[警告] PostgreSQL(:5432)未运行,请手动启动后再继续" -ForegroundColor Yellow
}

# ---- 2. Redis ----
if (Test-Port 6379) { Write-Host "[OK]   Redis :6379 已运行" -ForegroundColor Green }
elseif (-not (Try-StartService 'redis|memurai' 'Redis')) {
  Write-Host "[警告] Redis(:6379)未运行,请手动启动后再继续" -ForegroundColor Yellow
}

# ---- 3. MinIO ----
if (Test-Port 9000) {
  Write-Host "[OK]   MinIO :9000 已运行" -ForegroundColor Green
} elseif (Test-Path "C:\minio\minio.exe") {
  New-Window "MinIO" "`$env:MINIO_ROOT_USER='pqchat'; `$env:MINIO_ROOT_PASSWORD='pqchat_dev_password'; & 'C:\minio\minio.exe' server C:\minio\data --console-address ':9001'"
  Write-Host "[启动] MinIO → http://localhost:9001(控制台)" -ForegroundColor Green
  for ($i=0; $i -lt 15; $i++) { Start-Sleep -Milliseconds 600; if (Test-Port 9000) { break } }
} else {
  Write-Host "[警告] 未找到 C:\minio\minio.exe,媒体收发功能将不可用" -ForegroundColor Yellow
}

Start-Sleep -Seconds 1

# ---- 4. 后端 ----
New-Window "后端(:8080)" "Set-Location '$root\apps\server'; Write-Host '正在启动后端...' -ForegroundColor Cyan; & '$go' run ./cmd/server"
Write-Host "[启动] 后端 → http://localhost:8080(健康检查 /healthz)" -ForegroundColor Green

# ---- 5. 管理后台 ----
New-Window "管理后台(:5174)" "Set-Location '$root\apps\admin'; if (-not (Test-Path node_modules)) { npm install }; npm run dev"
Write-Host "[启动] 管理后台 → http://localhost:5174" -ForegroundColor Green

# ---- 6. 客户端 ----
if (-not $NoClient) {
  if ($Browser) {
    New-Window "客户端(浏览器 :5173)" "Set-Location '$root\apps\client'; if (-not (Test-Path node_modules)) { npm install }; npm run dev"
    Write-Host "[启动] 客户端(浏览器预览)→ http://localhost:5173" -ForegroundColor Green
    Write-Host "       注意:浏览器预览不支持端到端聊天,完整体验请用桌面应用(去掉 -Browser)。" -ForegroundColor DarkYellow
  } else {
    New-Window "客户端(Tauri 桌面)" "Set-Location '$root\apps\client'; if (-not (Test-Path node_modules)) { npm install }; Write-Host '首次编译 Rust 核心较慢,请耐心等待桌面窗口弹出...' -ForegroundColor Cyan; npm run tauri dev"
    Write-Host "[启动] 桌面客户端(Tauri,首次编译较慢)" -ForegroundColor Green
  }
}

Write-Host ""
Write-Host "================ 测试账号 ================" -ForegroundColor Cyan
Write-Host "管理后台(http://localhost:5174):" -ForegroundColor White
Write-Host "    用户名 admin    口令 admin123456" -ForegroundColor Gray
Write-Host ""
Write-Host "普通用户(在桌面客户端登录,口令统一 Pqchat123456):" -ForegroundColor White
Write-Host "    alice@pqchat.local    昵称 Alice" -ForegroundColor Gray
Write-Host "    bob@pqchat.local      昵称 Bob" -ForegroundColor Gray
Write-Host "    carol@pqchat.local    昵称 Carol" -ForegroundColor Gray
Write-Host ""
Write-Host "体验端到端聊天:再开一个客户端实例(在 apps\client 下执行 npm run tauri dev)," -ForegroundColor White
Write-Host "两端分别登录不同账号,在「我的 ID」复制对方 ID 后发起会话即可。" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor Cyan
