#Requires -RunAsAdministrator
# SentinelCore Agent — Windows Service Installer (PowerShell)
# Run: powershell -ExecutionPolicy Bypass -File install-service.ps1
#
# Parameters:
#   -ApiUrl        SentinelCore API base URL  (default: http://localhost:8000)
#   -ApiKey        API key for authentication (default: empty — local logging only)
#   -AutoQuarantine  Auto-quarantine confirmed threats (default: false)
#   -InstallDir    Installation directory     (default: C:\Program Files\SentinelCore)

param(
    [string]$ApiUrl        = "http://localhost:8000",
    [string]$ApiKey        = "",
    [switch]$AutoQuarantine,
    [string]$InstallDir    = "$env:ProgramFiles\SentinelCore"
)

$ServiceName   = "SentinelCoreAgent"
$DisplayName   = "SentinelCore Agent"
$Description   = "SentinelCore real-time malware detection — filesystem, process, FIM, and network monitoring."
$BinaryName    = "sentinel-agent.exe"
$BinaryPath    = Join-Path $InstallDir $BinaryName

Write-Host "=== SentinelCore Agent Installer ===" -ForegroundColor Cyan
Write-Host "Install dir : $InstallDir"
Write-Host "API URL     : $ApiUrl"
Write-Host "API Key     : $(if ($ApiKey) { '***' } else { '(none — local logging)' })"
Write-Host "Auto-Q      : $($AutoQuarantine.IsPresent)"
Write-Host ""

# ── Stop + remove existing service ────────────────────────────────────────────
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# ── Copy binary ───────────────────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceBin = Join-Path $scriptDir $BinaryName

if (-not (Test-Path $sourceBin)) {
    # Try two levels up (running from repo root)
    $sourceBin = Join-Path $scriptDir "..\..\target\x86_64-pc-windows-msvc\release\$BinaryName"
}

if (-not (Test-Path $sourceBin)) {
    Write-Error "$BinaryName not found. Place it next to this script or build first:`n  cargo build --release --target x86_64-pc-windows-msvc"
    exit 1
}

Write-Host "Copying $BinaryName to $InstallDir..." -ForegroundColor Green
Copy-Item $sourceBin $BinaryPath -Force

# ── Write env config ──────────────────────────────────────────────────────────
$envContent = @"
SENTINEL_API_URL=$ApiUrl
SENTINEL_API_KEY=$ApiKey
RUST_LOG=info
"@
Set-Content -Path (Join-Path $InstallDir "agent.env") -Value $envContent

# ── Build service binary path ─────────────────────────────────────────────────
$args = "run --api-url `"$ApiUrl`""
if ($ApiKey)              { $args += " --api-key `"$ApiKey`"" }
if ($AutoQuarantine)      { $args += " --auto-quarantine" }

$binPathWithArgs = "`"$BinaryPath`" $args"

# ── Create Windows service ────────────────────────────────────────────────────
Write-Host "Creating Windows service '$ServiceName'..." -ForegroundColor Green
New-Service -Name $ServiceName `
            -DisplayName $DisplayName `
            -Description $Description `
            -BinaryPathName $binPathWithArgs `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null

# Set recovery — restart on failure (5s, 10s, 30s)
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# ── Start service ─────────────────────────────────────────────────────────────
Write-Host "Starting service..." -ForegroundColor Green
Start-Service -Name $ServiceName

$status = (Get-Service -Name $ServiceName).Status
Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Cyan
Write-Host "Service status : $status"
Write-Host ""
Write-Host "Commands:"
Write-Host "  Get-Service $ServiceName          # Check status"
Write-Host "  Stop-Service $ServiceName         # Stop agent"
Write-Host "  Start-Service $ServiceName        # Start agent"
Write-Host "  sc.exe delete $ServiceName        # Uninstall"
Write-Host ""
Write-Host "Logs: Event Viewer → Applications and Services → SentinelCore"
