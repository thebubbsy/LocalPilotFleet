<#
.SYNOPSIS
    Installs cloudflared as a persistent Windows Service for LocalPilot Fleet.

.DESCRIPTION
    Copies the Cloudflare Tunnel config.yml to the system-wide config directory,
    runs 'cloudflared service install', starts the service, and reports its status.

    Requires Administrator privileges (the script will self-check and exit if not
    elevated).

.PARAMETER ConfigPath
    Path to the cloudflare/config.yml file to deploy.
    Defaults to the config.yml in the same directory as this script.

.PARAMETER TunnelName
    Name of the Cloudflare Tunnel. Used for display / verification only.
    Defaults to 'localpilot-fleet'.

.EXAMPLE
    # Run from an elevated PowerShell prompt:
    .\cloudflare\Install-CloudflaredService.ps1
    .\cloudflare\Install-CloudflaredService.ps1 -ConfigPath .\cloudflare\config.yml -TunnelName my-fleet
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ConfigPath  = '',
    [string] $TunnelName  = 'localpilot-fleet'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Ok   { param([string]$T); Write-Host "  [OK]  $T" -ForegroundColor Green  }
function Write-Warn { param([string]$T); Write-Host "  [!!]  $T" -ForegroundColor Yellow }
function Write-Fail { param([string]$T); Write-Host "  [XX]  $T" -ForegroundColor Red    }
function Write-Info { param([string]$T); Write-Host "  [~]   $T" -ForegroundColor Cyan   }

# ─── Constants ────────────────────────────────────────────────────────────────
$CLOUDFLARED    = 'C:\Program Files (x86)\cloudflared\cloudflared.exe'
$SERVICE_NAME   = 'cloudflared'
$SYSTEM_CFG_DIR = 'C:\ProgramData\cloudflared'
$SYSTEM_CFG     = Join-Path $SYSTEM_CFG_DIR 'config.yml'
$LOG_DIR        = 'C:\ProgramData\LocalPilotFleet\logs'

# Resolve config path
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot 'config.yml'
}

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  LocalPilot Fleet -- cloudflared Service Installer' -ForegroundColor Cyan
Write-Host '  -------------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

# ─── 1. Elevation check ───────────────────────────────────────────────────────
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Fail 'This script must be run as Administrator.'
    Write-Warn 'Re-launch PowerShell with "Run as administrator" and try again.'
    exit 1
}
Write-Ok 'Running with Administrator privileges.'

# ─── 2. Verify cloudflared exists ─────────────────────────────────────────────
if (-not (Test-Path $CLOUDFLARED)) {
    Write-Fail "cloudflared.exe not found at: $CLOUDFLARED"
    exit 1
}
$cfVersion = & $CLOUDFLARED --version 2>&1 | Select-Object -First 1
Write-Ok "cloudflared: $cfVersion"

# ─── 3. Verify config.yml exists ──────────────────────────────────────────────
if (-not (Test-Path $ConfigPath)) {
    Write-Fail "config.yml not found at: $ConfigPath"
    Write-Warn 'Run Generate-TunnelConfig.ps1 first to create config.yml.'
    exit 1
}

# Basic sanity check: ensure <TUNNEL-ID> placeholder has been replaced
$configContent = Get-Content $ConfigPath -Raw
if ($configContent -match '<TUNNEL-ID>') {
    Write-Fail 'config.yml still contains the <TUNNEL-ID> placeholder.'
    Write-Warn 'Edit config.yml and replace <TUNNEL-ID> with your actual tunnel UUID.'
    exit 1
}
Write-Ok "config.yml verified: $ConfigPath"

# ─── 4. Create log directory ──────────────────────────────────────────────────
if (-not (Test-Path $LOG_DIR)) {
    if ($PSCmdlet.ShouldProcess($LOG_DIR, 'Create log directory')) {
        New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
        Write-Ok "Log directory created: $LOG_DIR"
    }
} else {
    Write-Info "Log directory exists: $LOG_DIR"
}

# ─── 5. Copy config to system-wide location ───────────────────────────────────
if ($PSCmdlet.ShouldProcess($SYSTEM_CFG, 'Copy config.yml to system config dir')) {
    if (-not (Test-Path $SYSTEM_CFG_DIR)) {
        New-Item -ItemType Directory -Path $SYSTEM_CFG_DIR -Force | Out-Null
    }
    Copy-Item -Path $ConfigPath -Destination $SYSTEM_CFG -Force
    Write-Ok "Config deployed to: $SYSTEM_CFG"
}

# ─── 6. Check if service already exists ───────────────────────────────────────
$existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Warn "Service '$SERVICE_NAME' already exists (Status: $($existingService.Status))."
    Write-Info 'Stopping existing service before reinstall...'
    if ($PSCmdlet.ShouldProcess($SERVICE_NAME, 'Stop service')) {
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Write-Info 'Uninstalling existing service...'
    if ($PSCmdlet.ShouldProcess($SERVICE_NAME, 'Uninstall service')) {
        & $CLOUDFLARED service uninstall 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
}

# ─── 7. Install the service ───────────────────────────────────────────────────
Write-Info "Installing cloudflared Windows Service (tunnel: $TunnelName)..."
if ($PSCmdlet.ShouldProcess('cloudflared service', 'Install')) {
    $installOutput = & $CLOUDFLARED --config $SYSTEM_CFG service install 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "cloudflared service install failed (exit $LASTEXITCODE):"
        $installOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        exit 1
    }
    Write-Ok 'cloudflared service installed.'
}

# ─── 8. Start the service ─────────────────────────────────────────────────────
if ($PSCmdlet.ShouldProcess($SERVICE_NAME, 'Start service')) {
    Start-Sleep -Seconds 1
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 3
}

# ─── 9. Report status ─────────────────────────────────────────────────────────
$svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if ($svc) {
    $statusColor = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host ''
    Write-Host "  Service Name  : $($svc.Name)" -ForegroundColor White
    Write-Host "  Display Name  : $($svc.DisplayName)" -ForegroundColor White
    Write-Host "  Status        : " -ForegroundColor White -NoNewline
    Write-Host "$($svc.Status)" -ForegroundColor $statusColor
    Write-Host "  Start Type    : $($svc.StartType)" -ForegroundColor White
    Write-Host ''

    if ($svc.Status -eq 'Running') {
        Write-Ok "cloudflared is running as a Windows Service and will auto-start on boot."
    } else {
        Write-Warn "Service installed but status is '$($svc.Status)'. Check logs at: $LOG_DIR"
    }
} else {
    Write-Fail 'Could not retrieve service status after installation.'
    exit 1
}

Write-Host ''
Write-Info "To stop the service  : Stop-Service -Name $SERVICE_NAME"
Write-Info "To remove the service: & '$CLOUDFLARED' service uninstall"
Write-Info "Log file             : $LOG_DIR\cloudflared.log"
Write-Host ''
Write-Ok 'Install-CloudflaredService.ps1 complete.'
Write-Host ''
