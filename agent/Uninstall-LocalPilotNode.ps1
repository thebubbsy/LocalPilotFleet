<#
.SYNOPSIS
    LocalPilot Fleet — Node Agent Uninstaller.
    Removes all Scheduled Tasks, agent files, and stored configuration.

.DESCRIPTION
    Cleanly removes the LocalPilot Fleet Node Agent from this machine:
      1. Unregisters all three Scheduled Tasks
      2. Removes C:\ProgramData\LocalPilotFleet\ directory
      3. Optionally calls the server to mark this device as deregistered

    Run as Administrator.

.PARAMETER ServerUrl
    Fleet Command Center URL. If provided with -Deregister, calls DELETE on the device.
    Defaults to value from config.json if available.

.PARAMETER FleetKey
    X-Fleet-Key for deregistration call (only needed with -Deregister).

.PARAMETER Deregister
    If set, notifies the Fleet Command Center to remove this device from the dashboard.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    # Uninstall silently (keep device record on server):
    .\Uninstall-LocalPilotNode.ps1 -Force

.EXAMPLE
    # Uninstall and remove from Fleet dashboard:
    .\Uninstall-LocalPilotNode.ps1 -Deregister -FleetKey "localpilot-secret-key-2026" -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = '',

    [Parameter(Mandatory = $false)]
    [string]$FleetKey = '',

    [switch]$Deregister,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$INSTALL_DIR    = 'C:\ProgramData\LocalPilotFleet'
$CONFIG_FILE    = "$INSTALL_DIR\config.json"
$TASK_NAMES     = @('LocalPilot-Heartbeat', 'LocalPilot-Telemetry', 'LocalPilot-Watchdog')
$AGENT_VERSION  = '1.0.0'

function Write-Step  { param([string]$S, [string]$M); Write-Host "[$S] $M" -ForegroundColor Cyan }
function Write-OK    { param([string]$M); Write-Host "  ✓ $M" -ForegroundColor Green }
function Write-Warn  { param([string]$M); Write-Host "  ! $M" -ForegroundColor Yellow }
function Write-Fail  { param([string]$M); Write-Host "  ✗ $M" -ForegroundColor Red }

# ─── Elevation check ─────────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail 'This script must be run as Administrator.'
    exit 1
}

# ─── Load config (best-effort) ────────────────────────────────────────────────
$config = $null
$deviceId = $null
if (Test-Path $CONFIG_FILE) {
    try {
        $config   = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
        $deviceId = $config.device_id
        if (-not $ServerUrl -and $config.server_url) { $ServerUrl = $config.server_url }
    } catch {
        Write-Warn "Could not read config.json: $($_.Exception.Message)"
    }
}

# ─── Confirmation prompt ──────────────────────────────────────────────────────
if (-not $Force) {
    Write-Host ''
    Write-Host '  LocalPilot Fleet Node Agent Uninstaller' -ForegroundColor Red
    Write-Host "  This will remove all agent files and Scheduled Tasks from $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host ''
    $confirm = Read-Host '  Type "REMOVE" to confirm uninstallation'
    if ($confirm -ne 'REMOVE') {
        Write-Host '  Uninstallation cancelled.' -ForegroundColor Gray
        exit 0
    }
}

Write-Host ''
Write-Step '1/4' 'Unregistering Scheduled Tasks...'

foreach ($taskName in $TASK_NAMES) {
    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            # Stop the task if running
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-OK "Removed Scheduled Task: $taskName"
        } else {
            Write-Warn "Scheduled Task not found (already removed?): $taskName"
        }
    } catch {
        Write-Fail "Failed to remove task '$taskName': $($_.Exception.Message)"
    }
}

# ─── Optional: Deregister from Fleet Command Center ──────────────────────────
Write-Step '2/4' 'Server deregistration...'

if ($Deregister -and $deviceId) {
    if (-not $ServerUrl) {
        Write-Warn 'Cannot deregister: no ServerUrl provided or found in config.json.'
    } else {
        $deregHeaders = @{ 'Content-Type' = 'application/json' }
        if ($FleetKey) {
            $deregHeaders['X-Fleet-Key'] = $FleetKey
        } elseif ($config -and $config.node_token) {
            $deregHeaders['Authorization'] = "Bearer $($config.node_token)"
        }

        try {
            $deregResp = Invoke-RestMethod `
                -Uri        "$ServerUrl/api/v1/fleet/devices/$deviceId" `
                -Method     DELETE `
                -Headers    $deregHeaders `
                -TimeoutSec 10 `
                -ErrorAction Stop

            Write-OK "Device $deviceId deregistered from Fleet Command Center"
            Write-OK "Server response: $($deregResp.message)"
        } catch {
            Write-Warn "Deregistration request failed: $($_.Exception.Message)"
            Write-Warn "The device record may remain on the server — remove it manually from the dashboard."
        }
    }
} elseif ($Deregister -and -not $deviceId) {
    Write-Warn 'Cannot deregister: device_id not found in config.json.'
} else {
    Write-Warn 'Skipping server deregistration (-Deregister not specified).'
    Write-Warn 'The device record will remain on the Fleet dashboard — remove it manually if desired.'
}

# ─── Remove install directory ─────────────────────────────────────────────────
Write-Step '3/4' "Removing install directory: $INSTALL_DIR..."

if (Test-Path $INSTALL_DIR) {
    try {
        Remove-Item -Path $INSTALL_DIR -Recurse -Force -ErrorAction Stop
        Write-OK "Removed: $INSTALL_DIR"
    } catch {
        Write-Fail "Failed to remove install directory: $($_.Exception.Message)"
        Write-Warn "You may need to manually delete: $INSTALL_DIR"
    }
} else {
    Write-Warn "Install directory not found (already removed?): $INSTALL_DIR"
}

# ─── Final confirmation ───────────────────────────────────────────────────────
Write-Step '4/4' 'Cleanup verification...'

$remainingTasks = $TASK_NAMES | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue }
if ($remainingTasks) {
    Write-Warn "The following tasks could not be removed: $($remainingTasks -join ', ')"
} else {
    Write-OK 'All Scheduled Tasks removed'
}

if (Test-Path $INSTALL_DIR) {
    Write-Warn "Install directory still exists: $INSTALL_DIR"
} else {
    Write-OK 'Install directory removed'
}

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Magenta
Write-Host '  LocalPilot Fleet Node Agent — Uninstallation Complete' -ForegroundColor Green
Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Magenta
Write-Host ''
Write-Host "  Device     : $env:COMPUTERNAME" -ForegroundColor White
if ($deviceId) { Write-Host "  Device ID  : $deviceId" -ForegroundColor White }
Write-Host "  Deregistered: $Deregister" -ForegroundColor White
Write-Host ''
Write-Host '  All agent components have been removed from this machine.' -ForegroundColor Gray
if (-not $Deregister) {
    Write-Host "  The device record still exists on the Fleet dashboard — remove it at:" -ForegroundColor Yellow
    if ($ServerUrl) { Write-Host "    $ServerUrl" -ForegroundColor Yellow }
}
Write-Host ''
