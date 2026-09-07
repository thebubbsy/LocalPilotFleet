<#
.SYNOPSIS
    One-command launcher for LocalPilot Fleet Command Center.

.DESCRIPTION
    Reads or creates fleet-config.json, generates a secure FleetKey on first run,
    starts the Node.js backend server, then opens the dashboard in the default
    browser. Traps Ctrl+C for graceful shutdown.

.PARAMETER Port
    TCP port the Fleet server will listen on. Defaults to 8443.

.PARAMETER FleetKey
    API authentication key (Bearer token). On first run a cryptographically
    random UUID is generated automatically and saved to fleet-config.json.
    Pass this flag to override the saved key.

.PARAMETER Dashboard
    Path to the dashboard static files directory.
    Defaults to .\dashboard relative to the project root.

.PARAMETER DbPath
    Path to the SQLite database file.
    Defaults to .\server\data\fleet.db relative to the project root.

.PARAMETER NoBrowser
    Switch. If set, the browser will NOT be opened automatically after startup.

.EXAMPLE
    .\Start-LocalPilotFleet.ps1
    .\Start-LocalPilotFleet.ps1 -Port 9443 -NoBrowser
    .\Start-LocalPilotFleet.ps1 -FleetKey 'my-custom-secret-key'
#>

[CmdletBinding()]
param(
    [int]    $Port      = 8443,
    [string] $FleetKey  = '',
    [string] $Dashboard = '',
    [string] $DbPath    = '',
    [switch] $NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Resolve project root (directory containing this script) ──────────────────
$ProjectRoot = $PSScriptRoot
$ConfigFile  = Join-Path $ProjectRoot 'fleet-config.json'

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ''
    Write-Host '  +================================================================+' -ForegroundColor Cyan
    Write-Host '  |        LocalPilot Fleet Command Center                         |' -ForegroundColor Cyan
    Write-Host '  |        Zero-cloud device management for your personal fleet     |' -ForegroundColor Cyan
    Write-Host '  +================================================================+' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Ok   { param([string]$T); Write-Host "  [OK]  $T" -ForegroundColor Green  }
function Write-Warn { param([string]$T); Write-Host "  [!!]  $T" -ForegroundColor Yellow }
function Write-Fail { param([string]$T); Write-Host "  [XX]  $T" -ForegroundColor Red    }
function Write-Info { param([string]$T); Write-Host "  [~]   $T" -ForegroundColor Cyan   }

function New-SecureFleetKey {
    # Generate a cryptographically random UUID-format key using RNGCryptoServiceProvider
    $bytes = [byte[]]::new(16)
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()

    # Force version 4 (random) UUID bits
    $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x40
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80

    $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    return '{0}-{1}-{2}-{3}-{4}' -f `
        $hex.Substring(0,  8),
        $hex.Substring(8,  4),
        $hex.Substring(12, 4),
        $hex.Substring(16, 4),
        $hex.Substring(20, 12)
}

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Banner

# ─── 1. Check Node.js is available ────────────────────────────────────────────
Write-Info 'Checking Node.js...'
try {
    $nodeVersion = & node --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "node --version exited $LASTEXITCODE" }
    Write-Ok "Node.js $nodeVersion"
} catch {
    Write-Fail 'Node.js is not installed or not on PATH.'
    Write-Warn 'Install Node.js 18+ from https://nodejs.org/ then retry.'
    exit 1
}

# Validate version >= 18
$versionNumber = [int]($nodeVersion -replace 'v(\d+)\..*', '$1')
if ($versionNumber -lt 18) {
    Write-Warn "Node.js $nodeVersion detected, but version 18+ is required."
    Write-Warn 'Please upgrade: https://nodejs.org/'
    exit 1
}

# ─── 2. Verify server entrypoint exists ───────────────────────────────────────
$ServerEntry = Join-Path $ProjectRoot 'server\src\index.js'
if (-not (Test-Path $ServerEntry)) {
    Write-Fail "Server entrypoint not found: $ServerEntry"
    Write-Warn 'Ensure the LocalPilot Fleet source files are present.'
    exit 1
}
Write-Ok "Server entrypoint: $ServerEntry"

# ─── 3. Resolve defaults ──────────────────────────────────────────────────────
if ([string]::IsNullOrWhiteSpace($Dashboard)) {
    $Dashboard = Join-Path $ProjectRoot 'dashboard'
}
if ([string]::IsNullOrWhiteSpace($DbPath)) {
    $DbPath = Join-Path $ProjectRoot 'server\data\fleet.db'
}

# Ensure server/data directory exists
$DbDir = Split-Path $DbPath -Parent
if (-not (Test-Path $DbDir)) {
    New-Item -ItemType Directory -Path $DbDir -Force | Out-Null
    Write-Ok "Created database directory: $DbDir"
}

# ─── 4. Read or create fleet-config.json ──────────────────────────────────────
$isFirstRun = $false
$config     = $null

if (Test-Path $ConfigFile) {
    try {
        $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        Write-Ok "Loaded fleet-config.json"
    } catch {
        Write-Warn "fleet-config.json is malformed -- creating a fresh one."
        $config = $null
    }
}

if ($null -eq $config) {
    $isFirstRun = $true
    $config = [PSCustomObject]@{
        fleetKey     = ''
        port         = $Port
        dashboard    = $Dashboard
        dbPath       = $DbPath
        createdAt    = (Get-Date -Format 'o')
        version      = '1.0.0'
    }
}

# ─── 5. Resolve FleetKey ──────────────────────────────────────────────────────
if (-not [string]::IsNullOrWhiteSpace($FleetKey)) {
    # CLI flag overrides saved key
    $config.fleetKey = $FleetKey
} elseif ([string]::IsNullOrWhiteSpace($config.fleetKey)) {
    # No saved key and none supplied -- generate one
    $config.fleetKey = New-SecureFleetKey
    $isFirstRun = $true
}

# Override config with CLI flags if supplied
if ($PSBoundParameters.ContainsKey('Port')) { $config.port = $Port }

# ─── 6. Save config ───────────────────────────────────────────────────────────
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8

# ─── 7. First-run key announcement ───────────────────────────────────────────
if ($isFirstRun) {
    Write-Host ''
    Write-Host '  +============================================================+' -ForegroundColor Yellow
    Write-Host '  |  FIRST RUN -- YOUR FLEET KEY HAS BEEN GENERATED           |' -ForegroundColor Yellow
    Write-Host '  |                                                            |' -ForegroundColor Yellow
    Write-Host "  |  Fleet Key: $($config.fleetKey.PadRight(48))|" -ForegroundColor White
    Write-Host '  |                                                            |' -ForegroundColor Yellow
    Write-Host '  |  Save this key! You need it to enroll managed devices.    |' -ForegroundColor Yellow
    Write-Host '  |  It is also stored in fleet-config.json.                  |' -ForegroundColor Yellow
    Write-Host '  +============================================================+' -ForegroundColor Yellow
    Write-Host ''
    Start-Sleep -Seconds 2
}

# ─── 8. Display startup summary ───────────────────────────────────────────────
$resolvedPort      = $config.port
$resolvedKey       = $config.fleetKey
$resolvedDashboard = $Dashboard
$resolvedDb        = $DbPath

Write-Host ''
Write-Host '  Configuration' -ForegroundColor Gray
Write-Host "    Port      : $resolvedPort"        -ForegroundColor White
Write-Host "    Fleet Key : $resolvedKey"         -ForegroundColor White
Write-Host "    Dashboard : $resolvedDashboard"   -ForegroundColor White
Write-Host "    Database  : $resolvedDb"          -ForegroundColor White
Write-Host ''

# ─── 9. Build node command arguments ──────────────────────────────────────────
$nodeArgs = @(
    $ServerEntry,
    '--port',      $resolvedPort,
    '--fleet-key', $resolvedKey,
    '--dashboard', $resolvedDashboard,
    '--db',        $resolvedDb
)

Write-Info "Starting server: node $($nodeArgs -join ' ')"
Write-Host ''
Write-Host '  Press Ctrl+C to stop the server gracefully.' -ForegroundColor DarkGray
Write-Host ''

# ─── 9b. Check for port collision ─────────────────────────────────────────────
$activeListen = Get-NetTCPConnection -LocalPort $resolvedPort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($activeListen) {
    $proc = Get-Process -Id $activeListen.OwningProcess -ErrorAction SilentlyContinue
    Write-Warn "Port $resolvedPort is currently in use by PID $($activeListen.OwningProcess) ($($proc.ProcessName))."
    if ($proc.ProcessName -eq 'node') {
        Write-Info "Terminating previous orphaned server process (PID $($activeListen.OwningProcess))..."
        Stop-Process -Id $activeListen.OwningProcess -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
    } else {
        Write-Fail "Please stop the conflicting process '$($proc.ProcessName)' or specify a different -Port."
        exit 1
    }
}

# ─── 10. Launch Node.js server process ────────────────────────────────────────
$nodeProc = $null
try {
    $nodeProc = Start-Process `
        -FilePath        'node' `
        -ArgumentList    $nodeArgs `
        -NoNewWindow     `
        -PassThru

    # Give the server a moment to bind the port
    Start-Sleep -Milliseconds 1200

    if ($nodeProc.HasExited) {
        Write-Fail "Node.js process exited immediately (code: $($nodeProc.ExitCode))."
        Write-Warn 'Check for port conflicts or missing dependencies.'
        exit 1
    }

    Write-Ok "Server PID $($nodeProc.Id) is running on port $resolvedPort."

    # ─── 11. Open dashboard in default browser ─────────────────────────────────
    if (-not $NoBrowser) {
        $dashboardUrl = "http://localhost:$resolvedPort"
        Write-Info "Opening dashboard: $dashboardUrl"
        Start-Sleep -Milliseconds 800
        Start-Process $dashboardUrl
    }

    Write-Host ''
    Write-Host "  Dashboard : http://localhost:$resolvedPort"            -ForegroundColor Cyan
    Write-Host "  Health    : http://localhost:$resolvedPort/api/v1/health" -ForegroundColor Cyan
    Write-Host ''

    # ─── 12. Wait for the node process and handle Ctrl+C ─────────────────────
    # Register a Ctrl+C trap for graceful shutdown
    [Console]::TreatControlCAsInput = $false
    $null = Register-EngineEvent -SourceIdentifier 'PowerShell.Exiting' -Action {
        if ($null -ne $nodeProc -and -not $nodeProc.HasExited) {
            Write-Host ''
            Write-Host '  Shutting down LocalPilot Fleet...' -ForegroundColor Yellow
            $nodeProc.Kill($true)   # Kill process tree
        }
    }

    try {
        $nodeProc.WaitForExit()
        $exitCode = $nodeProc.ExitCode
        Write-Host ''
        if ($exitCode -eq 0) {
            Write-Ok "Server exited cleanly (code 0)."
        } else {
            Write-Warn "Server exited with code $exitCode."
        }
    } catch [System.OperationCanceledException] {
        # Ctrl+C caught
    }

} catch {
    Write-Fail "Failed to start Node.js server: $_"
    exit 1
} finally {
    if ($null -ne $nodeProc -and -not $nodeProc.HasExited) {
        Write-Host '  Sending shutdown signal...' -ForegroundColor Yellow
        try { $nodeProc.Kill($true) } catch {}
        $nodeProc.WaitForExit(5000) | Out-Null
    }
    Write-Host ''
    Write-Ok 'LocalPilot Fleet stopped. Goodbye.'
    Write-Host ''
}
