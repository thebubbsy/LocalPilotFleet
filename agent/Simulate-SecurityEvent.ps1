<#
.SYNOPSIS
    LocalPilot Fleet — Development Test Harness for Security Events.
    Simulates security events without requiring Administrator rights or real Windows events.

.DESCRIPTION
    Posts synthetic, realistic security events directly to the Fleet Command Center's
    POST /api/v1/nodes/events endpoint. Useful for:
      - Testing the alert pipeline (Toast, Discord, Slack, Telegram webhooks)
      - Verifying Server-Sent Events stream on the dashboard
      - CI/CD smoke testing without modifying the real OS state

    All simulated events are clearly marked in their details payload with
    'simulated: true' so they can be identified in the audit log.

.PARAMETER EventType
    The event type to simulate:
      UserCreated          — New local user account creation (Event 4720, HIGH)
      UserDeleted          — Local user account deletion (Event 4726, MEDIUM)
      PrivilegeEscalation  — User added to Administrators group (Event 4732, CRITICAL)
      SoftwareInstalled    — MSI application installed (Event 1033, MEDIUM)
      AppProhibited        — Prohibited application detected (APP_PROHIBITED_DETECTED, CRITICAL)

.PARAMETER ServerUrl
    Fleet Command Center URL. Defaults to 'http://localhost:8443'.

.PARAMETER FleetKey
    X-Fleet-Key for authentication (used if Token not provided and DeviceId not set).

.PARAMETER DeviceId
    Device UUID to post the event as. If not provided, reads from config.json.

.PARAMETER Token
    Node Bearer token. If not provided, reads from config.json.

.PARAMETER Username
    Simulated username for user-related events. Defaults to 'simulated_user'.

.PARAMETER AppName
    Simulated application name for software events. Defaults to 'SimTest 1.0'.

.PARAMETER DryRun
    If set, prints the payload to console without sending it to the server.

.EXAMPLE
    # Simulate a new user creation:
    .\Simulate-SecurityEvent.ps1 -EventType UserCreated -ServerUrl "http://localhost:8443"

.EXAMPLE
    # Simulate privilege escalation with a specific token:
    .\Simulate-SecurityEvent.ps1 -EventType PrivilegeEscalation -DeviceId "abc-123" -Token "lp_node_..."

.EXAMPLE
    # Dry-run to inspect payload without sending:
    .\Simulate-SecurityEvent.ps1 -EventType SoftwareInstalled -DryRun
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('UserCreated', 'UserDeleted', 'PrivilegeEscalation', 'SoftwareInstalled', 'AppProhibited')]
    [string]$EventType,

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'http://localhost:8443',

    [Parameter(Mandatory = $false)]
    [string]$FleetKey = '',

    [Parameter(Mandatory = $false)]
    [string]$DeviceId = '',

    [Parameter(Mandatory = $false)]
    [string]$Token = '',

    [Parameter(Mandatory = $false)]
    [string]$Username = 'simulated_user',

    [Parameter(Mandatory = $false)]
    [string]$AppName = 'SimTest 1.0',

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Load config if DeviceId/Token not provided ────────────────────────────
$CONFIG_FILE = 'C:\ProgramData\LocalPilotFleet\config.json'

if ((-not $DeviceId -or -not $Token) -and (Test-Path $CONFIG_FILE)) {
    try {
        $config = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
        if (-not $DeviceId) { $DeviceId = $config.device_id }
        if (-not $Token)    { $Token    = $config.node_token }
        if ($ServerUrl -eq 'http://localhost:8443' -and $config.server_url) {
            $ServerUrl = $config.server_url
        }
        Write-Host "  [Config] Loaded config.json — Device: $DeviceId" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not load config.json: $($_.Exception.Message)"
    }
}

if (-not $DeviceId) {
    Write-Error "No DeviceId provided and config.json not found. Pass -DeviceId <uuid> or enroll this node first."
    exit 1
}

if (-not $Token -and -not $FleetKey) {
    Write-Error "No authentication available. Provide -Token <bearer> or -FleetKey <key>."
    exit 1
}

# ─── Build authentication headers ────────────────────────────────────────────
$headers = @{ 'Content-Type' = 'application/json' }
if ($Token) {
    $headers['Authorization'] = "Bearer $Token"
} elseif ($FleetKey) {
    $headers['X-Fleet-Key'] = $FleetKey
}

# ─── Simulated event payload factory ─────────────────────────────────────────
$now = Get-Date
$hostname = $env:COMPUTERNAME
$simulatorVersion = '1.0.0'

$payload = switch ($EventType) {
    'UserCreated' {
        @{
            event_type   = 'USER_CREATED'
            event_id     = 4720
            event_source = 'Security'
            severity     = 'HIGH'
            summary      = "[SIMULATED] New local user account '$Username' created on $hostname"
            timestamp    = $now.ToString('o')
            details      = @{
                TargetUserName   = $Username
                TargetDomain     = $hostname
                SubjectUserName  = $env:USERNAME
                SubjectUserSid   = 'S-1-5-21-SIMULATED-1001'
                PrivilegeList    = '-'
                Hostname         = $hostname
                WindowsEventId   = 4720
                simulated        = $true
                simulator_version = $simulatorVersion
            }
        }
    }
    'UserDeleted' {
        @{
            event_type   = 'USER_DELETED'
            event_id     = 4726
            event_source = 'Security'
            severity     = 'MEDIUM'
            summary      = "[SIMULATED] Local user account '$Username' deleted on $hostname"
            timestamp    = $now.ToString('o')
            details      = @{
                TargetUserName   = $Username
                TargetDomain     = $hostname
                SubjectUserName  = $env:USERNAME
                SubjectUserSid   = 'S-1-5-21-SIMULATED-1001'
                Hostname         = $hostname
                WindowsEventId   = 4726
                simulated        = $true
                simulator_version = $simulatorVersion
            }
        }
    }
    'PrivilegeEscalation' {
        @{
            event_type   = 'ADMIN_ADDED'
            event_id     = 4732
            event_source = 'Security'
            severity     = 'CRITICAL'
            summary      = "[SIMULATED] Privilege escalation: '$Username' added to local Administrators group on $hostname"
            timestamp    = $now.ToString('o')
            details      = @{
                MemberName       = $Username
                MemberSid        = 'S-1-5-21-SIMULATED-2002'
                GroupName        = 'Administrators'
                SubjectUserName  = $env:USERNAME
                SubjectUserSid   = 'S-1-5-21-SIMULATED-1001'
                Hostname         = $hostname
                WindowsEventId   = 4732
                simulated        = $true
                simulator_version = $simulatorVersion
            }
        }
    }
    'SoftwareInstalled' {
        @{
            event_type   = 'APP_INSTALLED'
            event_id     = 1033
            event_source = 'MsiInstaller'
            severity     = 'MEDIUM'
            summary      = "[SIMULATED] Application installed via MSI: '$AppName' on $hostname"
            timestamp    = $now.ToString('o')
            details      = @{
                ProductName      = $AppName
                ProductVersion   = '1.0.0.0'
                Publisher        = 'LocalPilot Simulator Corp.'
                InstallType      = 'MSI'
                Hostname         = $hostname
                WindowsEventId   = 1033
                simulated        = $true
                simulator_version = $simulatorVersion
            }
        }
    }
    'AppProhibited' {
        @{
            event_type   = 'APP_PROHIBITED_DETECTED'
            event_id     = 1033
            event_source = 'LocalPilotWatchdog'
            severity     = 'CRITICAL'
            summary      = "[SIMULATED] Prohibited application '$AppName' detected on $hostname — policy enforcement triggered"
            timestamp    = $now.ToString('o')
            details      = @{
                ProductName      = $AppName
                WingetId         = 'SimulatedPublisher.SimulatedApp'
                PolicyRule       = 'Prohibited'
                Action           = 'uninstall_and_alert'
                Hostname         = $hostname
                DeviceId         = $DeviceId
                simulated        = $true
                simulator_version = $simulatorVersion
            }
        }
    }
}

# ─── Display payload ──────────────────────────────────────────────────────────
Write-Host ''
Write-Host '═══════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '  LocalPilot Fleet — Security Event Simulator' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host "  EventType  : $EventType → $($payload.event_type)" -ForegroundColor White
Write-Host "  Severity   : $($payload.severity)" -ForegroundColor $(
    switch ($payload.severity) {
        'CRITICAL' { 'Red' }
        'HIGH'     { 'DarkRed' }
        'MEDIUM'   { 'Yellow' }
        default    { 'Gray' }
    }
)
Write-Host "  Summary    : $($payload.summary)" -ForegroundColor White
Write-Host "  Target URL : $ServerUrl/api/v1/nodes/events" -ForegroundColor DarkGray
Write-Host "  Device ID  : $DeviceId" -ForegroundColor DarkGray
Write-Host ''

$payloadJson = $payload | ConvertTo-Json -Depth 5

if ($DryRun) {
    Write-Host '  [DRY RUN] Payload (not sent):' -ForegroundColor Yellow
    Write-Host $payloadJson -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  [DRY RUN] No request sent.' -ForegroundColor Yellow
    exit 0
}

# ─── Send to server ───────────────────────────────────────────────────────────
Write-Host '  Sending event...' -ForegroundColor DarkGray

try {
    $startTime = Get-Date
    $resp = Invoke-RestMethod `
        -Uri        "$ServerUrl/api/v1/nodes/events" `
        -Method     POST `
        -Body       $payloadJson `
        -Headers    $headers `
        -TimeoutSec 15 `
        -ErrorAction Stop
    $elapsed = [int]((Get-Date) - $startTime).TotalMilliseconds

    Write-Host ''
    Write-Host '  ✓ Event dispatched successfully!' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Server Response:' -ForegroundColor Cyan
    Write-Host "    Status         : $($resp.status)" -ForegroundColor White
    Write-Host "    Event Record ID: $($resp.event_record_id)" -ForegroundColor White
    Write-Host "    Toast Fired    : $($resp.toast_fired)" -ForegroundColor White
    Write-Host "    Webhooks       : $($resp.webhooks_dispatched -join ', ')" -ForegroundColor White
    Write-Host "    Round-trip     : ${elapsed}ms" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Check the Fleet dashboard for the live event.' -ForegroundColor Cyan
    Write-Host ''

    exit 0
} catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }

    Write-Host ''
    Write-Host '  ✗ Event dispatch failed!' -ForegroundColor Red
    Write-Host "    HTTP Status  : $($statusCode ?? 'N/A')" -ForegroundColor Red
    Write-Host "    Error        : $($_.Exception.Message)" -ForegroundColor Red

    # Try to extract and print the response body for context
    try {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $body   = $reader.ReadToEnd()
        Write-Host "    Response Body: $body" -ForegroundColor DarkRed
    } catch { }

    Write-Host ''
    exit 1
}
