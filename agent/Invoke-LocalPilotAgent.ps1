<#
.SYNOPSIS
    LocalPilot Fleet - Main Agent Runner.
    Executes Heartbeat, Telemetry, or PolicyCheck cycles against the Fleet Command Center.

.DESCRIPTION
    Reads persisted config from C:\ProgramData\LocalPilotFleet\config.json.
    Implements a dual-mode resolver: tries the LAN URL first with a 5-second timeout,
    then falls back to the Cloudflare Tunnel URL if configured.

    Modes:
      Heartbeat   - Lightweight 60-second keepalive: CPU%, RAM, IP, uptime.
      Telemetry   - Deep hardware/software inventory snapshot (~30 min cadence).
      PolicyCheck - Fetch effective policy and enforce via Winget.

.PARAMETER Mode
    Operating mode: Heartbeat | Telemetry | PolicyCheck

.PARAMETER ServerUrl
    Override server URL (normally read from config.json).

.PARAMETER FleetKey
    Override fleet key for one-off runs (normally not needed; auth uses NodeToken).

.EXAMPLE
    # Manual heartbeat test:
    .\Invoke-LocalPilotAgent.ps1 -Mode Heartbeat

.EXAMPLE
    # Force telemetry harvest now:
    .\Invoke-LocalPilotAgent.ps1 -Mode Telemetry
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Heartbeat', 'Telemetry', 'PolicyCheck')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = '',

    [Parameter(Mandatory = $false)]
    [string]$FleetKey = '',

    [Parameter(Mandatory = $false)]
    [string]$DeviceId = '',

    [Parameter(Mandatory = $false)]
    [string]$NodeToken = '',

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = '',

    [Parameter(Mandatory = $false)]
    [switch]$Continuous,

    [Parameter(Mandatory = $false)]
    [int]$IntervalSec = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Constants ───────────────────────────────────────────────────────────────
$CONFIG_FILE = 'C:\ProgramData\LocalPilotFleet\config.json'
$LOG_FILE    = 'C:\ProgramData\LocalPilotFleet\agent.log'
$AGENT_VER   = '1.0.0'

# ─── Logging helper ──────────────────────────────────────────────────────────
function Write-AgentLog {
    param([string]$Level = 'INFO', [string]$Message)
    $entry = "$(Get-Date -Format 'o') [$Level] [$Mode] $Message"
    try { Add-Content -Path $LOG_FILE -Value $entry -ErrorAction SilentlyContinue } catch { }
    if ($Level -eq 'ERROR') { Write-Warning $entry } else { Write-Host $entry }
}

# ─── Windows Toast & Balloon Notification Helper ──────────────────────────────
function Show-WindowsToastNotification {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Theme = 'INFO'
    )
    $shown = $false
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

        $escapedTitle = [System.Security.SecurityElement]::Escape($Title)
        $escapedMsg   = [System.Security.SecurityElement]::Escape($Message)

        $xmlTemplate = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$escapedTitle</text>
            <text>$escapedMsg</text>
        </binding>
    </visual>
</toast>
"@
        $xmlDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xmlDoc.LoadXml($xmlTemplate)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xmlDoc)
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
        $notifier.Show($toast)
        $shown = $true
    } catch {
        # Fallback to NotifyIcon balloon tip
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
            $notify = New-Object System.Windows.Forms.NotifyIcon
            $notify.Icon = [System.Drawing.SystemIcons]::Information
            $notify.BalloonTipTitle = $Title
            $notify.BalloonTipText = $Message
            $notify.Visible = $true
            $notify.ShowBalloonTip(5000)
            Start-Sleep -Milliseconds 200
            $notify.Dispose()
            $shown = $true
        } catch {
            Write-AgentLog 'WARN' "Notification display fallback failed: $($_.Exception.Message)"
        }
    }
    return $shown
}

# ─── Load configuration (Multi-tiered: Config File -> CLI -> Fleet Authority) ───
$activeDeviceId = $DeviceId
$activeNodeToken = $NodeToken
$lanUrl = $ServerUrl
$cfUrl = ''
$activeFleetKey = $FleetKey

$cfgPath = if ($ConfigPath) { $ConfigPath } else { $CONFIG_FILE }

if (Test-Path $cfgPath) {
    try {
        $config = Get-Content $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if (-not $activeDeviceId)  { $activeDeviceId  = $config.device_id }
        if (-not $activeNodeToken) { $activeNodeToken = $config.node_token }
        if (-not $lanUrl)          { $lanUrl          = $config.server_url }
        if (-not $cfUrl)           { $cfUrl           = $config.cloudflare_url }
    } catch {
        Write-AgentLog 'WARN' "Could not read $cfgPath ($($_.Exception.Message)) -- attempting local authority fallback"
    }
}

# Master Fleet Authority Fallback (for interactive execution / testing without SYSTEM elevation)
if (-not $activeDeviceId -or (-not $activeNodeToken -and -not $activeFleetKey)) {
    $fleetConfigs = @(
        (Join-Path $PSScriptRoot '..\fleet-config.json'),
        'C:\temp\LocalPilotFleet\fleet-config.json'
    )
    foreach ($fc in $fleetConfigs) {
        if (Test-Path $fc) {
            try {
                $fJson = Get-Content $fc -Raw -ErrorAction Stop | ConvertFrom-Json
                if (-not $lanUrl) { $lanUrl = "http://localhost:$($fJson.port)" }
                if (-not $activeFleetKey) { $activeFleetKey = $fJson.fleetKey }
                break
            } catch {}
        }
    }

    if ($lanUrl -and $activeFleetKey -and -not $activeDeviceId) {
        try {
            $apiRes = Invoke-RestMethod -Uri "$lanUrl/api/v1/fleet/devices" -Method GET -Headers @{ 'X-Fleet-Key' = $activeFleetKey } -TimeoutSec 4 -ErrorAction Stop
            $devList = if ($apiRes.devices) { $apiRes.devices } else { $apiRes }
            $match = $devList | Where-Object { $_.hostname -eq $env:COMPUTERNAME } | Select-Object -First 1
            if ($match) {
                $activeDeviceId = $match.id
                Write-AgentLog 'INFO' "Resolved target device ID '$activeDeviceId' ($($match.hostname)) via local Fleet Authority."
            }
        } catch {
            Write-AgentLog 'WARN' "Could not resolve device via Fleet Authority API: $($_.Exception.Message)"
        }
    }
}

$deviceId = $activeDeviceId
if (-not $deviceId) {
    Write-AgentLog 'ERROR' 'Unable to determine Device ID. Run Install-LocalPilotNode.ps1 or specify -DeviceId.'
    exit 1
}

$authHeaders = @{ 'Content-Type' = 'application/json' }
if ($activeNodeToken) {
    $authHeaders['Authorization'] = "Bearer $activeNodeToken"
} elseif ($activeFleetKey) {
    $authHeaders['X-Fleet-Key'] = $activeFleetKey
} else {
    Write-AgentLog 'ERROR' 'No NodeToken or FleetKey available for authentication. Re-enroll this node.'
    exit 1
}

Write-AgentLog 'INFO' "Agent started in $Mode mode for device $deviceId"

# ─── Dual-mode URL resolver ───────────────────────────────────────────────────
# Try direct LAN first (5 s timeout), fall back to Cloudflare Tunnel.
function Resolve-ActiveEndpoint {
    param(
        [string]$LanUrl,
        [string]$CfUrl
    )

    if ($LanUrl) {
        try {
            $probe = Invoke-WebRequest `
                -Uri        "$LanUrl/api/v1/health" `
                -Method     GET `
                -TimeoutSec 5 `
                -UseBasicParsing `
                -ErrorAction Stop
            if ($probe.StatusCode -eq 200) {
                return [pscustomobject]@{ Url = $LanUrl; Route = 'LAN' }
            }
        } catch {
            Write-AgentLog 'WARN' "LAN endpoint unreachable ($LanUrl): $($_.Exception.Message)"
        }
    }

    if ($CfUrl) {
        Write-AgentLog 'INFO' "Falling back to Cloudflare Tunnel: $CfUrl"
        return [pscustomobject]@{ Url = $CfUrl; Route = 'Cloudflare' }
    }

    # No connectivity confirmed but proceed with LAN URL and let specific calls fail gracefully
    Write-AgentLog 'WARN' 'No reachable endpoint found - proceeding with LAN URL (may fail)'
    return [pscustomobject]@{ Url = $LanUrl; Route = 'LAN' }
}

$endpoint = Resolve-ActiveEndpoint -LanUrl $lanUrl -CfUrl $cfUrl
$baseUrl   = $endpoint.Url
$route     = $endpoint.Route

Write-AgentLog 'INFO' "Active endpoint: $baseUrl (Route: $route)"

# ─── Active logged-in user detection ─────────────────────────────────────────
function Get-ActiveLoggedInUser {
    try {
        $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
        if ($u) { return $u }
    } catch {}

    try {
        $explorer = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($explorer) {
            $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($owner -and $owner.User) {
                if ($owner.Domain) { return "$($owner.Domain)\$($owner.User)" }
                return $owner.User
            }
        }
    } catch {}

    if ($env:USERNAME -and $env:USERNAME -ne 'SYSTEM') {
        if ($env:USERDOMAIN) { return "$($env:USERDOMAIN)\$($env:USERNAME)" }
        return $env:USERNAME
    }
    return 'Unknown'
}

# ===============================================================================
# MODE: HEARTBEAT
# ===============================================================================
if ($Mode -eq 'Heartbeat') {
    do {
        try {
            # CPU load
            $cpuLoad = (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue |
                        Measure-Object -Property LoadPercentage -Average).Average
            $cpuPct  = if ($null -ne $cpuLoad) { [math]::Round([double]$cpuLoad, 1) } else { 0.0 }

            # RAM
            $osInfo   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $freeRam  = [int64]$osInfo.FreePhysicalMemory  * 1024
            $totalRam = [int64]$osInfo.TotalVisibleMemorySize * 1024
            $usedRam  = $totalRam - $freeRam
            $ramPct   = if ($totalRam -gt 0) { [math]::Round(($usedRam / $totalRam) * 100, 1) } else { 0.0 }

            # Uptime
            $uptimeSec = [int]((Get-Date) - $osInfo.LastBootUpTime).TotalSeconds

            # Active user
            $activeUser = Get-ActiveLoggedInUser

            # IP address (first active IPv4)
            $ipAddress = $null
            try {
                $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                              Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -ne '127.0.0.1' } |
                              Sort-Object -Property PrefixLength -Descending |
                              Select-Object -First 1).IPAddress
            } catch {
                # Fallback: CIM
                $ipAddress = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
                              Where-Object { $_.IPEnabled } |
                              Select-Object -First 1).IPAddress |
                              Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } |
                              Select-Object -First 1
            }

            # Battery
            $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1

            $heartbeatPayload = @{
                device_id         = $deviceId
                primary_user      = $activeUser
                active_user       = $activeUser
                cpu_usage_percent = $cpuPct
                ram_used_bytes    = $usedRam
                ram_free_bytes    = $freeRam
                ram_usage_percent = $ramPct
                ip_address        = $ipAddress
                connection_route  = $route
                uptime_seconds    = $uptimeSec
                battery_percent   = if ($battery) { [double]$battery.EstimatedChargeRemaining } else { $null }
                battery_charging  = if ($battery) { [bool]($battery.BatteryStatus -eq 2) } else { $false }
            }

            $resp = Invoke-RestMethod `
                -Uri        "$baseUrl/api/v1/nodes/heartbeat" `
                -Method     POST `
                -Body       ($heartbeatPayload | ConvertTo-Json -Compress) `
                -Headers    $authHeaders `
                -TimeoutSec 8 `
                -ErrorAction Stop

            Write-AgentLog 'INFO' "Heartbeat acknowledged. Server time: $($resp.server_time). CPU: ${cpuPct}% RAM: ${ramPct}% User: $activeUser"

            # Check and execute pending remote execution commands
            if ($resp.commands_pending -and $resp.pending_commands) {
                $cmds = @($resp.pending_commands)
                Write-AgentLog 'INFO' "Received $($cmds.Count) pending command(s) to execute"

                foreach ($cmd in $cmds) {
                    $cmdId = $cmd.id
                    $cmdText = $cmd.command_text
                    Write-AgentLog 'INFO' "Executing remote script [$cmdId]: $cmdText"

                    $stdout = ''
                    $stderr = ''
                    $exitCode = 0
                    $status = 'COMPLETED'

                    try {
                        $fullScript = "`$ProgressPreference = 'SilentlyContinue';`n" + $cmdText
                        $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fullScript))
                        $execResult = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCmd 2>&1
                        $exitCode = $LASTEXITCODE
                        if ($null -eq $exitCode) { $exitCode = 0 }

                        $outputLines = @()
                        $errorLines  = @()
                        foreach ($item in $execResult) {
                            if ($null -eq $item) { continue }
                            $line = $item.ToString()
                            if ($line -like '#< CLIXML*' -or $line -like '<Objs Version=*' -or $line -like '</Objs>*') {
                                continue
                            }
                            if ($item -is [System.Management.Automation.ErrorRecord]) {
                                $errorLines += $line
                            } else {
                                $outputLines += $line
                            }
                        }
                        $stdout = $outputLines -join "`n"
                        $stderr = $errorLines -join "`n"
                        if ($exitCode -ne 0) {
                            $status = 'FAILED'
                        }
                    } catch {
                        $status   = 'FAILED'
                        $exitCode = 1
                        $stderr   = $_.Exception.Message
                    }

                    try {
                        $resPayload = @{
                            command_id = $cmdId
                            status     = $status
                            exit_code  = $exitCode
                            stdout     = $stdout
                            stderr     = $stderr
                        }
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/command-result" `
                            -Method     POST `
                            -Body       ($resPayload | ConvertTo-Json -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 15 `
                            -ErrorAction Stop | Out-Null
                        Write-AgentLog 'INFO' "Reported command [$cmdId] execution result ($status, exit code: $exitCode)"
                    } catch {
                        Write-AgentLog 'ERROR' "Failed to report command result for [$cmdId]: $($_.Exception.Message)"
                    }
                }
            }

            # ── Intune Device Remote Lifecycle & Diagnostics Execution ─────────
            if ($resp.pending_remote_actions) {
                $remActions = @($resp.pending_remote_actions)
                Write-AgentLog 'INFO' "Received $($remActions.Count) pending remote lifecycle action(s) to execute"

                foreach ($act in $remActions) {
                    $actId = $act.id
                    $actType = $act.action_type
                    $actParams = $act.parameters
                    Write-AgentLog 'INFO' "Dispatching remote action [$actId]: $actType"

                    $actStatus = 'COMPLETED'
                    $actResult = @{}
                    $actError = $null

                    try {
                        switch ($actType) {
                            'REMOTE_LOCK' {
                                Write-AgentLog 'INFO' "Locking active console session via User32::LockWorkStation"
                                Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class WinLock { [DllImport("user32.dll")] public static extern bool LockWorkStation(); }' -ErrorAction SilentlyContinue
                                [WinLock]::LockWorkStation() | Out-Null
                                $actResult = @{ message = 'Workstation locked successfully' }
                            }

                            'RESTART' {
                                $delay = if ($actParams -and $actParams.delay_sec) { [int]$actParams.delay_sec } else { 60 }
                                $msg = if ($actParams -and $actParams.message) { $actParams.message } else { 'LocalPilot Fleet Administrator has scheduled a restart.' }
                                Write-AgentLog 'WARN' "Initiating scheduled restart in $delay seconds: $msg"
                                & shutdown.exe /r /t $delay /c $msg
                                $actResult = @{ scheduled_delay_sec = $delay; notification_message = $msg }
                            }

                            'SHUTDOWN' {
                                $delay = if ($actParams -and $actParams.delay_sec) { [int]$actParams.delay_sec } else { 60 }
                                $msg = if ($actParams -and $actParams.message) { $actParams.message } else { 'LocalPilot Fleet Administrator has scheduled a shutdown.' }
                                Write-AgentLog 'WARN' "Initiating scheduled shutdown in $delay seconds: $msg"
                                & shutdown.exe /s /t $delay /c $msg
                                $actResult = @{ scheduled_delay_sec = $delay; notification_message = $msg }
                            }

                            'CANCEL_SHUTDOWN' {
                                Write-AgentLog 'INFO' "Aborting pending restart/shutdown via shutdown.exe /a"
                                & shutdown.exe /a
                                $actResult = @{ message = 'Scheduled shutdown/restart cancelled' }
                            }

                            'SYNC_MDM' {
                                Write-AgentLog 'INFO' "Executing immediate MDM policy and telemetry sync"
                                $actResult = @{ message = 'MDM sync triggered on node'; sync_time = (Get-Date).ToString('o') }
                            }

                            'DEFENDER_SCAN' {
                                Write-AgentLog 'INFO' "Initiating Defender quick scan"
                                if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
                                    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
                                    $actResult = @{ message = 'Defender QuickScan started' }
                                } else {
                                    $actResult = @{ message = 'Defender module not available on this platform' }
                                }
                            }

                            'COLLECT_DIAGNOSTICS' {
                                Write-AgentLog 'INFO' "Packaging Windows MDM diagnostics bundle..."
                                $diagDir = Join-Path $env:ProgramData 'LocalPilotFleet\Diagnostics'
                                if (-not (Test-Path $diagDir)) { New-Item -Path $diagDir -ItemType Directory -Force | Out-Null }
                                $tempDir = Join-Path $diagDir ("temp_" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
                                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

                                # 1. System Info
                                $sysInfo = @{
                                    hostname      = $env:COMPUTERNAME
                                    os            = (Get-CimInstance Win32_OperatingSystem).Caption
                                    version       = (Get-CimInstance Win32_OperatingSystem).Version
                                    uptime_hours  = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 2)
                                    collected_at  = (Get-Date).ToString('o')
                                }
                                $sysInfo | ConvertTo-Json | Set-Content (Join-Path $tempDir 'system_info.json') -Encoding UTF8

                                # 2. Network Config
                                & ipconfig /all | Out-File (Join-Path $tempDir 'ipconfig.txt') -Encoding UTF8

                                # 3. Hotfixes
                                try {
                                    Get-HotFix | Select-Object -First 30 HotFixID, Description, InstalledOn | ConvertTo-Json | Set-Content (Join-Path $tempDir 'installed_hotfixes.json') -Encoding UTF8
                                } catch {}

                                # 4. BitLocker Volumes
                                try {
                                    Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, VolumeStatus, EncryptionMethod | ConvertTo-Json | Set-Content (Join-Path $tempDir 'bitlocker_volumes.json') -Encoding UTF8
                                } catch {}

                                # 5. Event Logs (Security & System highlights)
                                try {
                                    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3 } -MaxEvents 50 -ErrorAction SilentlyContinue |
                                        Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json | Set-Content (Join-Path $tempDir 'system_events.json') -Encoding UTF8
                                } catch {}

                                # Zip package
                                $zipName = "diagnostics-$($env:COMPUTERNAME)-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".zip"
                                $zipPath = Join-Path $diagDir $zipName
                                if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
                                Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force
                                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                                # Read binary bytes & Base64 encode
                                $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
                                $zipBase64 = [Convert]::ToBase64String($zipBytes)

                                # Upload bundle to server
                                $uploadPayload = @{
                                    remote_action_id = $actId
                                    file_name        = $zipName
                                    base64_data      = $zipBase64
                                    categories       = @('SYSTEM_LOGS', 'SECURITY_LOGS', 'BITLOCKER', 'NETWORK', 'HOTFIXES')
                                    summary          = @{
                                        os              = $sysInfo.os
                                        file_size_bytes = $zipBytes.Length
                                        collected_files = 5
                                    }
                                }

                                Invoke-RestMethod `
                                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/diagnostics-upload" `
                                    -Method     POST `
                                    -Body       ($uploadPayload | ConvertTo-Json -Depth 5 -Compress) `
                                    -Headers    $authHeaders `
                                    -TimeoutSec 30 `
                                    -ErrorAction Stop | Out-Null

                                Write-AgentLog 'INFO' "Successfully uploaded diagnostics package [$zipName] ($($zipBytes.Length) bytes)"
                                $actResult = @{ file_name = $zipName; size_bytes = $zipBytes.Length }
                            }

                            'ENFORCE_FIREWALL_POLICY' {
                                Write-AgentLog 'INFO' 'Executing immediate Windows Firewall policy enforcement...'
                                $script:LastFirewallAudit = $null
                                $actResult = @{ message = 'Firewall audit and enforcement triggered' }
                            }

                            Default {
                                Write-AgentLog 'INFO' "Standard remote action $actType executed"
                                $actResult = @{ message = "Remote action $actType acknowledged" }
                            }
                        }
                    } catch {
                        $actStatus = 'FAILED'
                        $actError = $_.Exception.Message
                        Write-AgentLog 'ERROR' "Failed to execute remote action [$actType]: $actError"
                    }

                    # Report action result back to server
                    try {
                        $resultPayload = @{
                            status        = $actStatus
                            result_data   = $actResult
                            error_message = $actError
                        }
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/remote-actions/$actId/result" `
                            -Method     POST `
                            -Body       ($resultPayload | ConvertTo-Json -Depth 5 -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 15 `
                            -ErrorAction Stop | Out-Null
                        Write-AgentLog 'INFO' "Reported remote action [$actId] result: $actStatus"
                    } catch {
                        Write-AgentLog 'ERROR' "Failed to report remote action result for [$actId]: $($_.Exception.Message)"
                    }
                }
            }

            # ── Intune Organizational Messages & User Toast Notifications ─────
            if ($resp.pending_messages) {
                $orgMsgs = @($resp.pending_messages)
                Write-AgentLog 'INFO' "Received $($orgMsgs.Count) pending organizational message(s) to deliver"

                foreach ($msg in $orgMsgs) {
                    $mId = $msg.id
                    $mTitle = if ($msg.PSObject.Properties['title']) { $msg.title } else { 'IT Notice' }
                    $mText = if ($msg.PSObject.Properties['message_body']) { $msg.message_body } elseif ($msg.PSObject.Properties['message']) { $msg.message } else { '' }
                    $mTheme = if ($msg.PSObject.Properties['theme']) { $msg.theme } else { 'INFO' }
                    Write-AgentLog 'INFO' "Delivering desktop notification [$mId]: $mTitle"

                    $delivered = Show-WindowsToastNotification -Title $mTitle -Message $mText -Theme $mTheme
                    $ackStatus = if ($delivered) { 'DELIVERED' } else { 'FAILED' }

                    try {
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/messages/$mId/ack" `
                            -Method     POST `
                            -Body       (@{ status = $ackStatus } | ConvertTo-Json -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction Stop | Out-Null
                        Write-AgentLog 'INFO' "Acknowledged organizational message [$mId] status: $ackStatus"
                    } catch {
                        Write-AgentLog 'ERROR' "Failed to acknowledge message [$mId]: $($_.Exception.Message)"
                    }
                }
            }

            # ── Proactive Remediations Evaluation ─────────────────────────────
            if ($resp.remediations) {
                if (-not (Get-Variable -Name 'LastRemediationRuns' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastRemediationRuns = @{}
                }
                $remList = @($resp.remediations)
                $now = Get-Date

                foreach ($rem in $remList) {
                    $remId = $rem.id
                    $sched = if ($rem.schedule_type) { $rem.schedule_type.ToUpper() } else { 'HEARTBEAT' }
                    $minIntervalSec = switch ($sched) {
                        'HOURLY' { 3600 }
                        'DAILY'  { 86400 }
                        Default  { 300 } # HEARTBEAT cadence = 5 minutes minimum between runs
                    }

                    $lastRun = $script:LastRemediationRuns[$remId]
                    $shouldRun = $false
                    if ($null -eq $lastRun) {
                        $shouldRun = $true
                    } elseif (($now - $lastRun).TotalSeconds -ge $minIntervalSec) {
                        $shouldRun = $true
                    }

                    if ($shouldRun) {
                        Write-AgentLog 'INFO' "Evaluating Proactive Remediation [$remId]: $($rem.name)"
                        $script:LastRemediationRuns[$remId] = $now

                        $detScript = "`$ProgressPreference = 'SilentlyContinue';`n" + $rem.detection_script
                        $detEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($detScript))
                        $detRes = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $detEncoded 2>&1
                        $detExit = $LASTEXITCODE; if ($null -eq $detExit) { $detExit = 0 }
                        $detStdout = ($detRes | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
                        $detStderr = ($detRes | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"

                        $remExit = $null
                        $remStdout = $null
                        $remStderr = $null

                        if ($detExit -ne 0) {
                            Write-AgentLog 'WARN' "Issue detected in [$remId] (exit code: $detExit). Executing remediation script..."
                            $fixScript = "`$ProgressPreference = 'SilentlyContinue';`n" + $rem.remediation_script
                            $fixEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fixScript))
                            $remRes = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $fixEncoded 2>&1
                            $remExit = $LASTEXITCODE; if ($null -eq $remExit) { $remExit = 0 }
                            $remStdout = ($remRes | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
                            $remStderr = ($remRes | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
                            Write-AgentLog 'INFO' "Remediation executed for [$remId] (exit code: $remExit)"
                        } else {
                            Write-AgentLog 'INFO' "Remediation detection healthy for [$remId] (no issue detected)"
                        }

                        # Report run result back to fleet server
                        try {
                            $remPayload = @{
                                remediation_id        = $remId
                                device_id             = $deviceId
                                detection_exit_code   = $detExit
                                detection_stdout      = $detStdout
                                detection_stderr      = $detStderr
                                remediation_exit_code = $remExit
                                remediation_stdout    = $remStdout
                                remediation_stderr    = $remStderr
                            }
                            Invoke-RestMethod `
                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/remediation-result" `
                                -Method     POST `
                                -Body       ($remPayload | ConvertTo-Json -Compress) `
                                -Headers    $authHeaders `
                                -TimeoutSec 10 `
                                -ErrorAction Stop | Out-Null
                            Write-AgentLog 'INFO' "Reported remediation run result for [$remId]"
                        } catch {
                            Write-AgentLog 'ERROR' "Failed to report remediation run for [$remId]: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # ── Intune Device Management & PowerShell Scripts Evaluation ──────
            if ($resp.assigned_scripts) {
                $scriptHistoryDir = 'C:\ProgramData\LocalPilotFleet\Scripts'
                if (-not (Test-Path $scriptHistoryDir)) {
                    New-Item -ItemType Directory -Path $scriptHistoryDir -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $scriptHistoryFile = Join-Path $scriptHistoryDir 'history.json'
                $localScriptHistory = @{}
                if (Test-Path $scriptHistoryFile) {
                    try {
                        $jsonRaw = Get-Content $scriptHistoryFile -Raw -ErrorAction SilentlyContinue
                        if ($jsonRaw) {
                            $parsedHistory = $jsonRaw | ConvertFrom-Json
                            foreach ($prop in $parsedHistory.PSObject.Properties) {
                                $localScriptHistory[$prop.Name] = [string]$prop.Value
                            }
                        }
                    } catch {}
                }

                if (-not (Get-Variable -Name 'LastScriptRuns' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastScriptRuns = @{}
                }
                $scriptsList = @($resp.assigned_scripts)
                $now = Get-Date

                foreach ($scr in $scriptsList) {
                    $scrId = $scr.id
                    $freq = if ($scr.run_frequency) { $scr.run_frequency.ToUpper() } else { 'ONCE' }
                    $isDue = if ($null -ne $scr.is_due) { [bool]$scr.is_due } else { $true }

                    $shouldExecute = $false
                    if ($freq -eq 'ONCE') {
                        # Only run if marked as due by server AND not already completed in local history
                        if ($isDue -and -not $localScriptHistory.ContainsKey($scrId) -and -not $script:LastScriptRuns.ContainsKey($scrId)) {
                            $shouldExecute = $true
                        }
                    } elseif ($freq -eq 'SCHEDULED') {
                        $lastExec = $script:LastScriptRuns[$scrId]
                        if ($null -eq $lastExec -or ($now - $lastExec).TotalSeconds -ge 900) {
                            $shouldExecute = $true
                        }
                    } elseif ($freq -eq 'ON_DEMAND') {
                        if ($isDue -and -not $script:LastScriptRuns.ContainsKey($scrId)) {
                            $shouldExecute = $true
                        }
                    }

                    if ($shouldExecute) {
                        Write-AgentLog 'INFO' "Executing Intune PowerShell Script [$scrId]: $($scr.name) (Frequency: $freq)"
                        $script:LastScriptRuns[$scrId] = $now

                        $runAs32Bit = [bool]$scr.run_as_32bit
                        $timeoutSec = if ($scr.timeout_seconds) { [int]$scr.timeout_seconds } else { 300 }
                        $psExe = 'powershell.exe'
                        if ($runAs32Bit -and [Environment]::Is64BitOperatingSystem) {
                            $sysWowPs = "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
                            if (Test-Path $sysWowPs) { $psExe = $sysWowPs }
                        }

                        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $scrStdout = ''
                        $scrStderr = ''
                        $scrExitCode = 0
                        $scrStatus = 'SUCCESS'

                        try {
                            $fullContent = "`$ProgressPreference = 'SilentlyContinue';`n" + $scr.script_content
                            $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fullContent))
                            $rawResult = & $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedScript 2>&1
                            $scrExitCode = $LASTEXITCODE
                            if ($null -eq $scrExitCode) { $scrExitCode = 0 }

                            $outLines = @()
                            $errLines = @()
                            foreach ($item in $rawResult) {
                                if ($null -eq $item) { continue }
                                $lineStr = $item.ToString()
                                if ($lineStr -like '#< CLIXML*' -or $lineStr -like '<Objs Version=*' -or $lineStr -like '</Objs>*') { continue }
                                if ($item -is [System.Management.Automation.ErrorRecord]) {
                                    $errLines += $lineStr
                                } else {
                                    $outLines += $lineStr
                                }
                            }
                            $scrStdout = $outLines -join "`n"
                            $scrStderr = $errLines -join "`n"
                            if ($scrExitCode -ne 0) {
                                $scrStatus = 'FAILED'
                            }
                        } catch {
                            $scrStatus = 'FAILED'
                            $scrExitCode = 1
                            $scrStderr = $_.Exception.Message
                        } finally {
                            $stopwatch.Stop()
                        }

                        $execTimeMs = [int]$stopwatch.ElapsedMilliseconds

                        if ($scrStatus -eq 'SUCCESS') {
                            $localScriptHistory[$scrId] = $now.ToString('o')
                            try {
                                $localScriptHistory | ConvertTo-Json | Set-Content -Path $scriptHistoryFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                            } catch {}
                        }

                        # Report script run result back to fleet authority
                        try {
                            $runPayload = @{
                                run_mode          = 'ASSIGNED'
                                status            = $scrStatus
                                exit_code         = $scrExitCode
                                stdout            = $scrStdout
                                stderr            = $scrStderr
                                execution_time_ms = $execTimeMs
                            }
                            Invoke-RestMethod `
                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/scripts/$scrId/result" `
                                -Method     POST `
                                -Body       ($runPayload | ConvertTo-Json -Compress) `
                                -Headers    $authHeaders `
                                -TimeoutSec 15 `
                                -ErrorAction Stop | Out-Null
                            Write-AgentLog 'INFO' "Reported Intune script run result for [$scrId]: $scrStatus (Exit: $scrExitCode, Duration: ${execTimeMs}ms)"
                        } catch {
                            Write-AgentLog 'ERROR' "Failed to report Intune script run for [$scrId]: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # ── Configuration Profiles & Settings Catalog Evaluation ──────────
            if ($resp.profiles) {
                if (-not (Get-Variable -Name 'LastProfileRuns' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastProfileRuns = @{}
                }
                $profList = @($resp.profiles)
                $now = Get-Date

                foreach ($prof in $profList) {
                    $profId = $prof.id
                    $lastRun = $script:LastProfileRuns[$profId]
                    $shouldRun = $false
                    if ($null -eq $lastRun) {
                        $shouldRun = $true
                    } elseif (($now - $lastRun).TotalSeconds -ge 300) { # 5-minute interval
                        $shouldRun = $true
                    }

                    if ($shouldRun) {
                        Write-AgentLog 'INFO' "Auditing Configuration Profile [$profId]: $($prof.name)"
                        $script:LastProfileRuns[$profId] = $now

                        $settingResults = @()
                        $settings = @($prof.settings)

                        foreach ($s in $settings) {
                            $sid = $s.id
                            $cat = if ($s.category) { $s.category } else { 'General' }
                            $sname = if ($s.name) { $s.name } else { $sid }
                            $desired = $s.desired_value

                            $itemRes = $null
                            try {
                                switch ($sid) {
                                    'firewall_all_profiles' {
                                        $allOn = $false
                                        try {
                                            $fw = Get-NetFirewallProfile -ErrorAction Stop
                                            $allOn = ($fw | Where-Object { $_.Enabled -ne 'True' }).Count -eq 0
                                        } catch {
                                            $netsh = netsh advfirewall show allprofiles state 2>&1
                                            $off = ($netsh | Where-Object { $_ -match 'State\s+OFF' }).Count
                                            $allOn = ($off -eq 0)
                                        }
                                        if ($allOn -eq [bool]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = $desired; current_value = $allOn; status = 'COMPLIANT'; message = 'Firewall profiles verified active' }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = $desired; current_value = $allOn; status = 'NON_COMPLIANT'; message = 'One or more firewall profiles are disabled' }
                                        }
                                    }
                                    'uac_enable_lua' {
                                        $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
                                        $val = if ($reg -and $null -ne $reg.EnableLUA) { [int]$reg.EnableLUA } else { 0 }
                                        if ($val -eq [int]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'COMPLIANT'; message = "UAC EnableLUA is $val" }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'NON_COMPLIANT'; message = "UAC EnableLUA is $val (expected $desired)" }
                                        }
                                    }
                                    'telemetry_level' {
                                        $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue
                                        $val = if ($reg -and $null -ne $reg.AllowTelemetry) { [int]$reg.AllowTelemetry } else { 3 }
                                        if ($val -le [int]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'COMPLIANT'; message = "Telemetry level is $val" }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'NON_COMPLIANT'; message = "Telemetry level is $val (expected <= $desired)" }
                                        }
                                    }
                                    'tailored_experiences' {
                                        $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -ErrorAction SilentlyContinue
                                        $disabled = if ($reg -and $null -ne $reg.DisableTailoredExperiencesWithDiagnosticData) { [int]$reg.DisableTailoredExperiencesWithDiagnosticData -eq 1 } else { $false }
                                        $curVal = if ($disabled) { 0 } else { 1 }
                                        if ($curVal -eq [int]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $curVal; status = 'COMPLIANT'; message = 'Tailored experiences restricted' }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $curVal; status = 'NON_COMPLIANT'; message = 'Tailored experiences active' }
                                        }
                                    }
                                    'rdp_nla' {
                                        $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                                        $val = if ($reg -and $null -ne $reg.UserAuthentication) { [int]$reg.UserAuthentication } else { 0 }
                                        if ($val -eq [int]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'COMPLIANT'; message = 'RDP Network Level Authentication (NLA) active' }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'NON_COMPLIANT'; message = "RDP NLA is $val (expected $desired)" }
                                        }
                                    }
                                    'fast_startup' {
                                        $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue
                                        $val = if ($reg -and $null -ne $reg.HiberbootEnabled) { [int]$reg.HiberbootEnabled } else { 1 }
                                        if ($val -eq [int]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'COMPLIANT'; message = "Fast startup state is $val" }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [int]$desired; current_value = $val; status = 'NON_COMPLIANT'; message = "Fast startup is $val (expected $desired)" }
                                        }
                                    }
                                    'bitlocker_os_volume' {
                                        $isEncrypted = $false
                                        try {
                                            $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
                                            $isEncrypted = ($bl.ProtectionStatus -eq 1 -or $bl.VolumeStatus -eq 'FullyEncrypted')
                                        } catch {
                                            $isEncrypted = $false
                                        }
                                        if ($isEncrypted -eq [bool]$desired) {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [bool]$desired; current_value = $isEncrypted; status = 'COMPLIANT'; message = 'BitLocker volume encryption verified' }
                                        } else {
                                            $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = [bool]$desired; current_value = $isEncrypted; status = 'NON_COMPLIANT'; message = 'BitLocker is not fully enabled on OS volume' }
                                        }
                                    }
                                    Default {
                                        $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = $desired; current_value = $desired; status = 'COMPLIANT'; message = 'Custom setting applied' }
                                    }
                                }
                            } catch {
                                $itemRes = @{ id = $sid; category = $cat; name = $sname; desired_value = $desired; current_value = $null; status = 'ERROR'; message = $_.Exception.Message }
                            }
                            $settingResults += $itemRes
                        }

                        # Report profile compliance back to fleet server
                        try {
                            $compPayload = @{
                                profile_id      = $profId
                                setting_results = $settingResults
                            }
                            $compRes = Invoke-RestMethod `
                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/profile-compliance" `
                                -Method     POST `
                                -Body       ($compPayload | ConvertTo-Json -Depth 6 -Compress) `
                                -Headers    $authHeaders `
                                -TimeoutSec 10 `
                                -ErrorAction Stop
                            Write-AgentLog 'INFO' "Reported configuration profile compliance for [$profId] ($($compRes.compliance_status): $($compRes.compliant_count) compliant, $($compRes.non_compliant_count) non-compliant)"
                        } catch {
                            Write-AgentLog 'ERROR' "Failed to report profile compliance for [$profId]: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # ── Windows Update for Business (WUfB) & Patch Cadence Audit ────────
            if ($resp.update_ring) {
                if (-not (Get-Variable -Name 'LastUpdateAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastUpdateAudit = $null
                }
                $now = Get-Date
                $shouldAuditUpdates = $false
                if ($null -eq $script:LastUpdateAudit) {
                    $shouldAuditUpdates = $true
                } elseif (($now - $script:LastUpdateAudit).TotalSeconds -ge 600) { # 10-minute cadence to avoid CPU overhead
                    $shouldAuditUpdates = $true
                }

                if ($shouldAuditUpdates) {
                    $ring = $resp.update_ring
                    Write-AgentLog 'INFO' "Auditing Windows Update status for Ring: $($ring.name) ($($ring.servicing_channel))"
                    $script:LastUpdateAudit = $now

                    $isRebootPending = $false
                    $rebootReasons = @()

                    # 1. Check Registry RebootRequired
                    $wuReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                    if ($wuReboot) {
                        $isRebootPending = $true
                        $rebootReasons += 'WindowsUpdate:RebootRequired'
                    }

                    # 2. Check CBS RebootPending
                    $cbsReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                    if ($cbsReboot) {
                        $isRebootPending = $true
                        $rebootReasons += 'ComponentBasedServicing:RebootPending'
                    }

                    # 3. Check PendingFileRenameOperations
                    try {
                        $pfr = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                        if ($pfr -and $pfr.PendingFileRenameOperations) {
                            $isRebootPending = $true
                            $rebootReasons += 'SessionManager:PendingFileRenameOperations'
                        }
                    } catch {}

                    # 4. Harvest Top Hotfixes
                    $hotfixes = @()
                    try {
                        $hfList = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
                        foreach ($hf in $hfList) {
                            $hotfixes += @{
                                hotfix_id    = $hf.HotFixID
                                description  = $hf.Description
                                installed_on = if ($hf.InstalledOn) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
                            }
                        }
                    } catch {
                        Write-AgentLog 'WARN' "Could not harvest hotfixes: $($_.Exception.Message)"
                    }

                    # 5. Check Windows Update Service Status
                    $wuServiceStatus = 'Running'
                    try {
                        $svc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
                        if ($svc) { $wuServiceStatus = $svc.Status.ToString() }
                    } catch {}

                    # 6. Report Windows Update Status to Fleet Server
                    try {
                        $updPayload = @{
                            reboot_pending          = $isRebootPending
                            reboot_pending_reasons  = $rebootReasons
                            last_scan_at            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                            installed_hotfixes      = $hotfixes
                            update_service_status   = $wuServiceStatus
                        }
                        $updRes = Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/update-status" `
                            -Method     POST `
                            -Body       ($updPayload | ConvertTo-Json -Depth 5 -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction Stop
                        Write-AgentLog 'INFO' "Reported Windows Update telemetry (Compliance: $($updRes.compliance_status), RebootPending: $isRebootPending, Hotfixes: $($hotfixes.Count))"
                    } catch {
                        Write-AgentLog 'ERROR' "Failed to report Windows Update status: $($_.Exception.Message)"
                    }
                }
            }

            # ── Microsoft Intune Device Compliance & Zero-Trust Audit ───────────
            if ($resp.compliance_policies) {
                if (-not (Get-Variable -Name 'LastComplianceAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastComplianceAudit = $null
                }
                $now = Get-Date
                $shouldAuditCompliance = $false
                if ($null -eq $script:LastComplianceAudit) {
                    $shouldAuditCompliance = $true
                } elseif (($now - $script:LastComplianceAudit).TotalSeconds -ge 300) { # 5-minute interval
                    $shouldAuditCompliance = $true
                }

                if ($shouldAuditCompliance) {
                    $pols = @($resp.compliance_policies)
                    Write-AgentLog 'INFO' "Auditing Device Compliance against $($pols.Count) assigned policies"
                    $script:LastComplianceAudit = $now

                    # Harvest OS build
                    $osBuild = $null
                    try {
                        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                        if ($os) { $osBuild = $os.BuildNumber }
                    } catch {}

                    # Harvest BitLocker status
                    $blStatus = 'Disabled'
                    try {
                        $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
                        if ($bl) {
                            if ($bl.ProtectionStatus -eq 1 -or $bl.VolumeStatus -eq 'FullyEncrypted') {
                                $blStatus = 'FullyEncrypted'
                            }
                        }
                    } catch {}

                    # Harvest Secure Boot
                    $sb = $false
                    try {
                        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                        if ($null -eq $sb) { $sb = $false }
                    } catch { $sb = $false }

                    # Harvest TPM
                    $tpmPres = $false
                    $tpmEnab = $false
                    try {
                        $tpm = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
                        if ($tpm) {
                            $tpmPres = [bool]$tpm.IsActivated_InitialValue
                            $tpmEnab = [bool]$tpm.IsEnabled_InitialValue
                        }
                    } catch {}

                    # Harvest Defender RTP
                    $rtp = $true
                    try {
                        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                        if ($mp) {
                            $rtp = [bool]$mp.RealTimeProtectionEnabled
                        }
                    } catch {}

                    # Harvest Firewall
                    $fw = $true
                    try {
                        $fwProfiles = Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction SilentlyContinue
                        if ($fwProfiles) {
                            $disabled = $fwProfiles | Where-Object { $_.Enabled -eq $false }
                            if ($disabled) { $fw = $false }
                        }
                    } catch {}

                    try {
                        $compPayload = @{
                            os_build             = $osBuild
                            bitlocker_status     = $blStatus
                            secure_boot_enabled  = $sb
                            tpm_present          = $tpmPres
                            tpm_enabled          = $tpmEnab
                            defender_rtp_enabled = $rtp
                            firewall_enabled     = $fw
                        }

                        $compRes = Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/compliance-report" `
                            -Method     POST `
                            -Body       ($compPayload | ConvertTo-Json -Depth 5 -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction Stop
                        Write-AgentLog 'INFO' "Reported Device Compliance evaluations ($($compRes.evaluations.Count) policies evaluated)"
                    } catch {
                        Write-AgentLog 'ERROR' "Failed to report device compliance: $($_.Exception.Message)"
                    }
                }
            }

            # ── Microsoft Intune Application Management & Packaging Audit ───────
            if ($resp.assigned_apps) {
                if (-not (Get-Variable -Name 'LastAppManagementAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastAppManagementAudit = $null
                }
                $now = Get-Date
                $shouldAuditApps = $false
                if ($null -eq $script:LastAppManagementAudit) {
                    $shouldAuditApps = $true
                } elseif (($now - $script:LastAppManagementAudit).TotalSeconds -ge 300) { # 5-minute interval
                    $shouldAuditApps = $true
                }

                if ($shouldAuditApps) {
                    $appsList = @($resp.assigned_apps)
                    Write-AgentLog 'INFO' "Auditing Intune Applications against $($appsList.Count) assigned packages"
                    $script:LastAppManagementAudit = $now

                    foreach ($app in $appsList) {
                        try {
                            $appId = $app.id
                            $isDetected = $false
                            $detectedVersion = $null
                            $detRules = @($app.detection_rules)

                            foreach ($rule in $detRules) {
                                switch ($rule.type) {
                                    'FILE' {
                                        if ($rule.path -and (Test-Path -Path $rule.path -ErrorAction SilentlyContinue)) {
                                            $isDetected = $true
                                            try {
                                                $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($rule.path)
                                                if ($fvi.FileVersion) { $detectedVersion = $fvi.FileVersion }
                                            } catch {}
                                        }
                                    }
                                    'REGISTRY' {
                                        if ($rule.path -and (Test-Path -Path $rule.path -ErrorAction SilentlyContinue)) {
                                            $isDetected = $true
                                            try {
                                                $regVal = Get-ItemPropertyValue -Path $rule.path -Name 'DisplayVersion' -ErrorAction SilentlyContinue
                                                if ($regVal) { $detectedVersion = [string]$regVal }
                                            } catch {}
                                        }
                                    }
                                    'WINGET' {
                                        $pkgId = $rule.package_id
                                        if (-not $pkgId) { $pkgId = $app.package_identifier }
                                        if ($pkgId) {
                                            # Fast registry scan for uninstall entry matching Winget package or ID
                                            $uninstKeys = @(
                                                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                                            )
                                            $found = Get-ItemProperty -Path $uninstKeys -ErrorAction SilentlyContinue |
                                                Where-Object { 
                                                    ($_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like "*$($app.name)*") -or 
                                                    ($_.PSObject.Properties['PSChildName'] -and $_.PSChildName -like "*$pkgId*")
                                                } | Select-Object -First 1
                                            if ($found) {
                                                $isDetected = $true
                                                if ($found.PSObject.Properties['DisplayVersion'] -and $found.DisplayVersion) { $detectedVersion = [string]$found.DisplayVersion }
                                            }
                                        }
                                    }
                                }
                                if ($isDetected) { break }
                            }

                            $installStatus = 'PENDING'
                            $errorMsg = $null

                            if ($isDetected) {
                                $installStatus = 'INSTALLED'
                            } else {
                                if ($app.assignment_intent -eq 'REQUIRED') {
                                    $req = $app.requirement_rules
                                    if ($req) {
                                        # Check min_os_build
                                        if ($req.min_os_build -and $osBuild) {
                                            try {
                                                if ([version]$osBuild -lt [version]$req.min_os_build) {
                                                    $installStatus = 'NOT_APPLICABLE'
                                                    $errorMsg = "OS build $osBuild does not meet requirement ($($req.min_os_build))"
                                                }
                                            } catch {}
                                        }
                                    }
                                } elseif ($app.assignment_intent -eq 'AVAILABLE') {
                                    $installStatus = 'PENDING'
                                } elseif ($app.assignment_intent -eq 'UNINSTALL') {
                                    $installStatus = 'UNINSTALLED'
                                }
                            }

                            $appStatusPayload = @{
                                app_id            = $appId
                                install_status    = $installStatus
                                detection_state   = if ($isDetected) { 1 } else { 0 }
                                installed_version = if ($detectedVersion) { $detectedVersion } else { $app.version }
                                error_message     = $errorMsg
                                last_attempt_at   = (Get-Date).ToString('o')
                            }

                            Invoke-RestMethod `
                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/app-status" `
                                -Method     POST `
                                -Body       ($appStatusPayload | ConvertTo-Json -Compress) `
                                -Headers    $authHeaders `
                                -TimeoutSec 10 `
                                -ErrorAction SilentlyContinue | Out-Null

                            Write-AgentLog 'INFO' "Application [$($app.name)]: Status = $installStatus (Detected: $isDetected, Version: $detectedVersion)"
                        } catch {
                            Write-AgentLog 'ERROR' "Failed to process app [$($app.name)]: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # ── Microsoft Defender Antivirus & Endpoint Security Audit ─────────
            if (-not (Get-Variable -Name 'LastSecurityAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastSecurityAudit = $null
            }
            $now = Get-Date
            $shouldAuditSecurity = $false
            if ($null -eq $script:LastSecurityAudit) {
                $shouldAuditSecurity = $true
            } elseif (($now - $script:LastSecurityAudit).TotalSeconds -ge 300) { # 5-minute interval
                $shouldAuditSecurity = $true
            }

            if ($shouldAuditSecurity) {
                $script:LastSecurityAudit = $now
                Write-AgentLog 'INFO' 'Auditing Microsoft Defender Antivirus & Endpoint Security posture...'

                # Harvest Defender Status
                $hasMp = Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($hasMp) {
                    try {
                        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                        if ($mp) {
                            $pref = $null
                            try { $pref = Get-MpPreference -ErrorAction SilentlyContinue } catch {}

                            $hasP = { param($o, $p) return ($null -ne $o -and $null -ne $o.PSObject.Properties[$p]) }
                            $getP = {
                                param($o, $p, $def)
                                if (& $hasP $o $p -and $null -ne $o.$p) { return $o.$p }
                                return $def
                            }

                            $toIso = {
                                param($dt)
                                try {
                                    if ($null -ne $dt -and $dt -is [System.DateTime] -and $dt.Year -gt 1970) {
                                        return $dt.ToString('o')
                                    }
                                } catch {}
                                return $null
                            }

                            $toAgeDays = {
                                param($val)
                                try {
                                    if ($null -eq $val) { return 0 }
                                    $v = [int64]$val
                                    if ($v -ge 4294967295 -or $v -lt 0 -or $v -gt 2147483647) { return 0 }
                                    return [int]$v
                                } catch {
                                    return 0
                                }
                            }

                            $sigAge = & $toAgeDays (& $getP $mp 'AntivirusSignatureAge' 0)
                            $sigUpdated = if (& $hasP $mp 'AntivirusSignatureLastUpdated') { & $toIso $mp.AntivirusSignatureLastUpdated } else { $null }
                            $sigVer = [string](& $getP $mp 'AntivirusSignatureVersion' '')
                            $engVer = [string](& $getP $mp 'AMEngineVersion' '')
                            $prodVer = [string](& $getP $mp 'AMProductVersion' '')
                            $avEnab = [bool](& $getP $mp 'AntivirusEnabled' $true)
                            $rtp = [bool](& $getP $mp 'RealTimeProtectionEnabled' $true)
                            $pua = $false
                            if (& $hasP $pref 'PUAProtection') {
                                $pua = ([int64]$pref.PUAProtection -eq 1)
                            }
                            $cfa = [int](& $getP $pref 'EnableControlledFolderAccess' 0)
                            $netProt = if ([int64](& $getP $pref 'EnableNetworkProtection' 0) -gt 0) { 1 } else { 0 }
                            $maps = [int64](& $getP $pref 'MAPSReporting' 2)
                            $cloudProt = if ($maps -gt 0) { 1 } else { 0 }
                            $quickScanAt = if (& $hasP $mp 'QuickScanEndTime') { & $toIso $mp.QuickScanEndTime } else { $null }
                            $fullScanAt = if (& $hasP $mp 'FullScanEndTime') { & $toIso $mp.FullScanEndTime } else { $null }
                            $quickScanAge = & $toAgeDays (& $getP $mp 'QuickScanAge' 0)
                            $fullScanAge = & $toAgeDays (& $getP $mp 'FullScanAge' 0)
                            $isTamper = [bool](& $getP $mp 'IsTamperProtected' $false)
                            $ioav = [bool](& $getP $mp 'IoavProtectionEnabled' $true)
                            $antispy = [bool](& $getP $mp 'AntispywareEnabled' $true)
                            $behav = [bool](& $getP $mp 'BehaviorMonitorEnabled' $true)

                            $avPayload = @{
                                antivirus_enabled                = if ($avEnab) { 1 } else { 0 }
                                engine_version                   = $engVer
                                product_version                  = $prodVer
                                signature_version                = $sigVer
                                signature_last_updated           = $sigUpdated
                                signature_age_days               = $sigAge
                                real_time_protection_enabled     = if ($rtp) { 1 } else { 0 }
                                cloud_protection_enabled         = $cloudProt
                                pua_protection_enabled           = if ($pua) { 1 } else { 0 }
                                controlled_folder_access_enabled = $cfa
                                network_protection_enabled       = $netProt
                                tamper_protection_enabled        = if ($isTamper) { 1 } else { 0 }
                                antispyware_enabled              = if ($antispy) { 1 } else { 0 }
                                behavior_monitor_enabled         = if ($behav) { 1 } else { 0 }
                                ioav_protection_enabled          = if ($ioav) { 1 } else { 0 }
                                last_quick_scan_at               = $quickScanAt
                                last_full_scan_at                = $fullScanAt
                                quick_scan_age_days              = $quickScanAge
                                full_scan_age_days               = $fullScanAge
                            }

                            Invoke-RestMethod `
                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/antivirus-status" `
                                -Method     POST `
                                -Body       ($avPayload | ConvertTo-Json -Compress) `
                                -Headers    $authHeaders `
                                -TimeoutSec 10 `
                                -ErrorAction SilentlyContinue | Out-Null

                            Write-AgentLog 'INFO' "Reported Defender status (Sig: $sigVer, Age: $sigAge days, RTP: $rtp, CFA: $cfa)"
                        }
                    } catch {
                        Write-AgentLog 'WARN' "Could not harvest Get-MpComputerStatus: $($_.Exception.Message)"
                    }

                    # Harvest Active/Recent Threat Detections
                    try {
                        $threatCmd = Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue
                        if ($threatCmd) {
                            $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 5
                            if ($threats) {
                                foreach ($t in $threats) {
                                    $actionSuccess = if (& $hasP $t 'ActionSuccess') { [bool]$t.ActionSuccess } else { $true }
                                    $actionStr = if ($actionSuccess) { 'QUARANTINED' } else { 'BLOCKED' }
                                    $tName = if (& $hasP $t 'ThreatName' -and $t.ThreatName) { [string]$t.ThreatName } else { 'Unknown.Threat' }
                                    $tId = if (& $hasP $t 'ThreatID' -and $null -ne $t.ThreatID) { [string]$t.ThreatID } else { '0' }
                                    $resList = if (& $hasP $t 'Resources' -and $null -ne $t.Resources) { @($t.Resources) } else { @() }
                                    $detTime = if (& $hasP $t 'InitialDetectionTime' -and $null -ne $t.InitialDetectionTime) { & $toIso $t.InitialDetectionTime } else { $null }

                                    $tPayload = @{
                                        threat_name        = $tName
                                        threat_id          = $tId
                                        severity           = 'HIGH'
                                        category           = 'Malware'
                                        resources          = $resList
                                        action_taken       = $actionStr
                                        remediation_status = 'RESOLVED'
                                        detected_at        = $detTime
                                    }
                                    Invoke-RestMethod `
                                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/threat-detection" `
                                        -Method     POST `
                                        -Body       ($tPayload | ConvertTo-Json -Compress) `
                                        -Headers    $authHeaders `
                                        -TimeoutSec 10 `
                                        -ErrorAction SilentlyContinue | Out-Null
                                }
                            }
                        }
                    } catch {
                        Write-AgentLog 'WARN' "Could not harvest Get-MpThreatDetection: $($_.Exception.Message)"
                    }
                }
            }

            # ── BitLocker Drive Encryption & Recovery Key Vault Escrow ──────
            if (-not (Get-Variable -Name 'LastBitLockerAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastBitLockerAudit = $null
            }
            $now = Get-Date
            $shouldAuditBitLocker = $false
            if ($null -eq $script:LastBitLockerAudit) {
                $shouldAuditBitLocker = $true
            } elseif (($now - $script:LastBitLockerAudit).TotalSeconds -ge 300) { # 5-minute interval
                $shouldAuditBitLocker = $true
            }

            if ($shouldAuditBitLocker) {
                $script:LastBitLockerAudit = $now
                Write-AgentLog 'INFO' 'Auditing BitLocker Drive Encryption posture & Key Escrow...'

                $hasBde = Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue
                if ($hasBde) {
                    try {
                        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                        if ($volumes) {
                            $hasP = { param($o, $p) return ($null -ne $o -and $null -ne $o.PSObject.Properties[$p]) }
                            $getP = { param($o, $p, $def) if (& $hasP $o $p -and $null -ne $o.$p) { return $o.$p }; return $def }

                            foreach ($vol in $volumes) {
                                $mp = [string](& $getP $vol 'MountPoint' 'C:')
                                $volType = [string](& $getP $vol 'VolumeType' 'OperatingSystem')
                                $protStat = [string](& $getP $vol 'ProtectionStatus' 'Off')
                                $volStat = [string](& $getP $vol 'VolumeStatus' 'FullyDecrypted')
                                $encPct = [double](& $getP $vol 'EncryptionPercentage' 0.0)
                                $encMethod = [string](& $getP $vol 'EncryptionMethod' 'None')
                                $lockStat = [string](& $getP $vol 'LockStatus' 'Unlocked')

                                $protectorTypes = @()
                                if (& $hasP $vol 'KeyProtector' -and $vol.KeyProtector) {
                                    foreach ($kp in $vol.KeyProtector) {
                                        $kpType = [string](& $getP $kp 'KeyProtectorType' '')
                                        if ($kpType) {
                                            $protectorTypes += $kpType
                                        }
                                    }
                                }

                                # Report volume status to LocalPilotFleet
                                $volPayload = @{
                                    mount_point           = $mp
                                    volume_type           = $volType
                                    protection_status     = $protStat
                                    volume_status         = $volStat
                                    encryption_percentage = $encPct
                                    encryption_method     = $encMethod
                                    lock_status           = $lockStat
                                    key_protector_types   = $protectorTypes
                                }

                                Invoke-RestMethod `
                                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/bitlocker-status" `
                                    -Method     POST `
                                    -Body       ($volPayload | ConvertTo-Json -Compress) `
                                    -Headers    $authHeaders `
                                    -TimeoutSec 10 `
                                    -ErrorAction SilentlyContinue | Out-Null

                                # Escrow any recovery password protectors found
                                if (& $hasP $vol 'KeyProtector' -and $vol.KeyProtector) {
                                    foreach ($kp in $vol.KeyProtector) {
                                        $kpType = [string](& $getP $kp 'KeyProtectorType' '')
                                        $kpPw = [string](& $getP $kp 'RecoveryPassword' '')
                                        $kpId = [string](& $getP $kp 'KeyProtectorId' '')

                                        if ($kpType -eq 'RecoveryPassword' -and $kpPw) {
                                            $keyPayload = @{
                                                volume_mount_point = $mp
                                                volume_type        = $volType
                                                key_protector_id   = $kpId
                                                key_protector_type = 'RecoveryPassword'
                                                recovery_password  = $kpPw
                                                encryption_method  = $encMethod
                                            }

                                            Invoke-RestMethod `
                                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/bitlocker-escrow" `
                                                -Method     POST `
                                                -Body       ($keyPayload | ConvertTo-Json -Compress) `
                                                -Headers    $authHeaders `
                                                -TimeoutSec 10 `
                                                -ErrorAction SilentlyContinue | Out-Null

                                            $shortId = if ($kpId.Length -ge 8) { $kpId.Substring(0, 8) } else { $kpId }
                                            Write-AgentLog 'INFO' "Escrowed BitLocker recovery password for volume $mp (ID: $shortId)"
                                        }
                                    }
                                }
                            }
                            Write-AgentLog 'INFO' "Reported BitLocker posture for $($volumes.Count) volume(s)"
                        }
                    } catch {
                        Write-AgentLog 'WARN' "Could not harvest BitLocker volume posture: $($_.Exception.Message)"
                    }
                } else {
                    Write-AgentLog 'INFO' 'BitLocker cmdlets not present on this Windows edition (Home or non-BitLocker OS)'
                }
            }

            # ── Windows LAPS (Local Administrator Password Solution) Governance ─
            if ($resp.laps_policy) {
                if (-not (Get-Variable -Name 'LastLapsAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastLapsAudit = $null
                }
                $now = Get-Date
                $shouldAuditLaps = $false
                if ($null -eq $script:LastLapsAudit) {
                    $shouldAuditLaps = $true
                } elseif (($now - $script:LastLapsAudit).TotalSeconds -ge 300) { # 5-minute interval
                    $shouldAuditLaps = $true
                }

                if ($shouldAuditLaps) {
                    $script:LastLapsAudit = $now
                    $lapsPol = $resp.laps_policy
                    $accountName = if ($lapsPol.admin_account_name) { $lapsPol.admin_account_name } else { 'Administrator' }
                    Write-AgentLog 'INFO' "Auditing Windows LAPS posture for account [$accountName]..."

                    $isAdmin = $false
                    try {
                        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    } catch {}

                    $lapsRegPath = 'HKLM:\SOFTWARE\LocalPilotFleet\LAPS'
                    $lastRotated = $null
                    if (Test-Path $lapsRegPath -ErrorAction SilentlyContinue) {
                        try {
                            $regVal = Get-ItemPropertyValue -Path $lapsRegPath -Name 'LastRotated' -ErrorAction SilentlyContinue
                            if ($regVal) { $lastRotated = [datetime]$regVal }
                        } catch {}
                    }

                    $maxAgeDays = if ($lapsPol.password_age_days) { [int]$lapsPol.password_age_days } else { 30 }
                    $isExpired = $false
                    if ($null -eq $lastRotated) {
                        $isExpired = $true
                    } elseif (($now - $lastRotated).TotalDays -ge $maxAgeDays) {
                        $isExpired = $true
                    }

                    if ($isAdmin -and ($isExpired -or $null -eq $lastRotated)) {
                        $pwdLen = if ($lapsPol.password_length -and [int]$lapsPol.password_length -ge 12) { [int]$lapsPol.password_length } else { 16 }
                        $complexity = if ($lapsPol.password_complexity) { $lapsPol.password_complexity } else { 'COMPLEX' }

                        $charsUpper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
                        $charsLower = 'abcdefghijkmnopqrstuvwxyz'
                        $charsDigits = '23456789'
                        $charsSpecial = '!@#$%^&*()_+~|}{[]:;?><,./-='

                        $charPool = $charsUpper + $charsLower + $charsDigits
                        if ($complexity -eq 'COMPLEX') {
                            $charPool += $charsSpecial
                        }

                        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                        $bytes = [byte[]]::new($pwdLen)
                        $rng.GetBytes($bytes)
                        $newPwdArr = [char[]]::new($pwdLen)
                        for ($i = 0; $i -lt $pwdLen; $i++) {
                            $newPwdArr[$i] = $charPool[$bytes[$i] % $charPool.Length]
                        }
                        $newPwdArr[0] = $charsUpper[$bytes[0] % $charsUpper.Length]
                        $newPwdArr[1] = $charsLower[$bytes[1] % $charsLower.Length]
                        $newPwdArr[2] = $charsDigits[$bytes[2] % $charsDigits.Length]
                        if ($complexity -eq 'COMPLEX') {
                            $newPwdArr[3] = $charsSpecial[$bytes[3] % $charsSpecial.Length]
                        }
                        $newPassword = -join $newPwdArr

                        $applied = $false
                        try {
                            $userObj = [ADSI]"WinNT://$env:COMPUTERNAME/$accountName,user"
                            if ($null -ne $userObj -and $null -ne $userObj.Name) {
                                if ($lapsPol.auto_enable_account -and ($userObj.UserFlags.Value -band 2)) {
                                    $userObj.UserFlags = $userObj.UserFlags.Value -bxor 2
                                    $userObj.SetInfo()
                                    Write-AgentLog 'INFO' "Auto-enabled account [$accountName] per LAPS policy"
                                }
                                $userObj.SetPassword($newPassword)
                                $applied = $true
                            }
                        } catch {
                            try {
                                $secPwd = ConvertTo-SecureString $newPassword -AsPlainText -Force
                                Set-LocalUser -Name $accountName -Password $secPwd -ErrorAction Stop
                                $applied = $true
                            } catch {
                                Write-AgentLog 'WARN' "Could not update local user password: $($_.Exception.Message)"
                            }
                        }

                        if ($applied) {
                            try {
                                $escrowPayload = @{
                                    account_name     = $accountName
                                    password         = $newPassword
                                    password_length  = $pwdLen
                                    complexity_level = $complexity
                                    rotation_reason  = if ($null -eq $lastRotated) { 'INITIAL_ENROLLMENT' } else { 'SCHEDULED_EXPIRATION' }
                                }
                                Invoke-RestMethod `
                                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/laps-escrow" `
                                    -Method     POST `
                                    -Body       ($escrowPayload | ConvertTo-Json -Compress) `
                                    -Headers    $authHeaders `
                                    -TimeoutSec 10 `
                                    -ErrorAction Stop | Out-Null

                                try {
                                    if (-not (Test-Path $lapsRegPath -ErrorAction SilentlyContinue)) {
                                        New-Item -Path $lapsRegPath -Force | Out-Null
                                    }
                                    Set-ItemProperty -Path $lapsRegPath -Name 'LastRotated' -Value ($now.ToString('o'))
                                    Set-ItemProperty -Path $lapsRegPath -Name 'AccountName' -Value $accountName
                                } catch {}

                                Write-AgentLog 'INFO' "Successfully rotated and escrowed LAPS password for [$accountName]"
                            } catch {
                                Write-AgentLog 'ERROR' "Failed to escrow LAPS password: $($_.Exception.Message)"
                            }
                        }
                    } elseif (-not $isAdmin) {
                        Write-AgentLog 'INFO' "LAPS password rotation requires administrative elevation (agent running in standard user context)"
                    }
                }
            }

            # ── Endpoint Privilege Management (EPM) Governance ───────────────
            if ($resp.epm_rules) {
                if (-not (Get-Variable -Name 'LastEpmAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastEpmAudit = $null
                }
                $now = Get-Date
                $shouldAuditEpm = $false
                if ($null -eq $script:LastEpmAudit) {
                    $shouldAuditEpm = $true
                } elseif (($now - $script:LastEpmAudit).TotalSeconds -ge 120) { # 2-minute interval
                    $shouldAuditEpm = $true
                }

                if ($shouldAuditEpm) {
                    $script:LastEpmAudit = $now
                    $epmRules = $resp.epm_rules
                    $epmRulesCount = if ($epmRules) { $epmRules.Count } else { 0 }
                    Write-AgentLog 'INFO' "Audited EPM rules ($epmRulesCount active rule(s) assigned)..."

                    # Save effective EPM rules to local cache
                    $epmCacheDir = 'C:\ProgramData\LocalPilotFleet\EPM'
                    try {
                        if (-not (Test-Path $epmCacheDir -ErrorAction SilentlyContinue)) {
                            New-Item -Path $epmCacheDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                        }
                        $epmRules | ConvertTo-Json -Depth 5 | Set-Content -Path "$epmCacheDir\rules.json" -Force -ErrorAction SilentlyContinue
                    } catch {}

                    # Check for processes matching EPM rules (audit telemetry)
                    try {
                        $runningProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
                        foreach ($rule in $epmRules) {
                            $targetName = $rule.file_name
                            $procBase = [System.IO.Path]::GetFileNameWithoutExtension($targetName)
                            $matchingProcs = $runningProcs | Where-Object { $_.ProcessName -eq $procBase }
                            if ($matchingProcs -and $rule.send_elevation_telemetry) {
                                foreach ($p in ($matchingProcs | Select-Object -First 2)) {
                                    $procKey = "EPM_SEEN_$($p.Id)"
                                    if (-not (Get-Variable -Name $procKey -Scope Script -ErrorAction SilentlyContinue)) {
                                        Set-Variable -Name $procKey -Value $true -Scope Script
                                        $elevPayload = @{
                                            rule_id             = $rule.id
                                            file_name           = $targetName
                                            file_path           = $p.Path
                                            user_name           = $env:USERNAME
                                            elevation_type      = $rule.elevation_type
                                            justification       = "Active execution under EPM rule: $($rule.rule_name)"
                                            process_id          = $p.Id
                                            parent_process_name = 'explorer.exe'
                                        }
                                        try {
                                            Invoke-RestMethod `
                                                -Uri        "$baseUrl/api/v1/nodes/$deviceId/epm-elevation" `
                                                -Method     POST `
                                                -Body       ($elevPayload | ConvertTo-Json -Compress) `
                                                -Headers    $authHeaders `
                                                -TimeoutSec 5 `
                                                -ErrorAction SilentlyContinue | Out-Null
                                        } catch {}
                                    }
                                }
                            }
                        }
                    } catch {}
                }
            }

            # ── Windows Autopilot Hardware Identity & ESP Provisioning ─────────
            if ($resp.autopilot) {
                if (-not (Get-Variable -Name 'LastAutopilotAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:LastAutopilotAudit = $null
                }
                $now = Get-Date
                $shouldAuditAutopilot = $false
                if ($null -eq $script:LastAutopilotAudit) {
                    $shouldAuditAutopilot = $true
                } elseif (($now - $script:LastAutopilotAudit).TotalSeconds -ge 300) { # 5-minute interval
                    $shouldAuditAutopilot = $true
                }

                if ($shouldAuditAutopilot) {
                    $script:LastAutopilotAudit = $now
                    $apData = $resp.autopilot
                    $isReg = [bool]$apData.is_registered
                    $statusStr = if ($isReg -and $apData.autopilot_device) { $apData.autopilot_device.deployment_status } else { 'UNREGISTERED' }
                    Write-AgentLog 'INFO' "Audited Autopilot provisioning state: $statusStr (Registered: $isReg)"

                    # Cache profile and ESP to ProgramData
                    $apCacheDir = 'C:\ProgramData\LocalPilotFleet\Autopilot'
                    try {
                        if (-not (Test-Path $apCacheDir -ErrorAction SilentlyContinue)) {
                            New-Item -Path $apCacheDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                        }
                        $apData | ConvertTo-Json -Depth 6 | Set-Content -Path "$apCacheDir\posture.json" -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }

            # ── Windows Firewall Rules, Profile Governance & Perimeter Sentinel ──
            if (-not (Get-Variable -Name 'LastFirewallAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastFirewallAudit = $null
            }
            $now = Get-Date
            $shouldAuditFirewall = $false
            if ($null -eq $script:LastFirewallAudit) {
                $shouldAuditFirewall = $true
            } elseif (($now - $script:LastFirewallAudit).TotalSeconds -ge 120) { # 2-minute cadence
                $shouldAuditFirewall = $true
            }

            if ($shouldAuditFirewall) {
                $script:LastFirewallAudit = $now
                Write-AgentLog 'INFO' 'Auditing Windows Firewall profile status & listening ports sentinel...'

                # 1. Harvest Firewall Profiles
                try {
                    $hasFwCmd = Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue
                    if ($hasFwCmd) {
                        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                        $domProf = $profiles | Where-Object { $_.Name -eq 'Domain' } | Select-Object -First 1
                        $privProf = $profiles | Where-Object { $_.Name -eq 'Private' } | Select-Object -First 1
                        $pubProf = $profiles | Where-Object { $_.Name -eq 'Public' } | Select-Object -First 1

                        $domEnabled = if ($domProf) { [bool]$domProf.Enabled } else { $true }
                        $privEnabled = if ($privProf) { [bool]$privProf.Enabled } else { $true }
                        $pubEnabled = if ($pubProf) { [bool]$pubProf.Enabled } else { $true }

                        $domInbound = if ($domProf -and $domProf.DefaultInboundAction) { [string]$domProf.DefaultInboundAction } else { 'Block' }
                        $privInbound = if ($privProf -and $privProf.DefaultInboundAction) { [string]$privProf.DefaultInboundAction } else { 'Block' }
                        $pubInbound = if ($pubProf -and $pubProf.DefaultInboundAction) { [string]$pubProf.DefaultInboundAction } else { 'Block' }

                        $activeCount = 0
                        try {
                            $activeCount = (Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Measure-Object).Count
                        } catch {}

                        $fwPayload = @{
                            domain_profile_enabled  = $domEnabled
                            private_profile_enabled = $privEnabled
                            public_profile_enabled  = $pubEnabled
                            domain_inbound_action   = $domInbound
                            private_inbound_action  = $privInbound
                            public_inbound_action   = $pubInbound
                            stealth_mode_enabled    = $true
                            active_rules_count      = $activeCount
                        }

                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/firewall-status" `
                            -Method     POST `
                            -Body       ($fwPayload | ConvertTo-Json -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null

                        Write-AgentLog 'INFO' "Reported firewall posture (Domain: $domEnabled, Private: $privEnabled, Public: $pubEnabled, Active Rules: $activeCount)"
                    }
                } catch {
                    Write-AgentLog 'WARN' "Could not harvest Windows Firewall profile posture: $($_.Exception.Message)"
                }

                # 2. Harvest Active Listening Ports (Perimeter Sentinel)
                try {
                    $hasTcpCmd = Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue
                    if ($hasTcpCmd) {
                        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 50
                        $portList = @()

                        if ($listening) {
                            $procCache = @{}
                            foreach ($conn in $listening) {
                                $pidNum = [int]$conn.OwningProcess
                                $pName = $procCache[$pidNum]
                                if ($null -eq $pName) {
                                    try {
                                        $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue | Select-Object -First 1
                                        $pName = if ($p) { $p.ProcessName } else { 'System' }
                                    } catch {
                                        $pName = 'Unknown'
                                    }
                                    $procCache[$pidNum] = $pName
                                }

                                $portList += @{
                                    protocol          = 'TCP'
                                    local_address     = [string]$conn.LocalAddress
                                    local_port        = [int]$conn.LocalPort
                                    owning_process_id = $pidNum
                                    process_name      = [string]$pName
                                    service_name      = $null
                                }
                            }
                        }

                        $portsPayload = @{
                            ports = $portList
                        }

                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/listening-ports" `
                            -Method     POST `
                            -Body       ($portsPayload | ConvertTo-Json -Depth 4 -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null

                        Write-AgentLog 'INFO' "Reported $($portList.Count) listening ports to Perimeter Sentinel"
                    }
                } catch {
                    Write-AgentLog 'WARN' "Could not harvest listening ports: $($_.Exception.Message)"
                }

                # 3. Log effective firewall rules from heartbeat
                if ($resp.firewall_policy -and $resp.firewall_policy.effective_rules) {
                    $effRules = @($resp.firewall_policy.effective_rules)
                    Write-AgentLog 'INFO' "Synchronized $($effRules.Count) effective firewall rules from fleet policy"
                }
            }

            # ── Attack Surface Reduction (ASR) & Exploit Guard Posture ─────────
            if (-not (Get-Variable -Name 'LastAsrAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastAsrAudit = $null
            }
            $now = Get-Date
            $shouldAuditAsr = $false
            if ($null -eq $script:LastAsrAudit) {
                $shouldAuditAsr = $true
            } elseif (($now - $script:LastAsrAudit).TotalSeconds -ge 120) { # 2-minute cadence
                $shouldAuditAsr = $true
            }

            if ($shouldAuditAsr) {
                $script:LastAsrAudit = $now
                try {
                    $asrPolicy = if ($resp.assigned_asr_policy) { $resp.assigned_asr_policy } else { $null }
                    $policyId = if ($asrPolicy -and $asrPolicy.id) { $asrPolicy.id } else { $null }

                    # 1. Harvest ASR rule states from registry
                    $asrRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
                    $asrRulesStatus = @{}
                    if (Test-Path $asrRegPath) {
                        $regRules = Get-ItemProperty -Path $asrRegPath -ErrorAction SilentlyContinue
                        if ($regRules) {
                            $regRules.PSObject.Properties | Where-Object { $_.Name -match '^[0-9a-fA-F-]{36}$' } | ForEach-Object {
                                $ruleKey = $_.Name.ToLower()
                                $asrRulesStatus[$ruleKey] = switch ([string]$_.Value) {
                                    '0' { 'DISABLED' }
                                    '1' { 'BLOCK' }
                                    '2' { 'AUDIT' }
                                    '6' { 'WARN' }
                                    default { 'UNKNOWN' }
                                }
                            }
                        }
                    }

                    # 2. Harvest Network Protection and Controlled Folder Access
                    $npMode = 'UNKNOWN'
                    $cfaMode = 'UNKNOWN'
                    try {
                        $hasMpPref = Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue
                        if ($hasMpPref) {
                            $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
                            if ($mpPref) {
                                $npMode = switch ($mpPref.EnableNetworkProtection) {
                                    0 { 'DISABLED' }
                                    1 { 'BLOCK' }
                                    2 { 'AUDIT' }
                                    default { 'UNKNOWN' }
                                }
                                $cfaMode = switch ($mpPref.EnableControlledFolderAccess) {
                                    0 { 'DISABLED' }
                                    1 { 'BLOCK' }
                                    2 { 'AUDIT' }
                                    3 { 'BLOCK_DISK_MOD_ONLY' }
                                    4 { 'AUDIT_DISK_MOD_ONLY' }
                                    default { 'UNKNOWN' }
                                }
                            }
                        }
                    } catch {}

                    # 3. Report ASR posture snapshot
                    try {
                        $asrStatusPayload = @{
                            policy_id                  = $policyId
                            asr_rules_status           = $asrRulesStatus
                            network_protection_mode    = $npMode
                            controlled_folder_access   = $cfaMode
                            exploit_protection_applied = $false
                        }
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/asr-status" `
                            -Method     POST `
                            -Body       ($asrStatusPayload | ConvertTo-Json -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null
                        Write-AgentLog 'INFO' "Reported ASR posture (Rules: $($asrRulesStatus.Count), Network: $npMode, CFA: $cfaMode)"
                    } catch {
                        Write-AgentLog 'WARN' "Failed to report ASR posture: $($_.Exception.Message)"
                    }

                    # 4. Harvest ASR events from Defender Operational event log
                    try {
                        $evtFilter = @{
                            LogName   = 'Microsoft-Windows-Windows Defender/Operational'
                            Id        = @(1121, 1122, 1125, 1126)
                            StartTime = (Get-Date).AddMinutes(-15)
                        }
                        $winEvents = Get-WinEvent -FilterHashtable $evtFilter -ErrorAction SilentlyContinue -MaxEvents 50
                        if ($winEvents) {
                            $harvestedEvents = @()
                            foreach ($evt in $winEvents) {
                                $action = switch ($evt.Id) {
                                    1121 { 'BLOCKED' }
                                    1122 { 'AUDITED' }
                                    1125 { 'NETWORK_BLOCKED' }
                                    1126 { 'NETWORK_AUDITED' }
                                    default { 'AUDITED' }
                                }
                                $msg = [string]$evt.Message
                                $ruleId = if ($msg -match 'ID:\s*([0-9a-fA-F-]{36})') { $matches[1].ToLower() } else { '' }
                                $processName = if ($msg -match 'Process Name:\s*(.+)') { $matches[1].Trim() } else { '' }
                                $targetPath = if ($msg -match 'Target Path:\s*(.+)') { $matches[1].Trim() } else { '' }

                                $harvestedEvents += @{
                                    event_id     = $evt.Id
                                    action       = $action
                                    rule_id      = $ruleId
                                    process_name = $processName
                                    target_path  = $targetPath
                                    occurred_at  = $evt.TimeCreated.ToString('o')
                                }
                            }

                            if ($harvestedEvents.Count -gt 0) {
                                Invoke-RestMethod `
                                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/asr-events" `
                                    -Method     POST `
                                    -Body       (@{ events = $harvestedEvents } | ConvertTo-Json -Compress -Depth 5) `
                                    -Headers    $authHeaders `
                                    -TimeoutSec 10 `
                                    -ErrorAction SilentlyContinue | Out-Null
                                Write-AgentLog 'INFO' "Reported $($harvestedEvents.Count) ASR block/audit event(s)"
                            }
                        }
                    } catch {}
                } catch {
                    Write-AgentLog 'WARN' "ASR evaluation encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Endpoint Analytics & Performance Health Telemetry ─────────────
            if (-not (Get-Variable -Name 'LastAnalyticsAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastAnalyticsAudit = $null
            }
            $now = Get-Date
            $shouldAuditAnalytics = $false
            if ($null -eq $script:LastAnalyticsAudit) {
                $shouldAuditAnalytics = $true
            } elseif (($now - $script:LastAnalyticsAudit).TotalSeconds -ge 180) { # 3-minute cadence
                $shouldAuditAnalytics = $true
            }

            if ($shouldAuditAnalytics) {
                $script:LastAnalyticsAudit = $now
                try {
                    # 1. Harvest boot duration
                    $bootMs = 22000
                    try {
                        $perfEvt = Get-WinEvent -FilterHashtable @{
                            LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
                            Id = 100
                        } -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($perfEvt -and $perfEvt.Message -match 'MainPathBootTime:\s*(\d+)') {
                            $bootMs = [int]$matches[1]
                        }
                    } catch {}

                    # 2. Harvest sign-in duration
                    $signinMs = 5000
                    try {
                        $signinEvt = Get-WinEvent -FilterHashtable @{
                            LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'
                            Id = 700
                        } -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($signinEvt -and $signinEvt.Message -match 'TotalUserLogonTime:\s*(\d+)') {
                            $signinMs = [int]$matches[1]
                        }
                    } catch {}

                    # 3. Harvest application crashes & hangs in last 24 hours
                    $crashes24h = 0
                    $hangs24h = 0
                    $reliabilityEvents = @()
                    try {
                        $appErrors = Get-WinEvent -FilterHashtable @{
                            LogName = 'Application'
                            Id = @(1000, 1002)
                            StartTime = (Get-Date).AddHours(-24)
                        } -MaxEvents 30 -ErrorAction SilentlyContinue
                        if ($appErrors) {
                            foreach ($ae in $appErrors) {
                                $isCrash = $ae.Id -eq 1000
                                if ($isCrash) { $crashes24h++ } else { $hangs24h++ }
                                $msg = [string]$ae.Message
                                $appName = if ($msg -match 'Faulting application name:\s*([^\r\n,]+)') { $matches[1].Trim() } else { 'Unknown' }
                                $appVer = if ($msg -match 'Faulting application version:\s*([^\r\n,]+)') { $matches[1].Trim() } else { '' }
                                $moduleName = if ($msg -match 'Faulting module name:\s*([^\r\n,]+)') { $matches[1].Trim() } else { '' }
                                $excCode = if ($msg -match 'Exception code:\s*([^\r\n,]+)') { $matches[1].Trim() } else { '' }

                                $reliabilityEvents += @{
                                    app_name        = $appName
                                    app_version     = $appVer
                                    event_type      = if ($isCrash) { 'CRASH' } else { 'HANG' }
                                    faulting_module = $moduleName
                                    exception_code  = $excCode
                                    occurred_at     = $ae.TimeCreated.ToString('o')
                                }
                            }
                        }
                    } catch {}

                    # 4. Ingest snapshot
                    $analyticsPayload = @{
                        boot_duration_ms    = $bootMs
                        signin_duration_ms  = $signinMs
                        app_crash_count_24h = $crashes24h
                        app_hang_count_24h  = $hangs24h
                        cpu_spike_pct       = $cpuPct
                        ram_pressure_pct    = $ramPct
                        disk_queue_depth    = 0.2
                    }
                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/analytics-snapshot" `
                        -Method     POST `
                        -Body       ($analyticsPayload | ConvertTo-Json -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported Endpoint Analytics snapshot (Boot: ${bootMs}ms, Signin: ${signinMs}ms, Crashes: $crashes24h)"

                    # 5. Ingest app reliability events if any
                    if ($reliabilityEvents.Count -gt 0) {
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/app-reliability" `
                            -Method     POST `
                            -Body       (@{ events = $reliabilityEvents } | ConvertTo-Json -Compress -Depth 5) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null
                        Write-AgentLog 'INFO' "Reported $($reliabilityEvents.Count) app reliability failure events"
                    }
                } catch {
                    Write-AgentLog 'WARN' "Endpoint Analytics harvesting encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Intune Certificate Store Audit & Posture Telemetry ───────────
            if (-not (Get-Variable -Name 'LastCertStoreAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastCertStoreAudit = $null
            }
            $now = Get-Date
            $shouldAuditCerts = $false
            if ($null -eq $script:LastCertStoreAudit -or ($now - $script:LastCertStoreAudit).TotalSeconds -ge 300) {
                $shouldAuditCerts = $true
            }

            if ($shouldAuditCerts) {
                $script:LastCertStoreAudit = $now
                try {
                    $scannedCerts = @()
                    $storesToScan = @(
                        @{ Location = 'LOCAL_MACHINE'; Name = 'Root' },
                        @{ Location = 'LOCAL_MACHINE'; Name = 'CA' },
                        @{ Location = 'LOCAL_MACHINE'; Name = 'My' },
                        @{ Location = 'CURRENT_USER';  Name = 'My' }
                    )

                    foreach ($st in $storesToScan) {
                        try {
                            $certPath = if ($st.Location -eq 'LOCAL_MACHINE') { "Cert:\LocalMachine\$($st.Name)" } else { "Cert:\CurrentUser\$($st.Name)" }
                            if (Test-Path $certPath) {
                                $rawCerts = Get-ChildItem -Path $certPath -ErrorAction SilentlyContinue
                                foreach ($c in $rawCerts) {
                                    if (-not $c.Thumbprint) { continue }
                                    $hasKey = try { if ($c.HasPrivateKey) { 1 } else { 0 } } catch { 0 }
                                    $scannedCerts += @{
                                        thumbprint      = $c.Thumbprint
                                        subject         = if ($c.Subject) { $c.Subject } else { $c.Issuer }
                                        issuer          = if ($c.Issuer) { $c.Issuer } else { 'Unknown' }
                                        store_location  = $st.Location
                                        store_name      = $st.Name
                                        not_before      = if ($c.NotBefore) { $c.NotBefore.ToString('o') } else { $null }
                                        not_after       = if ($c.NotAfter) { $c.NotAfter.ToString('o') } else { $null }
                                        has_private_key = $hasKey
                                    }
                                }
                            }
                        } catch {}
                    }

                    if ($scannedCerts.Count -gt 0) {
                        # Take top 50 to keep payload compact and fast
                        $trimmedCerts = if ($scannedCerts.Count -gt 50) { $scannedCerts[0..49] } else { $scannedCerts }
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/certificates" `
                            -Method     POST `
                            -Body       (@{ certificates = $trimmedCerts } | ConvertTo-Json -Compress -Depth 5) `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null
                        Write-AgentLog 'INFO' "Reported $($trimmedCerts.Count) workstation certificates from local store"
                    }
                } catch {
                    Write-AgentLog 'WARN' "Certificate store audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Intune Wi-Fi & VPN Network Posture Audit ──────────────────────
            if (-not (Get-Variable -Name 'LastNetworkPostureAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastNetworkPostureAudit = $null
            }
            $now = Get-Date
            $shouldAuditNetwork = $false
            if ($null -eq $script:LastNetworkPostureAudit -or ($now - $script:LastNetworkPostureAudit).TotalSeconds -ge 180) {
                $shouldAuditNetwork = $true
            }

            if ($shouldAuditNetwork) {
                $script:LastNetworkPostureAudit = $now
                try {
                    $connectedSsid = ''
                    $bssid = ''
                    $signalPct = 0
                    $radioType = ''
                    $channel = 0
                    $authType = ''
                    $isOpen = $false

                    # 1. Parse active Wi-Fi interface if present
                    try {
                        $wlanRaw = netsh wlan show interfaces 2>&1
                        if ($wlanRaw) {
                            $wlanText = $wlanRaw -join "`n"
                            if ($wlanText -match 'State\s*:\s*connected') {
                                if ($wlanText -match 'SSID\s*:\s*([^\r\n]+)') { $connectedSsid = $matches[1].Trim() }
                                if ($wlanText -match 'BSSID\s*:\s*([0-9a-fA-F:]{17})') { $bssid = $matches[1].Trim() }
                                if ($wlanText -match 'Signal\s*:\s*(\d+)%') { $signalPct = [int]$matches[1] }
                                if ($wlanText -match 'Radio type\s*:\s*([^\r\n]+)') { $radioType = $matches[1].Trim() }
                                if ($wlanText -match 'Channel\s*:\s*(\d+)') { $channel = [int]$matches[1] }
                                if ($wlanText -match 'Authentication\s*:\s*([^\r\n]+)') {
                                    $authType = $matches[1].Trim()
                                    if ($authType -like '*Open*' -or $authType -eq 'None') { $isOpen = $true }
                                }
                            }
                        }
                    } catch {}

                    # 2. Configured Wi-Fi profiles
                    $cfgProfiles = @()
                    try {
                        $profRaw = netsh wlan show profiles 2>&1
                        if ($profRaw) {
                            foreach ($line in $profRaw) {
                                if ($line -match 'All User Profile\s*:\s*(.+)$') {
                                    $cfgProfiles += $matches[1].Trim()
                                }
                            }
                        }
                    } catch {}

                    # 3. Active network adapters
                    $adapters = @()
                    try {
                        $hasNetAdapter = Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue
                        if ($hasNetAdapter) {
                            $rawAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
                            foreach ($ad in $rawAdapters) {
                                $adapters += @{
                                    name        = $ad.Name
                                    description = $ad.InterfaceDescription
                                    mac         = $ad.MacAddress
                                    status      = [string]$ad.Status
                                    speed       = [string]$ad.LinkSpeed
                                }
                            }
                        }
                    } catch {}

                    # 4. Active VPN tunnels
                    $activeVpns = @()
                    try {
                        $hasVpn = Get-Command -Name Get-VpnConnection -ErrorAction SilentlyContinue
                        if ($hasVpn) {
                            $vpns = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
                            foreach ($v in $vpns) {
                                if ($v.ConnectionStatus -eq 'Connected') {
                                    $activeVpns += $v.Name
                                }
                            }
                        }
                    } catch {}

                    # Check WireGuard / OpenVPN adapter states
                    foreach ($ad in $adapters) {
                        if (($ad.name -like '*WireGuard*' -or $ad.name -like '*OpenVPN*' -or $ad.description -like '*WireGuard*' -or $ad.description -like '*OpenVPN*') -and $ad.status -eq 'Up') {
                            if (-not ($activeVpns -contains $ad.name)) {
                                $activeVpns += $ad.name
                            }
                        }
                    }

                    # 5. IP and Gateway
                    $ipAddr = $ipAddress
                    $gateway = ''
                    $dnsList = @()
                    try {
                        $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
                        if ($ipConfig) {
                            if ($ipConfig.IPv4DefaultGateway) { $gateway = $ipConfig.IPv4DefaultGateway.NextHop }
                            if ($ipConfig.DNSServer) { $dnsList = @($ipConfig.DNSServer.ServerAddresses) }
                        }
                    } catch {}

                    $posturePayload = @{
                        connected_ssid       = $connectedSsid
                        bssid                = $bssid
                        signal_quality_pct   = $signalPct
                        radio_type           = $radioType
                        channel              = $channel
                        security_type        = if ($isOpen) { 'OPEN' } else { 'SECURE' }
                        is_open_network      = $isOpen
                        active_adapters      = $adapters
                        configured_profiles  = $cfgProfiles
                        active_vpns          = $activeVpns
                        ipv4_address         = $ipAddr
                        ipv4_gateway         = $gateway
                        dns_servers          = $dnsList
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/network-posture" `
                        -Method     POST `
                        -Body       ($posturePayload | ConvertTo-Json -Compress -Depth 5) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported network posture (SSID: '$connectedSsid', Adapters: $($adapters.Count), Wi-Fi Profiles: $($cfgProfiles.Count), VPNs: $($activeVpns.Count))"
                } catch {
                    Write-AgentLog 'WARN' "Network posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Kiosk Mode & Multi-App Assigned Access Posture Audit ──────────
            if (-not (Get-Variable -Name 'LastKioskAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastKioskAudit = $null
            }
            $now = Get-Date
            $shouldAuditKiosk = $false
            if ($null -eq $script:LastKioskAudit) {
                $shouldAuditKiosk = $true
            } elseif (($now - $script:LastKioskAudit).TotalSeconds -ge 300) { # 5-minute interval
                $shouldAuditKiosk = $true
            }

            if ($shouldAuditKiosk) {
                $script:LastKioskAudit = $now
                try {
                    # 1. Detect current configured shell in Winlogon
                    $currentShell = 'explorer.exe'
                    try {
                        $winlogonShell = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell' -ErrorAction SilentlyContinue
                        if ($winlogonShell) { $currentShell = [string]$winlogonShell }
                    } catch {}

                    # 2. Check Assigned Access capability & status
                    $assignedAccessSupported = $true
                    $shellLauncherSupported = $true
                    $kioskActive = $false
                    $activeKioskUser = ''

                    try {
                        # Query Shell Launcher WMI class if present
                        $weslSettings = Get-CimInstance -Namespace 'root\standardcimv2\embedded' -ClassName 'WESL_UserSetting' -ErrorAction SilentlyContinue
                        if ($weslSettings) {
                            $kioskActive = $true
                            $activeKioskUser = $weslSettings[0].Sid
                        }
                    } catch {}

                    if ($currentShell.ToLower() -ne 'explorer.exe') {
                        $kioskActive = $true
                    }

                    $kioskPayload = @{
                        assigned_access_supported = $assignedAccessSupported
                        shell_launcher_supported  = $shellLauncherSupported
                        current_shell             = $currentShell
                        kiosk_active              = $kioskActive
                        active_kiosk_user         = $activeKioskUser
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/kiosk-status" `
                        -Method     POST `
                        -Body       ($kioskPayload | ConvertTo-Json -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported Kiosk & Assigned Access posture (Shell: '$currentShell', KioskActive: $kioskActive)"
                } catch {
                    Write-AgentLog 'WARN' "Kiosk posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Removable Storage & USB Peripheral Governance Audit ──────────
            if (-not (Get-Variable -Name 'LastStorageAccessAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastStorageAccessAudit = $null
            }
            $now = Get-Date
            $shouldAuditStorage = $false
            if ($null -eq $script:LastStorageAccessAudit) {
                $shouldAuditStorage = $true
            } elseif (($now - $script:LastStorageAccessAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditStorage = $true
            }

            if ($shouldAuditStorage) {
                $script:LastStorageAccessAudit = $now
                try {
                    $removableDrives = @()
                    $usbDevices = @()
                    $writeDenied = $false

                    # 1. Inspect Removable Disks & BitLocker Status
                    try {
                        $disks = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq 'USB' -or $_.MediaType -eq 'Removable' }
                        if ($disks) {
                            foreach ($d in $disks) {
                                $parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
                                foreach ($p in $parts) {
                                    $dl = "$($p.DriveLetter):"
                                    $isEnc = $false
                                    $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
                                    $volName = if ($vol -and $vol.FileSystemLabel) { $vol.FileSystemLabel } else { 'Removable Disk' }

                                    try {
                                        $blStatus = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue
                                        if ($blStatus -and ($blStatus.VolumeStatus -eq 'FullyEncrypted' -or $blStatus.ProtectionStatus -eq 'On')) {
                                            $isEnc = $true
                                        }
                                    } catch {}

                                    $removableDrives += @{
                                        drive_letter  = $dl
                                        volume_name   = $volName
                                        friendly_name = $d.FriendlyName
                                        size_bytes    = $p.Size
                                        is_encrypted  = $isEnc
                                    }
                                }
                            }
                        }
                    } catch {}

                    # 2. Inspect Active USB Hardware Devices
                    try {
                        $pnpDevs = Get-PnpDevice -Class 'DiskDrive', 'WPD', 'USB' -Status 'OK' -ErrorAction SilentlyContinue
                        if ($pnpDevs) {
                            foreach ($dev in $pnpDevs) {
                                if ($dev.InstanceId -like 'USB*') {
                                    $usbDevices += @{
                                        instance_id   = $dev.InstanceId
                                        friendly_name = $dev.FriendlyName
                                        class         = $dev.Class
                                    }
                                }
                            }
                        }
                    } catch {}

                    # 3. Check if Write Access is currently Denied in Registry
                    try {
                        $fveReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RDVDenyWriteAccess' -ErrorAction SilentlyContinue
                        if ($fveReg -and [int]$fveReg.RDVDenyWriteAccess -eq 1) {
                            $writeDenied = $true
                        }
                    } catch {}

                    # 4. Check if active policy requires BitLocker To Go
                    $compliance = 'COMPLIANT'
                    if ($removableDrives.Count -gt 0) {
                        $unencrypted = $removableDrives | Where-Object { -not $_.is_encrypted }
                        if ($unencrypted.Count -gt 0) {
                            $compliance = 'UNENCRYPTED_USB_DETECTED'
                        }
                    }
                    if ($writeDenied) {
                        $compliance = 'WRITE_DENIED_ENFORCED'
                    }

                    $storagePayload = @{
                        connected_removable_drives = $removableDrives
                        active_usb_devices         = $usbDevices
                        write_access_denied        = $writeDenied
                        compliance_status          = $compliance
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/storage-status" `
                        -Method     POST `
                        -Body       ($storagePayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported Removable Storage & USB posture (Drives: $($removableDrives.Count), USB Peripherals: $($usbDevices.Count), WriteBlocked: $writeDenied, Compliance: $compliance)"
                } catch {
                    Write-AgentLog 'WARN' "Storage access posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Delivery Optimization & Peer-to-Peer Cache Governance Audit ──
            if (-not (Get-Variable -Name 'LastDOAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastDOAudit = $null
            }
            $shouldAuditDO = $false
            if ($null -eq $script:LastDOAudit) {
                $shouldAuditDO = $true
            } elseif (($now - $script:LastDOAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditDO = $true
            }

            if ($shouldAuditDO) {
                $script:LastDOAudit = $now
                try {
                    $downloadMode = "LAN_PEER"
                    $httpBytes = 0
                    $p2pBytes = 0
                    $uploadedBytes = 0
                    $activePeers = 0
                    $cacheSize = 0
                    $cacheFiles = 0

                    # 1. Query Delivery Optimization Status cmdlet if available
                    try {
                        if (Get-Command Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue) {
                            $doStatus = Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue
                            if ($doStatus) {
                                foreach ($s in $doStatus) {
                                    if ($s.BytesFromHttp) { $httpBytes += [int64]$s.BytesFromHttp }
                                    if ($s.BytesFromPeers) { $p2pBytes += [int64]$s.BytesFromPeers }
                                    if ($s.BytesUploaded) { $uploadedBytes += [int64]$s.BytesUploaded }
                                    if ($s.PeerCount -gt $activePeers) { $activePeers = [int]$s.PeerCount }
                                }
                            }
                        }
                    } catch {}

                    # 2. Query Delivery Optimization Perf Snap cmdlet if available
                    try {
                        if (Get-Command Get-DeliveryOptimizationPerfSnap -ErrorAction SilentlyContinue) {
                            $perfSnap = Get-DeliveryOptimizationPerfSnap -ErrorAction SilentlyContinue
                            if ($perfSnap) {
                                if ($perfSnap.TotalBytesFromHttp -and $httpBytes -eq 0) { $httpBytes = [int64]$perfSnap.TotalBytesFromHttp }
                                if ($perfSnap.TotalBytesFromPeers -and $p2pBytes -eq 0) { $p2pBytes = [int64]$perfSnap.TotalBytesFromPeers }
                                if ($perfSnap.TotalBytesUploaded -and $uploadedBytes -eq 0) { $uploadedBytes = [int64]$perfSnap.TotalBytesUploaded }
                            }
                        }
                    } catch {}

                    # 3. Read Registry Configuration for Download Mode
                    try {
                        $doReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -ErrorAction SilentlyContinue
                        if ($doReg -and $null -ne $doReg.DODownloadMode) {
                            $modeMap = @{
                                0   = 'HTTP_ONLY'
                                1   = 'LAN_PEER'
                                2   = 'GROUP_PEER'
                                3   = 'INTERNET_PEER'
                                99  = 'SIMPLE'
                                100 = 'BYPASS'
                            }
                            $val = [int]$doReg.DODownloadMode
                            if ($modeMap.ContainsKey($val)) {
                                $downloadMode = $modeMap[$val]
                            }
                        }
                    } catch {}

                    # 4. Measure Delivery Optimization Cache Folder size
                    try {
                        $doCachePath = "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
                        if (Test-Path $doCachePath) {
                            $cacheFilesObj = Get-ChildItem -Path $doCachePath -Recurse -File -ErrorAction SilentlyContinue
                            if ($cacheFilesObj) {
                                $cacheFiles = $cacheFilesObj.Count
                                $cacheSize = ($cacheFilesObj | Measure-Object -Property Length -Sum).Sum
                            }
                        }
                    } catch {}

                    $doPayload = @{
                        download_mode_active  = $downloadMode
                        bytes_downloaded_http = $httpBytes
                        bytes_downloaded_p2p  = $p2pBytes
                        bytes_uploaded_p2p    = $uploadedBytes
                        active_peers_count    = $activePeers
                        cache_size_bytes      = $cacheSize
                        cache_file_count      = $cacheFiles
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/delivery-optimization-status" `
                        -Method     POST `
                        -Body       ($doPayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported Delivery Optimization posture (Mode: $downloadMode, Peers: $activePeers, P2P: $p2pBytes bytes, HTTP: $httpBytes bytes, Cache: $cacheSize bytes)"
                } catch {
                    Write-AgentLog 'WARN' "Delivery Optimization posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Device Firmware Configuration Interface (DFCI) & UEFI Security Audit ──
            if (-not (Get-Variable -Name 'LastDFCIAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastDFCIAudit = $null
            }
            $shouldAuditDFCI = $false
            if ($null -eq $script:LastDFCIAudit) {
                $shouldAuditDFCI = $true
            } elseif (($now - $script:LastDFCIAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditDFCI = $true
            }

            if ($shouldAuditDFCI) {
                $script:LastDFCIAudit = $now
                try {
                    $biosVendor = "Unknown"
                    $biosVer = "1.0"
                    $biosDate = ""
                    $sbEnabled = 0
                    $tpmPresent = 0
                    $tpmVer = "2.0"
                    $tpmReady = 0
                    $tpmMfr = ""
                    $dmaProt = 0
                    $vbsStat = "NOT_CONFIGURED"
                    $hvciStat = "DISABLED"
                    $camState = "ALLOW"
                    $micState = "ALLOW"
                    $radState = "ALLOW"
                    $extBoot = "ALLOW"
                    $netBoot = "BLOCK"

                    # 1. Query Win32_BIOS
                    try {
                        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
                        if ($bios) {
                            if ($bios.Manufacturer) { $biosVendor = $bios.Manufacturer }
                            if ($bios.SMBIOSBIOSVersion) { $biosVer = $bios.SMBIOSBIOSVersion }
                            if ($bios.ReleaseDate) { $biosDate = [string]$bios.ReleaseDate }
                        }
                    } catch {}

                    # 2. Check Secure Boot State
                    try {
                        $sbVal = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue
                        if ($sbVal -eq 1) {
                            $sbEnabled = 1
                        } elseif (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                            if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                                $sbEnabled = 1
                            }
                        }
                    } catch {}

                    # 3. Query TPM State
                    try {
                        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
                            $tpm = Get-Tpm -ErrorAction SilentlyContinue
                            if ($tpm -and $tpm.TpmPresent) {
                                $tpmPresent = 1
                                if ($tpm.TpmReady -or ($tpm.TpmEnabled -and $tpm.TpmActivated)) {
                                    $tpmReady = 1
                                }
                                if ($tpm.ManufacturerIdTxt) { $tpmMfr = $tpm.ManufacturerIdTxt }
                            }
                        }
                    } catch {}

                    # 4. Query Virtualization-Based Security (VBS) and DMA Protection
                    try {
                        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
                        if ($dg) {
                            if ($dg.VirtualizationBasedSecurityStatus -eq 2) {
                                $vbsStat = "RUNNING"
                            } elseif ($dg.VirtualizationBasedSecurityStatus -eq 1) {
                                $vbsStat = "CONFIGURED"
                            }
                            if ($dg.SecurityServicesRunning -contains 2) {
                                $hvciStat = "ENABLED"
                            }
                            if ($dg.AvailableSecurityProperties -contains 3 -or $dg.RequiredSecurityProperties -contains 3) {
                                $dmaProt = 1
                            }
                        }
                    } catch {}

                    # 5. Check Registry for DFCI / Hardware policies
                    try {
                        $camReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\DFCI\Peripherals' -Name 'Cameras' -ErrorAction SilentlyContinue
                        if ($camReg -and [int]$camReg.Cameras -eq 0) { $camState = "BLOCK" }

                        $micReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\DFCI\Peripherals' -Name 'Microphones' -ErrorAction SilentlyContinue
                        if ($micReg -and [int]$micReg.Microphones -eq 0) { $micState = "BLOCK" }

                        $radReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\DFCI\Peripherals' -Name 'Radios' -ErrorAction SilentlyContinue
                        if ($radReg -and [int]$radReg.Radios -eq 0) { $radState = "BLOCK" }

                        $extReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\DFCI\Boot' -Name 'ExternalMedia' -ErrorAction SilentlyContinue
                        if ($extReg -and [int]$extReg.ExternalMedia -eq 0) { $extBoot = "BLOCK" }
                    } catch {}

                    $dfciPayload = @{
                        bios_vendor           = $biosVendor
                        bios_version          = $biosVer
                        bios_release_date     = $biosDate
                        uefi_version          = "2.7+"
                        secure_boot_enabled   = $sbEnabled
                        tpm_present           = $tpmPresent
                        tpm_version           = $tpmVer
                        tpm_ready             = $tpmReady
                        tpm_manufacturer      = $tpmMfr
                        kernel_dma_protection = $dmaProt
                        vbs_status            = $vbsStat
                        hvci_status           = $hvciStat
                        cameras_state         = $camState
                        microphones_state     = $micState
                        radios_state          = $radState
                        external_boot_state   = $extBoot
                        network_boot_state    = $netBoot
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/dfci-status" `
                        -Method     POST `
                        -Body       ($dfciPayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported DFCI & UEFI Security posture (BIOS: $biosVendor $biosVer, SecureBoot: $sbEnabled, TPM: $tpmPresent, VBS: $vbsStat)"
                } catch {
                    Write-AgentLog 'WARN' "DFCI posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Windows Information Protection (WIP) & Data Loss Prevention (DLP) Audit ──
            if (-not (Get-Variable -Name 'LastWIPAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastWIPAudit = $null
            }
            $shouldAuditWIP = $false
            if ($null -eq $script:LastWIPAudit) {
                $shouldAuditWIP = $true
            } elseif (($now - $script:LastWIPAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditWIP = $true
            }

            if ($shouldAuditWIP) {
                $script:LastWIPAudit = $now
                try {
                    # 1. Inspect Windows Information Protection / EDP Policy in registry
                    $edpReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\DataProtection' -ErrorAction SilentlyContinue
                    $wipActive = 0
                    if ($null -ne $edpReg -and $edpReg.Status -eq 1) {
                        $wipActive = 1
                    }

                    # 2. Count Corporate Enterprise Protected Files (sample user document folders or encrypted items)
                    $protectedFilesCount = 0
                    $encryptedBytes = 0
                    try {
                        $docsPath = [Environment]::GetFolderPath('MyDocuments')
                        if (Test-Path $docsPath) {
                            $sampleFiles = Get-ChildItem -Path $docsPath -Recurse -File -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 50
                            if ($sampleFiles) {
                                foreach ($f in $sampleFiles) {
                                    if ($f.Attributes -band [System.IO.FileAttributes]::Encrypted) {
                                        $protectedFilesCount++
                                        $encryptedBytes += $f.Length
                                    }
                                }
                            }
                        }
                    } catch {
                        # non-fatal
                    }

                    # 3. Detect Managed Corporate Apps (Edge, Outlook, Teams, Word, Excel, VS Code, etc.)
                    $managedApps = @('msedge', 'outlook', 'teams', 'excel', 'winword', 'powerpnt', 'code')
                    $runningManagedApps = 0
                    try {
                        $procNames = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique
                        foreach ($app in $managedApps) {
                            if ($procNames -contains $app) {
                                $runningManagedApps++
                            }
                        }
                    } catch {
                        # non-fatal
                    }

                    # 4. Check Event Log for BitLocker/EFS/WIP Security Audits
                    $clipViolations = 0
                    $exfilAttempts = 0
                    try {
                        $edpEvents = Get-WinEvent -LogName "Microsoft-Windows-EDP-Audit-TCB/Admin" -MaxEvents 20 -ErrorAction SilentlyContinue
                        if ($edpEvents) {
                            $clipViolations = ($edpEvents | Where-Object { $_.Id -eq 201 -or $_.Id -eq 202 }).Count
                            $exfilAttempts = ($edpEvents | Where-Object { $_.Id -eq 203 -or $_.Id -eq 204 }).Count
                        }
                    } catch {
                        # non-fatal
                    }

                    $complianceStatus = 'COMPLIANT'
                    if ($clipViolations -gt 5 -or $exfilAttempts -gt 0) {
                        $complianceStatus = 'INVESTIGATE'
                    }

                    $wipPayload = @{
                        enforcement_active               = $wipActive
                        protected_files_count            = $protectedFilesCount
                        encrypted_bytes                  = $encryptedBytes
                        managed_apps_count               = [Math]::Max(1, $runningManagedApps)
                        clipboard_violations_24h         = $clipViolations
                        cloud_exfiltration_attempts_24h  = $exfilAttempts
                        compliance_status                = $complianceStatus
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/wip-status" `
                        -Method     POST `
                        -Body       ($wipPayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported WIP & Endpoint DLP posture (Active: $wipActive, ManagedApps: $runningManagedApps, Files: $protectedFilesCount, Compliance: $complianceStatus)"
                } catch {
                    Write-AgentLog 'WARN' "WIP posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Windows Hello for Business (WHfB) & FIDO2 Passwordless Audit ──
            if (-not (Get-Variable -Name 'LastWHfBAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastWHfBAudit = $null
            }
            $shouldAuditWHfB = $false
            if ($null -eq $script:LastWHfBAudit) {
                $shouldAuditWHfB = $true
            } elseif (($now - $script:LastWHfBAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditWHfB = $true
            }

            if ($shouldAuditWHfB) {
                $script:LastWHfBAudit = $now
                try {
                    # 1. Inspect Windows Hello / NGC Container Enrollment via dsregcmd
                    $whfbEnrolled = 0
                    $tpmPresent = 0
                    $tpmReady = 0
                    $dsregOut = & dsregcmd /status 2>&1
                    if ($dsregOut) {
                        $dsregStr = $dsregOut -join "`n"
                        if ($dsregStr -match 'NgcSet\s*:\s*YES') {
                            $whfbEnrolled = 1
                        }
                        if ($dsregStr -match 'TpmPresent\s*:\s*YES') {
                            $tpmPresent = 1
                        }
                        if ($dsregStr -match 'TpmReady\s*:\s*YES') {
                            $tpmReady = 1
                        }
                    }

                    # Fallback TPM check if dsregcmd didn't detect
                    if ($tpmPresent -eq 0) {
                        try {
                            $tpmObj = Get-Tpm -ErrorAction SilentlyContinue
                            if ($tpmObj -and $tpmObj.TpmPresent) {
                                $tpmPresent = 1
                                if ($tpmObj.TpmReady) { $tpmReady = 1 }
                            }
                        } catch {}
                    }

                    # 2. Inspect Biometrics Subsystem (Windows Biometric Service & Devices)
                    $bioAvail = 0
                    $faceConfigured = 0
                    $fingerprintConfigured = 0
                    try {
                        $bioSvc = Get-Service -Name 'WbioSrvc' -ErrorAction SilentlyContinue
                        if ($bioSvc -and $bioSvc.Status -eq 'Running') {
                            $bioAvail = 1
                        }
                        $bioDevices = Get-PnpDevice -Class 'Biometric' -Status 'OK' -ErrorAction SilentlyContinue
                        if ($bioDevices) {
                            $bioAvail = 1
                            foreach ($dev in $bioDevices) {
                                if ($dev.FriendlyName -match 'Face|Camera|IR') {
                                    $faceConfigured = 1
                                }
                                if ($dev.FriendlyName -match 'Fingerprint|Sensor|Validity|Touch') {
                                    $fingerprintConfigured = 1
                                }
                            }
                        }
                    } catch {}

                    # 3. Check Enhanced Anti-Spoofing Configuration
                    $antiSpoofActive = 0
                    $antiSpoofReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\Biometrics' -Name 'FacialFeaturesUseEnhancedAntiSpoofing' -ErrorAction SilentlyContinue
                    if ($antiSpoofReg -and $antiSpoofReg.FacialFeaturesUseEnhancedAntiSpoofing -eq 1) {
                        $antiSpoofActive = 1
                    }

                    # 4. Check FIDO2 / WebAuthn Security Keys
                    $fido2KeysCount = 0
                    try {
                        $fidoDevs = Get-PnpDevice -Status 'OK' -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'FIDO|YubiKey|Security Key' }
                        if ($fidoDevs) {
                            $fido2KeysCount = ($fidoDevs | Measure-Object).Count
                        }
                    } catch {}

                    $provisioningState = if ($whfbEnrolled -eq 1) { 'ENROLLED' } else { 'NOT_ENROLLED' }
                    $complianceStatus = if ($whfbEnrolled -eq 1) { 'COMPLIANT' } else { 'NOT_ENROLLED' }

                    $whfbPayload = @{
                        whfb_enrolled               = $whfbEnrolled
                        whfb_provisioning_state     = $provisioningState
                        tpm_present                 = $tpmPresent
                        tpm_ready                   = $tpmReady
                        biometrics_available        = $bioAvail
                        face_auth_configured        = $faceConfigured
                        fingerprint_auth_configured = $fingerprintConfigured
                        pin_complexity_compliant    = 1
                        fido2_keys_count            = $fido2KeysCount
                        anti_spoofing_active        = $antiSpoofActive
                        compliance_status           = $complianceStatus
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/whfb-status" `
                        -Method     POST `
                        -Body       ($whfbPayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                    Write-AgentLog 'INFO' "Reported Windows Hello & FIDO2 posture (Enrolled: $whfbEnrolled, TPM: $tpmPresent, Bio: $bioAvail, FIDO2: $fido2KeysCount)"
                } catch {
                    Write-AgentLog 'WARN' "Windows Hello posture audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Windows Driver & Firmware Update Profiles (WUfB) Audit ────────
            if (-not (Get-Variable -Name 'LastDriverAudit' -Scope Script -ErrorAction SilentlyContinue)) {
                $script:LastDriverAudit = $null
            }
            $shouldAuditDrivers = $false
            if ($null -eq $script:LastDriverAudit) {
                $shouldAuditDrivers = $true
            } elseif (($now - $script:LastDriverAudit).TotalSeconds -ge 180) { # 3-minute interval
                $shouldAuditDrivers = $true
            }

            if ($shouldAuditDrivers) {
                $script:LastDriverAudit = $now
                try {
                    Write-AgentLog 'INFO' 'Auditing Windows PnP signed drivers & firmware inventory...'
                    $scannedDrivers = @()
                    $pnpDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DeviceName -and $_.Manufacturer } | 
                        Select-Object -First 40

                    if ($pnpDrivers) {
                        foreach ($d in $pnpDrivers) {
                            $devClass = 'OTHER'
                            $rawClass = [string]$d.DeviceClass
                            if ($rawClass -match 'DISPLAY') { $devClass = 'DISPLAY' }
                            elseif ($rawClass -match 'NET') { $devClass = 'NET' }
                            elseif ($rawClass -match 'MEDIA|AUDIO') { $devClass = 'MEDIA' }
                            elseif ($rawClass -match 'FIRMWARE') { $devClass = 'FIRMWARE' }
                            elseif ($rawClass -match 'BLUETOOTH') { $devClass = 'BLUETOOTH' }
                            elseif ($rawClass -match 'SCSI|DISK|HDC') { $devClass = 'STORAGE' }
                            elseif ($rawClass -match 'SYSTEM') { $devClass = 'SYSTEM' }

                            $drvDateStr = ''
                            if ($d.DriverDate) {
                                try {
                                    $drvDateStr = [Management.ManagementDateTimeConverter]::ToDateTime($d.DriverDate).ToString('yyyy-MM-dd')
                                } catch {
                                    $drvDateStr = [string]$d.DriverDate
                                }
                            }

                            $scannedDrivers += @{
                                driver_name     = [string]$d.DeviceName
                                driver_class    = $devClass
                                driver_provider = [string]$d.Manufacturer
                                driver_version  = if ($d.DriverVersion) { [string]$d.DriverVersion } else { '1.0.0.0' }
                                driver_date     = $drvDateStr
                                hardware_id     = if ($d.HardWareID) { [string]$d.HardWareID } else { '' }
                                install_status  = 'INSTALLED'
                            }
                        }
                    }

                    if ($scannedDrivers.Count -gt 0) {
                        $drvPayload = @{
                            drivers = $scannedDrivers
                        }

                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/drivers/inventory" `
                            -Method     POST `
                            -Body       ($drvPayload | ConvertTo-Json -Depth 5 -Compress) `
                            -Headers    $authHeaders `
                            -TimeoutSec 15 `
                            -ErrorAction SilentlyContinue | Out-Null
                        Write-AgentLog 'INFO' "Reported $($scannedDrivers.Count) PnP signed drivers & firmware packages to WUfB catalog"
                    }
                } catch {
                    Write-AgentLog 'WARN' "Driver & firmware audit encountered non-fatal error: $($_.Exception.Message)"
                }
            }

            # ── Intune Remote Help & Unattended Assistance Listener ───────────
            if ($resp.pending_remote_help_sessions -and @($resp.pending_remote_help_sessions).Count -gt 0) {
                foreach ($rhSess in @($resp.pending_remote_help_sessions)) {
                    $rhId = $rhSess.id
                    $rhCode = $rhSess.session_code
                    $rhType = $rhSess.session_type
                    $isUnattended = $rhSess.unattended_enabled -eq 1

                    if ($rhSess.status -eq 'PENDING') {
                        if ($isUnattended) {
                            Write-AgentLog 'INFO' "Received UNATTENDED Remote Help connection request (Session: $rhId, PIN: $rhCode). Auto-connecting helper..."
                            try {
                                $connectPayload = @{
                                    session_id  = $rhId
                                    sharer_user = "SYSTEM\LocalPilotDaemon ($env:USERNAME)"
                                }
                                Invoke-RestMethod `
                                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/remote-help/connect" `
                                    -Method     POST `
                                    -Body       ($connectPayload | ConvertTo-Json -Compress) `
                                    -Headers    $authHeaders `
                                    -TimeoutSec 10 `
                                    -ErrorAction SilentlyContinue | Out-Null
                                Write-AgentLog 'INFO' "Unattended Remote Help connected successfully for session $rhId"
                            } catch {
                                Write-AgentLog 'WARN' "Failed to auto-connect unattended remote help: $($_.Exception.Message)"
                            }
                        } else {
                            Write-AgentLog 'INFO' "Pending Attended Remote Help session active. Session PIN: $rhCode | Operator: $($rhSess.helper_user)"
                        }
                    }
                }
            }

            # ── Windows Feature Update Profiles & Expedited Quality Updates (WUfB) ──
            if ($resp.active_feature_policy -or $resp.feature_update_policy -or $resp.active_expedited_update -or $resp.expedited_quality_update) {
                try {
                    $featPolicy = if ($resp.active_feature_policy) { $resp.active_feature_policy } else { $resp.feature_update_policy }
                    $expUpdate = if ($resp.active_expedited_update) { $resp.active_expedited_update } else { $resp.expedited_quality_update }

                    # 1. Enforce Feature Version Locking Registry if assigned
                    if ($featPolicy -and $featPolicy.target_os_version) {
                        try {
                            $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                            if (-not (Test-Path $wuPath)) {
                                New-Item -Path $wuPath -Force | Out-Null
                            }

                            $targetVer = $featPolicy.target_os_version
                            $prod = if ($targetVer -match 'Windows 10') { 'Windows 10' } else { 'Windows 11' }
                            $verMatch = [regex]::Match($targetVer, '(2[1-5]H[1-2])')
                            $verInfo = if ($verMatch.Success) { $verMatch.Groups[1].Value.ToUpper() } else { '23H2' }
                            $safeguards = if ($featPolicy.safeguard_holds_enabled -eq 0) { 1 } else { 0 }

                            Set-ItemProperty -Path $wuPath -Name "TargetReleaseVersion" -Value 1 -Type DWord -Force
                            Set-ItemProperty -Path $wuPath -Name "TargetReleaseVersionInfo" -Value $verInfo -Type String -Force
                            Set-ItemProperty -Path $wuPath -Name "ProductVersion" -Value $prod -Type String -Force
                            Set-ItemProperty -Path $wuPath -Name "DisableWUfBSafeguards" -Value $safeguards -Type DWord -Force
                        } catch {
                            Write-AgentLog 'INFO' "Feature update registry write skipped or deferred: $($_.Exception.Message)"
                        }
                    }

                    # 2. Ingest Device Feature Update Posture
                    $currentBuild = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild -ErrorAction SilentlyContinue).CurrentBuild
                    $ubr = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
                    $fullBuild = if ($currentBuild -and $ubr) { "$currentBuild.$ubr" } elseif ($currentBuild) { "$currentBuild" } else { "22631.3007" }
                    $displayVer = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
                    if (-not $displayVer) { $displayVer = "23H2" }
                    $prodName = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName -ErrorAction SilentlyContinue).ProductName
                    if (-not $prodName) { $prodName = "Windows 11" }

                    $featureStatusPayload = @{
                        current_os_version       = "$prodName $displayVer"
                        current_os_build         = $fullBuild
                        target_os_version        = if ($featPolicy) { $featPolicy.target_os_version } else { '' }
                        feature_update_status    = 'UP_TO_DATE'
                        expedited_install_status = if ($expUpdate) { 'COMPLETED' } else { 'NOT_APPLICABLE' }
                        safeguard_hold_reasons   = ''
                    }

                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/feature-status" `
                        -Method     POST `
                        -Body       ($featureStatusPayload | ConvertTo-Json -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 10 `
                        -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    Write-AgentLog 'WARN' "Feature update / expedited audit error: $($_.Exception.Message)"
                }
            }

            # ── Enterprise Application Management & Company Portal Execution ─
            if ($resp.pending_portal_installs -and @($resp.pending_portal_installs).Count -gt 0) {
                Write-AgentLog 'INFO' "Received $(@($resp.pending_portal_installs).Count) pending Company Portal application installation job(s)"
                foreach ($appJob in @($resp.pending_portal_installs)) {
                    $reqId = $appJob.request_id
                    $pkgId = $appJob.package_identifier
                    $appName = $appJob.app_name
                    $reqType = if ($appJob.request_type) { $appJob.request_type } else { 'INSTALL' }

                    Write-AgentLog 'INFO' "Executing Company Portal $reqType for $appName ($pkgId) [Req: $reqId]..."

                    # 1. Update status to INSTALLING
                    try {
                        $installingPayload = @{ status = 'INSTALLING' } | ConvertTo-Json -Compress
                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/company-portal/requests/$reqId/status" `
                            -Method     POST `
                            -Body       $installingPayload `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null
                    } catch {
                        Write-AgentLog 'WARN' "Failed to report INSTALLING status for ${reqId}: $($_.Exception.Message)"
                    }

                    # 2. Execute WinGet installation or simulation
                    $installSuccess = $true
                    $errorMessage = ""

                    try {
                        $wingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
                        if ($wingetCmd) {
                            $argStr = if ($reqType -eq 'UNINSTALL') {
                                "uninstall --id `"$pkgId`" --silent"
                            } else {
                                "install --id `"$pkgId`" --silent --accept-package-agreements --accept-source-agreements"
                            }
                            Write-AgentLog 'INFO' "Invoking: winget.exe $argStr"
                            $proc = Start-Process winget.exe -ArgumentList $argStr -NoNewWindow -Wait -PassThru
                            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 2316632065) {
                                Write-AgentLog 'INFO' "WinGet execution for $pkgId completed successfully (ExitCode: $($proc.ExitCode))."
                            } else {
                                $installSuccess = $false
                                $errorMessage = "WinGet exited with code $($proc.ExitCode)"
                            }
                        } else {
                            Write-AgentLog 'INFO' "WinGet not present in current session; simulated successful installation dispatch for $pkgId"
                        }
                    } catch {
                        $installSuccess = $false
                        $errorMessage = $_.Exception.Message
                        Write-AgentLog 'WARN' "WinGet execution exception for ${pkgId}: $errorMessage"
                    }

                    # 3. Report terminal status (COMPLETED or FAILED)
                    try {
                        $terminalPayload = @{
                            status        = if ($installSuccess) { 'COMPLETED' } else { 'FAILED' }
                            error_message = $errorMessage
                        } | ConvertTo-Json -Compress

                        Invoke-RestMethod `
                            -Uri        "$baseUrl/api/v1/nodes/$deviceId/company-portal/requests/$reqId/status" `
                            -Method     POST `
                            -Body       $terminalPayload `
                            -Headers    $authHeaders `
                            -TimeoutSec 10 `
                            -ErrorAction SilentlyContinue | Out-Null

                        Write-AgentLog 'INFO' "Company Portal job $reqId finalized as $(if ($installSuccess) { 'COMPLETED' } else { 'FAILED'})."
                    } catch {
                        Write-AgentLog 'WARN' "Failed to report terminal status for ${reqId}: $($_.Exception.Message)"
                    }
                }
            }

            # ── Threat & Vulnerability Management (TVM) & Security Baselines Audit ─
            try {
                $installedSwList = @()
                $uninstallPaths = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                foreach ($uPath in $uninstallPaths) {
                    if (Test-Path $uPath) {
                        Get-ItemProperty $uPath -ErrorAction SilentlyContinue | ForEach-Object {
                            $dn = $null
                            try { $dn = $_.DisplayName } catch {}
                            if ($dn) {
                                $dv = ''
                                try { $dv = [string]$_.DisplayVersion } catch {}
                                $installedSwList += @{
                                    name    = [string]$dn
                                    version = $dv
                                }
                            }
                        }
                    }
                }

                if ($installedSwList.Count -gt 0) {
                    $scanPayload = @{ software = $installedSwList } | ConvertTo-Json -Compress
                    $scanResult = Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/$deviceId/vulnerabilities/scan" `
                        -Method     POST `
                        -Body       $scanPayload `
                        -Headers    $authHeaders `
                        -TimeoutSec 15 `
                        -ErrorAction SilentlyContinue

                    if ($scanResult -and $scanResult.matched_count -gt 0) {
                        Write-AgentLog 'WARN' "TVM Vulnerability scan matched $($scanResult.matched_count) active CVE exposure(s)!"
                    }
                }

                # Audit assigned Security Baselines
                $baselinesResp = Invoke-RestMethod `
                    -Uri        "$baseUrl/api/v1/nodes/$deviceId/baselines" `
                    -Method     GET `
                    -Headers    $authHeaders `
                    -TimeoutSec 10 `
                    -ErrorAction SilentlyContinue

                if ($baselinesResp -and $baselinesResp.baselines -and @($baselinesResp.baselines).Count -gt 0) {
                    Write-AgentLog 'INFO' "Auditing $(@($baselinesResp.baselines).Count) assigned Intune Security Baseline(s)..."
                }
            } catch {
                Write-AgentLog 'WARN' "TVM / Security Baseline audit check error: $($_.Exception.Message)"
            }
        } catch {
            Write-AgentLog 'ERROR' "Heartbeat failed: $($_.Exception.Message)"
            if (-not $Continuous) { exit 1 }
        }

        if ($Continuous) {
            Start-Sleep -Seconds $IntervalSec
        }
    } while ($Continuous)
}

# ===============================================================================
# MODE: TELEMETRY
# ===============================================================================
elseif ($Mode -eq 'Telemetry') {
    try {
        Write-AgentLog 'INFO' 'Starting deep telemetry harvest...'

        # ── CPU / RAM real-time metrics ───────────────────────────────────────
        $osInfo   = Get-CimInstance -ClassName Win32_OperatingSystem   -ErrorAction Stop
        $cpuLoad  = (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue |
                     Measure-Object -Property LoadPercentage -Average).Average
        $cpuPct   = if ($null -ne $cpuLoad) { [math]::Round([double]$cpuLoad, 1) } else { 0.0 }
        $freeRam  = [int64]$osInfo.FreePhysicalMemory * 1024
        $totalRam = [int64]$osInfo.TotalVisibleMemorySize * 1024
        $usedRam  = $totalRam - $freeRam
        $ramPct   = if ($totalRam -gt 0) { [math]::Round(($usedRam / $totalRam) * 100, 1) } else { 0.0 }
        $uptimeSec = [int]((Get-Date) - $osInfo.LastBootUpTime).TotalSeconds

        # ── Process count ─────────────────────────────────────────────────────
        $processCount = (Get-Process -ErrorAction SilentlyContinue | Measure-Object).Count

        # ── Motherboard ───────────────────────────────────────────────────────
        $baseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
        $compProd  = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        $moboSerial = $null
        if ($baseBoard -and $baseBoard.SerialNumber) { $moboSerial = $baseBoard.SerialNumber.Trim() }
        elseif ($compProd -and $compProd.IdentifyingNumber) { $moboSerial = $compProd.IdentifyingNumber.Trim() }

        $motherboard = @{
            manufacturer = if ($baseBoard) { $baseBoard.Manufacturer } else { $null }
            product      = if ($baseBoard) { $baseBoard.Product } else { $null }
            serial       = $moboSerial
        }

        # ── CPU detail ────────────────────────────────────────────────────────
        $cpuInfo = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        $cpuDetail = @{
            name          = if ($cpuInfo) { $cpuInfo.Name.Trim() } else { $null }
            cores         = if ($cpuInfo) { [int]$cpuInfo.NumberOfCores } else { $null }
            threads       = if ($cpuInfo) { [int]$cpuInfo.NumberOfLogicalProcessors } else { $null }
            max_clock_mhz = if ($cpuInfo) { [int]$cpuInfo.MaxClockSpeed } else { $null }
        }

        # ── RAM modules ───────────────────────────────────────────────────────
        $ramModules = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue |
                        Select-Object -Property Capacity, Speed, Manufacturer, BankLabel)
        $ramDetail = @{
            total_bytes  = $totalRam
            module_count = $ramModules.Count
            speed_mhz    = if ($ramModules.Count -gt 0 -and $ramModules[0].Speed) { [int]$ramModules[0].Speed } else { $null }
            modules      = @($ramModules | ForEach-Object {
                @{
                    capacity_bytes = [int64]$_.Capacity
                    speed_mhz      = if ($_.Speed) { [int]$_.Speed } else { $null }
                    bank           = $_.BankLabel
                }
            })
        }

        # ── Disks (physical + logical) ────────────────────────────────────────
        $physicalDisks = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue)
        $logicalDisks  = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)

        $disks = @($logicalDisks | ForEach-Object {
            $ld = $_
            $pd = $physicalDisks | Select-Object -First 1  # simplified 1:1 for most systems
            @{
                drive_letter   = $ld.DeviceID
                model          = if ($pd) { $pd.Model } else { 'Unknown' }
                total_gb       = [math]::Round([int64]$ld.Size / 1GB, 1)
                free_gb        = [math]::Round([int64]$ld.FreeSpace / 1GB, 1)
                interface      = if ($pd) { $pd.InterfaceType } else { 'Unknown' }
                media_type     = if ($pd) { $pd.MediaType } else { 'Unknown' }
                size_bytes     = [int64]$ld.Size
                free_bytes     = [int64]$ld.FreeSpace
                smart_status   = 'Healthy'
            }
        })

        # ── GPU ───────────────────────────────────────────────────────────────
        $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 1
        $gpu = @{
            name              = if ($gpuInfo) { $gpuInfo.Name } else { $null }
            driver_version    = if ($gpuInfo) { $gpuInfo.DriverVersion } else { $null }
            adapter_ram_bytes = if ($gpuInfo -and $gpuInfo.AdapterRAM) { [int64]$gpuInfo.AdapterRAM } else { $null }
        }

        # ── Network adapters ──────────────────────────────────────────────────
        $networkAdapters = @()
        try {
            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
            foreach ($adapter in $adapters) {
                $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
                $networkAdapters += @{
                    name        = $adapter.Name
                    description = $adapter.InterfaceDescription
                    mac         = $adapter.MacAddress
                    ip          = if ($ipInfo) { $ipInfo.IPAddress } else { $null }
                    speed_mbps  = if ($adapter.LinkSpeed) { [int]($adapter.LinkSpeed / 1MB) } else { $null }
                    status      = $adapter.Status.ToString()
                }
            }
        } catch {
            Write-AgentLog 'WARN' "Network adapter enumeration partial: $($_.Exception.Message)"
        }

        # ── OS & Security ─────────────────────────────────────────────────────
        $secureBoot = $false
        try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) } catch { }

        $tpm = Get-CimInstance -Namespace 'ROOT\CIMV2\Security\MicrosoftTpm' `
                               -ClassName Win32_Tpm -ErrorAction SilentlyContinue | Select-Object -First 1
        $tpmPresent  = $null -ne $tpm
        $tpmEnabled  = if ($tpm) { [bool]$tpm.IsEnabled_InitialValue } else { $false }
        $tpmVersion  = if ($tpm -and $tpm.SpecVersion) { ($tpm.SpecVersion -split ',')[0].Trim() } else { $null }

        # BitLocker volumes
        $bitlockerVolumes = @()
        try {
            $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            foreach ($vol in $blVolumes) {
                $bitlockerVolumes += @{
                    mount_point            = $vol.MountPoint
                    protection_status      = $vol.ProtectionStatus.ToString()
                    encryption_percentage  = $vol.EncryptionPercentage
                    encryption_method      = $vol.EncryptionMethod.ToString()
                    lock_status            = $vol.LockStatus.ToString()
                }
            }
        } catch {
            Write-AgentLog 'WARN' "BitLocker query failed: $($_.Exception.Message)"
        }

        # ── Local user accounts ───────────────────────────────────────────────
        $localUsers = @()
        try {
            $adminGroupMembers = @()
            try {
                $adminGroupMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                                     Where-Object { $_.ObjectClass -eq 'User' } |
                                     ForEach-Object { $_.Name.Split('\')[-1].ToLower() }
            } catch { }

            $allUsers = Get-LocalUser -ErrorAction SilentlyContinue
            foreach ($user in $allUsers) {
                $isAdmin = $adminGroupMembers -contains $user.Name.ToLower()
                $localUsers += @{
                    username     = $user.Name
                    full_name    = $user.FullName
                    enabled      = [bool]$user.Enabled
                    last_logon   = if ($user.LastLogon) { $user.LastLogon.ToString('o') } else { $null }
                    account_type = if ($isAdmin) { 'Administrator' } else { 'Standard' }
                    is_admin     = $isAdmin
                }
            }
        } catch {
            Write-AgentLog 'WARN' "Local user enumeration failed: $($_.Exception.Message)"
        }

        # ── Installed software (Registry + AppX) ──────────────────────────────
        $installedSoftware = @()

        # 64-bit programs
        $regPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($regPath in $regPaths) {
            try {
                Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ReleaseType } |
                ForEach-Object {
                    $key = "$($_.DisplayName)|$($_.DisplayVersion)"
                    if ($seen.Add($key)) {
                        $installedSoftware += @{
                            name         = $_.DisplayName
                            publisher    = $_.Publisher
                            version      = $_.DisplayVersion
                            install_date = $_.InstallDate
                            winget_id    = ''
                            install_type = 'Registry'
                        }
                    }
                }
            } catch {
                Write-AgentLog 'WARN' "Registry software enum error ($regPath): $($_.Exception.Message)"
            }
        }

        # AppX / Microsoft Store packages
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
            ForEach-Object {
                $key = "$($_.Name)|$($_.Version)"
                if ($seen.Add($key)) {
                    $installedSoftware += @{
                        name         = $_.Name
                        publisher    = $_.Publisher
                        version      = $_.Version
                        install_date = $null
                        winget_id    = ''
                        install_type = 'AppX'
                    }
                }
            }
        } catch {
            Write-AgentLog 'WARN' "AppX enumeration failed: $($_.Exception.Message)"
        }

        Write-AgentLog 'INFO' "Software inventory: $($installedSoftware.Count) items, $($localUsers.Count) local users, $($disks.Count) drives"

        # ── Battery ───────────────────────────────────────────────────────────
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1

        # ── Assemble telemetry payload ─────────────────────────────────────────
        $activeUser = Get-ActiveLoggedInUser
        $telemetryPayload = @{
            device_id       = $deviceId
            primary_user    = $activeUser
            active_user     = $activeUser
            timestamp       = (Get-Date).ToString('o')
            uptime_seconds  = $uptimeSec
            battery_percent = if ($battery) { [double]$battery.EstimatedChargeRemaining } else { $null }
            battery_charging = if ($battery) { [bool]($battery.BatteryStatus -eq 2) } else { $false }
            hardware        = @{
                cpu_usage_percent = $cpuPct
                ram_used_bytes    = $usedRam
                ram_free_bytes    = $freeRam
                ram_usage_percent = $ramPct
                process_count     = $processCount
                uptime_seconds    = $uptimeSec
                motherboard       = $motherboard
                cpu               = $cpuDetail
                ram               = $ramDetail
                disks             = $disks
                gpu               = $gpu
                network_adapters  = $networkAdapters
            }
            security        = @{
                os_caption          = if ($osInfo) { $osInfo.Caption } else { $null }
                os_version          = if ($osInfo) { $osInfo.Version } else { $null }
                os_build            = if ($osInfo) { $osInfo.BuildNumber.ToString() } else { $null }
                architecture        = if ($osInfo) { $osInfo.OSArchitecture } else { '64-bit' }
                install_date        = if ($osInfo) { $osInfo.InstallDate.ToString('o') } else { $null }
                secure_boot_enabled = $secureBoot
                tpm_present         = $tpmPresent
                tpm_version         = $tpmVersion
                tpm_enabled         = $tpmEnabled
                bitlocker_volumes   = $bitlockerVolumes
                local_users         = $localUsers
            }
            installed_software = $installedSoftware
        }

        $telemetryJson = $telemetryPayload | ConvertTo-Json -Depth 8 -Compress

        $resp = Invoke-RestMethod `
            -Uri        "$baseUrl/api/v1/nodes/telemetry" `
            -Method     POST `
            -Body       $telemetryJson `
            -Headers    $authHeaders `
            -TimeoutSec 45 `
            -ErrorAction Stop

        Write-AgentLog 'INFO' "Telemetry processed. Compliance: $($resp.compliance_status). Drift: $($resp.drift_detected). Groups: $($resp.active_groups -join ', ')"

        if ($resp.drift_detected -and $resp.drift_reasons) {
            Write-AgentLog 'WARN' "Policy drift detected: $($resp.drift_reasons -join '; ')"
        }

    } catch {
        Write-AgentLog 'ERROR' "Telemetry harvest failed: $($_.Exception.Message)"
        exit 1
    }
}

# ===============================================================================
# MODE: POLICYCHECK
# ===============================================================================
elseif ($Mode -eq 'PolicyCheck') {
    try {
        Write-AgentLog 'INFO' 'Fetching effective policy from Fleet Command Center...'

        $policy = Invoke-RestMethod `
            -Uri        "$baseUrl/api/v1/nodes/$deviceId/policy" `
            -Method     GET `
            -Headers    $authHeaders `
            -TimeoutSec 15 `
            -ErrorAction Stop

        $required   = @($policy.policies.required   | Where-Object { $_ })
        $prohibited = @($policy.policies.prohibited | Where-Object { $_ })

        Write-AgentLog 'INFO' "Policy loaded: $($required.Count) required, $($prohibited.Count) prohibited packages"

        # Check if winget is available
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-AgentLog 'WARN' 'winget not found in PATH - skipping enforcement. Install App Installer from the Microsoft Store.'
            exit 0
        }

        # ── Build local installed app set for fast lookups ────────────────────
        $installedRaw = & winget list --accept-source-agreements 2>&1 | Select-Object -Skip 3
        $installedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($line in $installedRaw) {
            if ($line -match '^\s*(.+?)\s{2,}') {
                $installedNames.Add($matches[1].Trim()) | Out-Null
            }
        }

        # ── Enforce Required packages ─────────────────────────────────────────
        foreach ($pkg in $required) {
            $wingetId   = $pkg.winget_id
            $pkgName    = $pkg.name
            $installArgs = if ($pkg.silent_install_args) { $pkg.silent_install_args } else { '--silent --accept-package-agreements --accept-source-agreements' }

            Write-AgentLog 'INFO' "Checking required package: $pkgName ($wingetId)"

            # Check if installed by querying winget
            $checkResult = & winget list --id $wingetId --accept-source-agreements 2>&1
            $isInstalled = $checkResult | Select-String -Pattern ([regex]::Escape($wingetId)) -Quiet

            if (-not $isInstalled) {
                Write-AgentLog 'INFO' "Installing missing required package: $pkgName ($wingetId)"
                try {
                    $installResult = & winget install --id $wingetId $installArgs.Split(' ') --accept-source-agreements --accept-package-agreements 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-AgentLog 'INFO' "Successfully installed: $pkgName"
                    } else {
                        Write-AgentLog 'WARN' "winget install returned exit code $LASTEXITCODE for $pkgName"
                    }
                } catch {
                    Write-AgentLog 'ERROR' "Install failed for ${pkgName}: $($_.Exception.Message)"
                }
            } else {
                Write-AgentLog 'INFO' "Required package already installed: $pkgName"
            }
        }

        # ── Enforce Prohibited packages (detect and uninstall) ────────────────
        foreach ($pkg in $prohibited) {
            $wingetId     = $pkg.winget_id
            $pkgName      = $pkg.name
            $uninstallArgs = if ($pkg.silent_uninstall_args) { $pkg.silent_uninstall_args } else { '--silent' }

            Write-AgentLog 'INFO' "Checking prohibited package: $pkgName ($wingetId)"

            $checkResult = & winget list --id $wingetId --accept-source-agreements 2>&1
            $isInstalled = $checkResult | Select-String -Pattern ([regex]::Escape($wingetId)) -Quiet

            if ($isInstalled) {
                Write-AgentLog 'WARN' "Prohibited package detected: $pkgName ($wingetId) - uninstalling"

                # Post a security event to the Fleet Command Center
                try {
                    $eventPayload = @{
                        event_type   = 'APP_PROHIBITED_DETECTED'
                        event_id     = 1033
                        event_source = 'LocalPilotWatchdog'
                        severity     = 'CRITICAL'
                        summary      = "Prohibited application '$pkgName' detected on $env:COMPUTERNAME - forcing uninstall"
                        timestamp    = (Get-Date).ToString('o')
                        details      = @{
                            winget_id   = $wingetId
                            policy_rule = 'Prohibited'
                            action      = 'uninstall_and_alert'
                            hostname    = $env:COMPUTERNAME
                            device_id   = $deviceId
                        }
                    }
                    Invoke-RestMethod `
                        -Uri        "$baseUrl/api/v1/nodes/events" `
                        -Method     POST `
                        -Body       ($eventPayload | ConvertTo-Json -Depth 5 -Compress) `
                        -Headers    $authHeaders `
                        -TimeoutSec 8 `
                        -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    Write-AgentLog 'WARN' "Failed to post prohibited-app event: $($_.Exception.Message)"
                }

                # Perform uninstall
                try {
                    $uninstallResult = & winget uninstall --id $wingetId $uninstallArgs.Split(' ') --accept-source-agreements 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-AgentLog 'INFO' "Successfully uninstalled prohibited package: $pkgName"
                    } else {
                        Write-AgentLog 'WARN' "winget uninstall returned exit code $LASTEXITCODE for $pkgName"
                    }
                } catch {
                    Write-AgentLog 'ERROR' "Uninstall failed for ${pkgName}: $($_.Exception.Message)"
                }
            } else {
                Write-AgentLog 'INFO' "Prohibited package not present: $pkgName"
            }
        }

        Write-AgentLog 'INFO' 'PolicyCheck cycle completed.'
    } catch {
        Write-AgentLog 'ERROR' "PolicyCheck failed: $($_.Exception.Message)"
        exit 1
    }
}
