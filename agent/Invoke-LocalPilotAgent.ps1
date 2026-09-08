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
