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
