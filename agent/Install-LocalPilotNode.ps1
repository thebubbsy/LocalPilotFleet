<#
.SYNOPSIS
    LocalPilot Fleet - Node Agent Installer & Enrollment Script.
    Enrolls this PC into the LocalPilot Fleet and registers all Scheduled Tasks.

.DESCRIPTION
    Run once as Administrator on each managed 'slave' PC. Harvests hardware fingerprint,
    enrolls the node with the Fleet Command Center, stores the returned NodeToken securely,
    copies agent scripts, and arms three Scheduled Tasks:
      - LocalPilot-Heartbeat  (every 5 minutes)
      - LocalPilot-Telemetry  (every 30 minutes)
      - LocalPilot-Watchdog   (event-triggered on security & install events)

.PARAMETER ServerUrl
    Primary Fleet Command Center URL. Defaults to 'http://localhost:8443'.

.PARAMETER FleetKey
    Mandatory pre-shared enrollment key matching FLEET_KEY on the server.

.PARAMETER DeviceName
    Human-readable friendly name for this node. Defaults to $env:COMPUTERNAME.

.PARAMETER Group
    Logical group tag to include in enrollment tags. Defaults to 'Default'.

.PARAMETER CloudflareUrl
    Optional Cloudflare Tunnel URL fallback (e.g. https://fleet.yourdomain.com).
    When provided, the agent will fall back to this if the LAN URL is unreachable.

.EXAMPLE
    # Minimal LAN install:
    .\Install-LocalPilotNode.ps1 -FleetKey "localpilot-secret-key-2026"

.EXAMPLE
    # Roaming laptop with Cloudflare fallback:
    .\Install-LocalPilotNode.ps1 -ServerUrl "http://192.168.1.100:8443" `
        -FleetKey "localpilot-secret-key-2026" `
        -DeviceName "Sarah's Surface" `
        -Group "family" `
        -CloudflareUrl "https://fleet.yourdomain.com"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = 'http://localhost:8443',

    [Parameter(Mandatory = $true)]
    [string]$FleetKey,

    [Parameter(Mandatory = $false)]
    [string]$DeviceName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$Group = 'Default',

    [Parameter(Mandatory = $false)]
    [string]$CloudflareUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Constants ───────────────────────────────────────────────────────────────
$AGENT_VERSION  = '1.0.0'
$INSTALL_DIR    = 'C:\ProgramData\LocalPilotFleet'
$CONFIG_FILE    = "$INSTALL_DIR\config.json"
$LOG_FILE       = "$INSTALL_DIR\install.log"
$SCRIPT_DIR     = $PSScriptRoot

# ─── Helpers ─────────────────────────────────────────────────────────────────
function Write-Step {
    param([string]$Step, [string]$Message, [string]$Color = 'Cyan')
    $line = "[$Step] $Message"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LOG_FILE -Value "$(Get-Date -Format 'o') $line" -ErrorAction SilentlyContinue
}

function Write-Success { param([string]$Message); Write-Host "  [OK] $Message" -ForegroundColor Green }
function Write-Warn    { param([string]$Message); Write-Host "  ! $Message" -ForegroundColor Yellow }
function Write-Fail    { param([string]$Message); Write-Host "  [FAIL] $Message" -ForegroundColor Red }

# ─── Step 0: Elevation check ─────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail 'This script must be run as Administrator. Right-click -> Run as Administrator.'
    exit 1
}

# ─── Step 1: Create install directory ────────────────────────────────────────
Write-Step '1/7' 'Creating LocalPilot Fleet install directory...'
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -Path $INSTALL_DIR -ItemType Directory -Force | Out-Null
}
# Initialise log
"$(Get-Date -Format 'o') [Install] LocalPilot Fleet installation started on $env:COMPUTERNAME" | Set-Content -Path $LOG_FILE -Force

Write-Success "Install directory ready: $INSTALL_DIR"

# ─── Step 2: Enable required Windows security auditing ───────────────────────
Write-Step '2/7' 'Enabling Windows Security Audit policies (required for Watchdog)...'
try {
    & auditpol.exe /set /subcategory:'User Account Management' /success:enable /failure:enable 2>&1 | Out-Null
    & auditpol.exe /set /subcategory:'Security Group Management' /success:enable /failure:enable 2>&1 | Out-Null
    Write-Success 'Audit policies enabled (User Account Management, Security Group Management)'
} catch {
    Write-Warn "Could not configure audit policies: $($_.Exception.Message)"
}

# ─── Step 3: Harvest hardware fingerprint ────────────────────────────────────
Write-Step '3/7' 'Harvesting hardware fingerprint for enrollment...'

$compSys   = Get-CimInstance -ClassName Win32_ComputerSystem       -ErrorAction SilentlyContinue
$compProd  = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
$baseBoard = Get-CimInstance -ClassName Win32_BaseBoard             -ErrorAction SilentlyContinue
$os        = Get-CimInstance -ClassName Win32_OperatingSystem       -ErrorAction SilentlyContinue
$cpu       = Get-CimInstance -ClassName Win32_Processor             -ErrorAction SilentlyContinue | Select-Object -First 1
$gpu       = Get-CimInstance -ClassName Win32_VideoController       -ErrorAction SilentlyContinue | Select-Object -First 1
$battery   = Get-CimInstance -ClassName Win32_Battery               -ErrorAction SilentlyContinue | Select-Object -First 1
$tpm       = Get-CimInstance -Namespace 'ROOT\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue | Select-Object -First 1
$nicConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
             Where-Object { $_.IPEnabled -and $_.IPAddress } | Select-Object -First 1

# Serial: prefer baseBoard serial, fall back to ComputerSystemProduct IdentifyingNumber
$serialNumber = $null
if ($baseBoard -and $baseBoard.SerialNumber -and $baseBoard.SerialNumber.Trim() -ne '') {
    $serialNumber = $baseBoard.SerialNumber.Trim()
} elseif ($compProd -and $compProd.IdentifyingNumber -and $compProd.IdentifyingNumber.Trim() -ne '') {
    $serialNumber = $compProd.IdentifyingNumber.Trim()
}

$uuid = if ($compProd -and $compProd.UUID) { $compProd.UUID } else { $null }
$macAddress = if ($nicConfig) { $nicConfig.MACAddress } else { $null }
$ipAddress  = if ($nicConfig -and $nicConfig.IPAddress) { $nicConfig.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1 } else { $null }

# Secure Boot
$secureBoot = $false
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) } catch { }

# BitLocker
$bitlockerStatus = 'Disabled'
try {
    $blVol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
    if ($blVol) {
        $bitlockerStatus = switch ($blVol.ProtectionStatus) {
            'On'  { 'FullyEncrypted' }
            'Off' { 'Disabled' }
            default { 'Disabled' }
        }
    }
} catch { }

# TPM version parsing - SpecVersion is typically "2.0, 0, 1.38" so take first token
$tpmVersion = $null
if ($tpm -and $tpm.SpecVersion) {
    $tpmVersion = ($tpm.SpecVersion -split ',')[0].Trim()
}

# Active logged-in user detection
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

# Windows Autopilot Hardware Hash Harvesting
function Get-AutopilotHardwareData {
    try {
        $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction Stop
        if ($devDetail -and $devDetail.DeviceHardwareData) {
            return [string]$devDetail.DeviceHardwareData
        }
    } catch {}

    try {
        $cs = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        $biosObj = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $bbObj = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        $cpuObj = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

        $uId = if ($cs -and $cs.UUID) { $cs.UUID } else { '00000000-0000-0000-0000-000000000000' }
        $bSn = if ($biosObj -and $biosObj.SerialNumber) { $biosObj.SerialNumber } else { 'UNKNOWN-BIOS-SN' }
        $bbSn = if ($bbObj -and $bbObj.SerialNumber) { $bbObj.SerialNumber } else { 'UNKNOWN-BB-SN' }
        $cpId = if ($cpuObj -and $cpuObj.ProcessorId) { $cpuObj.ProcessorId } else { 'CPU-0' }

        $rawSeed = "OA3:$uId:$bSn:$bbSn:$cpId"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rawSeed))
        return "OA3_SYNTH_$([Convert]::ToBase64String($hashBytes))"
    } catch {
        return 'OA3_FALLBACK_HARDWARE_HASH_DATA'
    }
}

# Tags: include the group and 'managed'
$tags = @($Group, 'managed') | Where-Object { $_ -ne '' }

$enrollBody = @{
    hostname            = $env:COMPUTERNAME
    friendly_name       = $DeviceName
    serial_number       = $serialNumber
    hardware_hash       = Get-AutopilotHardwareData
    uuid                = $uuid
    mac_address         = $macAddress
    tags                = $tags
    os_name             = if ($os) { $os.Caption } else { 'Microsoft Windows' }
    os_version          = if ($os) { $os.Version } else { '10.0' }
    os_build            = if ($os) { $os.BuildNumber.ToString() } else { $null }
    os_architecture     = if ($os) { $os.OSArchitecture } else { '64-bit' }
    cpu_model           = if ($cpu) { $cpu.Name.Trim() } else { $null }
    cpu_cores           = if ($cpu) { [int]$cpu.NumberOfCores } else { $null }
    cpu_logical         = if ($cpu) { [int]$cpu.NumberOfLogicalProcessors } else { $null }
    total_ram_bytes     = if ($compSys) { [int64]$compSys.TotalPhysicalMemory } else { 1073741824 }
    gpu_name            = if ($gpu) { $gpu.Name } else { 'Generic Display Adapter' }
    has_battery         = [bool]($null -ne $battery)
    battery_percent     = if ($battery) { [double]$battery.EstimatedChargeRemaining } else { $null }
    battery_charging    = if ($battery) { [bool]($battery.BatteryStatus -eq 2) } else { $false }
    tpm_present         = [bool]($null -ne $tpm)
    tpm_version         = $tpmVersion
    tpm_enabled         = if ($tpm) { [bool]$tpm.IsEnabled_InitialValue } else { $false }
    secure_boot_enabled = $secureBoot
    bitlocker_status    = $bitlockerStatus
    primary_user        = Get-ActiveLoggedInUser
    agent_version       = $AGENT_VERSION
}

$serialDisplay = if ($serialNumber) { $serialNumber } else { 'N/A' }
Write-Success "Fingerprint harvested - Serial: $serialDisplay | RAM: $([math]::Round($enrollBody.total_ram_bytes / 1GB, 1)) GB"

# ─── Step 4: Enroll with the Fleet Command Center ────────────────────────────
Write-Step '4/7' "Enrolling '$DeviceName' with Fleet Command Center at $ServerUrl..."

$enrollHeaders = @{
    'Content-Type' = 'application/json'
    'X-Fleet-Key'  = $FleetKey
}
$enrollJson = $enrollBody | ConvertTo-Json -Depth 5 -Compress

$enrollResponse = $null
$activeServerUrl = $ServerUrl

# Try LAN first, fall back to Cloudflare Tunnel
try {
    $enrollResponse = Invoke-RestMethod `
        -Uri     "$ServerUrl/api/v1/nodes/enroll" `
        -Method  POST `
        -Body    $enrollJson `
        -Headers $enrollHeaders `
        -TimeoutSec 8 `
        -ErrorAction Stop
} catch {
    if ($CloudflareUrl) {
        Write-Warn "LAN enrollment unreachable ($($_.Exception.Message)). Falling back to Cloudflare Tunnel: $CloudflareUrl"
        $activeServerUrl = $CloudflareUrl
        $enrollResponse = Invoke-RestMethod `
            -Uri     "$CloudflareUrl/api/v1/nodes/enroll" `
            -Method  POST `
            -Body    $enrollJson `
            -Headers $enrollHeaders `
            -TimeoutSec 15 `
            -ErrorAction Stop
    } else {
        Write-Fail "Enrollment failed and no Cloudflare fallback configured."
        throw
    }
}

$deviceId  = $enrollResponse.device_id
$nodeToken = $enrollResponse.node_token

if (-not $deviceId -or -not $nodeToken) {
    Write-Fail 'Server returned an enrollment response missing device_id or node_token.'
    throw 'Invalid enrollment response from server.'
}

Write-Success "Enrolled! Device ID: $deviceId"
Write-Success "Assigned groups: $($enrollResponse.assigned_groups -join ', ')"

# ─── Step 5: Persist configuration ───────────────────────────────────────────
Write-Step '5/7' 'Persisting agent configuration...'

$hbInterval = if ($enrollResponse.heartbeat_interval_sec) { $enrollResponse.heartbeat_interval_sec } else { 300 }
$telInterval = if ($enrollResponse.telemetry_interval_min) { $enrollResponse.telemetry_interval_min } else { 30 }

$config = @{
    device_id             = $deviceId
    node_token            = $nodeToken
    server_url            = $ServerUrl
    cloudflare_url        = $CloudflareUrl
    active_server_url     = $activeServerUrl
    hostname              = $env:COMPUTERNAME
    device_name           = $DeviceName
    group                 = $Group
    agent_version         = $AGENT_VERSION
    enrolled_at           = (Get-Date).ToString('o')
    heartbeat_interval_sec = $hbInterval
    telemetry_interval_min = $telInterval
}

$config | ConvertTo-Json -Depth 3 | Set-Content -Path $CONFIG_FILE -Encoding UTF8 -Force

# Lock down permissions: only SYSTEM and Administrators can read the token
try {
    $acl = Get-Acl $CONFIG_FILE
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
    $sysRule   = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'Allow')
    $acl.SetAccessRule($sysRule)
    $acl.SetAccessRule($adminRule)
    Set-Acl -Path $CONFIG_FILE -AclObject $acl
    Write-Success "config.json secured (SYSTEM + Administrators only)"
} catch {
    Write-Warn "Could not restrict config.json ACL: $($_.Exception.Message)"
}

# ─── Step 6: Copy agent scripts to install directory ─────────────────────────
Write-Step '6/7' 'Copying agent scripts to install directory...'

$scriptsToCopy = @(
    'Invoke-LocalPilotAgent.ps1',
    'Watchdog-SecurityEvent.ps1',
    'Simulate-SecurityEvent.ps1',
    'Uninstall-LocalPilotNode.ps1'
)
foreach ($script in $scriptsToCopy) {
    $src = Join-Path $SCRIPT_DIR $script
    $dst = Join-Path $INSTALL_DIR $script
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Success "Copied $script"
    } else {
        Write-Warn "$script not found in script directory - skipping copy (will still register task)"
    }
}

# ─── Step 7: Register Scheduled Tasks ────────────────────────────────────────
Write-Step '7/7' 'Registering Scheduled Tasks...'

$psExe     = 'powershell.exe'
$commonArgs = '-NonInteractive -NoProfile -ExecutionPolicy Bypass -File'
$agentScript   = "`"$INSTALL_DIR\Invoke-LocalPilotAgent.ps1`""
$watchdogScript = "`"$INSTALL_DIR\Watchdog-SecurityEvent.ps1`""

# ── Task 1: LocalPilot-Heartbeat (every 5 minutes) ───────────────────────────
$hbAction  = New-ScheduledTaskAction -Execute $psExe `
    -Argument "$commonArgs $agentScript -Mode Heartbeat"
$hbTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$hbSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName    'LocalPilot-Heartbeat' `
    -Description 'LocalPilot Fleet - Lightweight keepalive heartbeat every 5 minutes' `
    -Action      $hbAction `
    -Trigger     $hbTrigger `
    -Settings    $hbSettings `
    -User        'NT AUTHORITY\SYSTEM' `
    -RunLevel    Highest `
    -Force | Out-Null

Write-Success 'Registered: LocalPilot-Heartbeat (every 5 minutes, SYSTEM)'

# ── Task 2: LocalPilot-Telemetry (every 30 minutes) ──────────────────────────
$telAction  = New-ScheduledTaskAction -Execute $psExe `
    -Argument "$commonArgs $agentScript -Mode Telemetry"
$telTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 30)
$telSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName    'LocalPilot-Telemetry' `
    -Description 'LocalPilot Fleet - Deep hardware/software telemetry harvest every 30 minutes' `
    -Action      $telAction `
    -Trigger     $telTrigger `
    -Settings    $telSettings `
    -User        'NT AUTHORITY\SYSTEM' `
    -RunLevel    Highest `
    -Force | Out-Null

Write-Success 'Registered: LocalPilot-Telemetry (every 30 minutes, SYSTEM)'

# ── Task 3: LocalPilot-Watchdog (event-triggered) ────────────────────────────
# Use schtasks /Create with XML for multi-log event trigger support,
# as New-ScheduledTaskTrigger only supports single-log event subscriptions.

$watchdogXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>LocalPilot Fleet - Real-time Security Event Watchdog</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;
        &lt;Query Id="0" Path="Security"&gt;
          &lt;Select Path="Security"&gt;*[System[(EventID=4720 or EventID=4726 or EventID=4728 or EventID=4732)]]&lt;/Select&gt;
        &lt;/Query&gt;
        &lt;Query Id="1" Path="Application"&gt;
          &lt;Select Path="Application"&gt;*[System[Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=11707)]]&lt;/Select&gt;
        &lt;/Query&gt;
        &lt;Query Id="2" Path="Microsoft-Windows-AppXDeployment-Server/Operational"&gt;
          &lt;Select Path="Microsoft-Windows-AppXDeployment-Server/Operational"&gt;*[System[(EventID=854)]]&lt;/Select&gt;
        &lt;/Query&gt;
      &lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -NoProfile -ExecutionPolicy Bypass -File "$INSTALL_DIR\Watchdog-SecurityEvent.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$xmlPath = "$env:TEMP\LocalPilot-Watchdog-$(Get-Random).xml"
try {
    $watchdogXml | Out-File -FilePath $xmlPath -Encoding Unicode -Force
    $schtasksResult = & schtasks.exe /Create /TN 'LocalPilot-Watchdog' /XML $xmlPath /F 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks.exe failed: $schtasksResult"
    }
    Write-Success 'Registered: LocalPilot-Watchdog (event-triggered: 4720/4726/4728/4732/MsiInstaller/AppX, SYSTEM)'
} finally {
    Remove-Item -Path $xmlPath -Force -ErrorAction SilentlyContinue
}

# ─── Summary ─────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '===============================================================' -ForegroundColor Magenta
Write-Host '  LocalPilot Fleet Node Agent - Installation Complete!' -ForegroundColor Green
Write-Host '===============================================================' -ForegroundColor Magenta
Write-Host ''
Write-Host "  Device Name   : $DeviceName" -ForegroundColor White
Write-Host "  Hostname      : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Device ID     : $deviceId" -ForegroundColor White
Write-Host "  Server URL    : $ServerUrl" -ForegroundColor White
if ($CloudflareUrl) {
    Write-Host "  Cloudflare URL: $CloudflareUrl" -ForegroundColor White
}
Write-Host "  Config File   : $CONFIG_FILE" -ForegroundColor White
Write-Host "  Agent Version : $AGENT_VERSION" -ForegroundColor White
Write-Host ''
Write-Host '  Scheduled Tasks:' -ForegroundColor Cyan
Write-Host '    LocalPilot-Heartbeat  ->` every 5 min (SYSTEM)' -ForegroundColor White
Write-Host '    LocalPilot-Telemetry  ->` every 30 min (SYSTEM)' -ForegroundColor White
Write-Host '    LocalPilot-Watchdog   ->` event-driven (SYSTEM)' -ForegroundColor White
Write-Host ''
Write-Host '  The node is now live. Check the Fleet dashboard at:' -ForegroundColor Cyan
Write-Host "    $activeServerUrl" -ForegroundColor Yellow
Write-Host ''
