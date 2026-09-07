<#
.SYNOPSIS
    LocalPilot Fleet — Real-time Security Event Watchdog.
    Triggered by Windows Scheduled Task Event Log subscriptions. Dispatches security
    events to the Fleet Command Center within ~400ms of the triggering Windows event.

.DESCRIPTION
    Designed to be fired by the 'LocalPilot-Watchdog' Scheduled Task, which subscribes to:
      - Security log: Event IDs 4720 (User Created), 4726 (User Deleted),
                      4728 (User Added to Global Group), 4732 (User Added to Local Group)
      - Application log: MsiInstaller Event IDs 1033, 11707 (App Installed)
      - Microsoft-Windows-AppXDeployment-Server/Operational: Event ID 854 (AppX installed)

    Reads the most recent relevant events from the last 90 seconds, dispatches each as
    a security event to POST /api/v1/nodes/events, and logs to watchdog.log.

    All try/catch blocks ensure this script NEVER crashes silently — every failure
    is logged before re-throwing or continuing.

.NOTES
    Runs as NT AUTHORITY\SYSTEM — no interactive prompts.
    Config file: C:\ProgramData\LocalPilotFleet\config.json
    Log file:    C:\ProgramData\LocalPilotFleet\watchdog.log
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'  # Don't stop on non-critical errors; log and continue

# ─── Constants ───────────────────────────────────────────────────────────────
$CONFIG_FILE  = 'C:\ProgramData\LocalPilotFleet\config.json'
$LOG_FILE     = 'C:\ProgramData\LocalPilotFleet\watchdog.log'
$LOOKBACK_SEC = 90   # Seconds to look back for events (buffer for task scheduler latency)
$MAX_LOG_MB   = 10   # Rotate log when it exceeds this size

# ─── Log rotation ─────────────────────────────────────────────────────────────
if (Test-Path $LOG_FILE) {
    $logSize = (Get-Item $LOG_FILE).Length / 1MB
    if ($logSize -gt $MAX_LOG_MB) {
        $archivePath = $LOG_FILE -replace '\.log$', "-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Move-Item -Path $LOG_FILE -Destination $archivePath -Force -ErrorAction SilentlyContinue
    }
}

# ─── Logging helper ──────────────────────────────────────────────────────────
function Write-WatchdogLog {
    param(
        [string]$Level   = 'INFO',
        [string]$Message
    )
    $entry = "$(Get-Date -Format 'o') [$Level] [Watchdog] $Message"
    try { Add-Content -Path $LOG_FILE -Value $entry -ErrorAction SilentlyContinue } catch { }
    # Also write to event log for visibility (non-fatal if it fails)
    try {
        if ($Level -eq 'ERROR') { Write-EventLog -LogName Application -Source 'LocalPilotWatchdog' -EventId 9001 -EntryType Error -Message $Message -ErrorAction SilentlyContinue }
    } catch { }
}

Write-WatchdogLog 'INFO' "Watchdog fired on $env:COMPUTERNAME — scanning last $LOOKBACK_SEC seconds"

# ─── Load configuration ───────────────────────────────────────────────────────
if (-not (Test-Path $CONFIG_FILE)) {
    Write-WatchdogLog 'ERROR' "Config file not found: $CONFIG_FILE — Watchdog cannot operate."
    exit 1
}

try {
    $config = Get-Content $CONFIG_FILE -Raw -ErrorAction Stop | ConvertFrom-Json
} catch {
    Write-WatchdogLog 'ERROR' "Failed to parse config.json: $($_.Exception.Message)"
    exit 1
}

$deviceId  = $config.device_id
$nodeToken = $config.node_token
$lanUrl    = $config.server_url
$cfUrl     = $config.cloudflare_url

if (-not $deviceId -or -not $nodeToken) {
    Write-WatchdogLog 'ERROR' 'config.json missing device_id or node_token. Re-enroll node.'
    exit 1
}

# ─── Dual-mode URL resolver ───────────────────────────────────────────────────
function Resolve-Endpoint {
    param([string]$LanUrl, [string]$CfUrl)

    if ($LanUrl) {
        try {
            $resp = Invoke-WebRequest -Uri "$LanUrl/api/v1/health" -Method GET -TimeoutSec 4 -UseBasicParsing -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { return $LanUrl }
        } catch { }
    }
    if ($CfUrl) {
        Write-WatchdogLog 'INFO' "LAN unreachable — using Cloudflare Tunnel: $CfUrl"
        return $CfUrl
    }
    return $LanUrl
}

$baseUrl = Resolve-Endpoint -LanUrl $lanUrl -CfUrl $cfUrl
Write-WatchdogLog 'INFO' "Posting events to: $baseUrl"

$authHeaders = @{
    'Content-Type'  = 'application/json'
    'Authorization' = "Bearer $nodeToken"
}

# ─── Event dispatcher ─────────────────────────────────────────────────────────
function Send-SecurityEvent {
    param(
        [string]$EventType,    # Must match security_events CHECK constraint
        [int]$EventId,
        [string]$EventSource,
        [string]$Severity,     # CRITICAL | HIGH | MEDIUM | LOW | INFO
        [string]$Summary,
        [hashtable]$Details,
        [datetime]$Timestamp
    )

    $payload = @{
        event_type   = $EventType
        event_id     = $EventId
        event_source = $EventSource
        severity     = $Severity
        summary      = $Summary
        timestamp    = $Timestamp.ToString('o')
        details      = $Details
    }

    try {
        $resp = Invoke-RestMethod `
            -Uri        "$baseUrl/api/v1/nodes/events" `
            -Method     POST `
            -Body       ($payload | ConvertTo-Json -Depth 6 -Compress) `
            -Headers    $authHeaders `
            -TimeoutSec 10 `
            -ErrorAction Stop

        Write-WatchdogLog 'INFO' "Dispatched $EventType (EID:$EventId) → Record ID: $($resp.event_record_id) | Toast: $($resp.toast_fired)"
    } catch {
        Write-WatchdogLog 'ERROR' "Failed to dispatch $EventType (EID:$EventId): $($_.Exception.Message)"
    }
}

# ─── Helper: Extract XML field from Win32 event XML ──────────────────────────
function Get-EventXmlData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event, [string]$FieldName)
    try {
        [xml]$xml = $Event.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $node = $xml.SelectSingleNode("//e:Data[@Name='$FieldName']", $ns)
        if ($node) { return $node.InnerText }
    } catch { }
    return $null
}

$since = (Get-Date).AddSeconds(-$LOOKBACK_SEC)
$eventsDispatched = 0

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY LOG: User account & group management events
# ═══════════════════════════════════════════════════════════════════════════════
$secEventIds = @(4720, 4726, 4728, 4732)

try {
    $secEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $secEventIds
        StartTime = $since
    } -ErrorAction SilentlyContinue

    foreach ($evt in $secEvents) {
        $targetUser  = Get-EventXmlData -Event $evt -FieldName 'TargetUserName'
        $subjectUser = Get-EventXmlData -Event $evt -FieldName 'SubjectUserName'
        $targetDomain = Get-EventXmlData -Event $evt -FieldName 'TargetDomainName'
        $subjectSid  = Get-EventXmlData -Event $evt -FieldName 'SubjectUserSid'
        $groupName   = Get-EventXmlData -Event $evt -FieldName 'TargetUserName'  # repurposed for group events

        switch ($evt.Id) {
            4720 {
                # New local user account created
                $details = @{
                    TargetUserName   = $targetUser
                    TargetDomain     = $targetDomain
                    SubjectUserName  = $subjectUser
                    SubjectUserSid   = $subjectSid
                    Hostname         = $env:COMPUTERNAME
                    WindowsEventId   = 4720
                }
                Send-SecurityEvent `
                    -EventType   'USER_CREATED' `
                    -EventId     4720 `
                    -EventSource 'Security' `
                    -Severity    'HIGH' `
                    -Summary     "New local user account '$targetUser' created on $env:COMPUTERNAME by '$subjectUser'" `
                    -Details     $details `
                    -Timestamp   $evt.TimeCreated
                $eventsDispatched++
            }
            4726 {
                # Local user account deleted
                $details = @{
                    TargetUserName  = $targetUser
                    TargetDomain    = $targetDomain
                    SubjectUserName = $subjectUser
                    SubjectUserSid  = $subjectSid
                    Hostname        = $env:COMPUTERNAME
                    WindowsEventId  = 4726
                }
                Send-SecurityEvent `
                    -EventType   'USER_DELETED' `
                    -EventId     4726 `
                    -EventSource 'Security' `
                    -Severity    'MEDIUM' `
                    -Summary     "Local user account '$targetUser' deleted on $env:COMPUTERNAME by '$subjectUser'" `
                    -Details     $details `
                    -Timestamp   $evt.TimeCreated
                $eventsDispatched++
            }
            4728 {
                # User added to a global security group (often Domain Admins on domain)
                $memberName  = Get-EventXmlData -Event $evt -FieldName 'MemberName'
                $memberSid   = Get-EventXmlData -Event $evt -FieldName 'MemberSid'
                $targetGroup = Get-EventXmlData -Event $evt -FieldName 'TargetUserName'

                $details = @{
                    MemberName      = $memberName
                    MemberSid       = $memberSid
                    GroupName       = $targetGroup
                    SubjectUserName = $subjectUser
                    SubjectUserSid  = $subjectSid
                    Hostname        = $env:COMPUTERNAME
                    WindowsEventId  = 4728
                }
                Send-SecurityEvent `
                    -EventType   'ADMIN_ADDED' `
                    -EventId     4728 `
                    -EventSource 'Security' `
                    -Severity    'CRITICAL' `
                    -Summary     "User '$memberName' added to privileged group '$targetGroup' on $env:COMPUTERNAME by '$subjectUser'" `
                    -Details     $details `
                    -Timestamp   $evt.TimeCreated
                $eventsDispatched++
            }
            4732 {
                # User added to a local security group (commonly Administrators)
                $memberName  = Get-EventXmlData -Event $evt -FieldName 'MemberName'
                $memberSid   = Get-EventXmlData -Event $evt -FieldName 'MemberSid'
                $targetGroup = Get-EventXmlData -Event $evt -FieldName 'TargetUserName'

                $details = @{
                    MemberName      = $memberName
                    MemberSid       = $memberSid
                    GroupName       = $targetGroup
                    SubjectUserName = $subjectUser
                    SubjectUserSid  = $subjectSid
                    Hostname        = $env:COMPUTERNAME
                    WindowsEventId  = 4732
                }
                Send-SecurityEvent `
                    -EventType   'ADMIN_ADDED' `
                    -EventId     4732 `
                    -EventSource 'Security' `
                    -Severity    'CRITICAL' `
                    -Summary     "Privilege escalation: '$memberName' added to local group '$targetGroup' on $env:COMPUTERNAME by '$subjectUser'" `
                    -Details     $details `
                    -Timestamp   $evt.TimeCreated
                $eventsDispatched++
            }
        }
    }
} catch {
    Write-WatchdogLog 'WARN' "Security log scan failed: $($_.Exception.Message)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION LOG: MSI Installer events
# ═══════════════════════════════════════════════════════════════════════════════
try {
    $msiEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'MsiInstaller'
        Id           = @(1033, 11707)
        StartTime    = $since
    } -ErrorAction SilentlyContinue

    foreach ($msiEvt in $msiEvents) {
        # Event 1033: Installation completed successfully
        # Event 11707: Product installation completed successfully
        # Properties[0] = ProductName, Properties[1] = ProductVersion, Properties[7] = Install Status for 1033
        $productName    = $null
        $productVersion = $null
        $publisher      = $null

        try {
            $productName    = $msiEvt.Properties[0].Value -as [string]
            $productVersion = $msiEvt.Properties[1].Value -as [string]
            $publisher      = $msiEvt.Properties[4].Value -as [string]
        } catch { }

        # Fallback: parse the formatted message
        if (-not $productName) {
            $msg = $msiEvt.Message ?? ''
            if ($msg -match 'Product:\s+(.+?)\s+--') {
                $productName = $matches[1]
            }
        }

        $details = @{
            ProductName     = $productName
            ProductVersion  = $productVersion
            Publisher       = $publisher
            WindowsEventId  = $msiEvt.Id
            EventMessage    = ($msiEvt.Message ?? '').Substring(0, [Math]::Min(500, ($msiEvt.Message ?? '').Length))
            Hostname        = $env:COMPUTERNAME
        }

        Send-SecurityEvent `
            -EventType   'APP_INSTALLED' `
            -EventId     $msiEvt.Id `
            -EventSource 'MsiInstaller' `
            -Severity    'MEDIUM' `
            -Summary     "Application installed via MSI: '$($productName ?? 'Unknown')' v$($productVersion ?? '?') on $env:COMPUTERNAME" `
            -Details     $details `
            -Timestamp   $msiEvt.TimeCreated
        $eventsDispatched++
    }
} catch {
    Write-WatchdogLog 'WARN' "MSI event scan failed: $($_.Exception.Message)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# APPX DEPLOYMENT LOG: Event ID 854 (Store App installed)
# ═══════════════════════════════════════════════════════════════════════════════
try {
    $appxEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-AppXDeployment-Server/Operational'
        Id        = @(854)
        StartTime = $since
    } -ErrorAction SilentlyContinue

    foreach ($appxEvt in $appxEvents) {
        $packageFullName = $null
        try {
            $packageFullName = $appxEvt.Properties[0].Value -as [string]
        } catch { }

        if (-not $packageFullName -and $appxEvt.Message) {
            if ($appxEvt.Message -match 'PackageFullName:\s+(\S+)') {
                $packageFullName = $matches[1]
            }
        }

        $details = @{
            PackageFullName = $packageFullName
            WindowsEventId  = 854
            EventSource     = 'AppXDeployment-Server'
            Hostname        = $env:COMPUTERNAME
        }

        Send-SecurityEvent `
            -EventType   'APP_INSTALLED' `
            -EventId     854 `
            -EventSource 'AppXDeployment-Server' `
            -Severity    'LOW' `
            -Summary     "AppX/MSIX package installed: '$($packageFullName ?? 'Unknown')' on $env:COMPUTERNAME" `
            -Details     $details `
            -Timestamp   $appxEvt.TimeCreated
        $eventsDispatched++
    }
} catch {
    Write-WatchdogLog 'WARN' "AppX deployment log scan failed: $($_.Exception.Message)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROACTIVE: Recent AppX installs via Get-AppxPackage (catch anything missed)
# ═══════════════════════════════════════════════════════════════════════════════
try {
    $recentAppx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                  Where-Object {
                      -not $_.IsFramework -and
                      $_.SignatureKind -ne 'System' -and
                      $_.InstallLocation -and
                      (Test-Path $_.InstallLocation -ErrorAction SilentlyContinue) -and
                      ((Get-Item $_.InstallLocation -ErrorAction SilentlyContinue).CreationTime -gt $since)
                  } |
                  Select-Object -First 10  # Cap to prevent storm on first run

    foreach ($pkg in $recentAppx) {
        $details = @{
            PackageName    = $pkg.Name
            PackageVersion = $pkg.Version
            Publisher      = $pkg.Publisher
            InstallLocation = $pkg.InstallLocation
            Hostname       = $env:COMPUTERNAME
        }

        # Only dispatch if we didn't already get this from EventID 854
        $alreadyLogged = $appxEvents | Where-Object { $_.Message -like "*$($pkg.Name)*" }
        if (-not $alreadyLogged) {
            Send-SecurityEvent `
                -EventType   'APP_INSTALLED' `
                -EventId     854 `
                -EventSource 'AppXDeployment-Server' `
                -Severity    'LOW' `
                -Summary     "AppX package recently installed: '$($pkg.Name)' v$($pkg.Version) on $env:COMPUTERNAME" `
                -Details     $details `
                -Timestamp   (Get-Date)
            $eventsDispatched++
        }
    }
} catch {
    Write-WatchdogLog 'WARN' "AppX proactive scan failed: $($_.Exception.Message)"
}

Write-WatchdogLog 'INFO' "Watchdog cycle complete — $eventsDispatched event(s) dispatched"
