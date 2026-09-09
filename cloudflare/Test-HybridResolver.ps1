<#
.SYNOPSIS
    Tests dual-mode LAN / Cloudflare Tunnel connectivity for LocalPilot Fleet.

.DESCRIPTION
    Attempts to reach the Fleet health endpoint via LAN first (low-latency path).
    If the LAN is unreachable, falls back to the Cloudflare Tunnel URL.
    Reports which route is active, its latency in milliseconds, and the server
    version reported by the health endpoint.

.PARAMETER LanUrl
    Base URL of the Fleet server on the local network.
    Example: http://10.1.1.213:8443

.PARAMETER TunnelUrl
    Base URL of the Fleet server via Cloudflare Tunnel.
    Example: https://fleet.yourdomain.com

.PARAMETER FleetKey
    The Fleet API key (Bearer token). Used to authenticate the health check
    request when the server requires authorization.

.OUTPUTS
    PSCustomObject with properties:
        Route       -- 'lan' | 'tunnel' | 'offline'
        Latency_ms  -- Round-trip time in milliseconds (-1 if offline)
        ServerVersion -- Version string from the health payload (or $null)

.EXAMPLE
    .\Test-HybridResolver.ps1 -LanUrl http://10.1.1.213:8443 -TunnelUrl https://fleet.example.com -FleetKey abc123
    .\Test-HybridResolver.ps1 -LanUrl http://DADDY-PC:8443 -TunnelUrl https://fleet.example.com -FleetKey abc123
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $LanUrl,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TunnelUrl,

    [string] $FleetKey = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Info  { param([string]$T); Write-Host "  [~]  $T" -ForegroundColor Cyan    }
function Write-Ok    { param([string]$T); Write-Host "  [OK] $T" -ForegroundColor Green   }
function Write-Fail  { param([string]$T); Write-Host "  [XX] $T" -ForegroundColor Red     }
function Write-Warn  { param([string]$T); Write-Host "  [!!] $T" -ForegroundColor Yellow  }

function Invoke-HealthCheck {
    <#
    .DESCRIPTION
        GETs /api/v1/health from $BaseUrl, returns a hashtable with:
          Success    [bool]
          Latency_ms [long]
          Body       [hashtable or $null]
    #>
    param(
        [string] $BaseUrl,
        [string] $Key,
        [int]    $TimeoutSec = 3
    )

    $endpoint = ($BaseUrl.TrimEnd('/')) + '/api/v1/health'
    $headers  = @{}
    if (-not [string]::IsNullOrWhiteSpace($Key)) {
        $headers['Authorization'] = "Bearer $Key"
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-RestMethod `
            -Uri             $endpoint `
            -Method          GET `
            -Headers         $headers `
            -TimeoutSec      $TimeoutSec `
            -ErrorAction     Stop

        $stopwatch.Stop()
        return @{
            Success    = $true
            Latency_ms = $stopwatch.ElapsedMilliseconds
            Body       = $response
        }
    } catch {
        $stopwatch.Stop()
        return @{
            Success    = $false
            Latency_ms = $stopwatch.ElapsedMilliseconds
            Body       = $null
        }
    }
}

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '  LocalPilot Fleet -- Hybrid Connectivity Resolver' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------' -ForegroundColor DarkGray
Write-Info "LAN URL    : $LanUrl"
Write-Info "Tunnel URL : $TunnelUrl"
Write-Host ''

# ─── 1. Try LAN route ─────────────────────────────────────────────────────────
Write-Info 'Probing LAN route (3 s timeout)...'
$lanResult = Invoke-HealthCheck -BaseUrl $LanUrl -Key $FleetKey -TimeoutSec 3

if ($lanResult.Success) {
    $version = if ($lanResult.Body.PSObject.Properties['version']) { $lanResult.Body.version } elseif ($lanResult.Body.PSObject.Properties['service']) { $lanResult.Body.service } else { 'n/a' }
    Write-Ok "LAN route active (low latency) -- $($lanResult.Latency_ms) ms  |  server: $version"
    Write-Host ''

    return [PSCustomObject]@{
        Route         = 'lan'
        Latency_ms    = $lanResult.Latency_ms
        ServerVersion = $version
    }
}

Write-Fail "LAN unreachable ($($lanResult.Latency_ms) ms). Trying Cloudflare Tunnel..."
Write-Host ''

# ─── 2. Try Tunnel route ──────────────────────────────────────────────────────
Write-Info 'Probing Tunnel route (10 s timeout)...'
$tunnelResult = Invoke-HealthCheck -BaseUrl $TunnelUrl -Key $FleetKey -TimeoutSec 10

if ($tunnelResult.Success) {
    $version = if ($tunnelResult.Body.PSObject.Properties['version']) { $tunnelResult.Body.version } elseif ($tunnelResult.Body.PSObject.Properties['service']) { $tunnelResult.Body.service } else { 'n/a' }
    Write-Ok "Tunnel route active -- $($tunnelResult.Latency_ms) ms  |  server: $version"
    Write-Warn 'Using tunnel path -- expect higher latency than LAN.'
    Write-Host ''

    return [PSCustomObject]@{
        Route         = 'tunnel'
        Latency_ms    = $tunnelResult.Latency_ms
        ServerVersion = $version
    }
}

# ─── 3. Both routes failed ────────────────────────────────────────────────────
Write-Fail 'Both LAN and Tunnel routes are unreachable.'
Write-Warn 'Verify the Fleet server is running: .\Start-LocalPilotFleet.ps1'
Write-Host ''

return [PSCustomObject]@{
    Route         = 'offline'
    Latency_ms    = -1
    ServerVersion = $null
}
