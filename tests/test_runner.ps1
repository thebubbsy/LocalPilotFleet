<#
.SYNOPSIS
    LocalPilot Fleet Master End-to-End Test Suite Runner.
.DESCRIPTION
    Runs the comprehensive 4-tier requirement-driven E2E test suite for LocalPilot Fleet.
    Supports targeting the live server or running in spec-compliant isolated harness mode.
.PARAMETER Tier
    Which tier to execute: 'All', 'Tier1', 'Tier2', 'Tier3', 'Tier4'. Default is 'All'.
.PARAMETER ServerUrl
    Optional URL of a live running LocalPilot Fleet backend (e.g. "http://localhost:8443").
    If omitted, the test harness automatically boots an in-process spec contract server.
.PARAMETER FleetKey
    Pre-shared master enrollment key for test authorization.
.EXAMPLE
    .\test_runner.ps1 -Tier All
.EXAMPLE
    .\test_runner.ps1 -Tier Tier1 -ServerUrl "http://localhost:8443"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Tier1", "Tier2", "Tier3", "Tier4")]
    [string]$Tier = "All",

    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = "",

    [Parameter(Mandatory=$false)]
    [string]$FleetKey = "LP-FleetKey-984f48b8-6a3c-4e7a-9a99-4c6ec083b7f1"
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   LOCALPILOT FLEET COMMAND CENTER — END-TO-END TEST SUITE RUNNER              " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Execution Target: $(if ($ServerUrl) { $ServerUrl } else { 'Spec-Compliant Contract Harness' })" -ForegroundColor Gray
Write-Host " Selected Tier   : $Tier" -ForegroundColor Gray
Write-Host " Timestamp (UTC) : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))" -ForegroundColor Gray
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Gray

# Set environment variables if provided
if ($ServerUrl) {
    $env:FLEET_SERVER_URL = $ServerUrl
} else {
    Remove-Item env:FLEET_SERVER_URL -ErrorAction SilentlyContinue
}
if ($FleetKey) {
    $env:FLEET_KEY = $FleetKey
}

# Resolve test files
$testDir = $PSScriptRoot
$tierFiles = @{
    "Tier1" = "$testDir\tier1_features.test.js"
    "Tier2" = "$testDir\tier2_boundaries.test.js"
    "Tier3" = "$testDir\tier3_pairwise.test.js"
    "Tier4" = "$testDir\tier4_realworld.test.js"
}

$filesToRun = @()
switch ($Tier) {
    "All"   { $filesToRun = @($tierFiles["Tier1"], $tierFiles["Tier2"], $tierFiles["Tier3"], $tierFiles["Tier4"]) }
    "Tier1" { $filesToRun = @($tierFiles["Tier1"]) }
    "Tier2" { $filesToRun = @($tierFiles["Tier2"]) }
    "Tier3" { $filesToRun = @($tierFiles["Tier3"]) }
    "Tier4" { $filesToRun = @($tierFiles["Tier4"]) }
}

# Verify Node 22+ exists
try {
    $nodeVer = & node --version
    Write-Host " [OK] Runtime: Node.js $nodeVer detected" -ForegroundColor Green
} catch {
    Write-Error "Node.js executable not found. Node.js >= 22.0.0 is required."
    exit 1
}

Write-Host " [..] Launching test execution across $($filesToRun.Count) suite(s)..." -ForegroundColor Yellow
Write-Host ""

$startTime = [System.Diagnostics.Stopwatch]::StartNew()
$nodeArgs = @("--test") + $filesToRun

& node $nodeArgs
$exitCode = $LASTEXITCODE
$startTime.Stop()

Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Gray
if ($exitCode -eq 0) {
    Write-Host " [PASS] ALL TEST SUITES PASSED CLEANLY" -ForegroundColor Green
    Write-Host " Wall-clock Duration: $($startTime.ElapsedMilliseconds) ms" -ForegroundColor Gray
    Write-Host "================================================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host " [FAIL] TEST RUN FAILED (Exit code: $exitCode)" -ForegroundColor Red
    Write-Host " Wall-clock Duration: $($startTime.ElapsedMilliseconds) ms" -ForegroundColor Gray
    Write-Host "================================================================================" -ForegroundColor Red
    exit $exitCode
}
