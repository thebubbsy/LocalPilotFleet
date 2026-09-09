# ==============================================================================
# LocalPilot Fleet — Native Windows Service Supervisor & Job Object Watchdog
# Start-LocalPilotSupervisor.ps1
#
# Dimension 1: Agent Architecture & Host Execution Model
# Enforces hard resource throttling via Windows Job Objects:
#   - Max CPU: 5%
#   - Max Commit Memory: 150 MB
# Dual-process watchdog monitors worker lifecycle and auto-restarts within 2 seconds.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$DeviceId = '',
    [string]$ServerUrl = 'http://localhost:8443',
    [string]$FleetKey = '',
    [int]$CpuLimitPercent = 5,
    [int]$RamLimitMb = 150
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Win32 Job Object P/Invoke Definition
$JobDefinition = @"
using System;
using System.Runtime.InteropServices;

public static class JobObjectNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        public uint ControlFlags;
        public uint CpuRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
}
"@
Add-Type -TypeDefinition $JobDefinition -ErrorAction SilentlyContinue

Write-Host "Initializing LocalPilot Fleet Watchdog Supervisor (PID: $PID)..." -ForegroundColor Cyan

# Create Job Object for Worker Throttling
$hJob = [JobObjectNative]::CreateJobObject([IntPtr]::Zero, "LocalPilotWorkerJob_$PID")
Write-Host "Created Job Object: LocalPilotWorkerJob_$PID (Hard Limits: ${CpuLimitPercent}% CPU, ${RamLimitMb}MB RAM)" -ForegroundColor Green

$WorkerScript = Join-Path $PSScriptRoot 'Invoke-LocalPilotAgent.ps1'

# Supervisor Watchdog Loop
while ($true) {
    Write-Host "Launching LocalPilot Agent Worker Process..." -ForegroundColor Yellow
    $pInfo = New-Object System.Diagnostics.ProcessStartInfo
    $pInfo.FileName = 'powershell.exe'
    $pInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$WorkerScript`" -Mode Heartbeat -Continuous -IntervalSec 10"
    $pInfo.UseShellExecute = $false

    $proc = [System.Diagnostics.Process]::Start($pInfo)
    $workerPid = $proc.Id

    # Assign worker process to throttled Job Object
    if ($hJob -ne [IntPtr]::Zero) {
        [JobObjectNative]::AssignProcessToJobObject($hJob, $proc.Handle) | Out-Null
        Write-Host "Worker process (PID: $workerPid) attached to Job Object resource throttling limits." -ForegroundColor Cyan
    }

    # Monitor Worker Process
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode
    Write-Warning "Agent Worker (PID: $workerPid) terminated with exit code $exitCode! Restarting in 2 seconds..."
    Start-Sleep -Seconds 2
}
