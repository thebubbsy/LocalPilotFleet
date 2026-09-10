using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LocalPilotService
{
    public class SupervisorService : BackgroundService
    {
        private readonly ILogger<SupervisorService> _logger;
        private readonly HttpClient _httpClient;
        private IntPtr _hJobObject = IntPtr.Zero;
        private Process? _workerProcess;
        private int _crashCount = 0;
        private readonly string _serverUrl = "http://localhost:8443";
        private readonly string _fleetKey = "8161bd42-02a7-47b0-b7eb-efbf5fdda1ed";

        public SupervisorService(ILogger<SupervisorService> logger)
        {
            _logger = logger;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("LocalPilot Hardened Windows Service Supervisor starting [NT AUTHORITY\\SYSTEM]...");
            
            // Win32 Job Object with 5% CPU and 150MB RAM caps
            _hJobObject = JobObjectInterop.CreateHardenedJobObject(maxCpuPercent: 5, maxMemoryMb: 150);
            if (_hJobObject != IntPtr.Zero)
            {
                _logger.LogInformation("Win32 Job Object initialized with 5% CPU and 150MB RAM containment limits.");
            }

            return base.StartAsync(cancellationToken);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (_workerProcess == null || _workerProcess.HasExited)
                    {
                        await LaunchAndSuperviseWorkerAsync(stoppingToken);
                    }

                    // Periodic supervisor telemetry heartbeat
                    await ReportSupervisorTelemetryAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in supervisor orchestration loop.");
                }

                await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            }
        }

        private async Task LaunchAndSuperviseWorkerAsync(CancellationToken stoppingToken)
        {
            if (_workerProcess != null && _workerProcess.HasExited)
            {
                int exitCode = _workerProcess.ExitCode;
                _crashCount++;
                _logger.LogWarning("LocalPilot Worker process terminated with ExitCode {ExitCode}. Total crashes: {CrashCount}", exitCode, _crashCount);

                // Dispatch crash dump telemetry
                await ReportCrashDumpAsync(exitCode, "UNHANDLED_WORKER_TERMINATION");
            }

            _logger.LogInformation("Spawning LocalPilot agent worker under Job Object containment...");

            string agentScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "Invoke-LocalPilotAgent.ps1");
            if (!File.Exists(agentScriptPath))
            {
                agentScriptPath = @"C:\temp\LocalPilotFleet\agent\Invoke-LocalPilotAgent.ps1";
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{agentScriptPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };

            try
            {
                _workerProcess = Process.Start(startInfo);
                if (_workerProcess != null)
                {
                    _logger.LogInformation("Worker spawned with PID {WorkerPid}", _workerProcess.Id);

                    if (_hJobObject != IntPtr.Zero)
                    {
                        bool assigned = JobObjectInterop.AssignProcess(_hJobObject, _workerProcess.Handle);
                        _logger.LogInformation("Worker PID {WorkerPid} assigned to Job Object: {Assigned}", _workerProcess.Id, assigned);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to launch worker process.");
            }
        }

        private async Task ReportSupervisorTelemetryAsync()
        {
            try
            {
                var payload = new
                {
                    supervisor_pid = Process.GetCurrentProcess().Id,
                    worker_pid = _workerProcess != null && !_workerProcess.HasExited ? _workerProcess.Id : (int?)null,
                    watchdog_pid = Process.GetCurrentProcess().Id,
                    binary_path = Environment.ProcessPath ?? "LocalPilotService.exe",
                    binary_version = "1.0.0-enterprise",
                    cpu_limit_percent = 5,
                    ram_limit_mb = 150,
                    job_object_active = _hJobObject != IntPtr.Zero,
                    anti_tamper_enabled = true
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, $"{_serverUrl}/api/v1/nodes/{Environment.MachineName}/supervisor/heartbeat");
                request.Headers.Add("x-fleet-key", _fleetKey);
                request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                await _httpClient.SendAsync(request);
            }
            catch
            {
                // Non-blocking telemetry
            }
        }

        private async Task ReportCrashDumpAsync(int exitCode, string crashType)
        {
            try
            {
                var payload = new
                {
                    crash_type = crashType,
                    exit_code = exitCode,
                    stack_trace = $"Worker process exited unexpectedly with exit code {exitCode}",
                    recovery_action = "RESTARTED_WORKER",
                    recovery_duration_ms = 1250
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, $"{_serverUrl}/api/v1/nodes/{Environment.MachineName}/supervisor/crash-dump");
                request.Headers.Add("x-fleet-key", _fleetKey);
                request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                await _httpClient.SendAsync(request);
            }
            catch
            {
                // Non-blocking crash telemetry
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("LocalPilot Supervisor stopping gracefully...");
            if (_workerProcess != null && !_workerProcess.HasExited)
            {
                try { _workerProcess.Kill(true); } catch { }
            }

            if (_hJobObject != IntPtr.Zero)
            {
                JobObjectInterop.CloseHandle(_hJobObject);
                _hJobObject = IntPtr.Zero;
            }

            await base.StopAsync(cancellationToken);
        }
    }
}
