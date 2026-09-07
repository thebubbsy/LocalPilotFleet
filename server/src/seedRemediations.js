/**
 * Seed default remediations into target database if not present
 */
import { DatabaseSync } from 'node:sqlite';

export function seedRemediationsIfEmpty(db) {
  const count = db.prepare('SELECT COUNT(*) as c FROM remediations').get().c;
  if (count > 0) return;

  const insertRem = db.prepare(`
    INSERT OR IGNORE INTO remediations (
      id, name, description, publisher, target_group_id, detection_script, remediation_script, schedule_type, is_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);

  insertRem.run(
    'rem-temp-cleanup',
    'Auto-Clean Stale Temporary Files & Crash Dumps',
    'Detects if user or system temporary directories exceed 500 MB of stale files and safely purges files older than 24 hours.',
    'Microsoft / LocalPilot Core',
    'grp-all',
    `$tempPaths = @($env:TEMP, 'C:\\Windows\\Temp')
$totalBytes = 0
foreach ($p in $tempPaths) {
  if (Test-Path $p) {
    $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) }
    $totalBytes += ($files | Measure-Object -Property Length -Sum).Sum
  }
}
$totalMb = [math]::Round($totalBytes / 1MB, 1)
if ($totalMb -gt 500) {
  Write-Host "Stale temporary files detected: $totalMb MB"
  exit 1
}
Write-Host "Temp storage healthy: $totalMb MB stale files"
exit 0`,
    `$tempPaths = @($env:TEMP, 'C:\\Windows\\Temp')
$freedBytes = 0
foreach ($p in $tempPaths) {
  if (Test-Path $p) {
    $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) }
    foreach ($f in $files) {
      try {
        $len = $f.Length
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
        $freedBytes += $len
      } catch {}
    }
  }
}
$freedMb = [math]::Round($freedBytes / 1MB, 1)
Write-Host "Purged $freedMb MB of stale temporary files."
exit 0`,
    'HEARTBEAT'
  );

  insertRem.run(
    'rem-spooler-heal',
    'Self-Healing Print Spooler & Subsystem Services',
    'Monitors the Windows Print Spooler service; automatically restarts it and corrects startup configuration if stopped or hung.',
    'Microsoft / LocalPilot Core',
    'grp-all',
    `$svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if (-not $svc) { Write-Host "Print Spooler service not found"; exit 0 }
if ($svc.Status -ne 'Running') {
  Write-Host "Print Spooler is stopped (Current status: $($svc.Status))"
  exit 1
}
Write-Host "Print Spooler service is running normally"
exit 0`,
    `Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name Spooler -ErrorAction Stop
Write-Host "Print Spooler service restarted and set to Automatic startup."
exit 0`,
    'HEARTBEAT'
  );

  insertRem.run(
    'rem-dns-flush',
    'DNS Client Cache & Intranet Gateway Self-Heal',
    'Validates network resolution and flushes DNS cache when stale lookup tables degrade local network communication.',
    'LocalPilot Enterprise',
    'grp-all',
    `$dnsTest = Resolve-DnsName -Name "localhost" -ErrorAction SilentlyContinue
if (-not $dnsTest) {
  Write-Host "DNS client cache failed resolution test"
  exit 1
}
Write-Host "DNS client resolution operational"
exit 0`,
    `Clear-DnsClientCache
Write-Host "Flushed Windows DNS Client Cache successfully."
exit 0`,
    'HOURLY'
  );
}

// If executed directly, seed server/data/fleet.db
const db = new DatabaseSync('server/data/fleet.db');
seedRemediationsIfEmpty(db);
console.log('Seeded remediations into server/data/fleet.db successfully.');
