/**
 * LocalPilot Fleet — SQLite Database Engine
 * server/src/db.js
 *
 * Backed by Node.js 26 native node:sqlite (DatabaseSync).
 * Configures WAL mode, 5000ms busy timeout, 8 relational tables, 16 indexes, and seed data.
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

let dbInstance = null;

export function applyPragmas(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA cache_size = -64000;
    PRAGMA temp_store = MEMORY;
  `);
}

export function initDb(dbOrPath, options = {}) {
  let db;
  let shouldSeed = options.seed !== false;

  if (dbOrPath && typeof dbOrPath === 'object' && typeof dbOrPath.exec === 'function') {
    db = dbOrPath;
  } else if (typeof dbOrPath === 'string') {
    const dbDir = path.dirname(dbOrPath);
    if (dbDir && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    db = new DatabaseSync(dbOrPath);
    applyPragmas(db);
  } else {
    // If first argument is options object
    if (dbOrPath && typeof dbOrPath === 'object' && options.seed === undefined) {
      if (dbOrPath.seed !== undefined) shouldSeed = dbOrPath.seed;
    }
    const dbPath = process.env.DB_PATH || path.join(process.cwd(), 'data', 'fleet.db');
    const dbDir = path.dirname(dbPath);
    if (dbDir && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    db = new DatabaseSync(dbPath);
    applyPragmas(db);
  }

  // 8 Relational Tables DDL
  db.exec(`
    -- 1. DEVICES
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY NOT NULL,
      hostname TEXT NOT NULL,
      friendly_name TEXT,
      serial_number TEXT UNIQUE,
      uuid TEXT UNIQUE,
      mac_address TEXT,
      ip_address TEXT,
      public_ip TEXT,
      connection_route TEXT DEFAULT 'LAN' CHECK(connection_route IN ('LAN', 'Cloudflare', 'Unknown')),
      status TEXT DEFAULT 'online' CHECK(status IN ('online', 'offline', 'drifted', 'quarantined')),
      os_name TEXT NOT NULL,
      os_version TEXT NOT NULL,
      os_build TEXT,
      os_architecture TEXT DEFAULT '64-bit',
      cpu_model TEXT,
      cpu_cores INTEGER,
      cpu_logical INTEGER,
      total_ram_bytes INTEGER NOT NULL,
      total_ram_gb REAL GENERATED ALWAYS AS (ROUND(total_ram_bytes / 1073741824.0, 2)) STORED,
      gpu_name TEXT,
      has_battery INTEGER DEFAULT 0 CHECK(has_battery IN (0, 1)),
      battery_percent REAL,
      battery_charging INTEGER DEFAULT 0 CHECK(battery_charging IN (0, 1)),
      tpm_present INTEGER DEFAULT 0 CHECK(tpm_present IN (0, 1)),
      tpm_version TEXT,
      tpm_enabled INTEGER DEFAULT 0 CHECK(tpm_enabled IN (0, 1)),
      secure_boot_enabled INTEGER DEFAULT 0 CHECK(secure_boot_enabled IN (0, 1)),
      bitlocker_status TEXT DEFAULT 'Disabled' CHECK(bitlocker_status IN ('FullyEncrypted', 'FullyDecrypted', 'EncryptionInProgress', 'Disabled')),
      primary_user TEXT,
      tags_json TEXT DEFAULT '[]',
      assigned_group TEXT,
      node_token_hash TEXT NOT NULL,
      agent_version TEXT NOT NULL,
      enrolled_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      last_seen_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    -- 2. TELEMETRY_SNAPSHOTS
    CREATE TABLE IF NOT EXISTS telemetry_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (DATETIME('now')),
      cpu_usage_percent REAL NOT NULL,
      ram_used_bytes INTEGER NOT NULL,
      ram_free_bytes INTEGER NOT NULL,
      ram_usage_percent REAL NOT NULL,
      disk_free_gb REAL,
      disks_json TEXT NOT NULL,
      network_json TEXT,
      battery_percent REAL,
      battery_charging INTEGER DEFAULT 0,
      process_count INTEGER,
      uptime_seconds INTEGER,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 3. DYNAMIC_GROUPS
    CREATE TABLE IF NOT EXISTS dynamic_groups (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      rule_syntax TEXT NOT NULL,
      is_dynamic INTEGER DEFAULT 1 CHECK(is_dynamic IN (0, 1)),
      color TEXT DEFAULT '#3B82F6',
      icon TEXT DEFAULT 'laptop',
      priority INTEGER DEFAULT 100,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    -- 4. GROUP_MEMBERSHIPS
    CREATE TABLE IF NOT EXISTS group_memberships (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      is_dynamic_match INTEGER DEFAULT 1 CHECK(is_dynamic_match IN (0, 1)),
      manually_assigned INTEGER DEFAULT 0 CHECK(manually_assigned IN (0, 1)),
      evaluated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(group_id) REFERENCES dynamic_groups(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(group_id, device_id)
    );

    -- 5. SOFTWARE_CATALOG
    CREATE TABLE IF NOT EXISTS software_catalog (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      publisher TEXT,
      winget_id TEXT NOT NULL,
      version TEXT,
      category TEXT DEFAULT 'Utilities',
      description TEXT,
      icon_url TEXT,
      silent_install_args TEXT,
      silent_uninstall_args TEXT,
      detection_rule_json TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    -- 6. POLICY_ASSIGNMENTS
    CREATE TABLE IF NOT EXISTS policy_assignments (
      id TEXT PRIMARY KEY NOT NULL,
      group_id TEXT NOT NULL,
      software_id TEXT NOT NULL,
      assignment_type TEXT NOT NULL CHECK(assignment_type IN ('Required', 'Prohibited', 'Available')),
      auto_update INTEGER DEFAULT 1 CHECK(auto_update IN (0, 1)),
      enforcement_priority INTEGER DEFAULT 10,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(group_id) REFERENCES dynamic_groups(id) ON DELETE CASCADE,
      FOREIGN KEY(software_id) REFERENCES software_catalog(id) ON DELETE CASCADE,
      UNIQUE(group_id, software_id)
    );

    -- 7. SECURITY_EVENTS
    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN (
        'USER_CREATED', 'USER_DELETED', 'ADMIN_ADDED', 'ADMIN_REMOVED',
        'APP_INSTALLED', 'APP_PROHIBITED_DETECTED', 'POLICY_DRIFT',
        'TPM_VIOLATION', 'SECUREBOOT_DISABLED', 'BITLOCKER_OFFLINE', 'WATCHDOG_HEARTBEAT'
      )),
      event_id INTEGER,
      event_source TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
      summary TEXT NOT NULL,
      raw_payload_json TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0 CHECK(acknowledged IN (0, 1)),
      acknowledged_at TEXT,
      acknowledged_by TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 8. FLEET_SETTINGS
    CREATE TABLE IF NOT EXISTS fleet_settings (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL,
      data_type TEXT DEFAULT 'string' CHECK(data_type IN ('string', 'number', 'boolean', 'json')),
      description TEXT,
      is_secret INTEGER DEFAULT 0 CHECK(is_secret IN (0, 1)),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    -- 9. DEVICE_COMMANDS (Intune Remote Actions & PowerShell execution)
    CREATE TABLE IF NOT EXISTS device_commands (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      command_text TEXT NOT NULL,
      created_by TEXT DEFAULT 'admin',
      status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
      exit_code INTEGER,
      stdout TEXT,
      stderr TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      executed_at TEXT,
      completed_at TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 10. REMEDIATIONS (Intune Proactive Remediation Script Packages)
    CREATE TABLE IF NOT EXISTS remediations (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      publisher TEXT DEFAULT 'LocalPilot Fleet',
      target_group_id TEXT DEFAULT 'grp-all',
      detection_script TEXT NOT NULL,
      remediation_script TEXT NOT NULL,
      schedule_type TEXT DEFAULT 'HEARTBEAT' CHECK(schedule_type IN ('HEARTBEAT', 'HOURLY', 'DAILY')),
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 11. REMEDIATION_RUNS (Per-device detection and remediation telemetry)
    CREATE TABLE IF NOT EXISTS remediation_runs (
      id TEXT PRIMARY KEY NOT NULL,
      remediation_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      detection_exit_code INTEGER,
      detection_stdout TEXT,
      detection_stderr TEXT,
      detection_status TEXT CHECK(detection_status IN ('NO_ISSUE', 'ISSUE_DETECTED', 'ERROR')),
      remediation_exit_code INTEGER,
      remediation_stdout TEXT,
      remediation_stderr TEXT,
      remediation_status TEXT CHECK(remediation_status IN ('NOT_NEEDED', 'REMEDIATED', 'FAILED', 'ERROR')),
      executed_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(remediation_id) REFERENCES remediations(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );
  `);

  // Indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
    CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
    CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
    CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial_number);
    CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(node_token_hash);

    CREATE INDEX IF NOT EXISTS idx_telemetry_dev_time ON telemetry_snapshots(device_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_snapshots(timestamp);

    CREATE INDEX IF NOT EXISTS idx_dynamic_groups_priority ON dynamic_groups(priority ASC);

    CREATE INDEX IF NOT EXISTS idx_memberships_device ON group_memberships(device_id);
    CREATE INDEX IF NOT EXISTS idx_memberships_group ON group_memberships(group_id);

    CREATE UNIQUE INDEX IF NOT EXISTS idx_software_winget ON software_catalog(winget_id);

    CREATE INDEX IF NOT EXISTS idx_policy_group ON policy_assignments(group_id);
    CREATE INDEX IF NOT EXISTS idx_policy_software ON policy_assignments(software_id);

    CREATE INDEX IF NOT EXISTS idx_events_device ON security_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_events_sev_ack ON security_events(severity, acknowledged);
    CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_device_commands_dev_status ON device_commands(device_id, status);

    CREATE INDEX IF NOT EXISTS idx_remediations_target ON remediations(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_runs_dev ON remediation_runs(device_id, executed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_remediation_runs_rem ON remediation_runs(remediation_id, executed_at DESC);
  `);

  if (shouldSeed) {
    seedDatabase(db);
  }

  dbInstance = db;
  return dbInstance;
}

export function getDb() {
  if (!dbInstance) {
    return initDb();
  }
  return dbInstance;
}

export function closeDb() {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {}
    dbInstance = null;
  }
}

export function seedDatabase(db) {
  // 1. Settings
  const settingsCount = db.prepare('SELECT COUNT(*) as count FROM fleet_settings').get().count;
  if (settingsCount === 0) {
    const insertSetting = db.prepare(`
      INSERT OR IGNORE INTO fleet_settings (key, value, data_type, description, is_secret)
      VALUES (?, ?, ?, ?, ?)
    `);

    const defaults = [
      ['fleet_name', 'Daddy Command Fleet', 'string', 'Display title for dashboard header', 0],
      ['fleet_enrollment_key', 'localpilot-secret-key-2026', 'string', 'Pre-shared key required for new node enrollment', 1],
      ['server_port', '8443', 'number', 'Backend listening port', 0],
      ['heartbeat_interval_sec', '60', 'number', 'Frequency of lightweight node heartbeat', 0],
      ['telemetry_interval_min', '15', 'number', 'Frequency of deep hardware/software inventory harvest', 0],
      ['offline_threshold_sec', '180', 'number', 'Seconds without heartbeat before marking node offline', 0],
      ['toast_notifications_enabled', 'true', 'boolean', 'Show Windows native toast on Daddy PC', 0],
      ['discord_webhook_url', '', 'string', 'Discord Webhook URL for critical push notifications', 1],
      ['slack_webhook_url', '', 'string', 'Slack Incoming Webhook URL', 1],
      ['telegram_bot_token', '', 'string', 'Telegram Bot API Token', 1],
      ['telegram_chat_id', '', 'string', 'Telegram Chat ID for notifications', 0],
      ['cloudflare_tunnel_hostname', '', 'string', 'Public tunnel hostname e.g. fleet.yourdomain.com', 0],
      ['cloudflare_tunnel_id', '', 'string', 'Cloudflare Tunnel UUID', 0]
    ];

    for (const [k, v, dt, desc, sec] of defaults) {
      insertSetting.run(k, v, dt, desc, sec);
    }
  }

  // 2. Dynamic Groups
  const groupCount = db.prepare('SELECT COUNT(*) as count FROM dynamic_groups').get().count;
  if (groupCount === 0) {
    const insertGroup = db.prepare(`
      INSERT OR IGNORE INTO dynamic_groups (id, name, description, rule_syntax, is_dynamic, color, icon, priority)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const groups = [
      ['grp-all', 'All Devices', 'Default catch-all group containing every enrolled node', 'Device.Hostname -like "*"', 1, '#64748B', 'monitor', 10],
      ['grp-workstations', 'High-Performance Workstations', 'Desktops with >= 32GB RAM and dedicated NVIDIA GPU', 'Device.TotalRAM_GB -ge 32 and Device.GPU -like "*NVIDIA*" and Device.HasBattery -eq false', 1, '#10B981', 'cpu', 20],
      ['grp-family-laptops', 'Family Laptops', 'Portable battery-powered machines tagged for family members', 'Device.HasBattery -eq true and Device.Tags -contains "family"', 1, '#3B82F6', 'laptop', 30],
      ['grp-win11-modern', 'Windows 11 Modern Core', 'Windows 11 builds with active TPM 2.0 and SecureBoot enabled', 'Device.OSVersion -like "10.0.22*" and Device.TPMEnabled -eq true and Device.SecureBoot -eq true', 1, '#8B5CF6', 'shield-check', 40],
      ['grp-low-storage', 'Storage Warning Watchlist', 'Nodes with less than 50GB free space on system drive', 'Device.StorageFree_GB -lt 50', 1, '#EF4444', 'hard-drive', 50]
    ];

    for (const g of groups) {
      insertGroup.run(...g);
    }
  }

  // 3. Software Catalog
  const softCount = db.prepare('SELECT COUNT(*) as count FROM software_catalog').get().count;
  if (softCount === 0) {
    const insertSoft = db.prepare(`
      INSERT OR IGNORE INTO software_catalog (id, name, publisher, winget_id, version, category, description, silent_install_args)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const packages = [
      ['pkg-chrome', 'Google Chrome', 'Google LLC', 'Google.Chrome', 'latest', 'Browsers', 'Standard secure web browser', '--silent --accept-package-agreements --accept-source-agreements'],
      ['pkg-bitwarden', 'Bitwarden', 'Bitwarden Inc.', 'Bitwarden.Bitwarden', 'latest', 'Security', 'Password manager for family security', '--silent --accept-package-agreements --accept-source-agreements'],
      ['pkg-7zip', '7-Zip', 'Igor Pavlov', '7zip.7zip', 'latest', 'Utilities', 'Open source file archiver', '--silent --accept-package-agreements --accept-source-agreements'],
      ['pkg-vscode', 'Visual Studio Code', 'Microsoft Corporation', 'Microsoft.VisualStudioCode', 'latest', 'Development', 'Code editor for development workstations', '--silent --accept-package-agreements --accept-source-agreements'],
      ['pkg-steam', 'Steam', 'Valve Corporation', 'Valve.Steam', 'latest', 'Gaming', 'Gaming digital distribution platform', '--silent --accept-package-agreements --accept-source-agreements'],
      ['pkg-utorrent', 'uTorrent', 'BitTorrent Inc.', 'BitTorrent.uTorrent', '', 'Prohibited', 'Unapproved P2P torrent client', '--silent']
    ];

    for (const p of packages) {
      insertSoft.run(...p);
    }
  }

  // 4. Policy Assignments
  const polCount = db.prepare('SELECT COUNT(*) as count FROM policy_assignments').get().count;
  if (polCount === 0) {
    const insertPol = db.prepare(`
      INSERT OR IGNORE INTO policy_assignments (id, group_id, software_id, assignment_type, auto_update)
      VALUES (?, ?, ?, ?, ?)
    `);

    const policies = [
      ['pol-chrome-all', 'grp-all', 'pkg-chrome', 'Required', 1],
      ['pol-bitwarden-family', 'grp-family-laptops', 'pkg-bitwarden', 'Required', 1],
      ['pol-7zip-all', 'grp-all', 'pkg-7zip', 'Required', 1],
      ['pol-vscode-workstations', 'grp-workstations', 'pkg-vscode', 'Available', 1],
      ['pol-steam-workstations', 'grp-workstations', 'pkg-steam', 'Available', 1],
      ['pol-utorrent-prohibited-all', 'grp-all', 'pkg-utorrent', 'Prohibited', 0]
    ];

    for (const pol of policies) {
      insertPol.run(...pol);
    }
  }

  // 5. Realistic Seed Devices
  const devCount = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
  if (devCount === 0) {
    const insertDev = db.prepare(`
      INSERT OR IGNORE INTO devices (
        id, hostname, friendly_name, serial_number, uuid, mac_address, ip_address,
        connection_route, status, os_name, os_version, os_build, cpu_model, cpu_cores, cpu_logical,
        total_ram_bytes, gpu_name, has_battery, battery_percent, battery_charging,
        tpm_present, tpm_version, tpm_enabled, secure_boot_enabled, bitlocker_status,
        primary_user, tags_json, assigned_group, node_token_hash, agent_version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // dev 1: Dad's Rig
    insertDev.run(
      'dev-daddy-pc', 'DADDY-RIG', "Dad's Workstation", 'MB-9901-DADDY', '11111111-2222-3333-4444-555555555555',
      '00:15:5D:01:02:03', '192.168.1.100', 'LAN', 'online', 'Microsoft Windows 11 Pro', '10.0.22631', '22631.3296',
      'AMD Ryzen 7 7800X3D 8-Core Processor', 8, 16, 68719476736, 'NVIDIA GeForce RTX 4090', 0, null, 0,
      1, '2.0', 1, 1, 'FullyEncrypted', 'Dad', '["workstation", "gaming", "host"]', 'High-Performance Workstations',
      'hash_daddy_token', '1.0.0'
    );

    // dev 2: Living Room PC (Drifted with uTorrent)
    insertDev.run(
      'dev-livingroom-pc', 'LIVINGROOM-PC', 'Family Living Room PC', 'MB-5521-LIVING', '22222222-3333-4444-5555-666666666666',
      '00:15:5D:04:05:06', '192.168.1.145', 'LAN', 'drifted', 'Microsoft Windows 11 Home', '10.0.22631', '22631.3296',
      'AMD Ryzen 5 5600G with Radeon Graphics', 6, 12, 17179869184, 'AMD Radeon Graphics', 0, null, 0,
      1, '2.0', 1, 1, 'Disabled', 'Family', '["family", "livingroom"]', 'Family Laptops',
      'hash_livingroom_token', '1.0.0'
    );

    // dev 3: Sarah's Surface Laptop (Roaming via Cloudflare)
    insertDev.run(
      'dev-sarah-laptop', 'SARAHS-SURFACE', "Sarah's Laptop", 'MB-7712-SURFACE', '33333333-4444-5555-6666-777777777777',
      '00:15:5D:07:08:09', '172.56.21.4', 'Cloudflare', 'online', 'Microsoft Windows 11 Pro', '10.0.22631', '22631.3296',
      '12th Gen Intel(R) Core(TM) i7-1265U', 10, 12, 17179869184, 'Intel(R) Iris(R) Xe Graphics', 1, 74.5, 0,
      1, '2.0', 1, 1, 'FullyEncrypted', 'Sarah', '["family", "laptop", "roaming"]', 'Family Laptops',
      'hash_sarah_token', '1.0.0'
    );

    // Group Memberships
    const insertMember = db.prepare(`
      INSERT OR IGNORE INTO group_memberships (group_id, device_id, is_dynamic_match)
      VALUES (?, ?, 1)
    `);
    insertMember.run('grp-all', 'dev-daddy-pc');
    insertMember.run('grp-workstations', 'dev-daddy-pc');
    insertMember.run('grp-win11-modern', 'dev-daddy-pc');

    insertMember.run('grp-all', 'dev-livingroom-pc');
    insertMember.run('grp-win11-modern', 'dev-livingroom-pc');

    insertMember.run('grp-all', 'dev-sarah-laptop');
    insertMember.run('grp-family-laptops', 'dev-sarah-laptop');
    insertMember.run('grp-win11-modern', 'dev-sarah-laptop');

    // Sample Snapshot for Daddy PC
    db.prepare(`
      INSERT INTO telemetry_snapshots (
        device_id, cpu_usage_percent, ram_used_bytes, ram_free_bytes, ram_usage_percent,
        disk_free_gb, disks_json, process_count, uptime_seconds
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'dev-daddy-pc', 12.5, 21474836480, 47244640256, 31.2, 850.5,
      JSON.stringify([{ drive: 'C:', total_gb: 2000, free_gb: 850.5, smart_healthy: true }]),
      182, 345600
    );

    // Sample Alert for Living Room PC
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'dev-livingroom-pc', 'APP_PROHIBITED_DETECTED', 1033, 'LocalPilotWatchdog', 'CRITICAL',
      'Prohibited application "uTorrent" detected on LIVINGROOM-PC',
      JSON.stringify({ app: 'uTorrent', policy: 'Prohibited', detected_at: new Date().toISOString() }),
      0
    );

    // ── Seed Default Enterprise Remediations ──
    const insertRem = db.prepare(`
      INSERT INTO remediations (
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
  Write-Host "Stale temporary files detected: $totalMb MB (threshold: 500 MB)"
  exit 1
}
Write-Host "Temp storage healthy: $totalMb MB stale files (threshold: 500 MB)"
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

    // Sample Remediation Runs
    const insertRun = db.prepare(`
      INSERT INTO remediation_runs (
        id, remediation_id, device_id, detection_exit_code, detection_stdout, detection_stderr,
        detection_status, remediation_exit_code, remediation_stdout, remediation_stderr,
        remediation_status, executed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
    `);

    insertRun.run(
      'run-sample-01', 'rem-temp-cleanup', 'dev-daddy-pc',
      0, 'Temp storage healthy: 124.5 MB stale files (threshold: 500 MB)', '',
      'NO_ISSUE', null, null, null, 'NOT_NEEDED', '-10 minutes'
    );

    insertRun.run(
      'run-sample-02', 'rem-temp-cleanup', 'dev-livingroom-pc',
      1, 'Stale temporary files detected: 840.2 MB (threshold: 500 MB)', '',
      'ISSUE_DETECTED', 0, 'Purged 840.2 MB of stale temporary files.', '',
      'REMEDIATED', '-5 minutes'
    );

    insertRun.run(
      'run-sample-03', 'rem-spooler-heal', 'dev-daddy-pc',
      0, 'Print Spooler service is running normally', '',
      'NO_ISSUE', null, null, null, 'NOT_NEEDED', '-15 minutes'
    );
  }
}
