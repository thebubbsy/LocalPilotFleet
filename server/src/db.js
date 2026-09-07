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
        'TPM_VIOLATION', 'SECUREBOOT_DISABLED', 'BITLOCKER_OFFLINE', 'WATCHDOG_HEARTBEAT',
        'MALWARE_THREAT_DETECTED', 'ANTIVIRUS_RTP_DISABLED',
        'BITLOCKER_KEY_ESCROWED', 'BITLOCKER_KEY_REVEALED', 'BITLOCKER_ENCRYPTION_TRIGGERED'
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

    -- 12. CONFIGURATION_PROFILES (Intune Settings Catalog & Security Baselines)
    CREATE TABLE IF NOT EXISTS configuration_profiles (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      profile_type TEXT DEFAULT 'SettingsCatalog' CHECK(profile_type IN ('SettingsCatalog', 'SecurityBaseline', 'CustomPolicy')),
      target_group_id TEXT DEFAULT 'grp-all',
      settings_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 13. PROFILE_COMPLIANCE (Per-device Configuration Profile Evaluation State)
    CREATE TABLE IF NOT EXISTS profile_compliance (
      id TEXT PRIMARY KEY NOT NULL,
      profile_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      compliance_status TEXT NOT NULL CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'ERROR', 'PENDING')),
      compliant_count INTEGER NOT NULL DEFAULT 0,
      non_compliant_count INTEGER NOT NULL DEFAULT 0,
      error_count INTEGER NOT NULL DEFAULT 0,
      setting_results_json TEXT NOT NULL DEFAULT '[]',
      evaluated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(profile_id) REFERENCES configuration_profiles(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(profile_id, device_id)
    );

    -- 14. UPDATE_RINGS (Windows Update for Business / WUfB Patch Cadence)
    CREATE TABLE IF NOT EXISTS update_rings (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      servicing_channel TEXT DEFAULT 'GeneralAvailability' CHECK(servicing_channel IN (
        'GeneralAvailability', 'WindowsInsiderPreRelease', 'WindowsInsiderBeta', 'WindowsInsiderReleasePreview'
      )),
      quality_deferral_days INTEGER DEFAULT 0 CHECK(quality_deferral_days >= 0 AND quality_deferral_days <= 30),
      feature_deferral_days INTEGER DEFAULT 0 CHECK(feature_deferral_days >= 0 AND feature_deferral_days <= 365),
      active_hours_start INTEGER DEFAULT 8 CHECK(active_hours_start >= 0 AND active_hours_start <= 23),
      active_hours_end INTEGER DEFAULT 17 CHECK(active_hours_end >= 0 AND active_hours_end <= 23),
      automatic_update_mode TEXT DEFAULT 'AutoInstallAndRebootAtMaintenanceTime' CHECK(automatic_update_mode IN (
        'NotifyDownload', 'AutoInstallAndRebootAtMaintenanceTime', 'AutoInstallAndRebootWithoutEndUserControl', 'ResetToDefault'
      )),
      restart_deadline_days INTEGER DEFAULT 5 CHECK(restart_deadline_days >= 0 AND restart_deadline_days <= 30),
      is_paused INTEGER DEFAULT 0 CHECK(is_paused IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 15. DEVICE_UPDATE_STATUS (Per-device Windows Update, Reboot & Hotfix Telemetry)
    CREATE TABLE IF NOT EXISTS device_update_status (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL UNIQUE,
      ring_id TEXT,
      reboot_pending INTEGER DEFAULT 0 CHECK(reboot_pending IN (0, 1)),
      reboot_pending_reasons_json TEXT DEFAULT '[]',
      last_scan_at TEXT,
      last_install_at TEXT,
      installed_hotfixes_json TEXT DEFAULT '[]',
      update_service_status TEXT DEFAULT 'Running',
      compliance_status TEXT DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'REBOOT_PENDING', 'DRIFTED', 'ERROR')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(ring_id) REFERENCES update_rings(id) ON DELETE SET NULL
    );

    -- 16. COMPLIANCE_POLICIES (Microsoft Intune Device Compliance & Conditional Access Rules)
    CREATE TABLE IF NOT EXISTS compliance_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      platform TEXT DEFAULT 'Windows11' CHECK(platform IN ('Windows11', 'Windows10', 'AllWindows')),
      min_os_build TEXT DEFAULT '10.0.22000',
      max_os_build TEXT,
      require_bitlocker INTEGER DEFAULT 1 CHECK(require_bitlocker IN (0, 1)),
      require_secure_boot INTEGER DEFAULT 1 CHECK(require_secure_boot IN (0, 1)),
      require_tpm INTEGER DEFAULT 1 CHECK(require_tpm IN (0, 1)),
      require_defender_antivirus INTEGER DEFAULT 1 CHECK(require_defender_antivirus IN (0, 1)),
      require_defender_rtp INTEGER DEFAULT 1 CHECK(require_defender_rtp IN (0, 1)),
      require_firewall INTEGER DEFAULT 1 CHECK(require_firewall IN (0, 1)),
      max_antivirus_signature_age_days INTEGER DEFAULT 7 CHECK(max_antivirus_signature_age_days >= 1 AND max_antivirus_signature_age_days <= 60),
      grace_period_days INTEGER DEFAULT 3 CHECK(grace_period_days >= 0 AND grace_period_days <= 30),
      non_compliance_action TEXT DEFAULT 'MARK_NON_COMPLIANT' CHECK(non_compliance_action IN ('MARK_NON_COMPLIANT', 'QUARANTINE', 'ALERT_ONLY')),
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 17. DEVICE_COMPLIANCE_EVALUATIONS (Per-device compliance posture & grace periods)
    CREATE TABLE IF NOT EXISTS device_compliance_evaluations (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      compliance_status TEXT NOT NULL DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'IN_GRACE_PERIOD', 'NON_COMPLIANT', 'ERROR')),
      first_failed_at TEXT,
      grace_period_expires_at TEXT,
      rule_results_json TEXT DEFAULT '[]',
      evaluated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES compliance_policies(id) ON DELETE CASCADE,
      UNIQUE(device_id, policy_id)
    );

    -- 18. APPS (Microsoft Intune Application Management & Win32/Winget Packaging)
    CREATE TABLE IF NOT EXISTS apps (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      publisher TEXT,
      version TEXT,
      category TEXT DEFAULT 'Developer Tools' CHECK(category IN ('Productivity', 'Developer Tools', 'Utilities', 'Security', 'Media', 'System')),
      app_type TEXT NOT NULL DEFAULT 'WINGET' CHECK(app_type IN ('WINGET', 'WIN32', 'MSI', 'SCRIPT')),
      package_identifier TEXT,
      assignment_intent TEXT NOT NULL DEFAULT 'REQUIRED' CHECK(assignment_intent IN ('REQUIRED', 'AVAILABLE', 'UNINSTALL')),
      target_group_id TEXT DEFAULT 'grp-all',
      install_command TEXT,
      uninstall_command TEXT,
      detection_rules_json TEXT DEFAULT '[]',
      requirement_rules_json TEXT DEFAULT '{}',
      icon_url TEXT,
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 19. DEVICE_APP_STATUS (Per-device Application Installation Posture & Detection History)
    CREATE TABLE IF NOT EXISTS device_app_status (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      app_id TEXT NOT NULL,
      install_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(install_status IN ('INSTALLED', 'PENDING', 'INSTALLING', 'FAILED', 'UNINSTALLED', 'NOT_APPLICABLE')),
      detection_state INTEGER DEFAULT 0 CHECK(detection_state IN (0, 1)),
      installed_version TEXT,
      error_code INTEGER,
      error_message TEXT,
      last_attempt_at TEXT,
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
      UNIQUE(device_id, app_id)
    );

    -- 20. ENDPOINT_SECURITY_POLICIES (Microsoft Defender for Endpoint & Antivirus Governance)
    CREATE TABLE IF NOT EXISTS endpoint_security_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      real_time_protection INTEGER NOT NULL DEFAULT 1 CHECK(real_time_protection IN (0, 1)),
      cloud_protection_level TEXT NOT NULL DEFAULT 'HIGH' CHECK(cloud_protection_level IN ('DISABLED', 'BASIC', 'STANDARD', 'HIGH', 'HIGH_PLUS', 'ZERO_TOLERANCE')),
      controlled_folder_access TEXT NOT NULL DEFAULT 'AUDIT' CHECK(controlled_folder_access IN ('DISABLED', 'ENABLED', 'AUDIT', 'BLOCK_DISK_ONLY')),
      pua_protection TEXT NOT NULL DEFAULT 'ENABLED' CHECK(pua_protection IN ('DISABLED', 'ENABLED', 'AUDIT')),
      network_protection TEXT NOT NULL DEFAULT 'ENABLED' CHECK(network_protection IN ('DISABLED', 'ENABLED', 'AUDIT')),
      tamper_protection INTEGER NOT NULL DEFAULT 1 CHECK(tamper_protection IN (0, 1)),
      scan_schedule_type TEXT NOT NULL DEFAULT 'DAILY_QUICK' CHECK(scan_schedule_type IN ('DISABLED', 'DAILY_QUICK', 'WEEKLY_FULL')),
      scan_schedule_time TEXT DEFAULT '02:00',
      exclusions_json TEXT DEFAULT '{"paths":[],"extensions":[],"processes":[]}',
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 21. DEVICE_ANTIVIRUS_STATUS (Live Microsoft Defender Telemetry & Posture per Device)
    CREATE TABLE IF NOT EXISTS device_antivirus_status (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      antivirus_enabled INTEGER DEFAULT 1 CHECK(antivirus_enabled IN (0, 1)),
      engine_version TEXT,
      product_version TEXT,
      signature_version TEXT,
      signature_last_updated TEXT,
      signature_age_days INTEGER DEFAULT 0,
      real_time_protection_enabled INTEGER DEFAULT 1 CHECK(real_time_protection_enabled IN (0, 1)),
      cloud_protection_enabled INTEGER DEFAULT 1 CHECK(cloud_protection_enabled IN (0, 1)),
      pua_protection_enabled INTEGER DEFAULT 1 CHECK(pua_protection_enabled IN (0, 1)),
      controlled_folder_access_enabled INTEGER DEFAULT 0 CHECK(controlled_folder_access_enabled IN (0, 1, 2)),
      network_protection_enabled INTEGER DEFAULT 1 CHECK(network_protection_enabled IN (0, 1)),
      tamper_protection_enabled INTEGER DEFAULT 1 CHECK(tamper_protection_enabled IN (0, 1)),
      antispyware_enabled INTEGER DEFAULT 1 CHECK(antispyware_enabled IN (0, 1)),
      behavior_monitor_enabled INTEGER DEFAULT 1 CHECK(behavior_monitor_enabled IN (0, 1)),
      ioav_protection_enabled INTEGER DEFAULT 1 CHECK(ioav_protection_enabled IN (0, 1)),
      last_quick_scan_at TEXT,
      last_full_scan_at TEXT,
      quick_scan_age_days INTEGER DEFAULT 0,
      full_scan_age_days INTEGER DEFAULT 0,
      active_threat_count INTEGER DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(device_id)
    );

    -- 22. THREAT_DETECTIONS (Microsoft Defender Malware & Threat Log)
    CREATE TABLE IF NOT EXISTS threat_detections (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      threat_name TEXT NOT NULL,
      threat_id TEXT,
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
      category TEXT DEFAULT 'Malware',
      resources_json TEXT DEFAULT '[]',
      action_taken TEXT NOT NULL DEFAULT 'QUARANTINED' CHECK(action_taken IN ('QUARANTINED', 'REMOVED', 'CLEANED', 'BLOCKED', 'NO_ACTION', 'ALLOWED')),
      remediation_status TEXT NOT NULL DEFAULT 'RESOLVED' CHECK(remediation_status IN ('ACTIVE', 'RESOLVED', 'MANUAL_STEPS_REQUIRED', 'FAILED')),
      detected_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 23. BITLOCKER_POLICIES (Disk Encryption & Key Escrow Policies)
    CREATE TABLE IF NOT EXISTS bitlocker_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      encryption_method_os TEXT DEFAULT 'XtsAes128' CHECK(encryption_method_os IN ('XtsAes128', 'XtsAes256', 'Aes128', 'Aes256')),
      encryption_method_fixed TEXT DEFAULT 'XtsAes128' CHECK(encryption_method_fixed IN ('XtsAes128', 'XtsAes256', 'Aes128', 'Aes256')),
      require_tpm INTEGER DEFAULT 1 CHECK(require_tpm IN (0, 1)),
      recovery_key_rotation INTEGER DEFAULT 1 CHECK(recovery_key_rotation IN (0, 1)),
      hide_recovery_options_in_wizard INTEGER DEFAULT 1 CHECK(hide_recovery_options_in_wizard IN (0, 1)),
      silent_encryption_enabled INTEGER DEFAULT 1 CHECK(silent_encryption_enabled IN (0, 1)),
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 24. DEVICE_BITLOCKER_VOLUMES (Per-volume encryption status & protectors)
    CREATE TABLE IF NOT EXISTS device_bitlocker_volumes (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      mount_point TEXT NOT NULL,
      volume_type TEXT NOT NULL DEFAULT 'OperatingSystem' CHECK(volume_type IN ('OperatingSystem', 'FixedDataVolume', 'RemovableDataVolume')),
      protection_status TEXT NOT NULL DEFAULT 'Off' CHECK(protection_status IN ('On', 'Off', 'Unknown')),
      volume_status TEXT NOT NULL DEFAULT 'FullyDecrypted' CHECK(volume_status IN ('FullyEncrypted', 'FullyDecrypted', 'EncryptionInProgress', 'DecryptionInProgress', 'Unknown')),
      encryption_percentage REAL DEFAULT 0.0,
      encryption_method TEXT DEFAULT 'None',
      lock_status TEXT DEFAULT 'Unlocked' CHECK(lock_status IN ('Locked', 'Unlocked')),
      key_protector_types_json TEXT DEFAULT '[]',
      has_recovery_key INTEGER DEFAULT 0 CHECK(has_recovery_key IN (0, 1)),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(device_id, mount_point)
    );

    -- 25. BITLOCKER_RECOVERY_KEYS (Escrowed 48-digit Recovery Passwords)
    CREATE TABLE IF NOT EXISTS bitlocker_recovery_keys (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      volume_mount_point TEXT NOT NULL,
      volume_type TEXT DEFAULT 'OperatingSystem',
      key_protector_id TEXT NOT NULL,
      key_protector_type TEXT NOT NULL DEFAULT 'RecoveryPassword',
      recovery_password TEXT NOT NULL,
      encryption_method TEXT DEFAULT 'XtsAes128',
      backup_timestamp TEXT NOT NULL DEFAULT (DATETIME('now')),
      last_accessed_at TEXT,
      access_count INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(device_id, key_protector_id)
    );

    -- 26. BITLOCKER_AUDIT_LOGS (Key Reveal & Access Audit Paper Trail)
    CREATE TABLE IF NOT EXISTS bitlocker_audit_logs (
      id TEXT PRIMARY KEY NOT NULL,
      key_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      accessed_by TEXT NOT NULL DEFAULT 'Administrator',
      access_reason TEXT DEFAULT 'Troubleshooting / BitLocker Recovery PIN Loss',
      ip_address TEXT DEFAULT '127.0.0.1',
      accessed_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(key_id) REFERENCES bitlocker_recovery_keys(id) ON DELETE CASCADE,
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
    CREATE INDEX IF NOT EXISTS idx_commands_status ON device_commands(status);

    CREATE INDEX IF NOT EXISTS idx_remediations_target ON remediations(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_runs_dev ON remediation_runs(device_id, executed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_remediation_runs_rem ON remediation_runs(remediation_id, executed_at DESC);

    CREATE INDEX IF NOT EXISTS idx_profiles_target ON configuration_profiles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_profiles_type ON configuration_profiles(profile_type);
    CREATE INDEX IF NOT EXISTS idx_compliance_dev ON profile_compliance(device_id, evaluated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_compliance_prof ON profile_compliance(profile_id, compliance_status);

    CREATE INDEX IF NOT EXISTS idx_rings_target ON update_rings(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_dev_update_ring ON device_update_status(ring_id);
    CREATE INDEX IF NOT EXISTS idx_dev_update_reboot ON device_update_status(reboot_pending);

    CREATE INDEX IF NOT EXISTS idx_comp_pol_target ON compliance_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_comp_eval_dev ON device_compliance_evaluations(device_id, evaluated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_comp_eval_status ON device_compliance_evaluations(compliance_status);

    CREATE INDEX IF NOT EXISTS idx_apps_target_group ON apps(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_apps_intent ON apps(assignment_intent);
    CREATE INDEX IF NOT EXISTS idx_device_app_status_dev ON device_app_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_device_app_status_app ON device_app_status(app_id);
    CREATE INDEX IF NOT EXISTS idx_device_app_status_stat ON device_app_status(install_status);

    CREATE INDEX IF NOT EXISTS idx_sec_policies_target ON endpoint_security_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_dev_av_status_dev ON device_antivirus_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_dev_av_sig_age ON device_antivirus_status(signature_age_days);
    CREATE INDEX IF NOT EXISTS idx_dev_av_rtp ON device_antivirus_status(real_time_protection_enabled);
    CREATE INDEX IF NOT EXISTS idx_threats_dev ON threat_detections(device_id, detected_at DESC);
    CREATE INDEX IF NOT EXISTS idx_threats_status ON threat_detections(remediation_status);
    CREATE INDEX IF NOT EXISTS idx_threats_sev ON threat_detections(severity);

    CREATE INDEX IF NOT EXISTS idx_bit_pol_target ON bitlocker_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_bit_vol_dev ON device_bitlocker_volumes(device_id);
    CREATE INDEX IF NOT EXISTS idx_bit_vol_prot ON device_bitlocker_volumes(protection_status);
    CREATE INDEX IF NOT EXISTS idx_bit_keys_dev ON bitlocker_recovery_keys(device_id);
    CREATE INDEX IF NOT EXISTS idx_bit_keys_prot_id ON bitlocker_recovery_keys(key_protector_id);
    CREATE INDEX IF NOT EXISTS idx_bit_audit_key ON bitlocker_audit_logs(key_id);
    CREATE INDEX IF NOT EXISTS idx_bit_audit_time ON bitlocker_audit_logs(accessed_at DESC);
  `);

  // Schema migrations for existing databases
  try {
    const tableSqlRow = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'security_events'").get();
    if (tableSqlRow && tableSqlRow.sql && !tableSqlRow.sql.includes('BITLOCKER_KEY_ESCROWED')) {
      db.exec(`
        PRAGMA foreign_keys = OFF;
        CREATE TABLE security_events_migrated (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          device_id TEXT NOT NULL,
          event_type TEXT NOT NULL CHECK(event_type IN (
            'USER_CREATED', 'USER_DELETED', 'ADMIN_ADDED', 'ADMIN_REMOVED',
            'APP_INSTALLED', 'APP_PROHIBITED_DETECTED', 'POLICY_DRIFT',
            'TPM_VIOLATION', 'SECUREBOOT_DISABLED', 'BITLOCKER_OFFLINE', 'WATCHDOG_HEARTBEAT',
            'MALWARE_THREAT_DETECTED', 'ANTIVIRUS_RTP_DISABLED',
            'BITLOCKER_KEY_ESCROWED', 'BITLOCKER_KEY_REVEALED', 'BITLOCKER_ENCRYPTION_TRIGGERED'
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
        INSERT INTO security_events_migrated SELECT * FROM security_events;
        DROP TABLE security_events;
        ALTER TABLE security_events_migrated RENAME TO security_events;
        CREATE INDEX IF NOT EXISTS idx_events_device ON security_events(device_id);
        CREATE INDEX IF NOT EXISTS idx_events_sev_ack ON security_events(severity, acknowledged);
        CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at DESC);
        PRAGMA foreign_keys = ON;
      `);
    }
  } catch (migErr) {
    console.warn('[DB Migration Warning]:', migErr.message);
  }

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
  }

  // 6. Seed Default Enterprise Remediations
  const remCount = db.prepare('SELECT COUNT(*) as count FROM remediations').get().count;
  if (remCount === 0) {
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

    // Sample runs if sample devices exist
    const hasSampleDev = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasSampleDev) {
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

  // 7. Seed Default Configuration Profiles
  const profCount = db.prepare('SELECT COUNT(*) as count FROM configuration_profiles').get().count;
  if (profCount === 0) {
    const insertProfile = db.prepare(`
      INSERT INTO configuration_profiles (
        id, name, description, profile_type, target_group_id, settings_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertProfile.run(
      'prof-win11-baseline',
      'Windows 11 Enterprise Hardened Security Baseline',
      'Enforces Windows Defender Firewall across all network profiles, User Account Control (UAC) token elevation, and Network Level Authentication (NLA) for Remote Desktop.',
      'SecurityBaseline',
      'grp-all',
      JSON.stringify([
        {
          id: 'firewall_all_profiles',
          category: 'Network & Firewall',
          name: 'Windows Defender Firewall (All Profiles)',
          description: 'Enforce Domain, Private, and Public firewall profiles enabled',
          setting_type: 'boolean',
          desired_value: true,
          enforce: true
        },
        {
          id: 'uac_enable_lua',
          category: 'User Account Control',
          name: 'UAC Admin Approval Mode (EnableLUA)',
          description: 'Enforce User Account Control token filtering for administrators',
          setting_type: 'integer',
          desired_value: 1,
          enforce: true
        },
        {
          id: 'rdp_nla',
          category: 'Remote Access',
          name: 'Remote Desktop Network Level Authentication (NLA)',
          description: 'Require Network Level Authentication for remote connections',
          setting_type: 'integer',
          desired_value: 1,
          enforce: true
        }
      ]),
      '-2 days', '-2 days'
    );

    insertProfile.run(
      'prof-dev-privacy',
      'Developer Workstation Privacy & Anti-Telemetry Policy',
      'Suppresses diagnostic telemetry data collection and disables consumer experience advertising IDs.',
      'SettingsCatalog',
      'grp-all',
      JSON.stringify([
        {
          id: 'telemetry_level',
          category: 'System & Telemetry',
          name: 'Diagnostic Data Collection Level',
          description: 'Limit Windows telemetry to Security/Minimal (0 = Security, 1 = Basic, 3 = Full)',
          setting_type: 'integer',
          desired_value: 0,
          enforce: true
        },
        {
          id: 'tailored_experiences',
          category: 'Privacy',
          name: 'Windows Tailored Diagnostic Experiences',
          description: 'Prevent Windows from using diagnostic data for personalized tips and recommendations',
          setting_type: 'integer',
          desired_value: 0,
          enforce: true
        }
      ]),
      '-1 day', '-1 day'
    );

    insertProfile.run(
      'prof-gaming-tuning',
      'Gaming Rig Low-Latency & Game Mode Optimization',
      'Optimizes DPC latency and power state by disabling Windows Fast Startup (hybrid sleep) to avoid driver baggage across reboots.',
      'CustomPolicy',
      'grp-all',
      JSON.stringify([
        {
          id: 'fast_startup',
          category: 'System & Power',
          name: 'Fast Startup (Hiberboot)',
          description: 'Disable Fast Startup to guarantee true cold kernel reboot and clean DPC state',
          setting_type: 'integer',
          desired_value: 0,
          enforce: true
        }
      ]),
      '-12 hours', '-12 hours'
    );

    // Seed Profile Compliance Records (if sample devices exist)
    const hasSampleDevForComp = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasSampleDevForComp) {
      const insertCompliance = db.prepare(`
        INSERT INTO profile_compliance (
          id, profile_id, device_id, compliance_status, compliant_count, non_compliant_count, error_count,
          setting_results_json, evaluated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertCompliance.run(
        'comp-01',
        'prof-win11-baseline',
        'dev-daddy-pc',
        'COMPLIANT',
        3, 0, 0,
        JSON.stringify([
          { id: 'firewall_all_profiles', category: 'Network & Firewall', name: 'Windows Defender Firewall (All Profiles)', desired_value: true, current_value: true, status: 'COMPLIANT', message: 'Domain, Private, and Public firewalls active' },
          { id: 'uac_enable_lua', category: 'User Account Control', name: 'UAC Admin Approval Mode (EnableLUA)', desired_value: 1, current_value: 1, status: 'COMPLIANT', message: 'EnableLUA configured to 1' },
          { id: 'rdp_nla', category: 'Remote Access', name: 'Remote Desktop Network Level Authentication (NLA)', desired_value: 1, current_value: 1, status: 'COMPLIANT', message: 'NLA enabled on RDP-Tcp' }
        ]),
        '-1 hour'
      );

      insertCompliance.run(
        'comp-02',
        'prof-win11-baseline',
        'dev-livingroom-pc',
        'NON_COMPLIANT',
        2, 1, 0,
        JSON.stringify([
          { id: 'firewall_all_profiles', category: 'Network & Firewall', name: 'Windows Defender Firewall (All Profiles)', desired_value: true, current_value: true, status: 'COMPLIANT', message: 'Domain, Private, and Public firewalls active' },
          { id: 'uac_enable_lua', category: 'User Account Control', name: 'UAC Admin Approval Mode (EnableLUA)', desired_value: 1, current_value: 0, status: 'NON_COMPLIANT', message: 'EnableLUA is currently 0 (disabled)' },
          { id: 'rdp_nla', category: 'Remote Access', name: 'Remote Desktop Network Level Authentication (NLA)', desired_value: 1, current_value: 1, status: 'COMPLIANT', message: 'NLA enabled on RDP-Tcp' }
        ]),
        '-30 minutes'
      );

      insertCompliance.run(
        'comp-03',
        'prof-gaming-tuning',
        'dev-daddy-pc',
        'COMPLIANT',
        1, 0, 0,
        JSON.stringify([
          { id: 'fast_startup', category: 'System & Power', name: 'Fast Startup (Hiberboot)', desired_value: 0, current_value: 0, status: 'COMPLIANT', message: 'Fast Startup disabled' }
        ]),
        '-2 hours'
      );
    }
  }

  // 8. Seed Default Windows Update Rings
  const ringCount = db.prepare('SELECT COUNT(*) as count FROM update_rings').get().count;
  if (ringCount === 0) {
    const insertRing = db.prepare(`
      INSERT INTO update_rings (
        id, name, description, target_group_id, servicing_channel, quality_deferral_days,
        feature_deferral_days, active_hours_start, active_hours_end, automatic_update_mode,
        restart_deadline_days, is_paused, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertRing.run(
      'ring-fast-insider',
      'Ring 1: Homelab Fast & Canary Ring',
      'Early adoption ring for developer workstations and disposable VMs. 0 days deferral with 2-day reboot deadline.',
      'grp-workstations',
      'WindowsInsiderBeta',
      0, 0, 9, 18, 'AutoInstallAndRebootAtMaintenanceTime', 2,
      '-3 days', '-3 days'
    );

    insertRing.run(
      'ring-broad-production',
      'Ring 2: Broad Production Fleet',
      'Standard enterprise patch ring with 7-day quality update validation buffer and 5-day grace period.',
      'grp-all',
      'GeneralAvailability',
      7, 30, 8, 17, 'AutoInstallAndRebootAtMaintenanceTime', 5,
      '-2 days', '-2 days'
    );

    insertRing.run(
      'ring-gaming-vip',
      'Ring 3: Gaming & Low-Latency Rig Ring',
      'Extended active hours (08:00 - 02:00) and notify-download policy to prevent unwanted reboots during competitive play or long renders.',
      'grp-all',
      'GeneralAvailability',
      14, 90, 8, 2, 'NotifyDownload', 14,
      '-1 day', '-1 day'
    );

    // Sample device update status (if sample devices exist)
    const hasSampleDevForUpdate = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasSampleDevForUpdate) {
      const insertDevUpdate = db.prepare(`
        INSERT INTO device_update_status (
          id, device_id, ring_id, reboot_pending, reboot_pending_reasons_json, last_scan_at,
          last_install_at, installed_hotfixes_json, update_service_status, compliance_status, updated_at
        ) VALUES (?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), ?, 'Running', ?, DATETIME('now', ?))
      `);

      insertDevUpdate.run(
        'upd-01', 'dev-daddy-pc', 'ring-fast-insider', 0, '[]',
        '-2 hours', '-3 days',
        JSON.stringify([
          { hotfix_id: 'KB5043076', description: 'Security Update', installed_on: '2026-09-02' },
          { hotfix_id: 'KB5042099', description: 'Update', installed_on: '2026-08-20' }
        ]),
        'COMPLIANT', '-2 hours'
      );

      insertDevUpdate.run(
        'upd-02', 'dev-livingroom-pc', 'ring-broad-production', 1,
        JSON.stringify(['WindowsUpdate:KB5043076', 'ComponentBasedServicing:RebootPending']),
        '-45 minutes', '-1 day',
        JSON.stringify([
          { hotfix_id: 'KB5041585', description: 'Security Update', installed_on: '2026-08-15' }
        ]),
        'REBOOT_PENDING', '-45 minutes'
      );
    }
  }

  // 9. Seed Default Device Compliance Policies (Microsoft Intune Device Compliance)
  const compliancePolicyCount = db.prepare('SELECT COUNT(*) as count FROM compliance_policies').get().count;
  if (compliancePolicyCount === 0) {
    const insertPol = db.prepare(`
      INSERT INTO compliance_policies (
        id, name, description, target_group_id, platform, min_os_build,
        require_bitlocker, require_secure_boot, require_tpm, require_defender_antivirus,
        require_defender_rtp, require_firewall, max_antivirus_signature_age_days,
        grace_period_days, non_compliance_action, is_enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertPol.run(
      'pol-enterprise-baseline',
      'Windows 11 Enterprise Zero-Trust Compliance Policy',
      'Enforces BitLocker encryption, Secure Boot, TPM 2.0, Windows Defender RTP, and Firewall with a 3-day grace period.',
      'grp-all',
      'Windows11',
      '10.0.22000',
      1, 1, 1, 1, 1, 1, 7, 3, 'MARK_NON_COMPLIANT',
      '-3 days', '-3 days'
    );

    insertPol.run(
      'pol-strict-quarantine',
      'Strict Security & Anti-Tamper Policy (Workstations)',
      'Zero-tolerance anti-tamper policy. Devices missing Defender RTP or Firewall are immediately quarantined from the fleet.',
      'grp-workstations',
      'Windows11',
      '10.0.22621',
      1, 1, 1, 1, 1, 1, 3, 0, 'QUARANTINE',
      '-2 days', '-2 days'
    );

    insertPol.run(
      'pol-homelab-relaxed',
      'Homelab & Gaming Rig Relaxed Baseline',
      'Relaxed policy for personal gaming rigs and disposable test VMs with 7-day grace period and alert-only notifications.',
      'grp-all',
      'AllWindows',
      '10.0.19041',
      0, 0, 0, 1, 1, 0, 14, 7, 'ALERT_ONLY',
      '-1 day', '-1 day'
    );

    // Sample evaluations if sample devices exist
    const hasSampleDev = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasSampleDev) {
      const insertEval = db.prepare(`
        INSERT INTO device_compliance_evaluations (
          id, device_id, policy_id, compliance_status, first_failed_at,
          grace_period_expires_at, rule_results_json, evaluated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertEval.run(
        'eval-01', 'dev-daddy-pc', 'pol-enterprise-baseline', 'COMPLIANT', null, null,
        JSON.stringify([
          { rule: 'min_os_build', expected: '10.0.22000', actual: '10.0.22631', passed: true },
          { rule: 'require_bitlocker', expected: true, actual: true, passed: true },
          { rule: 'require_secure_boot', expected: true, actual: true, passed: true },
          { rule: 'require_tpm', expected: true, actual: true, passed: true },
          { rule: 'require_defender_rtp', expected: true, actual: true, passed: true },
          { rule: 'require_firewall', expected: true, actual: true, passed: true }
        ]),
        '-1 hour'
      );

      insertEval.run(
        'eval-02', 'dev-livingroom-pc', 'pol-enterprise-baseline', 'IN_GRACE_PERIOD',
        new Date(Date.now() - 86400000).toISOString(),
        new Date(Date.now() + 2 * 86400000).toISOString(),
        JSON.stringify([
          { rule: 'min_os_build', expected: '10.0.22000', actual: '10.0.22631', passed: true },
          { rule: 'require_bitlocker', expected: true, actual: false, passed: false, error: 'BitLocker is not enabled on OS volume C:' },
          { rule: 'require_secure_boot', expected: true, actual: true, passed: true },
          { rule: 'require_tpm', expected: true, actual: true, passed: true },
          { rule: 'require_defender_rtp', expected: true, actual: true, passed: true },
          { rule: 'require_firewall', expected: true, actual: true, passed: true }
        ]),
        '-30 minutes'
      );
    }
  }

  // 10. Seed Intune Applications & Status
  const appCount = db.prepare('SELECT COUNT(*) as count FROM apps').get().count;
  if (appCount === 0) {
    const insertApp = db.prepare(`
      INSERT INTO apps (
        id, name, description, publisher, version, category, app_type,
        package_identifier, assignment_intent, target_group_id,
        install_command, uninstall_command, detection_rules_json, requirement_rules_json, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    insertApp.run(
      'app-git',
      'Git for Windows',
      'Distributed version control system with Git Bash, Git GUI, and PowerShell CLI integration.',
      'Git for Windows Project',
      '2.44.0',
      'Developer Tools',
      'WINGET',
      'Git.Git',
      'REQUIRED',
      'grp-all',
      'winget install --id Git.Git --exact --silent --accept-source-agreements --accept-package-agreements',
      'winget uninstall --id Git.Git --exact --silent',
      JSON.stringify([
        { type: 'FILE', path: 'C:\\Program Files\\Git\\cmd\\git.exe', exists: true },
        { type: 'WINGET', package_id: 'Git.Git' }
      ]),
      JSON.stringify({ min_os_build: '10.0.19041', architecture: 'x64', min_ram_gb: 2, min_disk_free_gb: 2 })
    );

    insertApp.run(
      'app-vscode',
      'Visual Studio Code',
      'Lightweight but powerful source code editor with built-in support for JavaScript, TypeScript and Node.js.',
      'Microsoft',
      '1.98.0',
      'Developer Tools',
      'WINGET',
      'Microsoft.VisualStudioCode',
      'REQUIRED',
      'grp-workstations',
      'winget install --id Microsoft.VisualStudioCode --exact --silent --accept-source-agreements --accept-package-agreements',
      'winget uninstall --id Microsoft.VisualStudioCode --exact --silent',
      JSON.stringify([
        { type: 'FILE', path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe', exists: true },
        { type: 'WINGET', package_id: 'Microsoft.VisualStudioCode' }
      ]),
      JSON.stringify({ min_os_build: '10.0.19041', architecture: 'x64', min_ram_gb: 4, min_disk_free_gb: 5 })
    );

    insertApp.run(
      'app-7zip',
      '7-Zip Archiver',
      'High compression ratio file archiver with AES-256 encryption and multi-format extraction.',
      'Igor Pavlov',
      '24.09',
      'Utilities',
      'WINGET',
      '7zip.7zip',
      'REQUIRED',
      'grp-all',
      'winget install --id 7zip.7zip --exact --silent --accept-source-agreements --accept-package-agreements',
      'winget uninstall --id 7zip.7zip --exact --silent',
      JSON.stringify([
        { type: 'FILE', path: 'C:\\Program Files\\7-Zip\\7z.exe', exists: true },
        { type: 'REGISTRY', path: 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip', exists: true }
      ]),
      JSON.stringify({ min_os_build: '10.0.10240', architecture: 'x64', min_ram_gb: 1, min_disk_free_gb: 1 })
    );

    insertApp.run(
      'app-sysinternals',
      'Sysinternals Suite',
      'Technical troubleshooting utility suite for Windows systems including Process Explorer, ProcMon, and Autoruns.',
      'Microsoft',
      '2025.1',
      'System',
      'WINGET',
      'Microsoft.Sysinternals.Suite',
      'AVAILABLE',
      'grp-all',
      'winget install --id Microsoft.Sysinternals.Suite --exact --silent --accept-source-agreements --accept-package-agreements',
      'winget uninstall --id Microsoft.Sysinternals.Suite --exact --silent',
      JSON.stringify([
        { type: 'WINGET', package_id: 'Microsoft.Sysinternals.Suite' }
      ]),
      JSON.stringify({ min_os_build: '10.0.19041', architecture: 'x64', min_ram_gb: 2, min_disk_free_gb: 1 })
    );

    // Sample app statuses if sample devices exist
    const hasDaddy = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasDaddy) {
      const insertStatus = db.prepare(`
        INSERT INTO device_app_status (
          id, device_id, app_id, install_status, detection_state, installed_version, last_attempt_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);
      insertStatus.run('app-stat-01', 'dev-daddy-pc', 'app-git', 'INSTALLED', 1, '2.44.0', '-2 hours');
      insertStatus.run('app-stat-02', 'dev-daddy-pc', 'app-vscode', 'INSTALLED', 1, '1.98.0', '-2 hours');
      insertStatus.run('app-stat-03', 'dev-daddy-pc', 'app-7zip', 'INSTALLED', 1, '24.09', '-2 hours');
    }
  }

  // 11. Seed Endpoint Security Policies & Defender Telemetry
  const secPolicyCount = db.prepare('SELECT COUNT(*) as count FROM endpoint_security_policies').get().count;
  if (secPolicyCount === 0) {
    const insertSecPol = db.prepare(`
      INSERT INTO endpoint_security_policies (
        id, name, description, target_group_id,
        real_time_protection, cloud_protection_level, controlled_folder_access,
        pua_protection, network_protection, tamper_protection,
        scan_schedule_type, scan_schedule_time, exclusions_json, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    insertSecPol.run(
      'sec-baseline-enterprise',
      'Microsoft Defender Enterprise Baseline',
      'Standard enterprise security posture with High cloud protection, PUA blocking, Network Protection, and daily Quick Scans.',
      'grp-all',
      1, 'HIGH', 'AUDIT', 'ENABLED', 'ENABLED', 1, 'DAILY_QUICK', '02:00',
      JSON.stringify({ paths: [], extensions: [], processes: [] })
    );

    insertSecPol.run(
      'sec-ransomware-shield',
      'High-Security Ransomware Shield & Controlled Folders',
      'Strict zero-trust anti-ransomware configuration enforcing Controlled Folder Access, High+ cloud ML, and blocked script execution.',
      'grp-workstations',
      1, 'HIGH_PLUS', 'ENABLED', 'ENABLED', 'ENABLED', 1, 'DAILY_QUICK', '03:00',
      JSON.stringify({ paths: ['C:\\SecureVault'], extensions: [], processes: [] })
    );

    insertSecPol.run(
      'sec-dev-gaming',
      'Developer & High-Performance Rig Exclusions',
      'Optimized Defender configuration with developer directory exclusions (.git, node_modules, target) for maximum build speed.',
      'grp-workstations',
      1, 'STANDARD', 'AUDIT', 'ENABLED', 'ENABLED', 1, 'WEEKLY_FULL', '04:00',
      JSON.stringify({ paths: ['C:\\temp', 'C:\\dev'], extensions: ['.obj', '.pdb'], processes: ['node.exe', 'cargo.exe'] })
    );

    // Seed Defender telemetry for sample devices
    const hasDaddy = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasDaddy) {
      const insertAv = db.prepare(`
        INSERT INTO device_antivirus_status (
          id, device_id, antivirus_enabled, engine_version, product_version,
          signature_version, signature_last_updated, signature_age_days,
          real_time_protection_enabled, cloud_protection_enabled, pua_protection_enabled,
          controlled_folder_access_enabled, network_protection_enabled, tamper_protection_enabled,
          antispyware_enabled, behavior_monitor_enabled, ioav_protection_enabled,
          last_quick_scan_at, last_full_scan_at, quick_scan_age_days, full_scan_age_days,
          active_threat_count, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), ?, ?, ?, DATETIME('now'))
      `);

      insertAv.run(
        'av-daddy-01', 'dev-daddy-pc', 1, '1.1.24020.9', '4.18.24020.7',
        '1.407.382.0', '-1 hours', 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1,
        '-4 hours', '-3 days', 0, 3, 0
      );

      insertAv.run(
        'av-living-01', 'dev-livingroom-pc', 1, '1.1.24010.5', '4.18.24010.3',
        '1.405.120.0', '-8 days', 8,
        0, 1, 1, 0, 0, 1, 1, 0, 1,
        '-9 days', '-20 days', 9, 20, 1
      );

      insertAv.run(
        'av-sarah-01', 'dev-sarah-laptop', 1, '1.1.24020.9', '4.18.24020.7',
        '1.407.290.0', '-1 day', 1,
        1, 1, 1, 2, 1, 1, 1, 1, 1,
        '-1 day', '-7 days', 1, 7, 0
      );

      // Seed threat detection on livingroom PC
      const insertThreat = db.prepare(`
        INSERT INTO threat_detections (
          id, device_id, threat_name, threat_id, severity, category,
          resources_json, action_taken, remediation_status, detected_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
      `);

      insertThreat.run(
        'threat-01', 'dev-livingroom-pc', 'Trojan:Win32/Wacatac.B!ml', '2147735503',
        'HIGH', 'Trojan',
        JSON.stringify(['C:\\Users\\Family\\Downloads\\keygen.exe']),
        'QUARANTINED', 'ACTIVE', '-2 hours', '-2 hours'
      );

      insertThreat.run(
        'threat-02', 'dev-daddy-pc', 'PUA:Win32/CoinMiner', '2147741201',
        'MEDIUM', 'PotentiallyUnwantedApp',
        JSON.stringify(['C:\\temp\\miner_bench.exe']),
        'BLOCKED', 'RESOLVED', '-5 days', '-5 days'
      );
    }
  }

  // 12. BitLocker Policies, Volumes & Escrowed Keys
  const bitPolCount = db.prepare('SELECT COUNT(*) as count FROM bitlocker_policies').get().count;
  if (bitPolCount === 0) {
    const insertBitPol = db.prepare(`
      INSERT OR IGNORE INTO bitlocker_policies (
        id, name, description, target_group_id, encryption_method_os, encryption_method_fixed,
        require_tpm, recovery_key_rotation, hide_recovery_options_in_wizard, silent_encryption_enabled, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertBitPol.run(
      'bit-baseline-enterprise',
      'Enterprise Silent BitLocker Baseline',
      'Enforces silent XTS-AES 128-bit hardware encryption for all Windows operating system drives with TPM protector and automated recovery key escrow.',
      'grp-all',
      'XtsAes128', 'XtsAes128',
      1, 1, 1, 1, 1
    );

    insertBitPol.run(
      'bit-high-security',
      'High-Assurance Military Grade BitLocker',
      'Maximum security configuration requiring XTS-AES 256-bit encryption cipher and strict recovery password vaulting.',
      'grp-workstations',
      'XtsAes256', 'XtsAes256',
      1, 1, 1, 1, 1
    );

    // Seed BitLocker volumes for sample devices
    const hasDaddy = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasDaddy) {
      const insertVol = db.prepare(`
        INSERT OR IGNORE INTO device_bitlocker_volumes (
          id, device_id, mount_point, volume_type, protection_status, volume_status,
          encryption_percentage, encryption_method, lock_status, key_protector_types_json, has_recovery_key, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertVol.run('vol-daddy-c', 'dev-daddy-pc', 'C:', 'OperatingSystem', 'On', 'FullyEncrypted', 100.0, 'XtsAes128', 'Unlocked', JSON.stringify(['Tpm', 'RecoveryPassword']), 1, '-2 hours');
      insertVol.run('vol-daddy-d', 'dev-daddy-pc', 'D:', 'FixedDataVolume', 'On', 'FullyEncrypted', 100.0, 'XtsAes128', 'Unlocked', JSON.stringify(['RecoveryPassword']), 1, '-2 hours');
      insertVol.run('vol-sarah-c', 'dev-sarah-laptop', 'C:', 'OperatingSystem', 'On', 'FullyEncrypted', 100.0, 'XtsAes128', 'Unlocked', JSON.stringify(['Tpm', 'RecoveryPassword']), 1, '-1 day');
      insertVol.run('vol-living-c', 'dev-livingroom-pc', 'C:', 'OperatingSystem', 'Off', 'FullyDecrypted', 0.0, 'None', 'Unlocked', JSON.stringify([]), 0, '-3 days');

      const insertKey = db.prepare(`
        INSERT OR IGNORE INTO bitlocker_recovery_keys (
          id, device_id, volume_mount_point, volume_type, key_protector_id,
          key_protector_type, recovery_password, encryption_method, backup_timestamp, last_accessed_at, access_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), ?, ?)
      `);

      insertKey.run(
        'key-daddy-c', 'dev-daddy-pc', 'C:', 'OperatingSystem',
        '{E28B0F25-A2B8-439D-B147-9D72E15C0391}', 'RecoveryPassword',
        '419204-182940-582910-384910-184920-582910-482910-582910', 'XtsAes128',
        '-5 days', '2026-09-06 14:20:00', 1
      );

      insertKey.run(
        'key-daddy-d', 'dev-daddy-pc', 'D:', 'FixedDataVolume',
        '{98FA1204-512E-442C-B4A1-28CBA0249210}', 'RecoveryPassword',
        '629104-582910-184920-384910-482910-182940-582910-384910', 'XtsAes128',
        '-5 days', null, 0
      );

      insertKey.run(
        'key-sarah-c', 'dev-sarah-laptop', 'C:', 'OperatingSystem',
        '{B3920194-612A-438B-9321-482910482910}', 'RecoveryPassword',
        '194820-384910-582910-482910-182940-629104-384910-184920', 'XtsAes128',
        '-2 days', null, 0
      );

      const insertAudit = db.prepare(`
        INSERT OR IGNORE INTO bitlocker_audit_logs (
          id, key_id, device_id, accessed_by, access_reason, ip_address, accessed_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertAudit.run(
        'audit-01', 'key-daddy-c', 'dev-daddy-pc',
        'Tony (Fleet Admin)', 'Scheduled annual disaster recovery drill',
        '127.0.0.1', '-1 day'
      );
    }
  }
}
