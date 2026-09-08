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
        'BITLOCKER_KEY_ESCROWED', 'BITLOCKER_KEY_REVEALED', 'BITLOCKER_ENCRYPTION_TRIGGERED',
        'LAPS_PASSWORD_ESCROWED', 'LAPS_PASSWORD_REVEALED', 'LAPS_PASSWORD_ROTATED',
        'EPM_ELEVATION_REQUESTED', 'EPM_ELEVATION_APPROVED', 'EPM_ELEVATION_DENIED', 'EPM_PROCESS_ELEVATED',
        'AUTOPILOT_DEVICE_IMPORTED', 'AUTOPILOT_PROFILE_ASSIGNED', 'AUTOPILOT_PROVISIONING_STARTED', 'AUTOPILOT_PROVISIONING_COMPLETED', 'AUTOPILOT_PROVISIONING_FAILED',
        'REMOTE_ACTION_DISPATCHED', 'REMOTE_ACTION_COMPLETED', 'REMOTE_ACTION_FAILED', 'DIAGNOSTICS_COLLECTED', 'BULK_ACTION_EXECUTED',
        'FIREWALL_RULE_APPLIED', 'FIREWALL_DRIFT_DETECTED', 'ROGUE_PORT_DETECTED', 'FIREWALL_PROFILE_DISABLED',
        'SCRIPT_DISPATCHED', 'SCRIPT_EXECUTION_SUCCESS', 'SCRIPT_EXECUTION_FAILED'
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

    -- 27. LAPS_POLICIES (Windows Local Administrator Password Solution Governance)
    CREATE TABLE IF NOT EXISTS laps_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      admin_account_name TEXT NOT NULL DEFAULT 'Administrator',
      password_complexity TEXT NOT NULL DEFAULT 'COMPLEX' CHECK(password_complexity IN ('NUMERIC', 'ALPHABETICAL', 'ALPHANUMERIC', 'COMPLEX')),
      password_length INTEGER NOT NULL DEFAULT 16 CHECK(password_length >= 12 AND password_length <= 64),
      password_age_days INTEGER NOT NULL DEFAULT 30 CHECK(password_age_days >= 1 AND password_age_days <= 365),
      post_auth_reset_enabled INTEGER NOT NULL DEFAULT 0 CHECK(post_auth_reset_enabled IN (0, 1)),
      post_auth_reset_delay_hours INTEGER NOT NULL DEFAULT 4,
      auto_enable_account INTEGER NOT NULL DEFAULT 1 CHECK(auto_enable_account IN (0, 1)),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 28. LAPS_PASSWORDS (Encrypted Local Administrator Credentials & Expiration Tracking)
    CREATE TABLE IF NOT EXISTS laps_passwords (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL UNIQUE,
      account_name TEXT NOT NULL DEFAULT 'Administrator',
      encrypted_password TEXT NOT NULL,
      password_length INTEGER NOT NULL DEFAULT 16,
      complexity_level TEXT NOT NULL DEFAULT 'COMPLEX',
      last_rotated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      expires_at TEXT NOT NULL,
      rotation_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(rotation_status IN ('ACTIVE', 'ROTATION_PENDING', 'EXPIRED')),
      last_accessed_at TEXT,
      access_count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 29. LAPS_PASSWORD_HISTORY (Forensic Credential Archive & Rollback Vault)
    CREATE TABLE IF NOT EXISTS laps_password_history (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      account_name TEXT NOT NULL,
      encrypted_password TEXT NOT NULL,
      password_length INTEGER NOT NULL,
      complexity_level TEXT NOT NULL,
      rotated_at TEXT NOT NULL,
      retired_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      rotation_reason TEXT NOT NULL DEFAULT 'SCHEDULED' CHECK(rotation_reason IN ('INITIAL_ENROLLMENT', 'SCHEDULED_EXPIRATION', 'MANUAL_REQUEST', 'POST_AUTH_RESET')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 30. LAPS_AUDIT_LOGS (Access, Reveal & Rotation Paper Trail)
    CREATE TABLE IF NOT EXISTS laps_audit_logs (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      account_name TEXT NOT NULL DEFAULT 'Administrator',
      action TEXT NOT NULL CHECK(action IN ('REVEAL', 'ROTATE_REQUEST', 'ESCROW', 'HISTORY_REVEAL')),
      accessed_by TEXT NOT NULL DEFAULT 'Administrator',
      access_reason TEXT DEFAULT 'Emergency Maintenance / LAPS Password Recovery',
      ip_address TEXT DEFAULT '127.0.0.1',
      accessed_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 31. EPM_POLICIES (Endpoint Privilege Management Governance Policies)
    CREATE TABLE IF NOT EXISTS epm_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      default_elevation_action TEXT NOT NULL DEFAULT 'DENY' CHECK(default_elevation_action IN ('DENY', 'REQUIRE_JUSTIFICATION', 'AUTO_ELEVATE')),
      send_elevation_telemetry INTEGER DEFAULT 1 CHECK(send_elevation_telemetry IN (0, 1)),
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 32. EPM_ELEVATION_RULES (Granular File, Hash, and Certificate Elevation Rules)
    CREATE TABLE IF NOT EXISTS epm_elevation_rules (
      id TEXT PRIMARY KEY NOT NULL,
      policy_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      description TEXT,
      elevation_type TEXT NOT NULL CHECK(elevation_type IN ('AUTOMATIC', 'USER_CONFIRMED', 'SUPPORT_APPROVED')),
      file_name TEXT NOT NULL,
      file_path TEXT,
      file_hash_sha256 TEXT,
      publisher_certificate TEXT,
      child_process_rule TEXT NOT NULL DEFAULT 'ELEVATE_NONE' CHECK(child_process_rule IN ('ELEVATE_NONE', 'ELEVATE_ALL_CHILDREN', 'REQUIRE_RULE_MATCH')),
      min_file_version TEXT,
      max_file_version TEXT,
      is_enabled INTEGER DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES epm_policies(id) ON DELETE CASCADE
    );

    -- 33. EPM_ELEVATION_REQUESTS (Standard User Elevation Requests & Approval Queue)
    CREATE TABLE IF NOT EXISTS epm_elevation_requests (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      rule_id TEXT,
      requested_by_user TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_hash_sha256 TEXT,
      file_version TEXT,
      justification TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED')),
      reviewed_by TEXT,
      reviewed_at TEXT,
      review_notes TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(rule_id) REFERENCES epm_elevation_rules(id) ON DELETE SET NULL
    );

    -- 34. EPM_ELEVATION_LOGS (Forensic Process Elevation Execution Audit Trail)
    CREATE TABLE IF NOT EXISTS epm_elevation_logs (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      rule_id TEXT,
      user_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_hash_sha256 TEXT,
      elevation_type TEXT NOT NULL,
      justification TEXT,
      process_id INTEGER,
      parent_process_name TEXT,
      executed_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(rule_id) REFERENCES epm_elevation_rules(id) ON DELETE SET NULL
    );

    -- 35. AUTOPILOT_PROFILES (Windows Autopilot OOBE Deployment Profiles)
    CREATE TABLE IF NOT EXISTS autopilot_profiles (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      deployment_mode TEXT NOT NULL DEFAULT 'USER_DRIVEN' CHECK(deployment_mode IN ('USER_DRIVEN', 'SELF_DEPLOYING')),
      join_type TEXT NOT NULL DEFAULT 'WORKGROUP_LOCAL' CHECK(join_type IN ('WORKGROUP_LOCAL', 'ENTRA_CLOUD', 'HYBRID_DOMAIN')),
      account_type TEXT NOT NULL DEFAULT 'STANDARD' CHECK(account_type IN ('STANDARD', 'ADMINISTRATOR')),
      language_locale TEXT NOT NULL DEFAULT 'os-default',
      keyboard_layout TEXT NOT NULL DEFAULT 'os-default',
      device_name_template TEXT DEFAULT 'FLEET-%RAND:4%',
      skip_eula INTEGER NOT NULL DEFAULT 1 CHECK(skip_eula IN (0, 1)),
      skip_privacy_settings INTEGER NOT NULL DEFAULT 1 CHECK(skip_privacy_settings IN (0, 1)),
      skip_user_licensing INTEGER NOT NULL DEFAULT 1 CHECK(skip_user_licensing IN (0, 1)),
      target_group_id TEXT DEFAULT 'grp-all',
      is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 36. AUTOPILOT_DEVICES (Pre-provisioned Hardware Hashes & Lifecycle Registry)
    CREATE TABLE IF NOT EXISTS autopilot_devices (
      id TEXT PRIMARY KEY NOT NULL,
      serial_number TEXT NOT NULL UNIQUE,
      hardware_hash TEXT NOT NULL,
      windows_product_id TEXT DEFAULT '',
      model TEXT DEFAULT 'Generic PC',
      manufacturer TEXT DEFAULT 'OEM',
      group_tag TEXT DEFAULT '',
      assigned_user TEXT DEFAULT '',
      profile_id TEXT,
      deployment_status TEXT NOT NULL DEFAULT 'UNASSIGNED' CHECK(deployment_status IN ('UNASSIGNED', 'ASSIGNED', 'PROVISIONING', 'ENROLLED', 'FAILED')),
      device_id TEXT,
      last_contact_at TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(profile_id) REFERENCES autopilot_profiles(id) ON DELETE SET NULL,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
    );

    -- 37. ENROLLMENT_STATUS_PAGE_POLICIES (ESP Progress, App Blocker & Timeout Governance)
    CREATE TABLE IF NOT EXISTS enrollment_status_page_policies (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      show_progress INTEGER NOT NULL DEFAULT 1 CHECK(show_progress IN (0, 1)),
      block_until_completed INTEGER NOT NULL DEFAULT 1 CHECK(block_until_completed IN (0, 1)),
      allow_user_reset_on_failure INTEGER NOT NULL DEFAULT 1 CHECK(allow_user_reset_on_failure IN (0, 1)),
      timeout_minutes INTEGER NOT NULL DEFAULT 60 CHECK(timeout_minutes >= 10 AND timeout_minutes <= 1440),
      required_app_ids_json TEXT NOT NULL DEFAULT '[]',
      required_script_ids_json TEXT NOT NULL DEFAULT '[]',
      target_group_id TEXT DEFAULT 'grp-all',
      is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 38. AUTOPILOT_PROVISIONING_EVENTS (ESP Phase Progression & Hardware Telemetry Log)
    CREATE TABLE IF NOT EXISTS autopilot_provisioning_events (
      id TEXT PRIMARY KEY NOT NULL,
      autopilot_device_id TEXT NOT NULL,
      device_id TEXT,
      phase TEXT NOT NULL CHECK(phase IN ('DEVICE_PREPARATION', 'DEVICE_SETUP', 'ACCOUNT_SETUP')),
      step_name TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED', 'SKIPPED')),
      error_code TEXT,
      details TEXT,
      timestamp TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(autopilot_device_id) REFERENCES autopilot_devices(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
    );

    -- 39. DEVICE_REMOTE_ACTIONS (Intune Device Lifecycle, Remote Lock, Reboot, Wipe, Diagnostics & Sync)
    CREATE TABLE IF NOT EXISTS device_remote_actions (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      action_type TEXT NOT NULL CHECK(action_type IN (
        'REMOTE_LOCK', 'RESTART', 'SHUTDOWN', 'CANCEL_SHUTDOWN',
        'COLLECT_DIAGNOSTICS', 'FRESH_START', 'WIPE', 'RETIRE',
        'SYNC_MDM', 'DEFENDER_SCAN', 'ROTATE_BITLOCKER', 'ROTATE_LAPS'
      )),
      parameters_json TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'DISPATCHED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')),
      error_message TEXT,
      result_data_json TEXT DEFAULT '{}',
      dispatched_at TEXT,
      completed_at TEXT,
      initiated_by TEXT DEFAULT 'LocalPilot Administrator',
      bulk_action_id TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(bulk_action_id) REFERENCES bulk_device_actions(id) ON DELETE SET NULL
    );

    -- 40. DEVICE_DIAGNOSTICS_BUNDLES (Intune Standard Diagnostics Archive Vault)
    CREATE TABLE IF NOT EXISTS device_diagnostics_bundles (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      remote_action_id TEXT,
      file_name TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      content_type TEXT NOT NULL DEFAULT 'application/zip',
      categories_json TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'COLLECTING' CHECK(status IN ('COLLECTING', 'READY', 'FAILED')),
      storage_path TEXT NOT NULL,
      summary_json TEXT DEFAULT '{}',
      collected_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(remote_action_id) REFERENCES device_remote_actions(id) ON DELETE SET NULL
    );

    -- 41. BULK_DEVICE_ACTIONS (Multi-Device & Dynamic Group Remote Action Orchestration)
    CREATE TABLE IF NOT EXISTS bulk_device_actions (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      action_type TEXT NOT NULL,
      target_group_id TEXT,
      parameters_json TEXT NOT NULL DEFAULT '{}',
      total_devices INTEGER NOT NULL DEFAULT 0,
      dispatched_count INTEGER NOT NULL DEFAULT 0,
      completed_count INTEGER NOT NULL DEFAULT 0,
      failed_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'DISPATCHED' CHECK(status IN ('DISPATCHED', 'IN_PROGRESS', 'COMPLETED', 'PARTIALLY_FAILED', 'FAILED')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 42. FIREWALL_RULES (Microsoft Intune Endpoint Security Firewall Rules)
    CREATE TABLE IF NOT EXISTS firewall_rules (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      direction TEXT NOT NULL CHECK(direction IN ('INBOUND', 'OUTBOUND')),
      action TEXT NOT NULL CHECK(action IN ('ALLOW', 'BLOCK')),
      protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'ANY')),
      local_ports TEXT DEFAULT 'ANY',
      remote_ports TEXT DEFAULT 'ANY',
      local_addresses TEXT DEFAULT '*',
      remote_addresses TEXT DEFAULT '*',
      profiles_json TEXT NOT NULL DEFAULT '["Domain","Private","Public"]',
      program_path TEXT DEFAULT 'ANY',
      service_name TEXT DEFAULT 'ANY',
      target_group_id TEXT DEFAULT 'grp-all',
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      priority INTEGER DEFAULT 100,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 43. DEVICE_FIREWALL_STATUS (Per-Device Windows Firewall Profiles & Compliance Posture)
    CREATE TABLE IF NOT EXISTS device_firewall_status (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT UNIQUE NOT NULL,
      domain_profile_enabled INTEGER DEFAULT 1 CHECK(domain_profile_enabled IN (0, 1)),
      private_profile_enabled INTEGER DEFAULT 1 CHECK(private_profile_enabled IN (0, 1)),
      public_profile_enabled INTEGER DEFAULT 1 CHECK(public_profile_enabled IN (0, 1)),
      domain_inbound_action TEXT DEFAULT 'Block',
      private_inbound_action TEXT DEFAULT 'Block',
      public_inbound_action TEXT DEFAULT 'Block',
      stealth_mode_enabled INTEGER DEFAULT 1 CHECK(stealth_mode_enabled IN (0, 1)),
      active_rules_count INTEGER DEFAULT 0,
      compliance_status TEXT DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'DRIFTED', 'ERROR')),
      drift_summary_json TEXT DEFAULT '{}',
      last_audit_at TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 44. DEVICE_LISTENING_PORTS (Fleet Network Perimeter & Open Port Sentinel)
    CREATE TABLE IF NOT EXISTS device_listening_ports (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP')),
      local_address TEXT NOT NULL,
      local_port INTEGER NOT NULL,
      owning_process_id INTEGER,
      process_name TEXT,
      service_name TEXT,
      risk_level TEXT DEFAULT 'LOW' CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      status TEXT DEFAULT 'AUTHORIZED' CHECK(status IN ('AUTHORIZED', 'UNAUTHORIZED', 'SUSPICIOUS', 'EXPOSED_PUBLIC')),
      last_seen_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(device_id, protocol, local_address, local_port)
    );

    -- 45. DEVICE_SCRIPTS (Microsoft Intune Windows PowerShell Scripts Repository)
    CREATE TABLE IF NOT EXISTS device_scripts (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      script_content TEXT NOT NULL,
      run_as_account TEXT DEFAULT 'SYSTEM' CHECK (run_as_account IN ('SYSTEM', 'USER')),
      run_as_32bit INTEGER DEFAULT 0 CHECK (run_as_32bit IN (0, 1)),
      enforce_signature_check INTEGER DEFAULT 0 CHECK (enforce_signature_check IN (0, 1)),
      timeout_seconds INTEGER DEFAULT 60 CHECK (timeout_seconds >= 5 AND timeout_seconds <= 3600),
      target_group_id TEXT DEFAULT 'grp-all',
      assignment_intent TEXT DEFAULT 'ASSIGNED' CHECK (assignment_intent IN ('ASSIGNED', 'AVAILABLE')),
      run_frequency TEXT DEFAULT 'ONCE' CHECK (run_frequency IN ('ONCE', 'SCHEDULED', 'ON_DEMAND')),
      schedule_cron TEXT,
      enabled INTEGER DEFAULT 1 CHECK (enabled IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 46. DEVICE_SCRIPT_RUNS (Device Script Execution Logs & Real-Time Output)
    CREATE TABLE IF NOT EXISTS device_script_runs (
      id TEXT PRIMARY KEY NOT NULL,
      device_id TEXT NOT NULL,
      script_id TEXT NOT NULL,
      run_mode TEXT DEFAULT 'ASSIGNED' CHECK (run_mode IN ('ASSIGNED', 'ON_DEMAND', 'SCHEDULED')),
      status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'SUCCESS', 'FAILED', 'TIMED_OUT')),
      exit_code INTEGER,
      stdout TEXT,
      stderr TEXT,
      execution_time_ms INTEGER DEFAULT 0,
      executed_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(script_id) REFERENCES device_scripts(id) ON DELETE CASCADE
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

    CREATE INDEX IF NOT EXISTS idx_laps_pol_target ON laps_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_laps_pwd_dev ON laps_passwords(device_id);
    CREATE INDEX IF NOT EXISTS idx_laps_pwd_status ON laps_passwords(rotation_status);
    CREATE INDEX IF NOT EXISTS idx_laps_pwd_expires ON laps_passwords(expires_at);
    CREATE INDEX IF NOT EXISTS idx_laps_hist_dev ON laps_password_history(device_id, rotated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_laps_audit_dev ON laps_audit_logs(device_id, accessed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_laps_audit_action ON laps_audit_logs(action);

    CREATE INDEX IF NOT EXISTS idx_epm_pol_target ON epm_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_epm_rule_pol ON epm_elevation_rules(policy_id);
    CREATE INDEX IF NOT EXISTS idx_epm_req_dev ON epm_elevation_requests(device_id);
    CREATE INDEX IF NOT EXISTS idx_epm_req_status ON epm_elevation_requests(status);
    CREATE INDEX IF NOT EXISTS idx_epm_log_dev ON epm_elevation_logs(device_id);
    CREATE INDEX IF NOT EXISTS idx_epm_log_exec ON epm_elevation_logs(executed_at DESC);

    CREATE INDEX IF NOT EXISTS idx_ap_prof_target ON autopilot_profiles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_ap_dev_serial ON autopilot_devices(serial_number);
    CREATE INDEX IF NOT EXISTS idx_ap_dev_status ON autopilot_devices(deployment_status);
    CREATE INDEX IF NOT EXISTS idx_ap_dev_group_tag ON autopilot_devices(group_tag);
    CREATE INDEX IF NOT EXISTS idx_ap_dev_profile ON autopilot_devices(profile_id);
    CREATE INDEX IF NOT EXISTS idx_ap_dev_device_id ON autopilot_devices(device_id);
    CREATE INDEX IF NOT EXISTS idx_ap_esp_target ON enrollment_status_page_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_ap_prov_dev ON autopilot_provisioning_events(autopilot_device_id);
    CREATE INDEX IF NOT EXISTS idx_ap_prov_phase ON autopilot_provisioning_events(phase);
    CREATE INDEX IF NOT EXISTS idx_ap_prov_time ON autopilot_provisioning_events(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_dra_device ON device_remote_actions(device_id);
    CREATE INDEX IF NOT EXISTS idx_dra_status ON device_remote_actions(status);
    CREATE INDEX IF NOT EXISTS idx_dra_type ON device_remote_actions(action_type);
    CREATE INDEX IF NOT EXISTS idx_dra_created ON device_remote_actions(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_dra_bulk ON device_remote_actions(bulk_action_id);
    CREATE INDEX IF NOT EXISTS idx_ddb_device ON device_diagnostics_bundles(device_id);
    CREATE INDEX IF NOT EXISTS idx_ddb_status ON device_diagnostics_bundles(status);
    CREATE INDEX IF NOT EXISTS idx_bda_target ON bulk_device_actions(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_bda_status ON bulk_device_actions(status);

    CREATE INDEX IF NOT EXISTS idx_fwr_target ON firewall_rules(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_fwr_enabled ON firewall_rules(enabled);
    CREATE INDEX IF NOT EXISTS idx_fwr_direction ON firewall_rules(direction);
    CREATE INDEX IF NOT EXISTS idx_fwr_action ON firewall_rules(action);
    CREATE INDEX IF NOT EXISTS idx_dfs_device ON device_firewall_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_dfs_compliance ON device_firewall_status(compliance_status);
    CREATE INDEX IF NOT EXISTS idx_dlp_device ON device_listening_ports(device_id);
    CREATE INDEX IF NOT EXISTS idx_dlp_port ON device_listening_ports(local_port);
    CREATE INDEX IF NOT EXISTS idx_dlp_risk ON device_listening_ports(risk_level);
    CREATE INDEX IF NOT EXISTS idx_dlp_status ON device_listening_ports(status);

    CREATE INDEX IF NOT EXISTS idx_ds_target ON device_scripts(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_ds_enabled ON device_scripts(enabled);
    CREATE INDEX IF NOT EXISTS idx_dsr_device ON device_script_runs(device_id);
    CREATE INDEX IF NOT EXISTS idx_dsr_script ON device_script_runs(script_id);
    CREATE INDEX IF NOT EXISTS idx_dsr_status ON device_script_runs(status);
    CREATE INDEX IF NOT EXISTS idx_dsr_executed ON device_script_runs(executed_at DESC);
  `);

  // Schema migrations for existing databases
  try {
    const tableSqlRow = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'security_events'").get();
    if (tableSqlRow && tableSqlRow.sql && !tableSqlRow.sql.includes('SCRIPT_DISPATCHED')) {
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
            'BITLOCKER_KEY_ESCROWED', 'BITLOCKER_KEY_REVEALED', 'BITLOCKER_ENCRYPTION_TRIGGERED',
            'LAPS_PASSWORD_ESCROWED', 'LAPS_PASSWORD_REVEALED', 'LAPS_PASSWORD_ROTATED',
            'EPM_ELEVATION_REQUESTED', 'EPM_ELEVATION_APPROVED', 'EPM_ELEVATION_DENIED', 'EPM_PROCESS_ELEVATED',
            'AUTOPILOT_DEVICE_IMPORTED', 'AUTOPILOT_PROFILE_ASSIGNED', 'AUTOPILOT_PROVISIONING_STARTED', 'AUTOPILOT_PROVISIONING_COMPLETED', 'AUTOPILOT_PROVISIONING_FAILED',
            'REMOTE_ACTION_DISPATCHED', 'REMOTE_ACTION_COMPLETED', 'REMOTE_ACTION_FAILED', 'DIAGNOSTICS_COLLECTED', 'BULK_ACTION_EXECUTED',
            'FIREWALL_RULE_APPLIED', 'FIREWALL_DRIFT_DETECTED', 'ROGUE_PORT_DETECTED', 'FIREWALL_PROFILE_DISABLED',
            'SCRIPT_DISPATCHED', 'SCRIPT_EXECUTION_SUCCESS', 'SCRIPT_EXECUTION_FAILED'
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

  // 13. LAPS Policies, Passwords & Audit Logs
  const lapsPolCount = db.prepare('SELECT COUNT(*) as count FROM laps_policies').get().count;
  if (lapsPolCount === 0) {
    const insertLapsPol = db.prepare(`
      INSERT OR IGNORE INTO laps_policies (
        id, name, description, target_group_id, admin_account_name, password_complexity,
        password_length, password_age_days, post_auth_reset_enabled, post_auth_reset_delay_hours, auto_enable_account, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertLapsPol.run(
      'laps-enterprise-baseline',
      'Windows 11 Enterprise LAPS Baseline',
      'Enforces 16-character complex password rotation every 30 days on built-in Administrator account with automated escrow and zero-trust masking.',
      'grp-all', 'Administrator', 'COMPLEX', 16, 30, 0, 4, 1, 1
    );

    insertLapsPol.run(
      'laps-workstations-strict',
      'High-Assurance Workstation LAPS',
      'Maximum complexity 24-character password rotated every 14 days with post-authentication reset for dedicated developer and gaming rigs.',
      'grp-workstations', 'Administrator', 'COMPLEX', 24, 14, 1, 2, 1, 1
    );

    insertLapsPol.run(
      'laps-family-standard',
      'Family Fleet Standard Admin LAPS',
      'Rotates custom LocalAdmin account every 60 days with 14-character alphanumeric password for shared family laptops.',
      'grp-family-laptops', 'LocalAdmin', 'ALPHANUMERIC', 14, 60, 0, 4, 1, 1
    );

    // Seed sample LAPS credentials if sample devices exist
    const hasDaddy = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasDaddy) {
      const insertPwd = db.prepare(`
        INSERT OR IGNORE INTO laps_passwords (
          id, device_id, account_name, encrypted_password, password_length,
          complexity_level, last_rotated_at, expires_at, rotation_status, last_accessed_at, access_count, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), ?, DATETIME('now', ?), ?, DATETIME('now'))
      `);

      insertPwd.run(
        'laps-pwd-daddy', 'dev-daddy-pc', 'Administrator',
        'Kp9#mX2$vL5*qR8!', 16, 'COMPLEX',
        '-5 days', '+25 days', 'ACTIVE', '-1 day', 1
      );

      insertPwd.run(
        'laps-pwd-sarah', 'dev-sarah-laptop', 'LocalAdmin',
        '7nK3#pW9@xR2$vM8', 16, 'COMPLEX',
        '-28 days', '+2 days', 'ACTIVE', null, 0
      );

      insertPwd.run(
        'laps-pwd-living', 'dev-livingroom-pc', 'Administrator',
        '9vL2#mK8$pX5*qR3', 16, 'COMPLEX',
        '-45 days', '-15 days', 'EXPIRED', null, 0
      );

      const insertLapsAudit = db.prepare(`
        INSERT OR IGNORE INTO laps_audit_logs (
          id, device_id, account_name, action, accessed_by, access_reason, ip_address, accessed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertLapsAudit.run(
        'laps-audit-01', 'dev-daddy-pc', 'Administrator', 'REVEAL',
        'Tony (Fleet Admin)', 'Scheduled maintenance & local service reconfiguration',
        '127.0.0.1', '-1 day'
      );
    }
  }

  // 14. EPM Policies, Rules, Requests & Elevation Logs
  const epmPolCount = db.prepare('SELECT COUNT(*) as count FROM epm_policies').get().count;
  if (epmPolCount === 0) {
    const insertEpmPol = db.prepare(`
      INSERT OR IGNORE INTO epm_policies (
        id, name, description, target_group_id, default_elevation_action, send_elevation_telemetry, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertEpmPol.run(
      'epm-enterprise-baseline',
      'Enterprise Standard Elevation Policy',
      'Requires justification for administrative utility elevation and automatically audits elevated child processes.',
      'grp-all', 'REQUIRE_JUSTIFICATION', 1, 1
    );

    insertEpmPol.run(
      'epm-workstations-dev',
      'Developer & Engineering Rig Elevation Policy',
      'Auto-elevates approved dev and debugging tools with full hash verification and support-approved approval workflows.',
      'grp-workstations', 'REQUIRE_JUSTIFICATION', 1, 1
    );

    const insertEpmRule = db.prepare(`
      INSERT OR IGNORE INTO epm_elevation_rules (
        id, policy_id, rule_name, description, elevation_type, file_name, file_path, file_hash_sha256,
        publisher_certificate, child_process_rule, min_file_version, max_file_version, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEpmRule.run(
      'rule-procexp', 'epm-enterprise-baseline',
      'Sysinternals Process Explorer',
      'Allows standard users to run Process Explorer elevated with documented justification',
      'USER_CONFIRMED', 'procexp.exe', 'C:\\Program Files\\Sysinternals\\procexp.exe',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'Microsoft Corporation', 'ELEVATE_ALL_CHILDREN', null, null, 1
    );

    insertEpmRule.run(
      'rule-winget', 'epm-enterprise-baseline',
      'Windows Package Manager CLI',
      'Automatically elevates winget command line for background package deployment',
      'AUTOMATIC', 'winget.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe',
      null, 'Microsoft Corporation', 'ELEVATE_NONE', null, null, 1
    );

    insertEpmRule.run(
      'rule-wireshark', 'epm-workstations-dev',
      'Wireshark Network Analyzer',
      'Requires operator support approval before capturing raw packets with Npcap',
      'SUPPORT_APPROVED', 'Wireshark.exe', 'C:\\Program Files\\Wireshark\\Wireshark.exe',
      '8f434346648f6b96df89dda901c5176b10e6d05961fc5be67dfb9fb6330742d0',
      'Wireshark Foundation', 'ELEVATE_NONE', null, null, 1
    );

    insertEpmRule.run(
      'rule-afterburner', 'epm-workstations-dev',
      'MSI Afterburner Hardware Monitor',
      'Allows hardware tuning and GPU metrics monitoring under user confirmation',
      'USER_CONFIRMED', 'MSIAfterburner.exe', 'C:\\Program Files (x86)\\MSI Afterburner\\MSIAfterburner.exe',
      null, 'Micro-Star International Co., Ltd.', 'ELEVATE_NONE', null, null, 1
    );

    // Seed sample request & log if sample devices exist
    const hasDaddy = db.prepare('SELECT id FROM devices WHERE id = ?').get('dev-daddy-pc');
    if (hasDaddy) {
      const insertReq = db.prepare(`
        INSERT OR IGNORE INTO epm_elevation_requests (
          id, device_id, rule_id, requested_by_user, file_path, file_name,
          file_hash_sha256, file_version, justification, status, reviewed_by, reviewed_at, review_notes, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), ?, DATETIME('now', ?), DATETIME('now', ?))
      `);

      insertReq.run(
        'epm-req-01', 'dev-daddy-pc', 'rule-wireshark', 'Tony',
        'C:\\Program Files\\Wireshark\\Wireshark.exe', 'Wireshark.exe',
        '8f434346648f6b96df89dda901c5176b10e6d05961fc5be67dfb9fb6330742d0', '4.2.4',
        'Investigating intermittent DHCP dropouts on 10GbE network interface',
        'APPROVED', 'Fleet Master (Auto)', '-1 hour', 'Granted for 4 hours diagnostic window', '+3 hours', '-1 hour'
      );

      insertReq.run(
        'epm-req-02', 'dev-sarah-laptop', 'rule-procexp', 'Sarah',
        'C:\\Program Files\\Sysinternals\\procexp.exe', 'procexp.exe',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '17.05',
        'Need to inspect high background fan noise during photo export',
        'PENDING', null, null, null, null, '-10 minutes'
      );

      const insertLog = db.prepare(`
        INSERT OR IGNORE INTO epm_elevation_logs (
          id, device_id, rule_id, user_name, file_path, file_name,
          file_hash_sha256, elevation_type, justification, process_id, parent_process_name, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);

      insertLog.run(
        'epm-log-01', 'dev-daddy-pc', 'rule-procexp', 'Tony',
        'C:\\Program Files\\Sysinternals\\procexp.exe', 'procexp.exe',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'USER_CONFIRMED', 'Auditing thread affinity on 13900K E-cores',
        14280, 'explorer.exe', '-2 hours'
      );

      insertLog.run(
        'epm-log-02', 'dev-daddy-pc', 'rule-winget', 'Tony',
        'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe', 'winget.exe',
        null, 'AUTOMATIC', 'Background upgrade of Git for Windows',
        18944, 'powershell.exe', '-45 minutes'
      );
    }
  }

  // 15. Autopilot Profiles, Devices, ESP Policies & Provisioning Events
  const apProfCount = db.prepare('SELECT COUNT(*) as count FROM autopilot_profiles').get().count;
  if (apProfCount === 0) {
    const insertApProf = db.prepare(`
      INSERT OR IGNORE INTO autopilot_profiles (
        id, name, description, deployment_mode, join_type, account_type,
        language_locale, keyboard_layout, device_name_template,
        skip_eula, skip_privacy_settings, skip_user_licensing,
        target_group_id, is_default
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertApProf.run(
      'ap-prof-standard',
      'Standard Enterprise Workstation',
      'User-driven deployment with standard user privileges, automated naming, and streamlined OOBE privacy skips.',
      'USER_DRIVEN', 'WORKGROUP_LOCAL', 'STANDARD',
      'en-US', '0409:00000409', 'FLEET-WK-%RAND:4%',
      1, 1, 1, 'grp-all', 1
    );

    insertApProf.run(
      'ap-prof-kiosk',
      'Self-Deploying Lab & Kiosk Rig',
      'Zero-touch self-deploying profile granting local administrative privileges for homelab virtualization and automated testing rigs.',
      'SELF_DEPLOYING', 'WORKGROUP_LOCAL', 'ADMINISTRATOR',
      'en-US', '0409:00000409', 'FLEET-LAB-%RAND:4%',
      1, 1, 1, 'grp-workstations', 0
    );

    const insertEsp = db.prepare(`
      INSERT OR IGNORE INTO enrollment_status_page_policies (
        id, name, description, show_progress, block_until_completed,
        allow_user_reset_on_failure, timeout_minutes, required_app_ids_json, required_script_ids_json,
        target_group_id, is_default
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEsp.run(
      'esp-default',
      'Default Fleet Provisioning ESP',
      'Standard 60-minute blocking enrollment status page displaying preparation, device setup, and account setup phases.',
      1, 1, 1, 60, '[]', '[]', 'grp-all', 1
    );

    const insertApDev = db.prepare(`
      INSERT OR IGNORE INTO autopilot_devices (
        id, serial_number, hardware_hash, windows_product_id, model, manufacturer,
        group_tag, assigned_user, profile_id, deployment_status, device_id, last_contact_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
    `);

    const hasDaddy = db.prepare('SELECT id, serial_number FROM devices WHERE id = ?').get('dev-daddy-pc');
    const daddySerial = (hasDaddy && hasDaddy.serial_number) ? hasDaddy.serial_number : 'System Serial Number';

    insertApDev.run(
      'ap-dev-01', daddySerial,
      'T1BSR1VJRDAwMDEyMzQ1Njc4OTAqKipXRUJfSEFSRFdBUkVfSEFTSF9TQU1QTEVfQ0VSVElGSUVEKioqT0VBX0hBU0g=',
      '00330-80000-00000-AAOEM', 'Custom Gaming Workstation', 'ASUSTeK COMPUTER INC.',
      'Workstations', 'tony@localpilot.fleet', 'ap-prof-standard',
      hasDaddy ? 'ENROLLED' : 'ASSIGNED', hasDaddy ? hasDaddy.id : null, '-10 minutes'
    );

    insertApDev.run(
      'ap-dev-02', 'VMW-99210-LAB',
      'VjEtMS4wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',
      '00331-10000-00000-AAOEM', 'VMware Virtual Platform', 'VMware, Inc.',
      'Homelab', 'lab-admin@localpilot.fleet', 'ap-prof-kiosk',
      'ASSIGNED', null, '-2 hours'
    );

    insertApDev.run(
      'ap-dev-03', 'DELL-XPS-78213',
      'VjEtMi4wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',
      '00330-50000-00000-AAOEM', 'XPS 15 9530', 'Dell Inc.',
      'Executive', '', null,
      'UNASSIGNED', null, null
    );

    const insertProvEvent = db.prepare(`
      INSERT OR IGNORE INTO autopilot_provisioning_events (
        id, autopilot_device_id, device_id, phase, step_name, status, error_code, details, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
    `);

    insertProvEvent.run('ap-ev-01', 'ap-dev-01', hasDaddy ? hasDaddy.id : null, 'DEVICE_PREPARATION', 'Hardware Attestation & TPM 2.0 Validation', 'COMPLETED', null, 'TPM 2.0 endorsement key verified', '-3 hours');
    insertProvEvent.run('ap-ev-02', 'ap-dev-01', hasDaddy ? hasDaddy.id : null, 'DEVICE_PREPARATION', 'Zero-Trust Host Identity Issuance', 'COMPLETED', null, 'Node token generated and TLS certificate bound', '-2 hours 55 minutes');
    insertProvEvent.run('ap-ev-03', 'ap-dev-01', hasDaddy ? hasDaddy.id : null, 'DEVICE_SETUP', 'Security Baselines & BitLocker Encryption', 'COMPLETED', null, 'Applied enterprise baseline policy', '-2 hours 45 minutes');
    insertProvEvent.run('ap-ev-04', 'ap-dev-01', hasDaddy ? hasDaddy.id : null, 'DEVICE_SETUP', 'Required Core Applications', 'COMPLETED', null, 'Installed 3 required packages', '-2 hours 30 minutes');
    insertProvEvent.run('ap-ev-05', 'ap-dev-01', hasDaddy ? hasDaddy.id : null, 'ACCOUNT_SETUP', 'Primary User Account & LAPS Provisioning', 'COMPLETED', null, 'Created standard user profile and escrowed admin LAPS password', '-2 hours 15 minutes');

    // 12. Remote Actions, Diagnostics Bundles & Bulk Actions
    const insertAction = db.prepare(`
      INSERT OR IGNORE INTO device_remote_actions (
        id, device_id, action_type, parameters_json, status, error_message,
        result_data_json, dispatched_at, completed_at, initiated_by, bulk_action_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    const targetDevId = hasDaddy ? hasDaddy.id : 'dev-daddy-pc';

    insertAction.run(
      'dra-seed-01', targetDevId, 'SYNC_MDM', '{}', 'COMPLETED', null,
      JSON.stringify({ message: 'MDM policies and telemetry refreshed successfully', elapsed_ms: 340 }),
      '-4 hours', '-3 hours 59 minutes', 'Tony (Fleet Administrator)', null, '-4 hours', '-3 hours 59 minutes'
    );

    insertAction.run(
      'dra-seed-02', targetDevId, 'COLLECT_DIAGNOSTICS',
      JSON.stringify({ categories: ['SYSTEM_LOGS', 'SECURITY_LOGS', 'MDM_POLICIES', 'NETWORK'] }),
      'COMPLETED', null,
      JSON.stringify({ bundle_id: 'ddb-seed-01', file_name: 'diagnostics-daddy-pc-20260908.zip', file_size_bytes: 348160 }),
      '-2 hours', '-1 hour 58 minutes', 'Tony (Fleet Administrator)', null, '-2 hours', '-1 hour 58 minutes'
    );

    insertAction.run(
      'dra-seed-03', targetDevId, 'REMOTE_LOCK', '{}', 'COMPLETED', null,
      JSON.stringify({ message: 'User workstation session locked via User32::LockWorkStation' }),
      '-1 hour', '-59 minutes', 'Tony (Fleet Administrator)', null, '-1 hour', '-59 minutes'
    );

    const insertBundle = db.prepare(`
      INSERT OR IGNORE INTO device_diagnostics_bundles (
        id, device_id, remote_action_id, file_name, file_size_bytes, content_type,
        categories_json, status, storage_path, summary_json, collected_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertBundle.run(
      'ddb-seed-01', targetDevId, 'dra-seed-02', 'diagnostics-daddy-pc-20260908.zip', 348160, 'application/zip',
      JSON.stringify(['SYSTEM_LOGS', 'SECURITY_LOGS', 'MDM_POLICIES', 'NETWORK']), 'READY',
      'server/data/diagnostics/ddb-seed-01.zip',
      JSON.stringify({
        os_version: 'Windows 11 Enterprise (23H2)',
        event_log_records: 150,
        hotfixes_count: 24,
        active_adapters: 2,
        bitlocker_volumes: 1,
        antivirus_healthy: true
      }),
      '-1 hour 58 minutes', '-1 hour 58 minutes'
    );

    const insertBulk = db.prepare(`
      INSERT OR IGNORE INTO bulk_device_actions (
        id, name, action_type, target_group_id, parameters_json,
        total_devices, dispatched_count, completed_count, failed_count, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertBulk.run(
      'bda-seed-01', 'Fleet-wide Telemetry & Policy Synchronization', 'SYNC_MDM', 'grp-all', '{}',
      3, 3, 3, 0, 'COMPLETED', '-4 hours', '-3 hours 58 minutes'
    );

    // 13. Microsoft Intune Windows Firewall Rules & Network Perimeter Governance
    const insertFwRule = db.prepare(`
      INSERT OR IGNORE INTO firewall_rules (
        id, name, description, direction, action, protocol, local_ports, remote_ports,
        local_addresses, remote_addresses, profiles_json, program_path, service_name,
        target_group_id, enabled, priority, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertFwRule.run(
      'fwr-block-rdp-public',
      'Block Inbound Remote Desktop (RDP 3389) on Public Networks',
      'Restricts incoming Terminal Services / RDP connections when connected to untrusted public Wi-Fi hotspots and cellular networks.',
      'INBOUND', 'BLOCK', 'TCP', '3389', 'ANY', '*', '*',
      JSON.stringify(['Public']), 'ANY', 'ANY', 'grp-all', 1, 10,
      '-5 hours', '-5 hours'
    );

    insertFwRule.run(
      'fwr-block-smb-public',
      'Block Inbound NetBIOS & SMB File Sharing (Ports 137-139, 445) on Public Networks',
      'Prevents lateral traversal and SMB ransomware propagation by denying file and printer sharing ports on public interfaces.',
      'INBOUND', 'BLOCK', 'TCP', '137,138,139,445', 'ANY', '*', '*',
      JSON.stringify(['Public']), 'ANY', 'ANY', 'grp-all', 1, 20,
      '-5 hours', '-5 hours'
    );

    insertFwRule.run(
      'fwr-allow-fleet-intranet',
      'Allow LocalPilot Fleet Telemetry & WinRM (Ports 5985, 8443) on Private Subnets',
      'Enables authenticated on-premises fleet management, secure HTTP API commands, and remote configuration over the local intranet.',
      'INBOUND', 'ALLOW', 'TCP', '5985,8443', 'ANY', '*', '192.168.0.0/16,10.0.0.0/8',
      JSON.stringify(['Domain', 'Private']), 'ANY', 'ANY', 'grp-all', 1, 50,
      '-5 hours', '-5 hours'
    );

    insertFwRule.run(
      'fwr-block-bittorrent',
      'Block Known P2P & Torrent Swarm Traffic (Ports 6881-6889, 51413)',
      'Blocks unauthorized peer-to-peer file transfer protocols and tracker communications across all network profiles.',
      'INBOUND', 'BLOCK', 'TCP', '6881-6889,51413', 'ANY', '*', '*',
      JSON.stringify(['Domain', 'Private', 'Public']), 'ANY', 'ANY', 'grp-all', 1, 80,
      '-5 hours', '-5 hours'
    );

    insertFwRule.run(
      'fwr-allow-dev-web',
      'Allow Local Development Web Servers (Ports 3000, 5173, 8080) on Private LAN',
      'Permits inbound development preview traffic for Node.js, Vite, and Java servers across local trusted subnets.',
      'INBOUND', 'ALLOW', 'TCP', '3000,5173,8080', 'ANY', '*', 'LocalSubnet',
      JSON.stringify(['Private']), 'ANY', 'ANY', 'grp-all', 1, 90,
      '-5 hours', '-5 hours'
    );

    const insertFwStatus = db.prepare(`
      INSERT OR IGNORE INTO device_firewall_status (
        id, device_id, domain_profile_enabled, private_profile_enabled, public_profile_enabled,
        domain_inbound_action, private_inbound_action, public_inbound_action, stealth_mode_enabled,
        active_rules_count, compliance_status, drift_summary_json, last_audit_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertFwStatus.run(
      'dfs-seed-01', targetDevId,
      1, 1, 1,
      'Block', 'Block', 'Block', 1,
      5, 'COMPLIANT', '{}',
      '-15 minutes', '-4 hours', '-15 minutes'
    );

    const insertPort = db.prepare(`
      INSERT OR IGNORE INTO device_listening_ports (
        id, device_id, protocol, local_address, local_port, owning_process_id,
        process_name, service_name, risk_level, status, last_seen_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertPort.run(
      'dlp-seed-01', targetDevId, 'TCP', '0.0.0.0', 8443, 24756,
      'node.exe', 'LocalPilot Fleet Server', 'LOW', 'AUTHORIZED',
      '-5 minutes', '-4 hours', '-5 minutes'
    );

    insertPort.run(
      'dlp-seed-02', targetDevId, 'TCP', '0.0.0.0', 5985, 1024,
      'svchost.exe', 'Windows Remote Management (WS-Management)', 'MEDIUM', 'AUTHORIZED',
      '-5 minutes', '-4 hours', '-5 minutes'
    );

    insertPort.run(
      'dlp-seed-03', targetDevId, 'TCP', '127.0.0.1', 3000, 18420,
      'node.exe', 'Vite / React Dev Server', 'LOW', 'AUTHORIZED',
      '-5 minutes', '-2 hours', '-5 minutes'
    );
  }

  // 17. Device PowerShell Scripts
  const scriptCount = db.prepare('SELECT COUNT(*) as count FROM device_scripts').get().count;
  if (scriptCount === 0) {
    const insertScript = db.prepare(`
      INSERT OR IGNORE INTO device_scripts (
        id, name, description, script_content, run_as_account, run_as_32bit,
        enforce_signature_check, timeout_seconds, target_group_id, assignment_intent,
        run_frequency, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertScript.run(
      'ps-local-admins',
      'Enumerate Local Administrators Group & Privileged Accounts',
      'Audits all local and domain accounts with administrative privileges on the workstation',
      "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize",
      'SYSTEM', 0, 0, 60, 'grp-all', 'ASSIGNED', 'ONCE', 1,
      '-6 hours', '-6 hours'
    );

    insertScript.run(
      'ps-cert-audit',
      'Audit Local Machine Certificates & Expired SSL Roots',
      'Scans the LocalMachine certificate store for expired certificates or untrusted roots',
      "Get-ChildItem -Path Cert:\\LocalMachine\\My, Cert:\\LocalMachine\\Root | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) } | Select-Object Subject, Thumbprint, NotAfter | Format-Table -AutoSize",
      'SYSTEM', 0, 0, 60, 'grp-all', 'ASSIGNED', 'ONCE', 1,
      '-6 hours', '-6 hours'
    );

    insertScript.run(
      'ps-dns-health',
      'Network Stack Health, DNS Cache Flush & Gateway Reachability',
      'Validates default gateway ARP reachability and flushes local DNS client resolver cache',
      "Clear-DnsClientCache; Test-NetConnection -ComputerName 1.1.1.1 -InformationLevel Detailed | Select-Object ComputerName, PingSucceeded, RoundTripTime",
      'SYSTEM', 0, 0, 60, 'grp-all', 'ASSIGNED', 'ONCE', 1,
      '-6 hours', '-6 hours'
    );

    insertScript.run(
      'ps-disk-cleanup',
      'Enterprise Disk Footprint & Component Store Cleanup',
      'Analyzes WinSxS component store and temporary cache footprint',
      "Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
      'SYSTEM', 0, 0, 120, 'grp-low-storage', 'ASSIGNED', 'ONCE', 1,
      '-6 hours', '-6 hours'
    );

    insertScript.run(
      'ps-wua-reset',
      'Windows Update Agent Subsystem Diagnostics & Soft Reset',
      'Checks the Windows Update service state and restarts WUA services if stuck',
      "Get-Service -Name wuauserv, bits, cryptsvc | Select-Object Name, Status, StartType | Format-Table -AutoSize",
      'SYSTEM', 0, 0, 60, 'grp-win11-modern', 'ASSIGNED', 'ONCE', 1,
      '-6 hours', '-6 hours'
    );

    const targetDevId = '6ae3a5d2-6051-4c12-a604-fae0a0df41e6';
    const devExists = db.prepare('SELECT id FROM devices WHERE id = ?').get(targetDevId);
    if (devExists) {
      const insertRun = db.prepare(`
        INSERT OR IGNORE INTO device_script_runs (
          id, device_id, script_id, run_mode, status, exit_code, stdout, stderr, execution_time_ms, executed_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?), DATETIME('now', ?))
      `);

      insertRun.run(
        'dsr-seed-01', targetDevId, 'ps-local-admins', 'ASSIGNED', 'SUCCESS', 0,
        "Name                 PrincipalSource ObjectClass\n----                 --------------- -----------\nDESKTOP-R0H12DJ\\Tony Local           User\nAdministrator        Local           User",
        "", 420, '-1 hour', '-1 hour', '-1 hour'
      );
    }
  }
}
