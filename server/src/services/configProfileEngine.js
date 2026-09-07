/**
 * LocalPilot Fleet — Configuration Profiles & Settings Catalog Engine
 * server/src/services/configProfileEngine.js
 *
 * Implements Microsoft Intune-grade Settings Catalog, Endpoint Security Baselines,
 * dynamic group targeting, and setting-by-setting compliance evaluation.
 */

import crypto from 'node:crypto';

export class ConfigProfileEngine {
  /**
   * Return catalog of built-in Windows Settings with metadata, categories, types, and defaults.
   * Mirrors Microsoft Intune Settings Catalog taxonomy.
   */
  getSettingCatalogLibrary() {
    return [
      {
        id: 'firewall_all_profiles',
        category: 'Network & Firewall',
        name: 'Windows Defender Firewall (All Profiles)',
        description: 'Enforces Domain, Private, and Public network firewall states are active.',
        setting_type: 'boolean',
        default_value: true,
        recommended: true,
        audit_provider: 'NetFirewall',
        remediation_command: 'Set-NetFirewallProfile -All -Enabled True'
      },
      {
        id: 'uac_enable_lua',
        category: 'User Account Control',
        name: 'UAC Admin Approval Mode (EnableLUA)',
        description: 'Requires token virtualization and consent prompt for administrative operations.',
        setting_type: 'integer',
        default_value: 1,
        recommended: true,
        audit_provider: 'Registry',
        reg_path: 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
        reg_name: 'EnableLUA',
        remediation_command: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
      },
      {
        id: 'telemetry_level',
        category: 'System & Privacy',
        name: 'Diagnostic Data Telemetry Level',
        description: 'Configures Windows Diagnostic Data ingestion (0 = Security/Minimal, 1 = Basic/Required, 3 = Full).',
        setting_type: 'integer',
        default_value: 0,
        recommended: true,
        audit_provider: 'Registry',
        reg_path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection',
        reg_name: 'AllowTelemetry',
        remediation_command: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type DWord"
      },
      {
        id: 'tailored_experiences',
        category: 'System & Privacy',
        name: 'Windows Tailored Diagnostic Experiences',
        description: 'Suppresses personalized ads, consumer recommendations, and tips based on diagnostic data.',
        setting_type: 'integer',
        default_value: 0,
        recommended: true,
        audit_provider: 'Registry',
        reg_path: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent',
        reg_name: 'DisableTailoredExperiencesWithDiagnosticData',
        remediation_command: "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Type DWord"
      },
      {
        id: 'rdp_nla',
        category: 'Remote Access',
        name: 'Remote Desktop Network Level Authentication (NLA)',
        description: 'Requires clients to authenticate against the network before an RDP session is established.',
        setting_type: 'integer',
        default_value: 1,
        recommended: true,
        audit_provider: 'Registry',
        reg_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
        reg_name: 'UserAuthentication',
        remediation_command: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord"
      },
      {
        id: 'fast_startup',
        category: 'System & Power',
        name: 'Fast Startup Hybrid Sleep (Hiberboot)',
        description: 'Toggles hybrid hibernation upon shutdown (0 = Disabled for clean driver reboots and low DPC latency, 1 = Enabled).',
        setting_type: 'integer',
        default_value: 0,
        recommended: false,
        audit_provider: 'Registry',
        reg_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power',
        reg_name: 'HiberbootEnabled',
        remediation_command: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name 'HiberbootEnabled' -Value 0 -Type DWord"
      },
      {
        id: 'bitlocker_os_volume',
        category: 'Storage & Encryption',
        name: 'BitLocker Drive Encryption (OS Volume)',
        description: 'Validates that the host C: operating system volume is actively BitLocker encrypted.',
        setting_type: 'boolean',
        default_value: true,
        recommended: true,
        audit_provider: 'BitLocker',
        remediation_command: 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly'
      }
    ];
  }

  /**
   * Get all configuration profiles with calculated device compliance statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getAllProfiles(db) {
    const profiles = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM configuration_profiles p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.name ASC
    `).all();

    const complianceStats = db.prepare(`
      SELECT 
        profile_id,
        COUNT(*) as total_evaluated,
        SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count,
        SUM(CASE WHEN compliance_status = 'NON_COMPLIANT' THEN 1 ELSE 0 END) as non_compliant_count,
        SUM(CASE WHEN compliance_status = 'ERROR' THEN 1 ELSE 0 END) as error_count
      FROM profile_compliance
      GROUP BY profile_id
    `).all();

    const statsMap = new Map();
    for (const stat of complianceStats) {
      statsMap.set(stat.profile_id, stat);
    }

    return profiles.map(p => {
      let settings = [];
      try {
        settings = JSON.parse(p.settings_json || '[]');
      } catch {
        settings = [];
      }

      const stat = statsMap.get(p.id) || {
        total_evaluated: 0,
        compliant_count: 0,
        non_compliant_count: 0,
        error_count: 0
      };

      const complianceRate = stat.total_evaluated > 0
        ? Math.round((stat.compliant_count / stat.total_evaluated) * 100 * 10) / 10
        : 100.0;

      return {
        ...p,
        settings,
        settings_count: settings.length,
        compliance: {
          total_evaluated: stat.total_evaluated,
          compliant: stat.compliant_count,
          non_compliant: stat.non_compliant_count,
          error: stat.error_count,
          rate_percent: complianceRate
        }
      };
    });
  }

  /**
   * Get a single profile by ID with device-level compliance records.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getProfileById(db, id) {
    const profile = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM configuration_profiles p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.id = ?
    `).get(id);

    if (!profile) return null;

    let settings = [];
    try {
      settings = JSON.parse(profile.settings_json || '[]');
    } catch {
      settings = [];
    }

    // Get all device evaluations for this profile
    const evaluations = db.prepare(`
      SELECT 
        c.*,
        d.hostname,
        d.friendly_name,
        d.primary_user,
        d.status as device_status,
        d.os_name,
        d.os_version
      FROM profile_compliance c
      JOIN devices d ON c.device_id = d.id
      WHERE c.profile_id = ?
      ORDER BY c.evaluated_at DESC
    `).all(id);

    const parsedEvaluations = evaluations.map(ev => {
      let results = [];
      try {
        results = JSON.parse(ev.setting_results_json || '[]');
      } catch {
        results = [];
      }
      return {
        ...ev,
        setting_results: results
      };
    });

    const compliantCount = parsedEvaluations.filter(e => e.compliance_status === 'COMPLIANT').length;
    const nonCompliantCount = parsedEvaluations.filter(e => e.compliance_status === 'NON_COMPLIANT').length;
    const errorCount = parsedEvaluations.filter(e => e.compliance_status === 'ERROR').length;
    const total = parsedEvaluations.length;

    return {
      ...profile,
      settings,
      settings_count: settings.length,
      compliance: {
        total_evaluated: total,
        compliant: compliantCount,
        non_compliant: nonCompliantCount,
        error: errorCount,
        rate_percent: total > 0 ? Math.round((compliantCount / total) * 100 * 10) / 10 : 100.0
      },
      evaluations: parsedEvaluations
    };
  }

  /**
   * Create a new configuration profile.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} payload
   * @returns {object}
   */
  createProfile(db, payload) {
    const {
      id = `prof-${crypto.randomUUID().slice(0, 8)}`,
      name,
      description = '',
      profile_type = 'SettingsCatalog',
      target_group_id = 'grp-all',
      settings = []
    } = payload;

    if (!name || typeof name !== 'string' || !name.trim()) {
      throw new Error('Profile name is required');
    }

    const settingsJson = typeof settings === 'string' ? settings : JSON.stringify(settings || []);

    db.prepare(`
      INSERT INTO configuration_profiles (
        id, name, description, profile_type, target_group_id, settings_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `).run(id, name.trim(), description || '', profile_type, target_group_id, settingsJson);

    return this.getProfileById(db, id);
  }

  /**
   * Update an existing configuration profile.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} updates
   * @returns {object|null}
   */
  updateProfile(db, id, updates) {
    const existing = db.prepare('SELECT * FROM configuration_profiles WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name.trim() : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const profile_type = updates.profile_type !== undefined ? updates.profile_type : existing.profile_type;
    const target_group_id = updates.target_group_id !== undefined ? updates.target_group_id : existing.target_group_id;
    
    let settings_json = existing.settings_json;
    if (updates.settings !== undefined) {
      settings_json = typeof updates.settings === 'string' ? updates.settings : JSON.stringify(updates.settings || []);
    } else if (updates.settings_json !== undefined) {
      settings_json = updates.settings_json;
    }

    db.prepare(`
      UPDATE configuration_profiles
      SET name = ?, description = ?, profile_type = ?, target_group_id = ?, settings_json = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(name, description, profile_type, target_group_id, settings_json, id);

    return this.getProfileById(db, id);
  }

  /**
   * Delete a configuration profile and cascade compliance records.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deleteProfile(db, id) {
    const res = db.prepare('DELETE FROM configuration_profiles WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Find all configuration profiles targeting a device.
   * Matches on grp-all or any dynamic group the device belongs to.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {Array<object>}
   */
  getProfilesForDevice(db, deviceId) {
    const memberships = db.prepare(`
      SELECT group_id FROM group_memberships WHERE device_id = ?
    `).all(deviceId).map(r => r.group_id);

    const groupSet = new Set(['grp-all', ...memberships]);

    const allProfiles = db.prepare(`
      SELECT p.*, g.name as target_group_name
      FROM configuration_profiles p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.name ASC
    `).all();

    const targeted = allProfiles.filter(p => {
      if (!p.target_group_id || p.target_group_id === 'grp-all') return true;
      return groupSet.has(p.target_group_id);
    });

    // Attach latest compliance for this device
    const compRecords = db.prepare(`
      SELECT * FROM profile_compliance WHERE device_id = ?
    `).all(deviceId);

    const compMap = new Map();
    for (const c of compRecords) {
      compMap.set(c.profile_id, c);
    }

    return targeted.map(p => {
      let settings = [];
      try {
        settings = JSON.parse(p.settings_json || '[]');
      } catch {
        settings = [];
      }

      const comp = compMap.get(p.id);
      let results = [];
      if (comp?.setting_results_json) {
        try {
          results = JSON.parse(comp.setting_results_json);
        } catch {
          results = [];
        }
      }

      return {
        ...p,
        settings,
        compliance_status: comp ? comp.compliance_status : 'PENDING',
        last_evaluated_at: comp ? comp.evaluated_at : null,
        setting_results: results
      };
    });
  }

  /**
   * Record a device's compliance audit results for a profile.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} profileId
   * @param {Array<object>} settingResults
   * @returns {object}
   */
  recordDeviceCompliance(db, deviceId, profileId, settingResults = []) {
    let compliantCount = 0;
    let nonCompliantCount = 0;
    let errorCount = 0;

    for (const res of settingResults) {
      const status = (res.status || '').toUpperCase();
      if (status === 'COMPLIANT') compliantCount++;
      else if (status === 'NON_COMPLIANT') nonCompliantCount++;
      else if (status === 'ERROR') errorCount++;
      else nonCompliantCount++;
    }

    let complianceStatus = 'COMPLIANT';
    if (nonCompliantCount > 0) {
      complianceStatus = 'NON_COMPLIANT';
    } else if (errorCount > 0) {
      complianceStatus = 'ERROR';
    } else if (settingResults.length === 0) {
      complianceStatus = 'COMPLIANT';
    }

    const compId = `comp_${crypto.randomUUID().slice(0, 12)}`;
    const resultsJson = JSON.stringify(settingResults);

    db.prepare(`
      INSERT INTO profile_compliance (
        id, profile_id, device_id, compliance_status, compliant_count, non_compliant_count, error_count,
        setting_results_json, evaluated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
      ON CONFLICT(profile_id, device_id) DO UPDATE SET
        compliance_status = excluded.compliance_status,
        compliant_count = excluded.compliant_count,
        non_compliant_count = excluded.non_compliant_count,
        error_count = excluded.error_count,
        setting_results_json = excluded.setting_results_json,
        evaluated_at = DATETIME('now')
    `).run(compId, profileId, deviceId, complianceStatus, compliantCount, nonCompliantCount, errorCount, resultsJson);

    return {
      profile_id: profileId,
      device_id: deviceId,
      compliance_status: complianceStatus,
      compliant_count: compliantCount,
      non_compliant_count: nonCompliantCount,
      error_count: errorCount,
      setting_results: settingResults
    };
  }

  /**
   * Aggregate fleet-wide configuration profile compliance statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getFleetProfileStats(db) {
    const totalProfiles = db.prepare('SELECT COUNT(*) as count FROM configuration_profiles').get()?.count || 0;
    const totalEvaluations = db.prepare('SELECT COUNT(*) as count FROM profile_compliance').get()?.count || 0;
    const evaluatedDevices = db.prepare('SELECT COUNT(DISTINCT device_id) as count FROM profile_compliance').get()?.count || 0;

    const compliantEvals = db.prepare("SELECT COUNT(*) as count FROM profile_compliance WHERE compliance_status = 'COMPLIANT'").get()?.count || 0;
    const nonCompliantEvals = db.prepare("SELECT COUNT(*) as count FROM profile_compliance WHERE compliance_status = 'NON_COMPLIANT'").get()?.count || 0;
    const errorEvals = db.prepare("SELECT COUNT(*) as count FROM profile_compliance WHERE compliance_status = 'ERROR'").get()?.count || 0;

    const nonCompliantDevices = db.prepare("SELECT COUNT(DISTINCT device_id) as count FROM profile_compliance WHERE compliance_status != 'COMPLIANT'").get()?.count || 0;

    const complianceRate = totalEvaluations > 0
      ? Math.round((compliantEvals / totalEvaluations) * 100 * 10) / 10
      : 100.0;

    const profilesByType = db.prepare(`
      SELECT profile_type, COUNT(*) as count
      FROM configuration_profiles
      GROUP BY profile_type
    `).all();

    return {
      total_profiles: totalProfiles,
      total_evaluations: totalEvaluations,
      evaluated_devices: evaluatedDevices,
      compliant_evaluations: compliantEvals,
      non_compliant_evaluations: nonCompliantEvals,
      error_evaluations: errorEvals,
      non_compliant_devices: nonCompliantDevices,
      compliance_rate_percent: complianceRate,
      profiles_by_type: profilesByType
    };
  }
}

export const configProfileEngine = new ConfigProfileEngine();
