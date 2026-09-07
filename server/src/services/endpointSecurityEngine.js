/**
 * LocalPilot Fleet — Microsoft Defender for Endpoint & Antivirus Governance Engine
 * server/src/services/endpointSecurityEngine.js
 *
 * Implements Microsoft Intune-style Endpoint Security, Defender Antivirus policies,
 * live telemetry ingestion, signature age tracking, ransomware protection (Controlled Folders),
 * threat detection logging, and remote scan dispatching.
 */

import crypto from 'node:crypto';

export class EndpointSecurityEngine {
  /**
   * Get all endpoint security policies with assigned group details and stats.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getAllPolicies(db) {
    const policies = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM endpoint_security_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.name ASC
    `).all();

    return policies.map(p => {
      let exclusions = { paths: [], extensions: [], processes: [] };
      try {
        if (p.exclusions_json) exclusions = JSON.parse(p.exclusions_json);
      } catch {}

      // Count devices currently targeted by this policy
      let targetedDevices = 0;
      if (p.target_group_id === 'grp-all') {
        targetedDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
      } else if (p.target_group_id) {
        targetedDevices = db.prepare(`
          SELECT COUNT(DISTINCT device_id) as c
          FROM group_memberships
          WHERE group_id = ?
        `).get(p.target_group_id).c;
      }

      return {
        ...p,
        exclusions,
        targeted_devices: targetedDevices
      };
    });
  }

  /**
   * Get detailed policy by ID.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getPolicyById(db, id) {
    const policy = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM endpoint_security_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.id = ?
    `).get(id);

    if (!policy) return null;

    let exclusions = { paths: [], extensions: [], processes: [] };
    try {
      if (policy.exclusions_json) exclusions = JSON.parse(policy.exclusions_json);
    } catch {}

    return {
      ...policy,
      exclusions
    };
  }

  /**
   * Create a new endpoint security policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} payload
   * @returns {object}
   */
  createPolicy(db, payload) {
    const {
      name,
      description,
      target_group_id,
      real_time_protection = 1,
      cloud_protection_level = 'HIGH',
      controlled_folder_access = 'AUDIT',
      pua_protection = 'ENABLED',
      network_protection = 'ENABLED',
      tamper_protection = 1,
      scan_schedule_type = 'DAILY_QUICK',
      scan_schedule_time = '02:00',
      exclusions = { paths: [], extensions: [], processes: [] },
      is_enabled = 1
    } = payload;

    if (!name || !name.trim()) {
      throw new Error('Policy name is required');
    }

    const id = `sec-${crypto.randomUUID().slice(0, 8)}`;
    const validCloudLevels = ['DISABLED', 'BASIC', 'STANDARD', 'HIGH', 'HIGH_PLUS', 'ZERO_TOLERANCE'];
    const validCfa = ['DISABLED', 'ENABLED', 'AUDIT', 'BLOCK_DISK_ONLY'];
    const validPua = ['DISABLED', 'ENABLED', 'AUDIT'];
    const validNet = ['DISABLED', 'ENABLED', 'AUDIT'];
    const validScans = ['DISABLED', 'DAILY_QUICK', 'WEEKLY_FULL'];

    db.prepare(`
      INSERT INTO endpoint_security_policies (
        id, name, description, target_group_id,
        real_time_protection, cloud_protection_level, controlled_folder_access,
        pua_protection, network_protection, tamper_protection,
        scan_schedule_type, scan_schedule_time, exclusions_json, is_enabled,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `).run(
      id,
      name.trim(),
      description || '',
      target_group_id || 'grp-all',
      real_time_protection ? 1 : 0,
      validCloudLevels.includes(cloud_protection_level) ? cloud_protection_level : 'HIGH',
      validCfa.includes(controlled_folder_access) ? controlled_folder_access : 'AUDIT',
      validPua.includes(pua_protection) ? pua_protection : 'ENABLED',
      validNet.includes(network_protection) ? network_protection : 'ENABLED',
      tamper_protection ? 1 : 0,
      validScans.includes(scan_schedule_type) ? scan_schedule_type : 'DAILY_QUICK',
      scan_schedule_time || '02:00',
      JSON.stringify(exclusions),
      is_enabled ? 1 : 0
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing endpoint security policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} updates
   * @returns {object|null}
   */
  updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM endpoint_security_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name.trim() : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_group_id = updates.target_group_id !== undefined ? updates.target_group_id : existing.target_group_id;
    const real_time_protection = updates.real_time_protection !== undefined ? (updates.real_time_protection ? 1 : 0) : existing.real_time_protection;
    const cloud_protection_level = updates.cloud_protection_level !== undefined ? updates.cloud_protection_level : existing.cloud_protection_level;
    const controlled_folder_access = updates.controlled_folder_access !== undefined ? updates.controlled_folder_access : existing.controlled_folder_access;
    const pua_protection = updates.pua_protection !== undefined ? updates.pua_protection : existing.pua_protection;
    const network_protection = updates.network_protection !== undefined ? updates.network_protection : existing.network_protection;
    const tamper_protection = updates.tamper_protection !== undefined ? (updates.tamper_protection ? 1 : 0) : existing.tamper_protection;
    const scan_schedule_type = updates.scan_schedule_type !== undefined ? updates.scan_schedule_type : existing.scan_schedule_type;
    const scan_schedule_time = updates.scan_schedule_time !== undefined ? updates.scan_schedule_time : existing.scan_schedule_time;
    const exclusions_json = updates.exclusions !== undefined ? JSON.stringify(updates.exclusions) : (updates.exclusions_json || existing.exclusions_json);
    const is_enabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE endpoint_security_policies SET
        name = ?, description = ?, target_group_id = ?,
        real_time_protection = ?, cloud_protection_level = ?, controlled_folder_access = ?,
        pua_protection = ?, network_protection = ?, tamper_protection = ?,
        scan_schedule_type = ?, scan_schedule_time = ?, exclusions_json = ?,
        is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_group_id,
      real_time_protection, cloud_protection_level, controlled_folder_access,
      pua_protection, network_protection, tamper_protection,
      scan_schedule_type, scan_schedule_time, exclusions_json,
      is_enabled, id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete an endpoint security policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM endpoint_security_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get effective endpoint security policy for a specific device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object|null}
   */
  getEffectivePolicyForDevice(db, deviceId) {
    const policies = db.prepare(`
      SELECT p.*, g.priority as group_priority
      FROM endpoint_security_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.is_enabled = 1 AND (
        p.target_group_id = 'grp-all' OR
        EXISTS (SELECT 1 FROM group_memberships gm WHERE gm.device_id = ? AND gm.group_id = p.target_group_id)
      )
      ORDER BY COALESCE(g.priority, 999) ASC, p.created_at DESC
    `).all(deviceId);

    if (policies.length === 0) return null;

    // Use the highest priority policy as base
    const base = policies[0];
    let mergedExclusions = { paths: [], extensions: [], processes: [] };

    for (const p of policies) {
      try {
        if (p.exclusions_json) {
          const parsed = JSON.parse(p.exclusions_json);
          if (Array.isArray(parsed.paths)) mergedExclusions.paths.push(...parsed.paths);
          if (Array.isArray(parsed.extensions)) mergedExclusions.extensions.push(...parsed.extensions);
          if (Array.isArray(parsed.processes)) mergedExclusions.processes.push(...parsed.processes);
        }
      } catch {}
    }

    // Deduplicate exclusions
    mergedExclusions.paths = [...new Set(mergedExclusions.paths)];
    mergedExclusions.extensions = [...new Set(mergedExclusions.extensions)];
    mergedExclusions.processes = [...new Set(mergedExclusions.processes)];

    return {
      id: base.id,
      name: base.name,
      real_time_protection: base.real_time_protection === 1,
      cloud_protection_level: base.cloud_protection_level,
      controlled_folder_access: base.controlled_folder_access,
      pua_protection: base.pua_protection,
      network_protection: base.network_protection,
      tamper_protection: base.tamper_protection === 1,
      scan_schedule_type: base.scan_schedule_type,
      scan_schedule_time: base.scan_schedule_time,
      exclusions: mergedExclusions,
      applied_policies_count: policies.length
    };
  }

  /**
   * Record or update antivirus telemetry for a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  recordAntivirusStatus(db, deviceId, payload) {
    const existing = db.prepare('SELECT id FROM device_antivirus_status WHERE device_id = ?').get(deviceId);
    const id = existing ? existing.id : `av-${crypto.randomUUID().slice(0, 8)}`;

    const {
      antivirus_enabled = 1,
      engine_version = null,
      product_version = null,
      signature_version = null,
      signature_last_updated = null,
      signature_age_days = 0,
      real_time_protection_enabled = 1,
      cloud_protection_enabled = 1,
      pua_protection_enabled = 1,
      controlled_folder_access_enabled = 0,
      network_protection_enabled = 1,
      tamper_protection_enabled = 1,
      antispyware_enabled = 1,
      behavior_monitor_enabled = 1,
      ioav_protection_enabled = 1,
      last_quick_scan_at = null,
      last_full_scan_at = null,
      quick_scan_age_days = 0,
      full_scan_age_days = 0,
      active_threat_count = 0
    } = payload;

    const avEnabled = antivirus_enabled ? 1 : 0;
    const rtpEnabled = real_time_protection_enabled ? 1 : 0;
    const cloudEnabled = cloud_protection_enabled ? 1 : 0;
    const puaEnabled = pua_protection_enabled ? 1 : 0;
    const netEnabled = network_protection_enabled ? 1 : 0;
    const tamperEnabled = tamper_protection_enabled ? 1 : 0;
    const antispyEnabled = antispyware_enabled ? 1 : 0;
    const behavEnabled = behavior_monitor_enabled ? 1 : 0;
    const ioavEnabled = ioav_protection_enabled ? 1 : 0;
    const cfaVal = Number(controlled_folder_access_enabled) || 0;
    const sigAge = Math.max(0, Number(signature_age_days) || 0);

    db.prepare(`
      INSERT INTO device_antivirus_status (
        id, device_id, antivirus_enabled, engine_version, product_version,
        signature_version, signature_last_updated, signature_age_days,
        real_time_protection_enabled, cloud_protection_enabled, pua_protection_enabled,
        controlled_folder_access_enabled, network_protection_enabled, tamper_protection_enabled,
        antispyware_enabled, behavior_monitor_enabled, ioav_protection_enabled,
        last_quick_scan_at, last_full_scan_at, quick_scan_age_days, full_scan_age_days,
        active_threat_count, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
      ON CONFLICT(device_id) DO UPDATE SET
        antivirus_enabled = excluded.antivirus_enabled,
        engine_version = COALESCE(excluded.engine_version, device_antivirus_status.engine_version),
        product_version = COALESCE(excluded.product_version, device_antivirus_status.product_version),
        signature_version = COALESCE(excluded.signature_version, device_antivirus_status.signature_version),
        signature_last_updated = COALESCE(excluded.signature_last_updated, device_antivirus_status.signature_last_updated),
        signature_age_days = excluded.signature_age_days,
        real_time_protection_enabled = excluded.real_time_protection_enabled,
        cloud_protection_enabled = excluded.cloud_protection_enabled,
        pua_protection_enabled = excluded.pua_protection_enabled,
        controlled_folder_access_enabled = excluded.controlled_folder_access_enabled,
        network_protection_enabled = excluded.network_protection_enabled,
        tamper_protection_enabled = excluded.tamper_protection_enabled,
        antispyware_enabled = excluded.antispyware_enabled,
        behavior_monitor_enabled = excluded.behavior_monitor_enabled,
        ioav_protection_enabled = excluded.ioav_protection_enabled,
        last_quick_scan_at = COALESCE(excluded.last_quick_scan_at, device_antivirus_status.last_quick_scan_at),
        last_full_scan_at = COALESCE(excluded.last_full_scan_at, device_antivirus_status.last_full_scan_at),
        quick_scan_age_days = excluded.quick_scan_age_days,
        full_scan_age_days = excluded.full_scan_age_days,
        active_threat_count = excluded.active_threat_count,
        updated_at = DATETIME('now')
    `).run(
      id, deviceId, avEnabled, engine_version, product_version,
      signature_version, signature_last_updated, sigAge,
      rtpEnabled, cloudEnabled, puaEnabled,
      cfaVal, netEnabled, tamperEnabled,
      antispyEnabled, behavEnabled, ioavEnabled,
      last_quick_scan_at, last_full_scan_at, quick_scan_age_days, full_scan_age_days,
      active_threat_count
    );

    // If Real-Time Protection is disabled, log a HIGH severity security alert
    if (rtpEnabled === 0) {
      const dev = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
      const host = dev?.hostname || deviceId;
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
      `).run(
        deviceId,
        'ANTIVIRUS_RTP_DISABLED',
        1116,
        'Microsoft-Windows-WindowsDefender',
        'HIGH',
        `Microsoft Defender Real-Time Protection is DISABLED on ${host}`,
        JSON.stringify({ device_id: deviceId, hostname: host, signature_version })
      );
    }

    return this.getDeviceAntivirusStatus(db, deviceId);
  }

  /**
   * Get antivirus status for a specific device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object|null}
   */
  getDeviceAntivirusStatus(db, deviceId) {
    const status = db.prepare(`
      SELECT s.*, d.hostname, d.friendly_name, d.status as device_status, d.primary_user
      FROM device_antivirus_status s
      JOIN devices d ON s.device_id = d.id
      WHERE s.device_id = ?
    `).get(deviceId);

    if (!status) return null;

    // Determine posture health
    let health = 'HEALTHY';
    const issues = [];

    if (status.antivirus_enabled === 0) {
      health = 'CRITICAL';
      issues.push('Antivirus engine is disabled');
    }
    if (status.real_time_protection_enabled === 0) {
      health = 'CRITICAL';
      issues.push('Real-time protection is disabled');
    }
    if (status.signature_age_days > 7) {
      if (health !== 'CRITICAL') health = 'NEEDS_ATTENTION';
      issues.push(`Signatures are outdated (${status.signature_age_days} days old)`);
    }
    if (status.active_threat_count > 0) {
      health = 'CRITICAL';
      issues.push(`${status.active_threat_count} active malware threat(s) detected`);
    }

    const recentThreats = db.prepare(`
      SELECT * FROM threat_detections
      WHERE device_id = ?
      ORDER BY detected_at DESC
      LIMIT 10
    `).all(deviceId).map(t => {
      let resources = [];
      try { if (t.resources_json) resources = JSON.parse(t.resources_json); } catch {}
      return { ...t, resources };
    });

    const effectivePolicy = this.getEffectivePolicyForDevice(db, deviceId);

    return {
      ...status,
      health_status: health,
      posture_issues: issues,
      recent_threats: recentThreats,
      effective_policy: effectivePolicy
    };
  }

  /**
   * Get all device antivirus statuses across the fleet.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} options
   * @returns {Array<object>}
   */
  getAllDeviceAntivirusStatuses(db, options = {}) {
    const { status_filter, search } = options;

    const rows = db.prepare(`
      SELECT s.*, d.hostname, d.friendly_name, d.status as device_status, d.primary_user, d.ip_address
      FROM device_antivirus_status s
      JOIN devices d ON s.device_id = d.id
      ORDER BY s.active_threat_count DESC, s.signature_age_days DESC, d.hostname ASC
    `).all();

    return rows.map(r => {
      let health = 'HEALTHY';
      if (r.antivirus_enabled === 0 || r.real_time_protection_enabled === 0 || r.active_threat_count > 0) {
        health = 'CRITICAL';
      } else if (r.signature_age_days > 7) {
        health = 'NEEDS_ATTENTION';
      }
      return {
        ...r,
        health_status: health
      };
    }).filter(item => {
      if (status_filter && item.health_status !== status_filter) return false;
      if (search) {
        const q = search.toLowerCase();
        return item.hostname.toLowerCase().includes(q) ||
               (item.friendly_name && item.friendly_name.toLowerCase().includes(q)) ||
               (item.signature_version && item.signature_version.toLowerCase().includes(q));
      }
      return true;
    });
  }

  /**
   * Record a malware or threat detection.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  recordThreatDetection(db, deviceId, payload) {
    const {
      threat_name,
      threat_id,
      severity = 'HIGH',
      category = 'Malware',
      resources = [],
      action_taken = 'QUARANTINED',
      remediation_status = 'ACTIVE',
      detected_at
    } = payload;

    if (!threat_name) {
      throw new Error('Threat name is required');
    }

    const id = `threat-${crypto.randomUUID().slice(0, 8)}`;
    const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
    const validActions = ['QUARANTINED', 'REMOVED', 'CLEANED', 'BLOCKED', 'NO_ACTION', 'ALLOWED'];
    const validRemediation = ['ACTIVE', 'RESOLVED', 'MANUAL_STEPS_REQUIRED', 'FAILED'];

    const chosenSev = validSeverities.includes(severity) ? severity : 'HIGH';
    const chosenAction = validActions.includes(action_taken) ? action_taken : 'QUARANTINED';
    const chosenStatus = validRemediation.includes(remediation_status) ? remediation_status : 'ACTIVE';

    db.prepare(`
      INSERT INTO threat_detections (
        id, device_id, threat_name, threat_id, severity, category,
        resources_json, action_taken, remediation_status, detected_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, DATETIME('now')), DATETIME('now'))
    `).run(
      id,
      deviceId,
      threat_name,
      threat_id || null,
      chosenSev,
      category,
      JSON.stringify(resources),
      chosenAction,
      chosenStatus,
      detected_at || null
    );

    // Increment active threat count if active
    if (chosenStatus === 'ACTIVE') {
      db.prepare(`
        UPDATE device_antivirus_status
        SET active_threat_count = active_threat_count + 1, updated_at = DATETIME('now')
        WHERE device_id = ?
      `).run(deviceId);
    }

    // Insert watchdog security event for live alerting
    const dev = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
    const host = dev?.hostname || deviceId;

    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      deviceId,
      'MALWARE_THREAT_DETECTED',
      1116,
      'Microsoft-Windows-WindowsDefender',
      chosenSev === 'INFORMATIONAL' ? 'INFO' : chosenSev,
      `Defender detected ${threat_name} (${category}) on ${host} [Action: ${chosenAction}]`,
      JSON.stringify({ threat_id, threat_name, severity: chosenSev, action_taken: chosenAction, resources })
    );

    return {
      id,
      device_id: deviceId,
      threat_name,
      threat_id,
      severity: chosenSev,
      category,
      resources,
      action_taken: chosenAction,
      remediation_status: chosenStatus
    };
  }

  /**
   * Get threats list with filters.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} options
   * @returns {Array<object>}
   */
  getThreats(db, options = {}) {
    const { status, severity, device_id, limit = 50, offset = 0 } = options;

    const conditions = [];
    const params = [];

    if (status) {
      conditions.push('t.remediation_status = ?');
      params.push(status);
    }
    if (severity) {
      conditions.push('t.severity = ?');
      params.push(severity);
    }
    if (device_id) {
      conditions.push('t.device_id = ?');
      params.push(device_id);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const query = `
      SELECT t.*, d.hostname, d.friendly_name
      FROM threat_detections t
      JOIN devices d ON t.device_id = d.id
      ${whereClause}
      ORDER BY t.detected_at DESC
      LIMIT ? OFFSET ?
    `;

    const threats = db.prepare(query).all(...params, limit, offset);

    return threats.map(t => {
      let resources = [];
      try { if (t.resources_json) resources = JSON.parse(t.resources_json); } catch {}
      return { ...t, resources };
    });
  }

  /**
   * Remediate or update status of a threat detection.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} threatId
   * @param {string} resolutionStatus
   * @returns {object|null}
   */
  remediateThreat(db, threatId, resolutionStatus = 'RESOLVED') {
    const existing = db.prepare('SELECT * FROM threat_detections WHERE id = ?').get(threatId);
    if (!existing) return null;

    db.prepare(`
      UPDATE threat_detections
      SET remediation_status = ?
      WHERE id = ?
    `).run(resolutionStatus, threatId);

    // If resolved and previously active, decrement active count
    if (existing.remediation_status === 'ACTIVE' && resolutionStatus === 'RESOLVED') {
      db.prepare(`
        UPDATE device_antivirus_status
        SET active_threat_count = MAX(0, active_threat_count - 1), updated_at = DATETIME('now')
        WHERE device_id = ?
      `).run(existing.device_id);
    }

    return db.prepare('SELECT * FROM threat_detections WHERE id = ?').get(threatId);
  }

  /**
   * Get fleet-wide Endpoint Security KPI statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getSecurityStats(db) {
    const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;

    const avStats = db.prepare(`
      SELECT 
        COUNT(*) as total_reported,
        SUM(CASE WHEN antivirus_enabled = 1 AND real_time_protection_enabled = 1 THEN 1 ELSE 0 END) as fully_protected,
        SUM(CASE WHEN real_time_protection_enabled = 0 THEN 1 ELSE 0 END) as rtp_disabled,
        SUM(CASE WHEN signature_age_days > 7 THEN 1 ELSE 0 END) as outdated_signatures,
        SUM(CASE WHEN controlled_folder_access_enabled IN (1, 2) THEN 1 ELSE 0 END) as controlled_folders_active,
        SUM(CASE WHEN pua_protection_enabled = 1 THEN 1 ELSE 0 END) as pua_enabled,
        COALESCE(SUM(active_threat_count), 0) as total_active_threats
      FROM device_antivirus_status
    `).get();

    const activeThreatsCount = db.prepare(`
      SELECT COUNT(*) as c FROM threat_detections WHERE remediation_status = 'ACTIVE'
    `).get().c;

    const totalThreatsDetected = db.prepare(`
      SELECT COUNT(*) as c FROM threat_detections
    `).get().c;

    const threatsBySev = db.prepare(`
      SELECT severity, COUNT(*) as count
      FROM threat_detections
      WHERE remediation_status = 'ACTIVE'
      GROUP BY severity
    `).all();

    const sevMap = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
    for (const r of threatsBySev) {
      if (sevMap[r.severity] !== undefined) sevMap[r.severity] = r.count;
    }

    const protectionRate = totalDevices > 0
      ? Math.round(((avStats?.fully_protected || 0) / totalDevices) * 100 * 10) / 10
      : 100.0;

    return {
      total_devices: totalDevices,
      total_reported: avStats?.total_reported || 0,
      fully_protected_devices: avStats?.fully_protected || 0,
      protection_rate_percent: protectionRate,
      rtp_disabled_count: avStats?.rtp_disabled || 0,
      outdated_signatures_count: avStats?.outdated_signatures || 0,
      controlled_folders_active_count: avStats?.controlled_folders_active || 0,
      pua_enabled_count: avStats?.pua_enabled || 0,
      active_threats_count: activeThreatsCount,
      total_threats_detected: totalThreatsDetected,
      threats_by_severity: sevMap
    };
  }

  /**
   * Queue a remote Defender scan on a target device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} scanType 'QuickScan' | 'FullScan'
   * @returns {object}
   */
  queueScanCommand(db, deviceId, scanType = 'QuickScan') {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);

    const commandId = `cmd-scan-${crypto.randomUUID().slice(0, 8)}`;
    const st = scanType === 'FullScan' ? 'FullScan' : 'QuickScan';

    const script = `Start-MpScan -ScanType ${st} -ErrorAction Stop; Get-MpComputerStatus | Select-Object AntivirusSignatureAge, AntivirusSignatureVersion, QuickScanAge, FullScanAge | ConvertTo-Json -Compress`;

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'EndpointSecurityAdmin', 'PENDING', DATETIME('now'))
    `).run(commandId, deviceId, script);

    return {
      command_id: commandId,
      device_id: deviceId,
      hostname: dev.hostname,
      scan_type: st,
      status: 'PENDING',
      queued_at: new Date().toISOString()
    };
  }

  /**
   * Queue a remote Defender signature update on a target device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object}
   */
  queueSignatureUpdateCommand(db, deviceId) {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);

    const commandId = `cmd-sig-${crypto.randomUUID().slice(0, 8)}`;
    const script = `Update-MpSignature -ErrorAction Stop; Get-MpComputerStatus | Select-Object AntivirusSignatureAge, AntivirusSignatureVersion, EngineVersion | ConvertTo-Json -Compress`;

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'EndpointSecurityAdmin', 'PENDING', DATETIME('now'))
    `).run(commandId, deviceId, script);

    return {
      command_id: commandId,
      device_id: deviceId,
      hostname: dev.hostname,
      action: 'UpdateSignatures',
      status: 'PENDING',
      queued_at: new Date().toISOString()
    };
  }
}

export const endpointSecurityEngine = new EndpointSecurityEngine();
export default endpointSecurityEngine;
