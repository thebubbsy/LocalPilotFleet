/**
 * LocalPilot Fleet — Windows Update for Business (WUfB) & Update Rings Engine
 * server/src/services/updateRingEngine.js
 *
 * Provides patch policy management, active hours scheduling, quality/feature deferrals,
 * pending reboot tracking, and hotfix audit telemetry.
 */

import crypto from 'node:crypto';

export class UpdateRingEngine {
  /**
   * Get all update rings with device assignment and reboot pending counts.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getAllRings(db) {
    const rings = db.prepare(`
      SELECT r.*, g.name as target_group_name, g.color as target_group_color
      FROM update_rings r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      ORDER BY r.name ASC
    `).all();

    const deviceCounts = db.prepare(`
      SELECT 
        ring_id,
        COUNT(*) as total_devices,
        SUM(CASE WHEN reboot_pending = 1 THEN 1 ELSE 0 END) as reboot_pending_count,
        SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count
      FROM device_update_status
      WHERE ring_id IS NOT NULL
      GROUP BY ring_id
    `).all();

    const countMap = new Map();
    for (const dc of deviceCounts) {
      countMap.set(dc.ring_id, dc);
    }

    return rings.map(r => {
      const stats = countMap.get(r.id) || {
        total_devices: 0,
        reboot_pending_count: 0,
        compliant_count: 0
      };

      const complianceRate = stats.total_devices > 0
        ? Math.round((stats.compliant_count / stats.total_devices) * 100 * 10) / 10
        : 100.0;

      return {
        ...r,
        stats: {
          total_devices: stats.total_devices,
          reboot_pending_count: stats.reboot_pending_count,
          compliant_count: stats.compliant_count,
          compliance_rate_percent: complianceRate
        }
      };
    });
  }

  /**
   * Get update ring details by ID with assigned devices.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getRingById(db, id) {
    const ring = db.prepare(`
      SELECT r.*, g.name as target_group_name, g.color as target_group_color
      FROM update_rings r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      WHERE r.id = ?
    `).get(id);

    if (!ring) return null;

    const devices = db.prepare(`
      SELECT 
        s.*,
        d.hostname,
        d.friendly_name,
        d.primary_user,
        d.os_name,
        d.os_version,
        d.status as device_status
      FROM device_update_status s
      JOIN devices d ON s.device_id = d.id
      WHERE s.ring_id = ?
      ORDER BY s.updated_at DESC
    `).all(id);

    const parsedDevices = devices.map(d => {
      let reasons = [];
      let hotfixes = [];
      try { reasons = JSON.parse(d.reboot_pending_reasons_json || '[]'); } catch {}
      try { hotfixes = JSON.parse(d.installed_hotfixes_json || '[]'); } catch {}
      return {
        ...d,
        reboot_pending_reasons: reasons,
        installed_hotfixes: hotfixes
      };
    });

    const totalDevs = parsedDevices.length;
    const rebootPending = parsedDevices.filter(d => d.reboot_pending === 1).length;
    const compliant = parsedDevices.filter(d => d.compliance_status === 'COMPLIANT').length;

    return {
      ...ring,
      stats: {
        total_devices: totalDevs,
        reboot_pending_count: rebootPending,
        compliant_count: compliant,
        compliance_rate_percent: totalDevs > 0 ? Math.round((compliant / totalDevs) * 100 * 10) / 10 : 100.0
      },
      devices: parsedDevices
    };
  }

  /**
   * Create a new update ring.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} data
   * @returns {object}
   */
  createRing(db, data) {
    const {
      name,
      description = '',
      target_group_id = 'grp-all',
      servicing_channel = 'GeneralAvailability',
      quality_deferral_days = 0,
      feature_deferral_days = 0,
      active_hours_start = 8,
      active_hours_end = 17,
      automatic_update_mode = 'AutoInstallAndRebootAtMaintenanceTime',
      restart_deadline_days = 5,
      is_paused = 0
    } = data;

    if (!name || !name.trim()) {
      throw new Error('Update ring name is required');
    }

    const parseHour = (val, fallback) => {
      if (typeof val === 'number') return Math.min(23, Math.max(0, Math.floor(val)));
      if (typeof val === 'string') {
        const num = parseInt(val.split(':')[0], 10);
        if (!isNaN(num)) return Math.min(23, Math.max(0, num));
      }
      return fallback;
    };

    // Normalize servicing_channel
    let normalizedChannel = 'GeneralAvailability';
    const validChannels = [
      'GeneralAvailability',
      'WindowsInsiderPreRelease',
      'WindowsInsiderBeta',
      'WindowsInsiderReleasePreview'
    ];
    if (validChannels.includes(servicing_channel)) {
      normalizedChannel = servicing_channel;
    } else if (/canary|prerelease|dev/i.test(servicing_channel)) {
      normalizedChannel = 'WindowsInsiderPreRelease';
    } else if (/beta/i.test(servicing_channel)) {
      normalizedChannel = 'WindowsInsiderBeta';
    } else if (/preview/i.test(servicing_channel)) {
      normalizedChannel = 'WindowsInsiderReleasePreview';
    }

    // Normalize automatic_update_mode
    let normalizedMode = 'AutoInstallAndRebootAtMaintenanceTime';
    const validModes = [
      'NotifyDownload',
      'AutoInstallAndRebootAtMaintenanceTime',
      'AutoInstallAndRebootWithoutEndUserControl',
      'ResetToDefault'
    ];
    if (validModes.includes(automatic_update_mode)) {
      normalizedMode = automatic_update_mode;
    } else if (/notify/i.test(automatic_update_mode)) {
      normalizedMode = 'NotifyDownload';
    } else if (/without|force/i.test(automatic_update_mode)) {
      normalizedMode = 'AutoInstallAndRebootWithoutEndUserControl';
    }

    const id = `ring-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO update_rings (
        id, name, description, target_group_id, servicing_channel, quality_deferral_days,
        feature_deferral_days, active_hours_start, active_hours_end, automatic_update_mode,
        restart_deadline_days, is_paused, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `).run(
      id,
      name.trim(),
      description || '',
      target_group_id,
      normalizedChannel,
      Math.min(30, Math.max(0, Number(quality_deferral_days) || 0)),
      Math.min(365, Math.max(0, Number(feature_deferral_days) || 0)),
      parseHour(active_hours_start, 8),
      parseHour(active_hours_end, 17),
      normalizedMode,
      Math.min(30, Math.max(0, Number(restart_deadline_days) || 5)),
      is_paused ? 1 : 0
    );

    return this.getRingById(db, id);
  }

  /**
   * Update an existing update ring.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} updates
   * @returns {object|null}
   */
  updateRing(db, id, updates) {
    const existing = db.prepare('SELECT * FROM update_rings WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name.trim() : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_group_id = updates.target_group_id !== undefined ? updates.target_group_id : existing.target_group_id;
    const servicing_channel = updates.servicing_channel !== undefined ? updates.servicing_channel : existing.servicing_channel;
    const quality_deferral_days = updates.quality_deferral_days !== undefined ? Number(updates.quality_deferral_days) : existing.quality_deferral_days;
    const feature_deferral_days = updates.feature_deferral_days !== undefined ? Number(updates.feature_deferral_days) : existing.feature_deferral_days;
    const active_hours_start = updates.active_hours_start !== undefined ? Number(updates.active_hours_start) : existing.active_hours_start;
    const active_hours_end = updates.active_hours_end !== undefined ? Number(updates.active_hours_end) : existing.active_hours_end;
    const automatic_update_mode = updates.automatic_update_mode !== undefined ? updates.automatic_update_mode : existing.automatic_update_mode;
    const restart_deadline_days = updates.restart_deadline_days !== undefined ? Number(updates.restart_deadline_days) : existing.restart_deadline_days;
    const is_paused = updates.is_paused !== undefined ? (updates.is_paused ? 1 : 0) : existing.is_paused;

    db.prepare(`
      UPDATE update_rings SET
        name = ?, description = ?, target_group_id = ?, servicing_channel = ?,
        quality_deferral_days = ?, feature_deferral_days = ?, active_hours_start = ?,
        active_hours_end = ?, automatic_update_mode = ?, restart_deadline_days = ?,
        is_paused = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_group_id, servicing_channel,
      quality_deferral_days, feature_deferral_days, active_hours_start,
      active_hours_end, automatic_update_mode, restart_deadline_days,
      is_paused, id
    );

    return this.getRingById(db, id);
  }

  /**
   * Delete an update ring.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deleteRing(db, id) {
    const res = db.prepare('DELETE FROM update_rings WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Determine the effective update ring for a device based on its dynamic group memberships.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object|null}
   */
  getRingForDevice(db, deviceId) {
    const memberships = db.prepare(`
      SELECT group_id FROM group_memberships WHERE device_id = ?
    `).all(deviceId).map(r => r.group_id);

    const groupSet = new Set(['grp-all', ...memberships]);

    const allRings = db.prepare(`
      SELECT r.*, g.name as target_group_name, g.priority as group_priority
      FROM update_rings r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      ORDER BY COALESCE(g.priority, 999) ASC, r.created_at ASC
    `).all();

    const matchingRing = allRings.find(ring => {
      if (!ring.target_group_id || ring.target_group_id === 'grp-all') return true;
      return groupSet.has(ring.target_group_id);
    });

    return matchingRing || null;
  }

  /**
   * Record update status, pending reboot state, and hotfix telemetry reported by a node agent.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  recordDeviceUpdateStatus(db, deviceId, payload) {
    const {
      reboot_pending = 0,
      reboot_pending_reasons = [],
      last_scan_at = null,
      last_install_at = null,
      installed_hotfixes = [],
      update_service_status = 'Running'
    } = payload;

    const isRebootPending = (reboot_pending === true || reboot_pending === 1) ? 1 : 0;
    const complianceStatus = isRebootPending === 1 ? 'REBOOT_PENDING' : 'COMPLIANT';

    const effectiveRing = this.getRingForDevice(db, deviceId);
    const ringId = effectiveRing ? effectiveRing.id : null;

    const reasonsJson = typeof reboot_pending_reasons === 'string'
      ? reboot_pending_reasons
      : JSON.stringify(reboot_pending_reasons || []);

    const hotfixesJson = typeof installed_hotfixes === 'string'
      ? installed_hotfixes
      : JSON.stringify(installed_hotfixes || []);

    const id = `upd-${crypto.randomUUID().slice(0, 10)}`;

    db.prepare(`
      INSERT INTO device_update_status (
        id, device_id, ring_id, reboot_pending, reboot_pending_reasons_json,
        last_scan_at, last_install_at, installed_hotfixes_json, update_service_status,
        compliance_status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
      ON CONFLICT(device_id) DO UPDATE SET
        ring_id = excluded.ring_id,
        reboot_pending = excluded.reboot_pending,
        reboot_pending_reasons_json = excluded.reboot_pending_reasons_json,
        last_scan_at = COALESCE(excluded.last_scan_at, device_update_status.last_scan_at),
        last_install_at = COALESCE(excluded.last_install_at, device_update_status.last_install_at),
        installed_hotfixes_json = excluded.installed_hotfixes_json,
        update_service_status = excluded.update_service_status,
        compliance_status = excluded.compliance_status,
        updated_at = DATETIME('now')
    `).run(
      id,
      deviceId,
      ringId,
      isRebootPending,
      reasonsJson,
      last_scan_at,
      last_install_at,
      hotfixesJson,
      update_service_status,
      complianceStatus
    );

    return {
      device_id: deviceId,
      ring_id: ringId,
      reboot_pending: isRebootPending === 1,
      compliance_status: complianceStatus,
      effective_ring: effectiveRing
    };
  }

  /**
   * Aggregate fleet-wide Windows Update for Business statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getFleetUpdateStats(db) {
    const totalRings = db.prepare('SELECT COUNT(*) as count FROM update_rings').get()?.count || 0;
    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get()?.count || 0;
    const monitoredDevices = db.prepare('SELECT COUNT(*) as count FROM device_update_status').get()?.count || 0;
    const rebootPending = db.prepare('SELECT COUNT(*) as count FROM device_update_status WHERE reboot_pending = 1').get()?.count || 0;
    const compliantCount = db.prepare("SELECT COUNT(*) as count FROM device_update_status WHERE compliance_status = 'COMPLIANT'").get()?.count || 0;

    const complianceRate = monitoredDevices > 0
      ? Math.round((compliantCount / monitoredDevices) * 100 * 10) / 10
      : 100.0;

    // Collect top installed hotfixes across fleet
    const allStatuses = db.prepare('SELECT installed_hotfixes_json FROM device_update_status').all();
    const hotfixFreq = new Map();

    for (const row of allStatuses) {
      if (!row.installed_hotfixes_json) continue;
      try {
        const list = JSON.parse(row.installed_hotfixes_json);
        if (Array.isArray(list)) {
          for (const hf of list) {
            const kbid = hf.hotfix_id || hf.HotFixID || hf.id;
            if (kbid) {
              const current = hotfixFreq.get(kbid) || { hotfix_id: kbid, description: hf.description || hf.Description || 'Update', count: 0 };
              current.count++;
              hotfixFreq.set(kbid, current);
            }
          }
        }
      } catch {}
    }

    const topHotfixes = Array.from(hotfixFreq.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      total_rings: totalRings,
      total_devices: totalDevices,
      monitored_devices: monitoredDevices,
      reboot_pending_count: rebootPending,
      compliant_devices: compliantCount,
      compliance_rate_percent: complianceRate,
      top_hotfixes: topHotfixes
    };
  }
}

export const updateRingEngine = new UpdateRingEngine();
export default updateRingEngine;
