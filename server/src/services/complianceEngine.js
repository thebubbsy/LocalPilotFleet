/**
 * LocalPilot Fleet — Microsoft Intune Device Compliance & Conditional Access Engine
 * server/src/services/complianceEngine.js
 *
 * Implements Microsoft Intune-style Device Compliance policies, zero-trust security rule checks,
 * configurable grace periods, and conditional access non-compliance actions (Mark Non-Compliant,
 * Alert Only, Quarantine / Fleet Isolation).
 */

import crypto from 'node:crypto';

export class ComplianceEngine {
  /**
   * Get all compliance policies with summary evaluation statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getAllPolicies(db) {
    const policies = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM compliance_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.name ASC
    `).all();

    const evaluations = db.prepare(`
      SELECT 
        policy_id,
        COUNT(*) as total_evaluations,
        SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count,
        SUM(CASE WHEN compliance_status = 'IN_GRACE_PERIOD' THEN 1 ELSE 0 END) as in_grace_period_count,
        SUM(CASE WHEN compliance_status = 'NON_COMPLIANT' THEN 1 ELSE 0 END) as non_compliant_count,
        SUM(CASE WHEN compliance_status = 'ERROR' THEN 1 ELSE 0 END) as error_count
      FROM device_compliance_evaluations
      GROUP BY policy_id
    `).all();

    const evalMap = new Map();
    for (const ev of evaluations) {
      evalMap.set(ev.policy_id, ev);
    }

    return policies.map(p => {
      const stats = evalMap.get(p.id) || {
        total_evaluations: 0,
        compliant_count: 0,
        in_grace_period_count: 0,
        non_compliant_count: 0,
        error_count: 0
      };

      const complianceRate = stats.total_evaluations > 0
        ? Math.round((stats.compliant_count / stats.total_evaluations) * 100 * 10) / 10
        : 100.0;

      return {
        ...p,
        stats: {
          ...stats,
          compliance_rate_percent: complianceRate
        }
      };
    });
  }

  /**
   * Get detailed compliance policy by ID with device evaluations.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getPolicyById(db, id) {
    const policy = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM compliance_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.id = ?
    `).get(id);

    if (!policy) return null;

    const evals = db.prepare(`
      SELECT 
        e.*,
        d.hostname,
        d.friendly_name,
        d.primary_user,
        d.os_name,
        d.os_version,
        d.status as device_status
      FROM device_compliance_evaluations e
      JOIN devices d ON e.device_id = d.id
      WHERE e.policy_id = ?
      ORDER BY e.evaluated_at DESC
    `).all(id);

    const parsedEvals = evals.map(e => {
      let rules = [];
      try { rules = JSON.parse(e.rule_results_json || '[]'); } catch {}
      return {
        ...e,
        rule_results: rules
      };
    });

    const total = parsedEvals.length;
    const compliant = parsedEvals.filter(e => e.compliance_status === 'COMPLIANT').length;
    const inGrace = parsedEvals.filter(e => e.compliance_status === 'IN_GRACE_PERIOD').length;
    const nonCompliant = parsedEvals.filter(e => e.compliance_status === 'NON_COMPLIANT').length;

    return {
      ...policy,
      stats: {
        total_evaluations: total,
        compliant_count: compliant,
        in_grace_period_count: inGrace,
        non_compliant_count: nonCompliant,
        compliance_rate_percent: total > 0 ? Math.round((compliant / total) * 100 * 10) / 10 : 100.0
      },
      evaluations: parsedEvals
    };
  }

  /**
   * Create a new device compliance policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} payload
   * @returns {object}
   */
  createPolicy(db, payload) {
    const {
      name,
      description = '',
      target_group_id = 'grp-all',
      platform = 'Windows11',
      min_os_build = '10.0.22000',
      max_os_build = null,
      require_bitlocker = 1,
      require_secure_boot = 1,
      require_tpm = 1,
      require_defender_antivirus = 1,
      require_defender_rtp = 1,
      require_firewall = 1,
      max_antivirus_signature_age_days = 7,
      grace_period_days = 3,
      non_compliance_action = 'MARK_NON_COMPLIANT',
      is_enabled = 1
    } = payload;

    if (!name || !name.trim()) {
      throw new Error('Compliance policy name is required');
    }

    const id = `pol-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO compliance_policies (
        id, name, description, target_group_id, platform, min_os_build, max_os_build,
        require_bitlocker, require_secure_boot, require_tpm, require_defender_antivirus,
        require_defender_rtp, require_firewall, max_antivirus_signature_age_days,
        grace_period_days, non_compliance_action, is_enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `).run(
      id,
      name.trim(),
      description || '',
      target_group_id || 'grp-all',
      ['Windows11', 'Windows10', 'AllWindows'].includes(platform) ? platform : 'Windows11',
      min_os_build || '10.0.22000',
      max_os_build || null,
      require_bitlocker ? 1 : 0,
      require_secure_boot ? 1 : 0,
      require_tpm ? 1 : 0,
      require_defender_antivirus ? 1 : 0,
      require_defender_rtp ? 1 : 0,
      require_firewall ? 1 : 0,
      Math.max(1, Math.min(60, Number(max_antivirus_signature_age_days) || 7)),
      Math.max(0, Math.min(30, Number(grace_period_days) || 3)),
      ['MARK_NON_COMPLIANT', 'QUARANTINE', 'ALERT_ONLY'].includes(non_compliance_action) ? non_compliance_action : 'MARK_NON_COMPLIANT',
      is_enabled ? 1 : 0
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing compliance policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} updates
   * @returns {object|null}
   */
  updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM compliance_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name.trim() : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_group_id = updates.target_group_id !== undefined ? updates.target_group_id : existing.target_group_id;
    const platform = updates.platform !== undefined ? updates.platform : existing.platform;
    const min_os_build = updates.min_os_build !== undefined ? updates.min_os_build : existing.min_os_build;
    const max_os_build = updates.max_os_build !== undefined ? updates.max_os_build : existing.max_os_build;
    const require_bitlocker = updates.require_bitlocker !== undefined ? (updates.require_bitlocker ? 1 : 0) : existing.require_bitlocker;
    const require_secure_boot = updates.require_secure_boot !== undefined ? (updates.require_secure_boot ? 1 : 0) : existing.require_secure_boot;
    const require_tpm = updates.require_tpm !== undefined ? (updates.require_tpm ? 1 : 0) : existing.require_tpm;
    const require_defender_antivirus = updates.require_defender_antivirus !== undefined ? (updates.require_defender_antivirus ? 1 : 0) : existing.require_defender_antivirus;
    const require_defender_rtp = updates.require_defender_rtp !== undefined ? (updates.require_defender_rtp ? 1 : 0) : existing.require_defender_rtp;
    const require_firewall = updates.require_firewall !== undefined ? (updates.require_firewall ? 1 : 0) : existing.require_firewall;
    const max_antivirus_signature_age_days = updates.max_antivirus_signature_age_days !== undefined ? Number(updates.max_antivirus_signature_age_days) : existing.max_antivirus_signature_age_days;
    const grace_period_days = updates.grace_period_days !== undefined ? Number(updates.grace_period_days) : existing.grace_period_days;
    const non_compliance_action = updates.non_compliance_action !== undefined ? updates.non_compliance_action : existing.non_compliance_action;
    const is_enabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE compliance_policies SET
        name = ?, description = ?, target_group_id = ?, platform = ?,
        min_os_build = ?, max_os_build = ?, require_bitlocker = ?,
        require_secure_boot = ?, require_tpm = ?, require_defender_antivirus = ?,
        require_defender_rtp = ?, require_firewall = ?, max_antivirus_signature_age_days = ?,
        grace_period_days = ?, non_compliance_action = ?, is_enabled = ?,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_group_id, platform,
      min_os_build, max_os_build, require_bitlocker,
      require_secure_boot, require_tpm, require_defender_antivirus,
      require_defender_rtp, require_firewall, max_antivirus_signature_age_days,
      grace_period_days, non_compliance_action, is_enabled, id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete a compliance policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM compliance_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get applicable compliance policies for a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {Array<object>}
   */
  getPoliciesForDevice(db, deviceId) {
    const memberships = db.prepare(`
      SELECT group_id FROM group_memberships WHERE device_id = ?
    `).all(deviceId).map(r => r.group_id);

    const groupSet = new Set(['grp-all', ...memberships]);

    const allPolicies = db.prepare(`
      SELECT p.*, g.name as target_group_name
      FROM compliance_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.is_enabled = 1
      ORDER BY p.created_at ASC
    `).all();

    return allPolicies.filter(pol => {
      if (!pol.target_group_id || pol.target_group_id === 'grp-all') return true;
      return groupSet.has(pol.target_group_id);
    });
  }

  /**
   * Evaluate device telemetry against applicable compliance policies.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} telemetry
   * @returns {Array<object>}
   */
  evaluateDeviceCompliance(db, deviceId, telemetry = {}) {
    const applicablePolicies = this.getPoliciesForDevice(db, deviceId);
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    if (!device) return [];

    const results = [];
    let shouldQuarantine = false;
    let hasNonCompliant = false;

    for (const policy of applicablePolicies) {
      const ruleResults = [];

      // 1. Minimum OS Build
      if (policy.min_os_build) {
        const actualBuild = telemetry.os_build || device.os_build || '10.0.0';
        const buildPassed = this._compareBuilds(actualBuild, policy.min_os_build) >= 0;
        ruleResults.push({
          rule: 'min_os_build',
          name: 'Minimum Operating System Build',
          expected: policy.min_os_build,
          actual: actualBuild,
          passed: buildPassed,
          error: buildPassed ? null : `OS Build ${actualBuild} is below required ${policy.min_os_build}`
        });
      }

      // 2. BitLocker Drive Encryption
      if (policy.require_bitlocker === 1) {
        const blStatus = telemetry.bitlocker_status || device.bitlocker_status || 'Disabled';
        const blPassed = blStatus === 'FullyEncrypted';
        ruleResults.push({
          rule: 'require_bitlocker',
          name: 'BitLocker Volume Encryption',
          expected: 'FullyEncrypted',
          actual: blStatus,
          passed: blPassed,
          error: blPassed ? null : `BitLocker status is ${blStatus}`
        });
      }

      // 3. Secure Boot
      if (policy.require_secure_boot === 1) {
        const sb = telemetry.secure_boot_enabled !== undefined ? telemetry.secure_boot_enabled : device.secure_boot_enabled;
        const sbPassed = sb === 1 || sb === true;
        ruleResults.push({
          rule: 'require_secure_boot',
          name: 'UEFI Secure Boot Enabled',
          expected: true,
          actual: !!sbPassed,
          passed: sbPassed,
          error: sbPassed ? null : 'Secure Boot is disabled in firmware'
        });
      }

      // 4. TPM 2.0
      if (policy.require_tpm === 1) {
        const tpmPresent = telemetry.tpm_present !== undefined ? telemetry.tpm_present : device.tpm_present;
        const tpmEnabled = telemetry.tpm_enabled !== undefined ? telemetry.tpm_enabled : device.tpm_enabled;
        const tpmPassed = (tpmPresent === 1 || tpmPresent === true) && (tpmEnabled === 1 || tpmEnabled === true);
        ruleResults.push({
          rule: 'require_tpm',
          name: 'Trusted Platform Module (TPM 2.0)',
          expected: true,
          actual: !!tpmPassed,
          passed: tpmPassed,
          error: tpmPassed ? null : 'TPM is not present or not activated'
        });
      }

      // 5. Windows Defender Real-Time Protection
      if (policy.require_defender_rtp === 1) {
        const rtp = telemetry.defender_rtp_enabled !== undefined ? telemetry.defender_rtp_enabled : true;
        const rtpPassed = rtp === 1 || rtp === true;
        ruleResults.push({
          rule: 'require_defender_rtp',
          name: 'Microsoft Defender Real-Time Protection',
          expected: true,
          actual: !!rtpPassed,
          passed: rtpPassed,
          error: rtpPassed ? null : 'Defender Real-Time Protection is deactivated'
        });
      }

      // 6. Windows Firewall
      if (policy.require_firewall === 1) {
        const fw = telemetry.firewall_enabled !== undefined ? telemetry.firewall_enabled : true;
        const fwPassed = fw === 1 || fw === true;
        ruleResults.push({
          rule: 'require_firewall',
          name: 'Windows Defender Firewall Active',
          expected: true,
          actual: !!fwPassed,
          passed: fwPassed,
          error: fwPassed ? null : 'One or more Windows Firewall profiles are disabled'
        });
      }

      // Determine policy compliance state
      const isAllPassing = ruleResults.every(r => r.passed);
      const existingEval = db.prepare(`
        SELECT * FROM device_compliance_evaluations WHERE device_id = ? AND policy_id = ?
      `).get(deviceId, policy.id);

      let finalStatus = 'COMPLIANT';
      let firstFailedAt = null;
      let graceExpiresAt = null;

      if (isAllPassing) {
        finalStatus = 'COMPLIANT';
      } else {
        const now = new Date();
        const graceDays = policy.grace_period_days || 0;

        if (existingEval && existingEval.first_failed_at) {
          firstFailedAt = existingEval.first_failed_at;
          graceExpiresAt = existingEval.grace_period_expires_at;

          if (graceExpiresAt && new Date(graceExpiresAt) > now) {
            finalStatus = 'IN_GRACE_PERIOD';
          } else {
            finalStatus = 'NON_COMPLIANT';
          }
        } else {
          firstFailedAt = now.toISOString();
          if (graceDays > 0) {
            const exp = new Date(now.getTime() + graceDays * 86400000);
            graceExpiresAt = exp.toISOString();
            finalStatus = 'IN_GRACE_PERIOD';
          } else {
            graceExpiresAt = now.toISOString();
            finalStatus = 'NON_COMPLIANT';
          }
        }

        if (finalStatus === 'NON_COMPLIANT') {
          hasNonCompliant = true;
          if (policy.non_compliance_action === 'QUARANTINE') {
            shouldQuarantine = true;
          }
        }
      }

      const evalId = existingEval ? existingEval.id : `eval-${crypto.randomUUID().slice(0, 10)}`;
      db.prepare(`
        INSERT INTO device_compliance_evaluations (
          id, device_id, policy_id, compliance_status, first_failed_at,
          grace_period_expires_at, rule_results_json, evaluated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
        ON CONFLICT(device_id, policy_id) DO UPDATE SET
          compliance_status = excluded.compliance_status,
          first_failed_at = excluded.first_failed_at,
          grace_period_expires_at = excluded.grace_period_expires_at,
          rule_results_json = excluded.rule_results_json,
          evaluated_at = DATETIME('now')
      `).run(
        evalId,
        deviceId,
        policy.id,
        finalStatus,
        firstFailedAt,
        graceExpiresAt,
        JSON.stringify(ruleResults)
      );

      results.push({
        policy_id: policy.id,
        policy_name: policy.name,
        compliance_status: finalStatus,
        rules_evaluated: ruleResults.length,
        rules_passed: ruleResults.filter(r => r.passed).length,
        grace_period_expires_at: graceExpiresAt,
        rule_results: ruleResults
      });
    }

    // Update device status accordingly
    if (shouldQuarantine) {
      db.prepare("UPDATE devices SET status = 'quarantined', updated_at = DATETIME('now') WHERE id = ?").run(deviceId);
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, created_at
        ) VALUES (?, 'POLICY_DRIFT', 9001, 'ComplianceEngine', 'CRITICAL', ?, ?, DATETIME('now'))
      `).run(
        deviceId,
        `Device ${device.hostname} quarantined due to critical non-compliance breach`,
        JSON.stringify({ reason: 'Failed compliance policy with quarantine action', device_id: deviceId })
      );
    } else if (hasNonCompliant && device.status !== 'quarantined') {
      db.prepare("UPDATE devices SET status = 'drifted', updated_at = DATETIME('now') WHERE id = ?").run(deviceId);
    } else if (!hasNonCompliant && device.status === 'drifted') {
      db.prepare("UPDATE devices SET status = 'online', updated_at = DATETIME('now') WHERE id = ?").run(deviceId);
    }

    return results;
  }

  /**
   * Aggregate fleet-wide device compliance metrics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getFleetComplianceStats(db) {
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM compliance_policies').get()?.count || 0;
    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get()?.count || 0;

    const monitored = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count FROM device_compliance_evaluations
    `).get()?.count || 0;

    const nonCompliantDevs = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count 
      FROM device_compliance_evaluations 
      WHERE compliance_status = 'NON_COMPLIANT'
    `).get()?.count || 0;

    const inGraceDevs = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count 
      FROM device_compliance_evaluations 
      WHERE compliance_status = 'IN_GRACE_PERIOD' 
      AND device_id NOT IN (
        SELECT device_id FROM device_compliance_evaluations WHERE compliance_status = 'NON_COMPLIANT'
      )
    `).get()?.count || 0;

    const compliantDevs = Math.max(0, monitored - nonCompliantDevs - inGraceDevs);
    const complianceRate = monitored > 0
      ? Math.round((compliantDevs / monitored) * 100 * 10) / 10
      : 100.0;

    const quarantinedCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get()?.count || 0;

    return {
      total_policies: totalPolicies,
      total_devices: totalDevices,
      monitored_devices: monitored,
      compliant_devices: compliantDevs,
      in_grace_period_devices: inGraceDevs,
      non_compliant_devices: nonCompliantDevs,
      quarantined_devices: quarantinedCount,
      compliance_rate_percent: complianceRate
    };
  }

  /**
   * Helper to compare build strings (e.g. "10.0.22631" vs "10.0.22000").
   * @private
   */
  _compareBuilds(a, b) {
    const partsA = (a || '').split('.').map(Number);
    const partsB = (b || '').split('.').map(Number);
    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
      const valA = partsA[i] || 0;
      const valB = partsB[i] || 0;
      if (valA > valB) return 1;
      if (valA < valB) return -1;
    }
    return 0;
  }
}

export const complianceEngine = new ComplianceEngine();
export default complianceEngine;
