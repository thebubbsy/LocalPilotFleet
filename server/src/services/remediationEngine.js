/**
 * LocalPilot Fleet — Proactive Remediation Engine
 * server/src/services/remediationEngine.js
 */

import crypto from 'node:crypto';

export class RemediationEngine {
  /**
   * Get all enabled remediations targeting a specific device.
   * Matches on grp-all or any group the device is currently a member of.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {Array<object>}
   */
  getRemediationsForDevice(db, deviceId) {
    const memberships = db.prepare(`
      SELECT group_id FROM group_memberships WHERE device_id = ?
    `).all(deviceId).map(r => r.group_id);

    const groupSet = new Set(['grp-all', ...memberships]);
    const allRemediations = db.prepare(`
      SELECT r.*, g.name as target_group_name
      FROM remediations r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      WHERE r.is_enabled = 1
      ORDER BY r.name ASC
    `).all();

    return allRemediations.filter(rem => {
      if (!rem.target_group_id || rem.target_group_id === 'grp-all') return true;
      return groupSet.has(rem.target_group_id);
    });
  }

  /**
   * Record a remediation execution run reported by a node agent.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} payload
   * @returns {object}
   */
  recordRemediationRun(db, payload) {
    const {
      remediation_id,
      device_id,
      detection_exit_code = 0,
      detection_stdout = '',
      detection_stderr = '',
      remediation_exit_code = null,
      remediation_stdout = null,
      remediation_stderr = null
    } = payload;

    const runId = payload.id || `run_${crypto.randomUUID()}`;

    // Determine detection status
    const detCode = Number(detection_exit_code);
    const detection_status = detCode === 0 ? 'NO_ISSUE' : 'ISSUE_DETECTED';

    // Determine remediation status
    let remediation_status = 'NOT_NEEDED';
    if (detection_status === 'ISSUE_DETECTED') {
      if (remediation_exit_code !== null && remediation_exit_code !== undefined) {
        const remCode = Number(remediation_exit_code);
        remediation_status = remCode === 0 ? 'REMEDIATED' : 'FAILED';
      } else {
        remediation_status = 'FAILED';
      }
    }

    db.prepare(`
      INSERT INTO remediation_runs (
        id, remediation_id, device_id, detection_exit_code, detection_stdout, detection_stderr,
        detection_status, remediation_exit_code, remediation_stdout, remediation_stderr,
        remediation_status, executed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `).run(
      runId,
      remediation_id,
      device_id,
      detCode,
      detection_stdout || '',
      detection_stderr || '',
      detection_status,
      remediation_exit_code !== null ? Number(remediation_exit_code) : null,
      remediation_stdout !== null ? String(remediation_stdout) : null,
      remediation_stderr !== null ? String(remediation_stderr) : null,
      remediation_status
    );

    return {
      run_id: runId,
      remediation_id,
      device_id,
      detection_status,
      remediation_status
    };
  }

  /**
   * Aggregate fleet-wide proactive remediation health metrics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getFleetRemediationStats(db) {
    const totalPackages = db.prepare('SELECT COUNT(*) as count FROM remediations WHERE is_enabled = 1').get()?.count || 0;
    const totalRuns = db.prepare('SELECT COUNT(*) as count FROM remediation_runs').get()?.count || 0;
    const evaluatedDevices = db.prepare('SELECT COUNT(DISTINCT device_id) as count FROM remediation_runs').get()?.count || 0;

    const issuesDetected = db.prepare("SELECT COUNT(*) as count FROM remediation_runs WHERE detection_status = 'ISSUE_DETECTED'").get()?.count || 0;
    const remediated = db.prepare("SELECT COUNT(*) as count FROM remediation_runs WHERE remediation_status = 'REMEDIATED'").get()?.count || 0;
    const failed = db.prepare("SELECT COUNT(*) as count FROM remediation_runs WHERE remediation_status = 'FAILED'").get()?.count || 0;
    const healthy = db.prepare("SELECT COUNT(*) as count FROM remediation_runs WHERE detection_status = 'NO_ISSUE'").get()?.count || 0;

    const healingRate = issuesDetected > 0
      ? Math.round((remediated / issuesDetected) * 100 * 10) / 10
      : 100.0;

    return {
      total_packages: totalPackages,
      total_runs: totalRuns,
      evaluated_devices: evaluatedDevices,
      healthy_runs: healthy,
      issues_detected: issuesDetected,
      issues_remediated: remediated,
      remediations_failed: failed,
      self_healing_rate_pct: healingRate
    };
  }

  /**
   * List all remediation packages with enriched execution statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  listRemediations(db) {
    const packages = db.prepare(`
      SELECT r.*, g.name as target_group_name, g.color as target_group_color
      FROM remediations r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      ORDER BY r.created_at DESC
    `).all();

    return packages.map(pkg => {
      const stats = db.prepare(`
        SELECT
          COUNT(*) as total_runs,
          SUM(CASE WHEN detection_status = 'NO_ISSUE' THEN 1 ELSE 0 END) as no_issue_count,
          SUM(CASE WHEN detection_status = 'ISSUE_DETECTED' THEN 1 ELSE 0 END) as issue_detected_count,
          SUM(CASE WHEN remediation_status = 'REMEDIATED' THEN 1 ELSE 0 END) as remediated_count,
          SUM(CASE WHEN remediation_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
          MAX(executed_at) as last_run_at
        FROM remediation_runs
        WHERE remediation_id = ?
      `).get(pkg.id);

      return {
        ...pkg,
        is_enabled: Boolean(pkg.is_enabled),
        stats: {
          total_runs: stats?.total_runs || 0,
          no_issue_count: stats?.no_issue_count || 0,
          issue_detected_count: stats?.issue_detected_count || 0,
          remediated_count: stats?.remediated_count || 0,
          failed_count: stats?.failed_count || 0,
          last_run_at: stats?.last_run_at || null
        }
      };
    });
  }

  /**
   * Get detailed view of a single remediation package, including per-device run history.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getRemediationDetails(db, id) {
    const pkg = db.prepare(`
      SELECT r.*, g.name as target_group_name, g.color as target_group_color
      FROM remediations r
      LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
      WHERE r.id = ?
    `).get(id);

    if (!pkg) return null;

    const runs = db.prepare(`
      SELECT
        rr.*,
        d.hostname,
        d.friendly_name,
        d.primary_user
      FROM remediation_runs rr
      JOIN devices d ON rr.device_id = d.id
      WHERE rr.remediation_id = ?
      ORDER BY rr.executed_at DESC
      LIMIT 50
    `).all(id);

    return {
      ...pkg,
      is_enabled: Boolean(pkg.is_enabled),
      runs
    };
  }
}

export const remediationEngine = new RemediationEngine();
export default remediationEngine;
