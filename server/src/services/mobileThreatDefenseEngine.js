/**
 * LocalPilot Fleet — Mobile Threat Defense (MTD) & Risk Posture Engine (Iteration 69)
 * server/src/services/mobileThreatDefenseEngine.js
 *
 * Implements real-time OS-level threat signal ingestion (jailbreak / root detection,
 * SELinux permissive mode, SIP tampering, sideloaded app analysis), dynamic device
 * risk scoring, compliance policy evaluation, and automated remediation orchestration.
 */

import crypto from 'node:crypto';

export class MobileThreatDefenseEngine {

  /**
   * Aggregate fleet-wide MTD security metrics and threat levels
   */
  static getMtdStats(db) {
    if (!db) return {};

    const totalSignals = db.prepare('SELECT COUNT(*) as count FROM mtd_device_threat_signals').get()?.count || 0;
    const activeSignals = db.prepare("SELECT COUNT(*) as count FROM mtd_device_threat_signals WHERE status = 'ACTIVE'").get()?.count || 0;
    const criticalSignals = db.prepare("SELECT COUNT(*) as count FROM mtd_device_threat_signals WHERE status = 'ACTIVE' AND threat_level = 'CRITICAL'").get()?.count || 0;
    const highSignals = db.prepare("SELECT COUNT(*) as count FROM mtd_device_threat_signals WHERE status = 'ACTIVE' AND threat_level = 'HIGH'").get()?.count || 0;
    const mitigatedSignals = db.prepare("SELECT COUNT(*) as count FROM mtd_device_threat_signals WHERE status IN ('MITIGATED', 'RESOLVED')").get()?.count || 0;

    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM mtd_risk_compliance_policies').get()?.count || 0;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM mtd_risk_compliance_policies WHERE is_active = 1').get()?.count || 0;
    const totalRemediations = db.prepare('SELECT COUNT(*) as count FROM mtd_remediation_actions').get()?.count || 0;

    const quarantinedRow = db.prepare("SELECT COUNT(DISTINCT device_id) as count FROM mtd_device_threat_signals WHERE status = 'ACTIVE' AND threat_level IN ('CRITICAL', 'HIGH')").get();
    const quarantinedDevices = quarantinedRow?.count || 0;

    return {
      total_threat_signals: totalSignals,
      active_threat_signals: activeSignals,
      critical_threat_signals: criticalSignals,
      high_threat_signals: highSignals,
      mitigated_threat_signals: mitigatedSignals,
      total_policies: totalPolicies,
      active_policies: activePolicies,
      total_remediations: totalRemediations,
      quarantined_devices: quarantinedDevices,
      calculated_at: new Date().toISOString()
    };
  }

  /**
   * List threat signals with optional filtering
   */
  static getThreatSignals(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM mtd_device_threat_signals WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }

    if (query.signal_type) {
      sql += ' AND signal_type = ?';
      params.push(query.signal_type.toUpperCase());
    }

    if (query.threat_level) {
      sql += ' AND threat_level = ?';
      params.push(query.threat_level.toUpperCase());
    }

    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status.toUpperCase());
    }

    sql += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(Number(query.limit) || 100);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => this._hydrateSignal(r));
  }

  /**
   * Get single threat signal
   */
  static getSignal(db, id) {
    if (!db || !id) return null;
    const row = db.prepare('SELECT * FROM mtd_device_threat_signals WHERE id = ?').get(id);
    return row ? this._hydrateSignal(row) : null;
  }

  /**
   * Ingest new threat signal and evaluate compliance policies for auto-remediation
   */
  static ingestThreatSignal(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.device_id) throw new Error('device_id is required');
    if (!data.signal_type) throw new Error('signal_type is required');
    if (!data.threat_level) throw new Error('threat_level is required');

    const id = data.id || ('mtd-sig-' + crypto.randomBytes(4).toString('hex'));
    const sigType = data.signal_type.toUpperCase();
    const threatLevel = data.threat_level.toUpperCase();
    const engine = data.detection_engine || 'LOCALPILOT_NATIVE';
    const details = typeof data.threat_details === 'object' 
      ? JSON.stringify(data.threat_details) 
      : (data.threat_details_json || '{}');

    const stmt = db.prepare(`
      INSERT INTO mtd_device_threat_signals (
        id, device_id, signal_type, threat_level, detection_engine,
        threat_details_json, status, detected_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', DATETIME('now'))
    `);

    stmt.run(id, data.device_id, sigType, threatLevel, engine, details);

    const signal = this.getSignal(db, id);

    // Evaluate compliance policies against newly ingested threat
    const deviceRisk = this.calculateDeviceRiskScore(db, data.device_id);
    const triggeredRemediation = this._checkPolicyViolationsAndRemediate(db, data.device_id, signal, deviceRisk.risk_level);

    return {
      signal,
      risk_evaluation: deviceRisk,
      remediation_triggered: Boolean(triggeredRemediation),
      remediation: triggeredRemediation
    };
  }

  /**
   * Resolve / Mitigate a Threat Signal
   */
  static resolveThreatSignal(db, id, notes = 'Threat mitigated by administrator or clean scan') {
    if (!db || !id) return null;

    const signal = this.getSignal(db, id);
    if (!signal) return null;

    const details = {
      ...signal.threat_details,
      resolution_notes: notes,
      resolved_timestamp: new Date().toISOString()
    };

    const stmt = db.prepare(`
      UPDATE mtd_device_threat_signals SET
        status = 'RESOLVED',
        resolved_at = DATETIME('now'),
        threat_details_json = ?
      WHERE id = ?
    `);

    stmt.run(JSON.stringify(details), id);
    return this.getSignal(db, id);
  }

  /**
   * Calculate aggregated real-time Device Risk Score
   */
  static calculateDeviceRiskScore(db, deviceId) {
    if (!db || !deviceId) return { device_id: deviceId, risk_level: 'SECURE', active_signals_count: 0, signals: [] };

    const activeSignals = this.getThreatSignals(db, { device_id: deviceId, status: 'ACTIVE' });

    let riskLevel = 'SECURE';
    if (activeSignals.some(s => s.threat_level === 'CRITICAL')) {
      riskLevel = 'CRITICAL';
    } else if (activeSignals.some(s => s.threat_level === 'HIGH')) {
      riskLevel = 'HIGH';
    } else if (activeSignals.some(s => s.threat_level === 'MEDIUM')) {
      riskLevel = 'MEDIUM';
    } else if (activeSignals.some(s => s.threat_level === 'LOW')) {
      riskLevel = 'LOW';
    }

    return {
      device_id: deviceId,
      risk_level: riskLevel,
      active_signals_count: activeSignals.length,
      signals: activeSignals
    };
  }

  /**
   * List MTD Risk Compliance Policies
   */
  static getPolicies(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM mtd_risk_compliance_policies WHERE 1=1';
    const params = [];

    if (query.target_platform) {
      sql += " AND (target_platform = ? OR target_platform = 'COMBINED')";
      params.push(query.target_platform.toUpperCase());
    }

    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(Number(query.is_active));
    }

    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => ({
      ...r,
      is_active: Boolean(r.is_active)
    }));
  }

  /**
   * Get single policy by ID
   */
  static getPolicy(db, id) {
    if (!db || !id) return null;
    const r = db.prepare('SELECT * FROM mtd_risk_compliance_policies WHERE id = ?').get(id);
    return r ? { ...r, is_active: Boolean(r.is_active) } : null;
  }

  /**
   * Create MTD Compliance Policy
   */
  static createPolicy(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.name) throw new Error('Policy name is required');

    const id = data.id || ('mtd-pol-' + crypto.randomBytes(4).toString('hex'));
    const maxRisk = (data.max_allowed_risk_level || 'LOW').toUpperCase();
    const platform = (data.target_platform || 'COMBINED').toUpperCase();
    const action = (data.auto_remediation_action || 'BLOCK_ACCESS').toUpperCase();

    const stmt = db.prepare(`
      INSERT INTO mtd_risk_compliance_policies (
        id, name, max_allowed_risk_level, target_platform, auto_remediation_action, is_active
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      maxRisk,
      platform,
      action,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return this.getPolicy(db, id);
  }

  /**
   * Delete MTD Compliance Policy
   */
  static deletePolicy(db, id) {
    if (!db || !id) return false;
    const res = db.prepare('DELETE FROM mtd_risk_compliance_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * List Remediation Actions
   */
  static getRemediations(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT r.*, p.name as policy_name FROM mtd_remediation_actions r LEFT JOIN mtd_risk_compliance_policies p ON r.policy_id = p.id WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND r.device_id = ?';
      params.push(query.device_id);
    }

    if (query.status) {
      sql += ' AND r.status = ?';
      params.push(query.status.toUpperCase());
    }

    sql += ' ORDER BY r.executed_at DESC LIMIT ?';
    params.push(Number(query.limit) || 100);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      action_details: JSON.parse(r.action_details_json || '{}')
    }));
  }

  /**
   * Dispatch manual or automated remediation action
   */
  static dispatchRemediation(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.device_id) throw new Error('device_id is required');
    if (!data.action_type) throw new Error('action_type is required');

    const id = data.id || ('mtd-rem-' + crypto.randomBytes(4).toString('hex'));
    const actionType = data.action_type.toUpperCase();
    const status = data.status || 'EXECUTED';
    const details = typeof data.action_details === 'object'
      ? JSON.stringify(data.action_details)
      : (data.action_details_json || '{}');

    const stmt = db.prepare(`
      INSERT INTO mtd_remediation_actions (
        id, device_id, signal_id, policy_id, action_type, status, action_details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.device_id,
      data.signal_id || null,
      data.policy_id || null,
      actionType,
      status,
      details
    );

    return db.prepare('SELECT * FROM mtd_remediation_actions WHERE id = ?').get(id);
  }

  /**
   * Comprehensive Posture Evaluation for mobile / desktop client beacons
   */
  static evaluateDevicePosture(db, deviceId, posture = {}) {
    if (!db || !deviceId) throw new Error('Database and deviceId required');

    const violations = [];

    // 1. Check Jailbreak / Root
    if (posture.is_jailbroken || posture.is_rooted) {
      const sigType = posture.is_jailbroken ? 'JAILBREAK_DETECTED' : 'ROOT_DETECTED';
      violations.push(this.ingestThreatSignal(db, {
        device_id: deviceId,
        signal_type: sigType,
        threat_level: 'CRITICAL',
        threat_details: {
          indicator: posture.detection_indicator || 'Binary su/Cydia hooks detected',
          client_reported: true
        }
      }));
    }

    // 2. Check SELinux Permissive Mode
    if (posture.selinux_mode === 'PERMISSIVE') {
      violations.push(this.ingestThreatSignal(db, {
        device_id: deviceId,
        signal_type: 'SELINUX_PERMISSIVE',
        threat_level: 'HIGH',
        threat_details: { description: 'SELinux disabled or set to permissive' }
      }));
    }

    // 3. Check System Integrity Protection (SIP)
    if (posture.sip_enabled === false) {
      violations.push(this.ingestThreatSignal(db, {
        device_id: deviceId,
        signal_type: 'SYSTEM_INTEGRITY_DISABLED',
        threat_level: 'HIGH',
        threat_details: { description: 'Apple macOS System Integrity Protection disabled via csrutil' }
      }));
    }

    // 4. Check Sideloaded / Unknown Apps
    if (Array.isArray(posture.sideloaded_apps) && posture.sideloaded_apps.length > 0) {
      violations.push(this.ingestThreatSignal(db, {
        device_id: deviceId,
        signal_type: 'SIDELOADED_APP',
        threat_level: 'MEDIUM',
        threat_details: { packages: posture.sideloaded_apps }
      }));
    }

    const currentRisk = this.calculateDeviceRiskScore(db, deviceId);
    const compliant = currentRisk.risk_level === 'SECURE' || currentRisk.risk_level === 'LOW';

    return {
      device_id: deviceId,
      compliant,
      risk_level: currentRisk.risk_level,
      active_signals_count: currentRisk.active_signals_count,
      violations: violations.map(v => v.signal)
    };
  }

  /**
   * Internal helper to evaluate compliance policies against a threat signal
   */
  static _checkPolicyViolationsAndRemediate(db, deviceId, signal, currentRiskLevel) {
    const riskRanks = { SECURE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    const deviceRank = riskRanks[currentRiskLevel] || 0;

    const policies = this.getPolicies(db, { is_active: 1 });

    for (const pol of policies) {
      const maxRank = riskRanks[pol.max_allowed_risk_level] || 1;
      if (deviceRank > maxRank) {
        // Policy violation detected -> trigger automated remediation action
        return this.dispatchRemediation(db, {
          device_id: deviceId,
          signal_id: signal.id,
          policy_id: pol.id,
          action_type: pol.auto_remediation_action,
          action_details: {
            triggered_by_signal: signal.signal_type,
            threat_level: signal.threat_level,
            device_risk_level: currentRiskLevel,
            policy_name: pol.name
          }
        });
      }
    }

    return null;
  }

  /**
   * Internal helper to hydrate signal JSON details
   */
  static _hydrateSignal(r) {
    return {
      ...r,
      threat_details: JSON.parse(r.threat_details_json || '{}')
    };
  }
}
