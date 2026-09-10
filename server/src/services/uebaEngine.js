/**
 * LocalPilot Fleet — User & Entity Behavior Analytics (UEBA) & Insider Risk Intelligence Engine
 * server/src/services/uebaEngine.js
 *
 * Implements Microsoft Purview Insider Risk Management & CrowdStrike Falcon UEBA equivalent
 * anomalous behavior detection, dynamic composite risk scoring (0-100), flight-risk tracking,
 * and automated endpoint containment (Restricted USB/Clipboard, Session Revocation).
 */

import crypto from 'node:crypto';

export class UebaEngine {
  /**
   * Aggregate fleet-wide UEBA metrics
   */
  static getUebaStats(db) {
    const totalIndicators = db.prepare('SELECT COUNT(*) as count FROM ueba_risk_indicators').get()?.count || 0;
    const activeIndicators = db.prepare('SELECT COUNT(*) as count FROM ueba_risk_indicators WHERE is_active = 1').get()?.count || 0;

    const totalAnomalies = db.prepare('SELECT COUNT(*) as count FROM ueba_user_behavior_anomalies').get()?.count || 0;
    const openAnomalies = db.prepare("SELECT COUNT(*) as count FROM ueba_user_behavior_anomalies WHERE status = 'OPEN'").get()?.count || 0;

    const highRiskUsersCount = db.prepare("SELECT COUNT(*) as count FROM ueba_user_risk_profiles WHERE risk_level IN ('HIGH', 'CRITICAL')").get()?.count || 0;
    const flightRiskUsersCount = db.prepare('SELECT COUNT(*) as count FROM ueba_user_risk_profiles WHERE flight_risk_flag = 1').get()?.count || 0;

    const avgScoreRow = db.prepare('SELECT AVG(composite_risk_score) as avgScore FROM ueba_user_risk_profiles').get();
    const meanUserRiskScore = avgScoreRow?.avgScore ? Math.round(avgScoreRow.avgScore * 10) / 10 : 0.0;

    return {
      totalIndicators,
      activeIndicators,
      totalAnomalies,
      openAnomalies,
      highRiskUsersCount,
      flightRiskUsersCount,
      meanUserRiskScore,
      uebaOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve risk indicator catalog
   */
  static getRiskIndicators(db, query = {}) {
    let sql = 'SELECT * FROM ueba_risk_indicators WHERE 1=1';
    const params = [];

    if (query.category) {
      sql += ' AND category = ?';
      params.push(query.category);
    }
    if (query.severity) {
      sql += ' AND severity = ?';
      params.push(query.severity);
    }
    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    sql += ' ORDER BY risk_weight DESC, indicator_name ASC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Retrieve single risk indicator
   */
  static getRiskIndicatorById(db, id) {
    return db.prepare('SELECT * FROM ueba_risk_indicators WHERE id = ?').get(id) || null;
  }

  /**
   * Create risk indicator
   */
  static createRiskIndicator(db, data) {
    const id = data.id || ('uri-' + crypto.randomBytes(4).toString('hex'));
    const stmt = db.prepare(`
      INSERT INTO ueba_risk_indicators (
        id, indicator_name, category, description, risk_weight, threshold_value, severity, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.indicator_name.toUpperCase(),
      data.category,
      data.description || '',
      data.risk_weight || 15,
      data.threshold_value || 3.0,
      data.severity || 'MEDIUM',
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return this.getRiskIndicatorById(db, id);
  }

  /**
   * Update risk indicator
   */
  static updateRiskIndicator(db, id, data) {
    const existing = this.getRiskIndicatorById(db, id);
    if (!existing) return null;

    const updated = {
      description: data.description !== undefined ? data.description : existing.description,
      risk_weight: data.risk_weight !== undefined ? data.risk_weight : existing.risk_weight,
      threshold_value: data.threshold_value !== undefined ? data.threshold_value : existing.threshold_value,
      severity: data.severity !== undefined ? data.severity : existing.severity,
      is_active: data.is_active !== undefined ? (data.is_active ? 1 : 0) : existing.is_active
    };

    db.prepare(`
      UPDATE ueba_risk_indicators SET
        description = ?, risk_weight = ?, threshold_value = ?, severity = ?, is_active = ?
      WHERE id = ?
    `).run(updated.description, updated.risk_weight, updated.threshold_value, updated.severity, updated.is_active, id);

    return this.getRiskIndicatorById(db, id);
  }

  /**
   * Delete risk indicator
   */
  static deleteRiskIndicator(db, id) {
    const res = db.prepare('DELETE FROM ueba_risk_indicators WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Retrieve behavior anomalies with optional filtering
   */
  static getBehaviorAnomalies(db, query = {}) {
    let sql = 'SELECT * FROM ueba_user_behavior_anomalies WHERE 1=1';
    const params = [];

    if (query.user_principal) {
      sql += ' AND user_principal = ?';
      params.push(query.user_principal);
    }
    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status);
    }

    sql += ' ORDER BY detected_at DESC';
    const rows = db.prepare(sql).all(...params);
    return rows.map(r => {
      let details = {};
      try { details = JSON.parse(r.details_json || '{}'); } catch {}
      return { ...r, details };
    });
  }

  /**
   * Record behavior anomaly and recalculate user risk score
   */
  static recordBehaviorAnomaly(db, data) {
    const id = data.id || ('uuba-' + crypto.randomBytes(4).toString('hex'));
    const deviationScore = data.deviation_score || (
      data.baseline_value > 0 ? Math.round((data.observed_value / data.baseline_value) * 10) / 10 : 1.0
    );

    const detailsJson = typeof data.details === 'string' ?
      data.details : JSON.stringify(data.details || {});

    const stmt = db.prepare(`
      INSERT INTO ueba_user_behavior_anomalies (
        id, user_principal, device_id, hostname, indicator_id, anomaly_type,
        observed_value, baseline_value, deviation_score, status, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.user_principal.toLowerCase(),
      data.device_id,
      data.hostname,
      data.indicator_id,
      data.anomaly_type,
      data.observed_value || 0.0,
      data.baseline_value || 0.0,
      deviationScore,
      data.status || 'OPEN',
      detailsJson
    );

    // Recalculate user risk profile
    this.recalculateUserRisk(db, data.user_principal.toLowerCase());

    return db.prepare('SELECT * FROM ueba_user_behavior_anomalies WHERE id = ?').get(id);
  }

  /**
   * Transition anomaly investigation status
   */
  static updateAnomalyStatus(db, id, status, notes = '') {
    const existing = db.prepare('SELECT * FROM ueba_user_behavior_anomalies WHERE id = ?').get(id);
    if (!existing) return null;

    db.prepare('UPDATE ueba_user_behavior_anomalies SET status = ? WHERE id = ?').run(status, id);

    // Recalculate user profile
    this.recalculateUserRisk(db, existing.user_principal);

    return db.prepare('SELECT * FROM ueba_user_behavior_anomalies WHERE id = ?').get(id);
  }

  /**
   * Recalculate composite user risk score based on open anomalies and weights
   */
  static recalculateUserRisk(db, userPrincipal) {
    const anomalies = db.prepare(`
      SELECT a.*, i.risk_weight, i.severity, i.category
      FROM ueba_user_behavior_anomalies a
      LEFT JOIN ueba_risk_indicators i ON a.indicator_id = i.id
      WHERE a.user_principal = ? AND a.status IN ('OPEN', 'INVESTIGATING')
    `).all(userPrincipal);

    let compositeScore = 0;
    let hasFlightRisk = 0;

    for (const a of anomalies) {
      const weight = a.risk_weight || 15;
      const factor = Math.min(Math.max(a.deviation_score || 1.0, 1.0), 3.0);
      compositeScore += Math.round(weight * factor);
      if (a.category === 'FLIGHT_RISK') hasFlightRisk = 1;
    }

    compositeScore = Math.min(compositeScore, 100);

    let riskLevel = 'LOW';
    if (compositeScore >= 80) riskLevel = 'CRITICAL';
    else if (compositeScore >= 60) riskLevel = 'HIGH';
    else if (compositeScore >= 30) riskLevel = 'MEDIUM';

    const existing = db.prepare('SELECT * FROM ueba_user_risk_profiles WHERE user_principal = ?').get(userPrincipal);

    if (existing) {
      db.prepare(`
        UPDATE ueba_user_risk_profiles SET
          composite_risk_score = ?, risk_level = ?, flight_risk_flag = ?,
          anomalies_count = ?, last_assessed_at = DATETIME('now')
        WHERE user_principal = ?
      `).run(compositeScore, riskLevel, hasFlightRisk, anomalies.length, userPrincipal);
    } else {
      const id = 'uurp-' + crypto.randomBytes(4).toString('hex');
      const parts = userPrincipal.split('@')[0].split('.');
      const displayName = parts.map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(' ');

      db.prepare(`
        INSERT INTO ueba_user_risk_profiles (
          id, user_principal, display_name, department, composite_risk_score,
          risk_level, flight_risk_flag, containment_status, anomalies_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, userPrincipal, displayName, 'General Fleet', compositeScore,
        riskLevel, hasFlightRisk, 'MONITORED', anomalies.length
      );
    }

    return db.prepare('SELECT * FROM ueba_user_risk_profiles WHERE user_principal = ?').get(userPrincipal);
  }

  /**
   * Query user risk profiles
   */
  static getUserRiskProfiles(db, query = {}) {
    let sql = 'SELECT * FROM ueba_user_risk_profiles WHERE 1=1';
    const params = [];

    if (query.risk_level) {
      sql += ' AND risk_level = ?';
      params.push(query.risk_level);
    }
    if (query.flight_risk !== undefined) {
      sql += ' AND flight_risk_flag = ?';
      params.push(query.flight_risk ? 1 : 0);
    }
    if (query.containment_status) {
      sql += ' AND containment_status = ?';
      params.push(query.containment_status);
    }

    sql += ' ORDER BY composite_risk_score DESC, anomalies_count DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Get single user risk profile with anomaly history
   */
  static getUserRiskProfile(db, userPrincipal) {
    const profile = db.prepare('SELECT * FROM ueba_user_risk_profiles WHERE user_principal = ?').get(userPrincipal);
    if (!profile) return null;

    const anomalies = this.getBehaviorAnomalies(db, { user_principal: userPrincipal });
    return {
      ...profile,
      anomalies
    };
  }

  /**
   * Update containment state for a user (MONITORED, RESTRICTED, CONTAINED, REVOKED)
   */
  static updateUserContainment(db, userPrincipal, containmentStatus) {
    const existing = db.prepare('SELECT id FROM ueba_user_risk_profiles WHERE user_principal = ?').get(userPrincipal);
    if (!existing) return null;

    db.prepare(`
      UPDATE ueba_user_risk_profiles SET
        containment_status = ?, last_assessed_at = DATETIME('now')
      WHERE user_principal = ?
    `).run(containmentStatus, userPrincipal);

    return this.getUserRiskProfile(db, userPrincipal);
  }
}
