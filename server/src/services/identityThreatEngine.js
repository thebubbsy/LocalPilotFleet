/**
 * LocalPilot Fleet — Identity Threat Detection & Response (ITDR & Credential Defense Engine)
 * server/src/services/identityThreatEngine.js
 *
 * Implements Microsoft Defender for Identity (MDI) & CrowdStrike Falcon Identity equivalent
 * credential defense, Active Directory Kerberoasting / AS-REP roasting detection,
 * honeytoken tripwires, LSASS memory scraping protection, and automated account containment.
 */

import crypto from 'node:crypto';

export class IdentityThreatEngine {
  /**
   * Aggregate fleet-wide ITDR exposure and attack metrics
   */
  static getItdrStats(db) {
    const totalDetections = db.prepare('SELECT COUNT(*) as count FROM identity_threat_detections').get()?.count || 0;
    const activeDetections = db.prepare("SELECT COUNT(*) as count FROM identity_threat_detections WHERE status IN ('NEW', 'INVESTIGATING')").get()?.count || 0;
    const criticalRiskDetections = db.prepare('SELECT COUNT(*) as count FROM identity_threat_detections WHERE risk_score >= 90.0').get()?.count || 0;

    const totalHoneytokens = db.prepare('SELECT COUNT(*) as count FROM identity_honeytokens_catalog').get()?.count || 0;
    const activeHoneytokens = db.prepare('SELECT COUNT(*) as count FROM identity_honeytokens_catalog WHERE is_active = 1').get()?.count || 0;
    const triggeredHoneytokens = db.prepare('SELECT COUNT(*) as count FROM identity_honeytokens_catalog WHERE trigger_count > 0').get()?.count || 0;

    const totalAssessedAccounts = db.prepare('SELECT COUNT(*) as count FROM identity_account_risk_scores').get()?.count || 0;
    const highRiskAccounts = db.prepare("SELECT COUNT(*) as count FROM identity_account_risk_scores WHERE risk_level IN ('HIGH', 'CRITICAL')").get()?.count || 0;
    const containedAccounts = db.prepare("SELECT COUNT(*) as count FROM identity_account_risk_scores WHERE containment_status != 'NORMAL'").get()?.count || 0;

    return {
      totalDetections,
      activeDetections,
      criticalRiskDetections,
      totalHoneytokens,
      activeHoneytokens,
      triggeredHoneytokens,
      totalAssessedAccounts,
      highRiskAccounts,
      containedAccounts,
      itdrOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve identity threat detections with filters
   */
  static getDetections(db, query = {}) {
    let sql = 'SELECT * FROM identity_threat_detections WHERE 1=1';
    const params = [];

    if (query.attack_vector) {
      sql += ' AND attack_vector = ?';
      params.push(query.attack_vector);
    }
    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status);
    }
    if (query.target_account) {
      sql += ' AND target_account = ?';
      params.push(query.target_account);
    }
    if (query.source_host) {
      sql += ' AND source_host = ?';
      params.push(query.source_host);
    }
    if (query.min_risk) {
      sql += ' AND risk_score >= ?';
      params.push(parseFloat(query.min_risk));
    }

    sql += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => {
      try {
        r.evidence = JSON.parse(r.raw_evidence_json || '{}');
      } catch {
        r.evidence = {};
      }
      return r;
    });
  }

  /**
   * Retrieve a single detection by ID
   */
  static getDetectionById(db, id) {
    const row = db.prepare('SELECT * FROM identity_threat_detections WHERE id = ?').get(id);
    if (!row) return null;
    try {
      row.evidence = JSON.parse(row.raw_evidence_json || '{}');
    } catch {
      row.evidence = {};
    }
    return row;
  }

  /**
   * Record a new identity attack detection
   */
  static recordDetection(db, data = {}) {
    const targetAccount = data.target_account || data.targetAccount;
    const sourceHost = data.source_host || data.sourceHost;
    const attackVector = data.attack_vector || data.attackVector;

    if (!targetAccount || !sourceHost || !attackVector) {
      throw new Error('target_account, source_host, and attack_vector are required');
    }

    const validVectors = [
      'KERBEROASTING', 'ASREP_ROASTING', 'DCSYNC',
      'LSASS_MEMORY_DUMP', 'HONEYTOKEN_TRIGGERED',
      'PASSWORD_SPRAY', 'PASS_THE_HASH', 'GOLDEN_TICKET'
    ];
    if (!validVectors.includes(attackVector)) {
      throw new Error(`Invalid attack_vector. Must be one of: ${validVectors.join(', ')}`);
    }

    // Default risk scoring by attack vector
    const defaultRisks = {
      HONEYTOKEN_TRIGGERED: 99.0,
      GOLDEN_TICKET: 98.0,
      DCSYNC: 95.0,
      LSASS_MEMORY_DUMP: 95.0,
      KERBEROASTING: 88.0,
      PASS_THE_HASH: 85.0,
      ASREP_ROASTING: 80.0,
      PASSWORD_SPRAY: 75.0
    };
    const risk = data.risk_score !== undefined ? parseFloat(data.risk_score) : (defaultRisks[attackVector] || 75.0);

    const mitreTechniques = {
      KERBEROASTING: 'T1558.003',
      ASREP_ROASTING: 'T1558.004',
      GOLDEN_TICKET: 'T1558.001',
      DCSYNC: 'T1003.006',
      LSASS_MEMORY_DUMP: 'T1003.001',
      HONEYTOKEN_TRIGGERED: 'T1078.002',
      PASS_THE_HASH: 'T1550.002',
      PASSWORD_SPRAY: 'T1110.003'
    };
    const mitre = data.mitre_technique || mitreTechniques[attackVector] || 'T1558';

    const id = data.id || ('itd-' + crypto.randomBytes(6).toString('hex'));
    const evidenceJson = typeof data.evidence === 'object' ? JSON.stringify(data.evidence) : (data.raw_evidence_json || '{}');

    db.prepare(`
      INSERT INTO identity_threat_detections (
        id, target_account, source_host, source_ip, domain_controller,
        attack_vector, mitre_technique, risk_score, status, raw_evidence_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'NEW', ?)
    `).run(
      id,
      targetAccount,
      sourceHost,
      data.source_ip || data.sourceIp || '127.0.0.1',
      data.domain_controller || data.domainController || 'DC01.LOCALPILOT.CORP',
      attackVector,
      mitre,
      risk,
      evidenceJson
    );

    // Update or insert account risk score entry
    const existingAccount = db.prepare('SELECT * FROM identity_account_risk_scores WHERE account_name = ?').get(targetAccount);
    if (!existingAccount) {
      const accLevel = risk >= 90 ? 'CRITICAL' : risk >= 70 ? 'HIGH' : risk >= 40 ? 'MEDIUM' : 'LOW';
      db.prepare(`
        INSERT INTO identity_account_risk_scores (
          id, account_name, account_type, department, risk_score, risk_level, anomalous_logon_count, lateral_movement_count
        ) VALUES (?, ?, 'USER', 'Active Directory', ?, ?, 1, 0)
      `).run('iars-' + crypto.randomBytes(6).toString('hex'), targetAccount, risk, accLevel);
    } else {
      const newScore = Math.min(100.0, Math.max(existingAccount.risk_score, risk));
      const newLevel = newScore >= 90 ? 'CRITICAL' : newScore >= 70 ? 'HIGH' : newScore >= 40 ? 'MEDIUM' : 'LOW';
      db.prepare(`
        UPDATE identity_account_risk_scores SET
          risk_score = ?,
          risk_level = ?,
          anomalous_logon_count = anomalous_logon_count + 1,
          last_assessed_at = DATETIME('now')
        WHERE account_name = ?
      `).run(newScore, newLevel, targetAccount);
    }

    return this.getDetectionById(db, id);
  }

  /**
   * Update detection status and resolution notes
   */
  static updateDetectionStatus(db, id, status, remediationNotes = null) {
    const existing = db.prepare('SELECT * FROM identity_threat_detections WHERE id = ?').get(id);
    if (!existing) throw new Error('Identity threat detection not found');

    const validStatuses = ['NEW', 'INVESTIGATING', 'CONTAINED', 'DISMISSED'];
    if (!validStatuses.includes(status)) {
      throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
    }

    const resolvedAt = (status === 'CONTAINED' || status === 'DISMISSED') ? new Date().toISOString() : existing.resolved_at;
    const finalNotes = remediationNotes || existing.remediation_action_taken;

    db.prepare(`
      UPDATE identity_threat_detections SET
        status = ?,
        remediation_action_taken = ?,
        resolved_at = ?
      WHERE id = ?
    `).run(status, finalNotes, resolvedAt, id);

    return this.getDetectionById(db, id);
  }

  /**
   * Automated account containment action (Password Reset, Token Revocation, Account Lock)
   */
  static containAccount(db, accountName, action = 'ACCOUNT_LOCKED', adminNotes = null) {
    const validActions = ['NORMAL', 'PASSWORD_RESET_REQUIRED', 'TOKENS_REVOKED', 'ACCOUNT_LOCKED'];
    if (!validActions.includes(action)) {
      throw new Error(`Invalid containment action. Must be one of: ${validActions.join(', ')}`);
    }

    const existing = db.prepare('SELECT * FROM identity_account_risk_scores WHERE account_name = ?').get(accountName);
    if (!existing) {
      db.prepare(`
        INSERT INTO identity_account_risk_scores (
          id, account_name, account_type, department, risk_score, risk_level, containment_status
        ) VALUES (?, ?, 'USER', 'Contained Accounts', 80.0, 'HIGH', ?)
      `).run('iars-' + crypto.randomBytes(6).toString('hex'), accountName, action);
    } else {
      db.prepare(`
        UPDATE identity_account_risk_scores SET
          containment_status = ?,
          last_assessed_at = DATETIME('now')
        WHERE account_name = ?
      `).run(action, accountName);
    }

    // Automatically transition open detections for this account to CONTAINED
    db.prepare(`
      UPDATE identity_threat_detections SET
        status = 'CONTAINED',
        remediation_action_taken = ?,
        resolved_at = DATETIME('now')
      WHERE target_account = ? AND status IN ('NEW', 'INVESTIGATING')
    `).run(`Account containment executed: ${action}. ${adminNotes || ''}`, accountName);

    return db.prepare('SELECT * FROM identity_account_risk_scores WHERE account_name = ?').get(accountName);
  }

  /**
   * Retrieve honeytokens catalog
   */
  static getHoneytokens(db, query = {}) {
    let sql = 'SELECT * FROM identity_honeytokens_catalog WHERE 1=1';
    const params = [];

    if (query.honeytoken_type) {
      sql += ' AND honeytoken_type = ?';
      params.push(query.honeytoken_type);
    }
    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Register a new deception honeytoken asset
   */
  static createHoneytoken(db, data = {}) {
    const accountName = data.account_name || data.accountName;
    const honeytokenType = data.honeytoken_type || data.honeytokenType;

    if (!accountName || !honeytokenType) {
      throw new Error('account_name and honeytoken_type are required');
    }

    const validTypes = ['DECOY_USER_ACCOUNT', 'FAKE_SPN_SERVICE', 'CREDENTIAL_MANAGER_BLOB', 'REGISTRY_LSA_SECRET'];
    if (!validTypes.includes(honeytokenType)) {
      throw new Error(`Invalid honeytoken_type. Must be one of: ${validTypes.join(', ')}`);
    }

    const id = data.id || ('ihc-' + crypto.randomBytes(6).toString('hex'));

    db.prepare(`
      INSERT INTO identity_honeytokens_catalog (
        id, honeytoken_type, account_name, domain_name, spn, planted_on_host, description, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      id,
      honeytokenType,
      accountName,
      data.domain_name || data.domainName || 'LOCALPILOT.CORP',
      data.spn || null,
      data.planted_on_host || data.plantedOnHost || null,
      data.description || 'Decoy credential trap'
    );

    return db.prepare('SELECT * FROM identity_honeytokens_catalog WHERE id = ?').get(id);
  }

  /**
   * Trigger honeytoken tripwire
   */
  static triggerHoneytoken(db, idOrAccount, triggerHost = 'Unknown-Host', attackerIp = '127.0.0.1', details = {}) {
    const honeytoken = db.prepare('SELECT * FROM identity_honeytokens_catalog WHERE id = ? OR account_name = ?').get(idOrAccount, idOrAccount);
    if (!honeytoken) throw new Error('Honeytoken not found');

    db.prepare(`
      UPDATE identity_honeytokens_catalog SET
        trigger_count = trigger_count + 1,
        last_triggered_at = DATETIME('now')
      WHERE id = ?
    `).run(honeytoken.id);

    // Record high-priority detection
    const detection = this.recordDetection(db, {
      target_account: honeytoken.account_name,
      source_host: triggerHost,
      source_ip: attackerIp,
      attack_vector: 'HONEYTOKEN_TRIGGERED',
      risk_score: 99.0,
      evidence: {
        honeytoken_id: honeytoken.id,
        honeytoken_type: honeytoken.honeytoken_type,
        spn: honeytoken.spn,
        planted_host: honeytoken.planted_on_host,
        ...details
      }
    });

    return {
      triggered: true,
      honeytoken: db.prepare('SELECT * FROM identity_honeytokens_catalog WHERE id = ?').get(honeytoken.id),
      detection
    };
  }

  /**
   * Delete honeytoken from catalog
   */
  static deleteHoneytoken(db, id) {
    const res = db.prepare('DELETE FROM identity_honeytokens_catalog WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Retrieve account risk scores
   */
  static getAccountRiskProfiles(db, query = {}) {
    let sql = 'SELECT * FROM identity_account_risk_scores WHERE 1=1';
    const params = [];

    if (query.risk_level) {
      sql += ' AND risk_level = ?';
      params.push(query.risk_level);
    }
    if (query.containment_status) {
      sql += ' AND containment_status = ?';
      params.push(query.containment_status);
    }
    if (query.account_type) {
      sql += ' AND account_type = ?';
      params.push(query.account_type);
    }

    sql += ' ORDER BY risk_score DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Recalculate account risk profile from threat detections history
   */
  static assessAccountRisk(db, accountName) {
    const detections = db.prepare('SELECT risk_score, status FROM identity_threat_detections WHERE target_account = ?').all(accountName);
    const existing = db.prepare('SELECT * FROM identity_account_risk_scores WHERE account_name = ?').get(accountName);

    let maxRisk = 10.0;
    let anomalousCount = detections.length;

    for (const d of detections) {
      if (d.risk_score > maxRisk) maxRisk = d.risk_score;
    }

    const riskLevel = maxRisk >= 90 ? 'CRITICAL' : maxRisk >= 70 ? 'HIGH' : maxRisk >= 40 ? 'MEDIUM' : 'LOW';

    if (!existing) {
      db.prepare(`
        INSERT INTO identity_account_risk_scores (
          id, account_name, account_type, department, risk_score, risk_level, anomalous_logon_count, last_assessed_at
        ) VALUES (?, ?, 'USER', 'General', ?, ?, ?, DATETIME('now'))
      `).run('iars-' + crypto.randomBytes(6).toString('hex'), accountName, maxRisk, riskLevel, anomalousCount);
    } else {
      db.prepare(`
        UPDATE identity_account_risk_scores SET
          risk_score = ?,
          risk_level = ?,
          anomalous_logon_count = ?,
          last_assessed_at = DATETIME('now')
        WHERE account_name = ?
      `).run(maxRisk, riskLevel, anomalousCount, accountName);
    }

    return db.prepare('SELECT * FROM identity_account_risk_scores WHERE account_name = ?').get(accountName);
  }
}
