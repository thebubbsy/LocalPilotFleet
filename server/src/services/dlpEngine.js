/**
 * LocalPilot Fleet — Data Loss Prevention & Sensitive Information Defense Engine
 * server/src/services/dlpEngine.js
 *
 * Implements Microsoft Purview DLP & CrowdStrike Falcon Data Protection equivalent
 * sensitive data discovery (PCI, PII, Secrets, HIPAA), real-time exfiltration interception
 * (Removable USB, Clipboard paste, Network shares), and endpoint file exposure governance.
 */

import crypto from 'node:crypto';

export class DlpEngine {
  /**
   * Aggregate fleet-wide DLP statistics
   */
  static getDlpStats(db) {
    const totalRules = db.prepare('SELECT COUNT(*) as count FROM dlp_classification_rules').get()?.count || 0;
    const activeRules = db.prepare('SELECT COUNT(*) as count FROM dlp_classification_rules WHERE is_enabled = 1').get()?.count || 0;

    const totalExposures = db.prepare('SELECT COUNT(*) as count FROM dlp_file_scan_findings').get()?.count || 0;
    const unencryptedExposures = db.prepare("SELECT COUNT(*) as count FROM dlp_file_scan_findings WHERE remediation_status = 'UNENCRYPTED_EXPOSURE'").get()?.count || 0;
    const exposedDevices = db.prepare("SELECT COUNT(DISTINCT device_id) as count FROM dlp_file_scan_findings WHERE remediation_status = 'UNENCRYPTED_EXPOSURE'").get()?.count || 0;

    const totalExfiltrations = db.prepare('SELECT COUNT(*) as count FROM dlp_exfiltration_incidents').get()?.count || 0;
    const blockedExfiltrations = db.prepare("SELECT COUNT(*) as count FROM dlp_exfiltration_incidents WHERE action_taken = 'BLOCKED'").get()?.count || 0;

    return {
      totalRules,
      activeRules,
      totalExposures,
      unencryptedExposures,
      exposedDevices,
      totalExfiltrations,
      blockedExfiltrations,
      dlpOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve classification rules with filters
   */
  static getRules(db, query = {}) {
    let sql = 'SELECT * FROM dlp_classification_rules WHERE 1=1';
    const params = [];

    if (query.category) {
      sql += ' AND category = ?';
      params.push(query.category);
    }
    if (query.severity) {
      sql += ' AND severity = ?';
      params.push(query.severity);
    }
    if (query.is_enabled !== undefined) {
      sql += ' AND is_enabled = ?';
      params.push(query.is_enabled ? 1 : 0);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Retrieve single rule by ID
   */
  static getRuleById(db, id) {
    return db.prepare('SELECT * FROM dlp_classification_rules WHERE id = ?').get(id);
  }

  /**
   * Create a new classification rule
   */
  static createRule(db, data = {}) {
    const ruleName = data.rule_name || data.ruleName;
    const patternRegex = data.pattern_regex || data.patternRegex;
    if (!ruleName || !patternRegex) {
      throw new Error('rule_name and pattern_regex are required');
    }

    // Validate regex compilability
    try {
      new RegExp(patternRegex);
    } catch (e) {
      throw new Error('Invalid regular expression in pattern_regex: ' + e.message);
    }

    const validCategories = ['FINANCIAL_PCI', 'PERSONAL_PII', 'SECRETS_CREDENTIALS', 'HEALTH_HIPAA', 'INTELLECTUAL_PROPERTY', 'CUSTOM_REGEX'];
    const category = validCategories.includes(data.category) ? data.category : 'CUSTOM_REGEX';

    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const severity = validSeverities.includes(data.severity) ? data.severity : 'HIGH';

    const validActions = ['AUDIT_ONLY', 'BLOCK', 'ENCRYPT', 'QUARANTINE_FILE'];
    const enforcementAction = validActions.includes(data.enforcement_action) ? data.enforcement_action : 'BLOCK';

    const id = data.id || ('dcr-' + crypto.randomBytes(6).toString('hex'));
    const confidence = parseFloat(data.confidence_threshold) || 85.0;

    db.prepare(`
      INSERT INTO dlp_classification_rules (
        id, rule_name, category, severity, pattern_regex, confidence_threshold, enforcement_action, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      id,
      ruleName,
      category,
      severity,
      patternRegex,
      confidence,
      enforcementAction
    );

    return this.getRuleById(db, id);
  }

  /**
   * Update classification rule
   */
  static updateRule(db, id, updates = {}) {
    const existing = db.prepare('SELECT * FROM dlp_classification_rules WHERE id = ?').get(id);
    if (!existing) return null;

    if (updates.pattern_regex) {
      try {
        new RegExp(updates.pattern_regex);
      } catch (e) {
        throw new Error('Invalid regular expression: ' + e.message);
      }
    }

    const ruleName = updates.rule_name !== undefined ? updates.rule_name : existing.rule_name;
    const patternRegex = updates.pattern_regex !== undefined ? updates.pattern_regex : existing.pattern_regex;
    const category = updates.category !== undefined ? updates.category : existing.category;
    const severity = updates.severity !== undefined ? updates.severity : existing.severity;
    const confidence = updates.confidence_threshold !== undefined ? parseFloat(updates.confidence_threshold) : existing.confidence_threshold;
    const action = updates.enforcement_action !== undefined ? updates.enforcement_action : existing.enforcement_action;
    const isEnabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE dlp_classification_rules SET
        rule_name = ?, pattern_regex = ?, category = ?, severity = ?,
        confidence_threshold = ?, enforcement_action = ?, is_enabled = ?,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      ruleName, patternRegex, category, severity,
      confidence, action, isEnabled, id
    );

    return this.getRuleById(db, id);
  }

  /**
   * Delete classification rule
   */
  static deleteRule(db, id) {
    const res = db.prepare('DELETE FROM dlp_classification_rules WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Query file scan findings
   */
  static getScanFindings(db, query = {}) {
    let sql = 'SELECT * FROM dlp_file_scan_findings WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.remediation_status) {
      sql += ' AND remediation_status = ?';
      params.push(query.remediation_status);
    }
    if (query.sensitivity_severity) {
      sql += ' AND sensitivity_severity = ?';
      params.push(query.sensitivity_severity);
    }

    sql += ' ORDER BY detected_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Record a discovered sensitive file finding
   */
  static recordScanFinding(db, data = {}) {
    const deviceId = data.device_id || data.deviceId;
    const filePath = data.file_path || data.filePath;
    if (!deviceId || !filePath) {
      throw new Error('device_id and file_path are required');
    }

    const device = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
    const hostname = device ? device.hostname : (data.hostname || 'Unknown-Device');

    const ruleId = data.classification_rule_id || data.classificationRuleId || 'dcr-01';
    const rule = db.prepare('SELECT rule_name, severity FROM dlp_classification_rules WHERE id = ?').get(ruleId);
    const ruleName = rule ? rule.rule_name : (data.rule_name || 'Generic Sensitive File');
    const severity = rule ? rule.severity : (data.sensitivity_severity || 'HIGH');

    const id = data.id || ('dfsf-' + crypto.randomBytes(6).toString('hex'));
    const size = parseInt(data.file_size_bytes, 10) || 1024;
    const matchCount = parseInt(data.match_count, 10) || 1;

    db.prepare(`
      INSERT INTO dlp_file_scan_findings (
        id, device_id, hostname, file_path, file_size_bytes,
        classification_rule_id, rule_name, match_count, sensitivity_severity, remediation_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'UNENCRYPTED_EXPOSURE')
    `).run(
      id, deviceId, hostname, filePath, size,
      ruleId, ruleName, matchCount, severity
    );

    return db.prepare('SELECT * FROM dlp_file_scan_findings WHERE id = ?').get(id);
  }

  /**
   * Update finding remediation status
   */
  static updateFindingStatus(db, findingId, status, notes = null) {
    const existing = db.prepare('SELECT * FROM dlp_file_scan_findings WHERE id = ?').get(findingId);
    if (!existing) throw new Error('DLP finding not found');

    const validStatuses = ['UNENCRYPTED_EXPOSURE', 'SECURED_ENCRYPTED', 'FILE_QUARANTINED', 'EXCEPTION_APPROVED'];
    if (!validStatuses.includes(status)) {
      throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
    }

    const remediatedAt = (status === 'SECURED_ENCRYPTED' || status === 'FILE_QUARANTINED') ? new Date().toISOString() : existing.remediated_at;

    db.prepare(`
      UPDATE dlp_file_scan_findings SET
        remediation_status = ?,
        remediated_at = ?
      WHERE id = ?
    `).run(status, remediatedAt, findingId);

    return db.prepare('SELECT * FROM dlp_file_scan_findings WHERE id = ?').get(findingId);
  }

  /**
   * Retrieve intercepted exfiltration incidents
   */
  static getExfiltrationIncidents(db, query = {}) {
    let sql = 'SELECT * FROM dlp_exfiltration_incidents WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.channel) {
      sql += ' AND channel = ?';
      params.push(query.channel);
    }
    if (query.action_taken) {
      sql += ' AND action_taken = ?';
      params.push(query.action_taken);
    }

    sql += ' ORDER BY intercepted_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => {
      try {
        r.event_details = JSON.parse(r.raw_event_json || '{}');
      } catch {
        r.event_details = {};
      }
      return r;
    });
  }

  /**
   * Log an exfiltration attempt (USB transfer, clipboard paste, cloud upload)
   */
  static logExfiltrationIncident(db, data = {}) {
    const deviceId = data.device_id || data.deviceId;
    const channel = data.channel;
    const fileOrDataName = data.file_or_data_name || data.fileOrDataName;

    if (!deviceId || !channel || !fileOrDataName) {
      throw new Error('device_id, channel, and file_or_data_name are required');
    }

    const validChannels = ['REMOVABLE_USB', 'CLIPBOARD_PASTE', 'BROWSER_UPLOAD', 'NETWORK_SHARE', 'PRINTER_SPOOL'];
    if (!validChannels.includes(channel)) {
      throw new Error(`Invalid channel. Must be one of: ${validChannels.join(', ')}`);
    }

    const device = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
    const hostname = device ? device.hostname : (data.hostname || 'Unknown-Device');

    const validActions = ['BLOCKED', 'AUDITED', 'USER_JUSTIFIED', 'QUARANTINED'];
    const action = validActions.includes(data.action_taken) ? data.action_taken : 'BLOCKED';

    const id = data.id || ('dei-' + crypto.randomBytes(6).toString('hex'));
    const rawJson = typeof data.details === 'object' ? JSON.stringify(data.details) : (data.raw_event_json || '{}');

    db.prepare(`
      INSERT INTO dlp_exfiltration_incidents (
        id, device_id, hostname, user_account, channel, file_or_data_name,
        rule_id, rule_name, severity, action_taken, user_justification, raw_event_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      deviceId,
      hostname,
      data.user_account || data.userAccount || 'standard_user',
      channel,
      fileOrDataName,
      data.rule_id || data.ruleId || null,
      data.rule_name || data.ruleName || 'Sensitive Data Policy Violation',
      data.severity || 'CRITICAL',
      action,
      data.user_justification || null,
      rawJson
    );

    // Also dispatch security event alarm if BLOCKED or QUARANTINED
    if (action === 'BLOCKED' || action === 'QUARANTINED') {
      try {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, severity, summary, raw_payload_json
          ) VALUES (?, 'DATA_EXFILTRATION_BLOCKED', 'CRITICAL', ?, ?)
        `).run(
          deviceId,
          `DLP Guardrail Intercepted ${channel} Exfiltration of ${fileOrDataName}`,
          rawJson
        );
      } catch (e) {
        // Continue even if security_events schema differs
      }
    }

    const res = db.prepare('SELECT * FROM dlp_exfiltration_incidents WHERE id = ?').get(id);
    try {
      res.event_details = JSON.parse(res.raw_event_json || '{}');
    } catch {
      res.event_details = {};
    }
    return res;
  }

  /**
   * Fast in-memory regex evaluation of text against active rules
   */
  static scanContent(db, textContent = '') {
    if (!textContent) return { matches: [], totalMatched: 0 };

    const rules = db.prepare('SELECT * FROM dlp_classification_rules WHERE is_enabled = 1').all();
    const matches = [];

    for (const r of rules) {
      try {
        const regex = new RegExp(r.pattern_regex, 'g');
        const hits = textContent.match(regex);
        if (hits && hits.length > 0) {
          matches.push({
            rule_id: r.id,
            rule_name: r.rule_name,
            category: r.category,
            severity: r.severity,
            confidence_threshold: r.confidence_threshold,
            enforcement_action: r.enforcement_action,
            match_count: hits.length,
            sample_preview: hits[0].slice(0, 4) + '****' + hits[0].slice(-4)
          });
        }
      } catch {
        // Skip invalid regex
      }
    }

    return {
      matches,
      totalMatched: matches.length,
      scannedAt: new Date().toISOString()
    };
  }
}
