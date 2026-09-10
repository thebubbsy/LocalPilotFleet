/**
 * LocalPilot Fleet — EDR Incident Correlation & Multi-Stage Attack Storyline Service Engine
 * server/src/services/incidentCorrelationEngine.js
 *
 * Implements Microsoft Defender for Endpoint & CrowdStrike Falcon equivalent
 * incident correlation, cross-signal alert aggregation, multi-stage attack storyline synthesis,
 * MITRE ATT&CK kill-chain mapping, and automated SecOps triage workflow.
 */

import crypto from 'node:crypto';

export class IncidentCorrelationEngine {
  /**
   * Aggregate fleet-wide security incident metrics
   */
  static getIncidentStats(db) {
    const totalIncidents = db.prepare('SELECT COUNT(*) as count FROM incident_investigation_cases').get()?.count || 0;
    const activeIncidents = db.prepare("SELECT COUNT(*) as count FROM incident_investigation_cases WHERE status = 'ACTIVE'").get()?.count || 0;
    const criticalIncidents = db.prepare("SELECT COUNT(*) as count FROM incident_investigation_cases WHERE severity = 'CRITICAL' AND status != 'RESOLVED'").get()?.count || 0;
    const highIncidents = db.prepare("SELECT COUNT(*) as count FROM incident_investigation_cases WHERE severity = 'HIGH' AND status != 'RESOLVED'").get()?.count || 0;
    const containedIncidents = db.prepare("SELECT COUNT(*) as count FROM incident_investigation_cases WHERE status = 'CONTAINED'").get()?.count || 0;
    const resolvedIncidents = db.prepare("SELECT COUNT(*) as count FROM incident_investigation_cases WHERE status = 'RESOLVED'").get()?.count || 0;

    const totalAssociatedAlerts = db.prepare('SELECT COUNT(*) as count FROM incident_alert_associations').get()?.count || 0;
    const avgRisk = db.prepare("SELECT AVG(risk_score) as avg FROM incident_investigation_cases WHERE status = 'ACTIVE'").get()?.avg || 50;

    return {
      totalIncidents,
      activeIncidents,
      criticalIncidents,
      highIncidents,
      containedIncidents,
      resolvedIncidents,
      totalAssociatedAlerts,
      meanRiskScore: Math.round(avgRisk),
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve all incidents with optional query filters
   */
  static getIncidents(db, query = {}) {
    let sql = 'SELECT * FROM incident_investigation_cases WHERE 1=1';
    const params = [];

    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status);
    }
    if (query.severity) {
      sql += ' AND severity = ?';
      params.push(query.severity);
    }
    if (query.primary_device_id) {
      sql += ' AND primary_device_id = ?';
      params.push(query.primary_device_id);
    }
    if (query.classification) {
      sql += ' AND classification = ?';
      params.push(query.classification);
    }
    if (query.assigned_analyst) {
      sql += ' AND assigned_analyst = ?';
      params.push(query.assigned_analyst);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      attack_storyline: this._safeJsonParse(r.attack_storyline_json, []),
      mitre_tactics: this._safeJsonParse(r.mitre_tactics_json, [])
    }));
  }

  /**
   * Retrieve single incident with its associated alerts and kill-chain timeline
   */
  static getIncidentById(db, id) {
    const inc = db.prepare('SELECT * FROM incident_investigation_cases WHERE id = ?').get(id);
    if (!inc) return null;

    const alerts = db.prepare('SELECT * FROM incident_alert_associations WHERE incident_id = ? ORDER BY associated_at DESC').all(id);
    const timeline = db.prepare('SELECT * FROM incident_timeline_milestones WHERE incident_id = ? ORDER BY occurred_at ASC').all(id);

    return {
      ...inc,
      attack_storyline: this._safeJsonParse(inc.attack_storyline_json, []),
      mitre_tactics: this._safeJsonParse(inc.mitre_tactics_json, []),
      alerts,
      timeline
    };
  }

  /**
   * Create a new incident investigation case
   */
  static createIncident(db, data = {}) {
    const title = data.title;
    const deviceId = data.primary_device_id || data.primaryDeviceId;
    if (!title || !deviceId) {
      throw new Error('title and primary_device_id are required');
    }

    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    const hostname = device ? device.hostname : (data.primary_hostname || data.primaryHostname || 'Unknown-Host');

    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const severity = validSeverities.includes(data.severity) ? data.severity : 'MEDIUM';

    const validStatuses = ['ACTIVE', 'UNDER_INVESTIGATION', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
    const status = validStatuses.includes(data.status) ? data.status : 'ACTIVE';

    const validClassifications = ['UNCLASSIFIED', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE'];
    const classification = validClassifications.includes(data.classification) ? data.classification : 'UNCLASSIFIED';

    const id = data.id || ('inc-' + crypto.randomBytes(6).toString('hex'));
    const defaultRisk = severity === 'CRITICAL' ? 90 : (severity === 'HIGH' ? 75 : (severity === 'MEDIUM' ? 50 : 25));
    const riskScore = data.risk_score !== undefined ? parseInt(data.risk_score, 10) : defaultRisk;

    const storylineJson = typeof data.attack_storyline === 'object' ?
      JSON.stringify(data.attack_storyline) : (data.attack_storyline_json || '[]');

    const tacticsJson = Array.isArray(data.mitre_tactics) ?
      JSON.stringify(data.mitre_tactics) : (data.mitre_tactics_json || '[]');

    db.prepare(`
      INSERT INTO incident_investigation_cases (
        id, title, description, severity, status, classification,
        risk_score, primary_device_id, primary_hostname, assigned_analyst,
        root_cause, attack_storyline_json, mitre_tactics_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      title,
      data.description || null,
      severity,
      status,
      classification,
      riskScore,
      deviceId,
      hostname,
      data.assigned_analyst || data.assignedAnalyst || 'Unassigned',
      data.root_cause || data.rootCause || null,
      storylineJson,
      tacticsJson
    );

    return this.getIncidentById(db, id);
  }

  /**
   * Update incident fields
   */
  static updateIncident(db, id, updates = {}) {
    const existing = db.prepare('SELECT * FROM incident_investigation_cases WHERE id = ?').get(id);
    if (!existing) return null;

    const title = updates.title !== undefined ? updates.title : existing.title;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const severity = updates.severity !== undefined ? updates.severity : existing.severity;
    const status = updates.status !== undefined ? updates.status : existing.status;
    const classification = updates.classification !== undefined ? updates.classification : existing.classification;
    const risk_score = updates.risk_score !== undefined ? parseInt(updates.risk_score, 10) : existing.risk_score;
    const assigned_analyst = updates.assigned_analyst !== undefined ? updates.assigned_analyst : (updates.assignedAnalyst || existing.assigned_analyst);
    const root_cause = updates.root_cause !== undefined ? updates.root_cause : (updates.rootCause || existing.root_cause);

    let attack_storyline_json = existing.attack_storyline_json;
    if (updates.attack_storyline) {
      attack_storyline_json = JSON.stringify(updates.attack_storyline);
    } else if (updates.attack_storyline_json) {
      attack_storyline_json = updates.attack_storyline_json;
    }

    let mitre_tactics_json = existing.mitre_tactics_json;
    if (updates.mitre_tactics) {
      mitre_tactics_json = JSON.stringify(updates.mitre_tactics);
    } else if (updates.mitre_tactics_json) {
      mitre_tactics_json = updates.mitre_tactics_json;
    }

    db.prepare(`
      UPDATE incident_investigation_cases SET
        title = ?, description = ?, severity = ?, status = ?,
        classification = ?, risk_score = ?, assigned_analyst = ?,
        root_cause = ?, attack_storyline_json = ?, mitre_tactics_json = ?,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      title, description, severity, status,
      classification, risk_score, assigned_analyst,
      root_cause, attack_storyline_json, mitre_tactics_json,
      id
    );

    return this.getIncidentById(db, id);
  }

  /**
   * Close or resolve an incident investigation
   */
  static closeIncident(db, id, { resolution = 'RESOLVED', classification = 'TRUE_POSITIVE', rootCause = null, notes = null, resolvedBy = 'SecOps Lead' } = {}) {
    const existing = db.prepare('SELECT * FROM incident_investigation_cases WHERE id = ?').get(id);
    if (!existing) throw new Error('Incident not found');

    const updatedRootCause = rootCause || existing.root_cause || 'Root cause confirmed and neutralized';

    db.prepare(`
      UPDATE incident_investigation_cases SET
        status = ?,
        classification = ?,
        root_cause = ?,
        resolved_at = DATETIME('now'),
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(resolution, classification, updatedRootCause, id);

    // Record remediation closure milestone
    this.addMilestone(db, {
      incidentId: id,
      phaseName: 'REMEDIATION',
      milestoneTitle: `Incident ${resolution} by ${resolvedBy}`,
      details: notes || 'Incident containment verified and closed in SecOps console',
      mitreTechniqueId: 'T1036'
    });

    return this.getIncidentById(db, id);
  }

  /**
   * Associate an alert/event from any security module to this incident
   */
  static associateAlert(db, incidentId, { alertSource, alertId, alertSummary }) {
    if (!alertSource || !alertId || !alertSummary) {
      throw new Error('alertSource, alertId, and alertSummary are required');
    }

    const id = 'iaa-' + crypto.randomBytes(6).toString('hex');
    db.prepare(`
      INSERT INTO incident_alert_associations (
        id, incident_id, alert_source, alert_id, alert_summary
      ) VALUES (?, ?, ?, ?, ?)
    `).run(id, incidentId, alertSource, alertId, alertSummary);

    db.prepare(`UPDATE incident_investigation_cases SET updated_at = DATETIME('now') WHERE id = ?`).run(incidentId);

    return db.prepare('SELECT * FROM incident_alert_associations WHERE id = ?').get(id);
  }

  /**
   * Retrieve all associated alerts for an incident
   */
  static getIncidentAlerts(db, incidentId) {
    return db.prepare('SELECT * FROM incident_alert_associations WHERE incident_id = ? ORDER BY associated_at DESC').all(incidentId);
  }

  /**
   * Add a kill-chain timeline milestone to the incident
   */
  static addMilestone(db, {
    incidentId,
    phaseName,
    milestoneTitle,
    details = null,
    evidenceArtifact = null,
    mitreTechniqueId = null,
    occurredAt = null
  }) {
    if (!incidentId || !phaseName || !milestoneTitle) {
      throw new Error('incidentId, phaseName, and milestoneTitle are required');
    }

    const id = 'itm-' + crypto.randomBytes(6).toString('hex');
    const timestamp = occurredAt || new Date().toISOString();

    db.prepare(`
      INSERT INTO incident_timeline_milestones (
        id, incident_id, phase_name, milestone_title, details, evidence_artifact, mitre_technique_id, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, incidentId, phaseName, milestoneTitle, details, evidenceArtifact, mitreTechniqueId, timestamp);

    db.prepare(`UPDATE incident_investigation_cases SET updated_at = DATETIME('now') WHERE id = ?`).run(incidentId);

    return db.prepare('SELECT * FROM incident_timeline_milestones WHERE id = ?').get(id);
  }

  /**
   * Retrieve chronological attack milestones for an incident
   */
  static getIncidentTimeline(db, incidentId) {
    return db.prepare('SELECT * FROM incident_timeline_milestones WHERE incident_id = ? ORDER BY occurred_at ASC').all(incidentId);
  }

  /**
   * Automatic alert correlation: Inspects cross-signal security telemetry on a host,
   * detects correlated attack chains, and auto-generates or enriches an Incident Case.
   */
  static correlateAlerts(db, deviceId) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    // Collect recent alerts across tables
    const secEvents = db.prepare(`
      SELECT id, event_type, summary, severity, created_at FROM security_events
      WHERE device_id = ? ORDER BY id DESC LIMIT 5
    `).all(deviceId);

    const tamperEvents = db.prepare(`
      SELECT id, event_type, target_resource, attacker_process, action_taken, details, timestamp FROM tamper_audit_events
      WHERE device_id = ? ORDER BY timestamp DESC LIMIT 5
    `).all(deviceId);

    const isoLogs = db.prepare(`
      SELECT id, transition_type, reason, packet_summary, timestamp FROM isolation_audit_logs
      WHERE device_id = ? ORDER BY id DESC LIMIT 5
    `).all(deviceId);

    const quarantined = db.prepare(`
      SELECT id, file_name, threat_name, sha256_hash, quarantined_at FROM quarantined_files_inventory
      WHERE device_id = ? ORDER BY id DESC LIMIT 5
    `).all(deviceId);

    const totalSignals = secEvents.length + tamperEvents.length + isoLogs.length + quarantined.length;
    if (totalSignals === 0) {
      return { correlated: false, message: 'No alerts found to correlate for this device' };
    }

    // Check if active incident already exists
    let incident = db.prepare(`
      SELECT * FROM incident_investigation_cases
      WHERE primary_device_id = ? AND status IN ('ACTIVE', 'UNDER_INVESTIGATION')
      LIMIT 1
    `).get(deviceId);

    const isNew = !incident;
    if (isNew) {
      const riskScore = Math.min(95, 40 + (totalSignals * 12));
      const severity = riskScore >= 80 ? 'CRITICAL' : (riskScore >= 60 ? 'HIGH' : 'MEDIUM');

      incident = this.createIncident(db, {
        title: `Correlated Multi-Stage Attack on ${device.hostname}`,
        description: `Automated EDR correlation synthesized ${totalSignals} security signals across execution, evasion, and containment.`,
        severity,
        risk_score: riskScore,
        primary_device_id: deviceId,
        primary_hostname: device.hostname,
        assigned_analyst: 'Automated Correlation Engine',
        mitre_tactics: ['Initial Access', 'Execution', 'Defense Evasion', 'Command and Control']
      });
    }

    // Associate discovered alerts
    for (const s of secEvents) {
      try {
        this.associateAlert(db, incident.id, {
          alertSource: 'SECURITY_EVENTS',
          alertId: String(s.id),
          alertSummary: s.summary
        });
      } catch {}
    }

    for (const t of tamperEvents) {
      try {
        this.associateAlert(db, incident.id, {
          alertSource: 'TAMPER_AUDIT',
          alertId: String(t.id),
          alertSummary: `Tamper attempt intercepted on ${t.component_name}: ${t.summary}`
        });
        this.addMilestone(db, {
          incidentId: incident.id,
          phaseName: 'DEFENSE_EVASION',
          milestoneTitle: `Tamper Attempt: ${t.component_name}`,
          details: t.summary,
          mitreTechniqueId: 'T1562.001'
        });
      } catch {}
    }

    for (const q of quarantined) {
      try {
        this.associateAlert(db, incident.id, {
          alertSource: 'QUARANTINE_INVENTORY',
          alertId: String(q.id),
          alertSummary: `Threat Quarantined: ${q.file_name} (${q.threat_name})`
        });
        this.addMilestone(db, {
          incidentId: incident.id,
          phaseName: 'EXECUTION',
          milestoneTitle: `Malware Quarantined: ${q.file_name}`,
          details: q.threat_name,
          evidenceArtifact: q.sha256_hash,
          mitreTechniqueId: 'T1204.002'
        });
      } catch {}
    }

    for (const i of isoLogs) {
      try {
        this.associateAlert(db, incident.id, {
          alertSource: 'ISOLATION_LOGS',
          alertId: String(i.id),
          alertSummary: `Isolation Event: ${i.transition_type} - ${i.reason}`
        });
      } catch {}
    }

    // Refresh storyline JSON
    const storyline = this.generateAttackStorylineJson(db, incident.id);
    this.updateIncident(db, incident.id, { attack_storyline: storyline });

    return {
      correlated: true,
      created: isNew,
      incident: this.getIncidentById(db, incident.id),
      totalSignals
    };
  }

  /**
   * Synthesize a structured attack storyline process graph
   */
  static generateAttackStorylineJson(db, incidentId) {
    const milestones = db.prepare('SELECT * FROM incident_timeline_milestones WHERE incident_id = ? ORDER BY occurred_at ASC').all(incidentId);

    return milestones.map((m, idx) => ({
      nodeId: `node-${idx + 1}`,
      phase: m.phase_name,
      title: m.milestone_title,
      details: m.details,
      technique: m.mitre_technique_id,
      artifact: m.evidence_artifact,
      timestamp: m.occurred_at
    }));
  }

  static _safeJsonParse(str, fallback = []) {
    if (!str) return fallback;
    try {
      return JSON.parse(str);
    } catch {
      return fallback;
    }
  }
}
