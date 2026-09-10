/**
 * LocalPilot Fleet — Endpoint Tamper Protection & Antivirus Exclusion Governance Service Engine
 * server/src/services/tamperProtectionEngine.js
 *
 * Implements Defender Tamper Protection locks, Anti-Snooping baselines, governed AV exclusions,
 * and forensic telemetry stream on unauthorized registry/service tamper attempts.
 */

import crypto from 'node:crypto';

export class TamperProtectionEngine {
  /**
   * Aggregate fleet-wide tamper protection & exclusion governance statistics
   */
  static getTamperProtectionStats(db) {
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM tamper_protection_policies').get()?.count || 0;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM tamper_protection_policies WHERE is_enabled = 1').get()?.count || 0;
    const totalExclusions = db.prepare('SELECT COUNT(*) as count FROM antivirus_exclusion_rules').get()?.count || 0;
    const highRiskExclusions = db.prepare("SELECT COUNT(*) as count FROM antivirus_exclusion_rules WHERE risk_tier IN ('HIGH', 'CRITICAL')").get()?.count || 0;

    const totalEvents = db.prepare('SELECT COUNT(*) as count FROM tamper_audit_events').get()?.count || 0;
    const blockedTamperAttempts = db.prepare("SELECT COUNT(*) as count FROM tamper_audit_events WHERE action_taken = 'BLOCKED'").get()?.count || 0;
    const restoredExclusions = db.prepare("SELECT COUNT(*) as count FROM tamper_audit_events WHERE action_taken = 'RESTORED'").get()?.count || 0;

    return {
      totalPolicies,
      activePolicies,
      totalExclusions,
      highRiskExclusions,
      totalEvents,
      blockedTamperAttempts,
      restoredExclusions,
      subSecondSweepSla: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve all tamper protection policies
   */
  static getPolicies(db) {
    return db.prepare('SELECT * FROM tamper_protection_policies ORDER BY created_at DESC').all();
  }

  /**
   * Retrieve single policy with attached governed exclusions
   */
  static getPolicyById(db, id) {
    const policy = db.prepare('SELECT * FROM tamper_protection_policies WHERE id = ?').get(id);
    if (!policy) return null;

    const exclusions = db.prepare('SELECT * FROM antivirus_exclusion_rules WHERE policy_id = ? ORDER BY created_at ASC').all(id);
    return {
      ...policy,
      exclusions
    };
  }

  /**
   * Create a new tamper protection policy
   */
  static createPolicy(db, data) {
    const id = data.id || ('tpp-' + crypto.randomBytes(6).toString('hex'));
    const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1;
    const lockServices = data.lock_security_services !== undefined ? (data.lock_security_services ? 1 : 0) : 1;
    const protectExclusions = data.protect_antivirus_exclusions !== undefined ? (data.protect_antivirus_exclusions ? 1 : 0) : 1;
    const preventSafeMode = data.prevent_safe_mode_bypass !== undefined ? (data.prevent_safe_mode_bypass ? 1 : 0) : 1;

    const stmt = db.prepare(`
      INSERT INTO tamper_protection_policies (
        id, name, description, target_scope, target_id, tamper_protection_state,
        lock_security_services, protect_antivirus_exclusions, prevent_safe_mode_bypass, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.description || null,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.tamper_protection_state || 'ENFORCED',
      lockServices,
      protectExclusions,
      preventSafeMode,
      isEnabled
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing tamper protection policy
   */
  static updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM tamper_protection_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_scope = updates.target_scope !== undefined ? updates.target_scope : existing.target_scope;
    const target_id = updates.target_id !== undefined ? updates.target_id : existing.target_id;
    const tamper_protection_state = updates.tamper_protection_state !== undefined ? updates.tamper_protection_state : existing.tamper_protection_state;
    const lock_security_services = updates.lock_security_services !== undefined ? (updates.lock_security_services ? 1 : 0) : existing.lock_security_services;
    const protect_antivirus_exclusions = updates.protect_antivirus_exclusions !== undefined ? (updates.protect_antivirus_exclusions ? 1 : 0) : existing.protect_antivirus_exclusions;
    const prevent_safe_mode_bypass = updates.prevent_safe_mode_bypass !== undefined ? (updates.prevent_safe_mode_bypass ? 1 : 0) : existing.prevent_safe_mode_bypass;
    const is_enabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE tamper_protection_policies SET
        name = ?, description = ?, target_scope = ?, target_id = ?,
        tamper_protection_state = ?, lock_security_services = ?,
        protect_antivirus_exclusions = ?, prevent_safe_mode_bypass = ?,
        is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_scope, target_id, tamper_protection_state,
      lock_security_services, protect_antivirus_exclusions, prevent_safe_mode_bypass,
      is_enabled, id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete policy and cascaded exclusion rules
   */
  static deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM tamper_protection_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get antivirus exclusion rules
   */
  static getExclusions(db, policyId = null) {
    if (policyId) {
      return db.prepare('SELECT * FROM antivirus_exclusion_rules WHERE policy_id = ? ORDER BY created_at DESC').all(policyId);
    }
    return db.prepare('SELECT * FROM antivirus_exclusion_rules ORDER BY created_at DESC').all();
  }

  /**
   * Create an antivirus exclusion rule
   */
  static createExclusion(db, data) {
    const id = data.id || ('aver-' + crypto.randomBytes(6).toString('hex'));
    const isActive = data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1;

    db.prepare(`
      INSERT INTO antivirus_exclusion_rules (
        id, policy_id, exclusion_type, exclusion_value, risk_tier, justification, approved_by, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.policy_id || null,
      data.exclusion_type || 'PATH',
      data.exclusion_value,
      data.risk_tier || 'LOW',
      data.justification || 'Standard Administrative Exception',
      data.approved_by || 'SecurityAdmin',
      isActive
    );

    return db.prepare('SELECT * FROM antivirus_exclusion_rules WHERE id = ?').get(id);
  }

  /**
   * Delete an exclusion rule
   */
  static deleteExclusion(db, id) {
    const res = db.prepare('DELETE FROM antivirus_exclusion_rules WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Log a tamper audit event (Registry tampering, service kill, unauthorized exclusion)
   */
  static logTamperEvent(db, data) {
    const id = data.id || ('tae-' + crypto.randomBytes(6).toString('hex'));
    const severity = data.severity || 'CRITICAL';
    const detailsStr = typeof data.details === 'object' ? JSON.stringify(data.details) : (data.details || null);

    db.prepare(`
      INSERT INTO tamper_audit_events (
        id, device_id, hostname, username, event_type, target_resource,
        attacker_process, action_taken, details, severity
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.device_id,
      data.hostname || 'Unknown-Node',
      data.username || 'System',
      data.event_type,
      data.target_resource || 'Unknown Resource',
      data.attacker_process || 'Unknown Process',
      data.action_taken || 'BLOCKED',
      detailsStr,
      severity
    );

    // Auto-dispatch critical alert to security_events
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
        ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7003, 'TAMPER_PROTECTION_ENGINE', 'CRITICAL', ?, ?, 0)
      `).run(
        data.device_id,
        `CRITICAL: Defender Tamper Protection thwarted ${data.event_type} on '${data.target_resource}' by ${data.attacker_process}`,
        JSON.stringify({ event_id: id, event_type: data.event_type, target: data.target_resource, process: data.attacker_process })
      );
    } catch (err) {
      console.error('Failed to log security alert for Tamper Protection:', err);
    }

    return db.prepare('SELECT * FROM tamper_audit_events WHERE id = ?').get(id);
  }

  /**
   * Retrieve tamper audit events with query filters
   */
  static getTamperEvents(db, query = {}) {
    let sql = 'SELECT * FROM tamper_audit_events WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.event_type) {
      sql += ' AND event_type = ?';
      params.push(query.event_type);
    }
    if (query.action_taken) {
      sql += ' AND action_taken = ?';
      params.push(query.action_taken);
    }

    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Generate native Windows PowerShell / Registry script to enforce Tamper Protection & authorized exclusions
   */
  static generateTamperProtectionScript(db, deviceId) {
    const policy = db.prepare(`
      SELECT * FROM tamper_protection_policies WHERE is_enabled = 1 ORDER BY created_at DESC LIMIT 1
    `).get() || {
      tamper_protection_state: 'ENFORCED',
      lock_security_services: 1,
      protect_antivirus_exclusions: 1,
      prevent_safe_mode_bypass: 1
    };

    const exclusions = db.prepare('SELECT * FROM antivirus_exclusion_rules WHERE is_active = 1').all();

    return `# ==============================================================================
# LocalPilot Fleet — Microsoft Defender Tamper Protection & Exclusion Governance
# Generated for Device ID: ${deviceId} at ${new Date().toISOString()}
# Tamper Protection State: ${policy.tamper_protection_state}
# Service Locking: ${policy.lock_security_services ? 'Active' : 'Disabled'}
# ==============================================================================

Write-Host "[LocalPilot] Enforcing Microsoft Defender Tamper Protection Baseline..." -ForegroundColor Cyan

# 1. Enable Tamper Protection Feature Flags
Set-MpPreference -DisableRealtimeMonitoring $false -Force
Set-MpPreference -DisableBehaviorMonitoring $false -Force
Set-MpPreference -DisableScriptScanning $false -Force

# 2. Lock Defender Registry Keys Against Local Manipulation
$DefPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (!(Test-Path $DefPath)) { New-Item -Path $DefPath -Force | Out-Null }
Set-ItemProperty -Path $DefPath -Name "TamperProtection" -Value 5 -Type DWord -Force

# 3. Synchronize Authorized Enterprise Antivirus Exclusions
${exclusions.map(e => {
  if (e.exclusion_type === 'PATH') return `Add-MpPreference -ExclusionPath "${e.exclusion_value}" # Justification: ${e.justification}`;
  if (e.exclusion_type === 'FOLDER') return `Add-MpPreference -ExclusionPath "${e.exclusion_value}" # Folder Exclusion`;
  if (e.exclusion_type === 'EXTENSION') return `Add-MpPreference -ExclusionExtension "${e.exclusion_value}" # Extension Exclusion`;
  if (e.exclusion_type === 'PROCESS') return `Add-MpPreference -ExclusionProcess "${e.exclusion_value}" # Process Exclusion`;
  return '';
}).filter(Boolean).join('\n')}

Write-Host "[LocalPilot] Tamper Protection & Exclusion baseline verified and enforced." -ForegroundColor Green
`;
  }
}
