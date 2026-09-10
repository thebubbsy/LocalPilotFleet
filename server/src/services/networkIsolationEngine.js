/**
 * LocalPilot Fleet — Network Isolation & Host Quarantine Governance Service Engine
 * server/src/services/networkIsolationEngine.js
 *
 * Implements Defender for Endpoint & CrowdStrike Falcon equivalent live network isolation,
 * WFP firewall packet-filter containment, SecOps out-of-band exclusions, and forensic packet drop logging.
 */

import crypto from 'node:crypto';

export class NetworkIsolationEngine {
  /**
   * Aggregate fleet-wide host isolation and containment statistics
   */
  static getIsolationStats(db) {
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM network_isolation_policies').get()?.count || 0;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM network_isolation_policies WHERE is_enabled = 1').get()?.count || 0;
    const totalExclusions = db.prepare('SELECT COUNT(*) as count FROM isolation_exclusion_endpoints').get()?.count || 0;

    const totalLogs = db.prepare('SELECT COUNT(*) as count FROM isolation_audit_logs').get()?.count || 0;
    const isolatedHosts = db.prepare("SELECT COUNT(*) as count FROM host_containment_states WHERE containment_status = 'CONTAINED'").get()?.count || 0;
    const droppedPackets = db.prepare("SELECT COUNT(*) as count FROM isolation_audit_logs WHERE transition_type = 'UNAUTHORIZED_TRAFFIC_DROPPED'").get()?.count || 0;

    return {
      totalPolicies,
      activePolicies,
      totalExclusions,
      isolatedHosts,
      totalLogs,
      droppedPackets,
      containmentSla: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve all network isolation policies
   */
  static getPolicies(db) {
    return db.prepare('SELECT * FROM network_isolation_policies ORDER BY created_at DESC').all();
  }

  /**
   * Retrieve single isolation policy with attached out-of-band exclusion endpoints
   */
  static getPolicyById(db, id) {
    const policy = db.prepare('SELECT * FROM network_isolation_policies WHERE id = ?').get(id);
    if (!policy) return null;

    const exclusions = db.prepare('SELECT * FROM isolation_exclusion_endpoints WHERE policy_id = ? ORDER BY created_at ASC').all(id);
    return {
      ...policy,
      exclusions
    };
  }

  /**
   * Create a new network isolation policy
   */
  static createPolicy(db, data) {
    const id = data.id || ('nip-' + crypto.randomBytes(6).toString('hex'));
    const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1;
    const allowDns = data.allow_dns !== undefined ? (data.allow_dns ? 1 : 0) : 1;
    const allowDhcp = data.allow_dhcp !== undefined ? (data.allow_dhcp ? 1 : 0) : 1;
    const allowTelemetry = data.allow_fleet_telemetry !== undefined ? (data.allow_fleet_telemetry ? 1 : 0) : 1;

    const stmt = db.prepare(`
      INSERT INTO network_isolation_policies (
        id, name, description, target_scope, target_id, isolation_mode,
        allow_dns, allow_dhcp, allow_fleet_telemetry, honeypot_redirect_ip, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.description || null,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.isolation_mode || 'SELECTIVE_MANAGEMENT',
      allowDns,
      allowDhcp,
      allowTelemetry,
      data.honeypot_redirect_ip || null,
      isEnabled
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing network isolation policy
   */
  static updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM network_isolation_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_scope = updates.target_scope !== undefined ? updates.target_scope : existing.target_scope;
    const target_id = updates.target_id !== undefined ? updates.target_id : existing.target_id;
    const isolation_mode = updates.isolation_mode !== undefined ? updates.isolation_mode : existing.isolation_mode;
    const allow_dns = updates.allow_dns !== undefined ? (updates.allow_dns ? 1 : 0) : existing.allow_dns;
    const allow_dhcp = updates.allow_dhcp !== undefined ? (updates.allow_dhcp ? 1 : 0) : existing.allow_dhcp;
    const allow_fleet_telemetry = updates.allow_fleet_telemetry !== undefined ? (updates.allow_fleet_telemetry ? 1 : 0) : existing.allow_fleet_telemetry;
    const honeypot_redirect_ip = updates.honeypot_redirect_ip !== undefined ? updates.honeypot_redirect_ip : existing.honeypot_redirect_ip;
    const is_enabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE network_isolation_policies SET
        name = ?, description = ?, target_scope = ?, target_id = ?,
        isolation_mode = ?, allow_dns = ?, allow_dhcp = ?,
        allow_fleet_telemetry = ?, honeypot_redirect_ip = ?,
        is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_scope, target_id, isolation_mode,
      allow_dns, allow_dhcp, allow_fleet_telemetry, honeypot_redirect_ip,
      is_enabled, id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete policy and cascaded exclusion endpoints
   */
  static deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM network_isolation_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get out-of-band exclusion endpoints
   */
  static getExclusions(db, policyId = null) {
    if (policyId) {
      return db.prepare('SELECT * FROM isolation_exclusion_endpoints WHERE policy_id = ? ORDER BY created_at DESC').all(policyId);
    }
    return db.prepare('SELECT * FROM isolation_exclusion_endpoints ORDER BY created_at DESC').all();
  }

  /**
   * Create an out-of-band exclusion endpoint
   */
  static createExclusion(db, data) {
    const id = data.id || ('iee-' + crypto.randomBytes(6).toString('hex'));
    const isActive = data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1;

    db.prepare(`
      INSERT INTO isolation_exclusion_endpoints (
        id, policy_id, friendly_name, endpoint_type, endpoint_value, direction, port, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.policy_id || null,
      data.friendly_name,
      data.endpoint_type || 'IP_ADDRESS',
      data.endpoint_value,
      data.direction || 'OUTBOUND',
      data.port || null,
      isActive
    );

    return db.prepare('SELECT * FROM isolation_exclusion_endpoints WHERE id = ?').get(id);
  }

  /**
   * Delete an exclusion endpoint
   */
  static deleteExclusion(db, id) {
    const res = db.prepare('DELETE FROM isolation_exclusion_endpoints WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Isolate a target endpoint (engage WFP containment)
   */
  static isolateDevice(db, deviceId, { reason, initiated_by = 'SecOps Console', isolation_type = 'ALLOW_FLEET_MANAGEMENT_ONLY' } = {}) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    db.prepare(`
      INSERT INTO host_containment_states (
        device_id, containment_status, isolation_type, isolated_at, isolated_by, reason, updated_at
      ) VALUES (?, 'CONTAINED', ?, DATETIME('now'), ?, ?, DATETIME('now'))
      ON CONFLICT(device_id) DO UPDATE SET
        containment_status = 'CONTAINED',
        isolation_type = excluded.isolation_type,
        isolated_at = excluded.isolated_at,
        isolated_by = excluded.isolated_by,
        reason = excluded.reason,
        updated_at = DATETIME('now')
    `).run(deviceId, isolation_type, initiated_by, reason || 'Manual emergency containment dispatched by SecOps');

    // Emit forensic audit log
    const logId = 'ial-' + crypto.randomBytes(6).toString('hex');
    db.prepare(`
      INSERT INTO isolation_audit_logs (
        id, device_id, hostname, transition_type, initiated_by, reason,
        packet_summary, details, severity
      ) VALUES (?, ?, ?, 'HOST_ISOLATED', ?, ?, 'WFP rules engaged: DROP_ALL except LocalPilot server', ?, 'CRITICAL')
    `).run(
      logId,
      deviceId,
      device.hostname,
      initiated_by,
      reason || 'Active threat quarantine',
      JSON.stringify({ isolation_type, engaged_firewall: 'WFP_LOCALPILOT_ISOLATE' })
    );

    // Record security event
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
        ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7004, 'NETWORK_ISOLATION_ENGINE', 'CRITICAL', ?, ?, 0)
      `).run(
        deviceId,
        `CRITICAL: Host network isolation engaged for ${device.hostname} (${deviceId}) - ${reason || 'Emergency Containment'}`,
        JSON.stringify({ device_id: deviceId, isolation_type, initiated_by })
      );
    } catch {}

    return db.prepare('SELECT * FROM host_containment_states WHERE device_id = ?').get(deviceId);
  }

  /**
   * Release a contained endpoint back into production network
   */
  static releaseDevice(db, deviceId, { reason, initiated_by = 'SecOps Console' } = {}) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    db.prepare(`
      UPDATE host_containment_states SET
        containment_status = 'UNCONTAINED',
        updated_at = DATETIME('now')
      WHERE device_id = ?
    `).run(deviceId);

    // Emit audit log
    const logId = 'ial-' + crypto.randomBytes(6).toString('hex');
    db.prepare(`
      INSERT INTO isolation_audit_logs (
        id, device_id, hostname, transition_type, initiated_by, reason,
        packet_summary, details, severity
      ) VALUES (?, ?, ?, 'HOST_RELEASED', ?, ?, 'WFP isolation rules revoked: Full network access restored', ?, 'INFO')
    `).run(
      logId,
      deviceId,
      device.hostname,
      initiated_by,
      reason || 'Remediation completed and verified',
      JSON.stringify({ released_at: new Date().toISOString() })
    );

    return db.prepare('SELECT * FROM host_containment_states WHERE device_id = ?').get(deviceId);
  }

  /**
   * Log an isolation event (packet drop, unauthorized connection attempt)
   */
  static logIsolationEvent(db, data) {
    const id = data.id || ('ial-' + crypto.randomBytes(6).toString('hex'));
    const severity = data.severity || (data.transition_type === 'HOST_ISOLATED' ? 'CRITICAL' : 'HIGH');
    const detailsStr = typeof data.details === 'object' ? JSON.stringify(data.details) : (data.details || null);

    db.prepare(`
      INSERT INTO isolation_audit_logs (
        id, device_id, hostname, transition_type, initiated_by, reason,
        packet_summary, details, severity
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.device_id,
      data.hostname || 'Unknown-Node',
      data.transition_type,
      data.initiated_by || 'Windows Filtering Platform',
      data.reason || 'Network packet dropped by host isolation filter',
      data.packet_summary || null,
      detailsStr,
      severity
    );

    return db.prepare('SELECT * FROM isolation_audit_logs WHERE id = ?').get(id);
  }

  /**
   * Retrieve isolation audit logs with query filters
   */
  static getIsolationLogs(db, query = {}) {
    let sql = 'SELECT * FROM isolation_audit_logs WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.transition_type) {
      sql += ' AND transition_type = ?';
      params.push(query.transition_type);
    }

    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Generate native Windows PowerShell / WFP netsh script to enforce host quarantine
   */
  static generateIsolationScript(db, deviceId) {
    const state = db.prepare('SELECT * FROM host_containment_states WHERE device_id = ?').get(deviceId) || {
      containment_status: 'CONTAINED',
      isolation_type: 'ALLOW_FLEET_MANAGEMENT_ONLY'
    };

    const exclusions = db.prepare('SELECT * FROM isolation_exclusion_endpoints WHERE is_active = 1').all();

    if (state.containment_status === 'UNCONTAINED') {
      return `# LocalPilot Fleet — Restore Network Access
Write-Host "[LocalPilot] Revoking Host Isolation Rules..." -ForegroundColor Cyan
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Block-Inbound" | Out-Null
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Block-Outbound" | Out-Null
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Allow-Management" | Out-Null
Write-Host "[LocalPilot] Endpoint network access fully restored." -ForegroundColor Green
`;
    }

    return `# ==============================================================================
# LocalPilot Fleet — Host Network Quarantine & Isolation Enforcement
# Generated for Device ID: ${deviceId} at ${new Date().toISOString()}
# Isolation Mode: ${state.isolation_type}
# ==============================================================================

Write-Host "[LocalPilot] Engaging Emergency Host Network Isolation..." -ForegroundColor Yellow

# 1. Flush Existing Quarantine Rules
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Block-Inbound" | Out-Null
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Block-Outbound" | Out-Null
netsh advfirewall firewall delete rule name="LocalPilot-Isolation-Allow-Management" | Out-Null

# 2. Block All Inbound and Outbound Traffic (Zero-Trust Quarantine)
netsh advfirewall firewall add rule name="LocalPilot-Isolation-Block-Inbound" dir=in action=block protocol=any enable=yes | Out-Null
netsh advfirewall firewall add rule name="LocalPilot-Isolation-Block-Outbound" dir=out action=block protocol=any enable=yes | Out-Null

# 3. Allow Out-of-Band SecOps Management & LocalPilot Server
netsh advfirewall firewall add rule name="LocalPilot-Isolation-Allow-Management" dir=out action=allow remoteip=127.0.0.1 remoteport=8443 protocol=TCP enable=yes | Out-Null

# 4. Out-of-band Endpoint Exceptions
${exclusions.map(e => {
  return `# Whitelist Exception: ${e.friendly_name} (${e.endpoint_type}: ${e.endpoint_value})
netsh advfirewall firewall add rule name="LocalPilot-Iso-Allow-${e.id}" dir=out action=allow remoteip=${e.endpoint_value} enable=yes | Out-Null`;
}).join('\n')}

# 5. Allow DNS (UDP 53) and DHCP (UDP 67,68) for lease persistence
netsh advfirewall firewall add rule name="LocalPilot-Isolation-Allow-DNS" dir=out action=allow protocol=UDP remoteport=53 enable=yes | Out-Null
netsh advfirewall firewall add rule name="LocalPilot-Isolation-Allow-DHCP" dir=out action=allow protocol=UDP remoteport=67,68 enable=yes | Out-Null

Write-Host "[LocalPilot] Host network containment active. Only authorized fleet channels permitted." -ForegroundColor Red
`;
  }
}
