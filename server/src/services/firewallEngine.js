/**
 * LocalPilot Fleet — Microsoft Intune Windows Firewall Rules & Network Perimeter Governance Engine
 * server/src/services/firewallEngine.js
 *
 * Provides enterprise firewall policy definitions, port filtering, profile enforcement,
 * open listening port sentinel monitoring, risk classification, and drift detection.
 */

import { broadcastEvent } from '../routes/events.js';

const HIGH_RISK_PORTS = new Set([23, 137, 138, 139, 445, 3389, 5900]);
const MEDIUM_RISK_PORTS = new Set([21, 22, 5985, 5986]);

/**
 * Log a security event into the database
 */
function logSecurityEvent(db, { deviceId, eventType, severity, summary, payload = {} }) {
  try {
    const insert = db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `);
    insert.run(
      deviceId,
      eventType,
      4000,
      'Microsoft-Windows-WindowsFirewall',
      severity,
      summary,
      JSON.stringify(payload)
    );
  } catch (err) {
    console.warn('[FirewallEngine] Failed to log security event:', err.message);
  }
}

/**
 * Create an enterprise firewall rule
 */
export function createRule(db, payload) {
  const {
    name,
    description = '',
    direction = 'INBOUND',
    action = 'ALLOW',
    protocol = 'TCP',
    local_ports = 'ANY',
    remote_ports = 'ANY',
    local_addresses = '*',
    remote_addresses = '*',
    profiles = ['Domain', 'Private', 'Public'],
    program_path = 'ANY',
    service_name = 'ANY',
    target_group_id = 'grp-all',
    enabled = 1,
    priority = 100
  } = payload;

  if (!name || !name.trim()) {
    throw new Error('Firewall rule name is required');
  }

  const validDirections = ['INBOUND', 'OUTBOUND'];
  if (!validDirections.includes(direction.toUpperCase())) {
    throw new Error(`Invalid direction: ${direction}. Allowed: ${validDirections.join(', ')}`);
  }

  const validActions = ['ALLOW', 'BLOCK'];
  if (!validActions.includes(action.toUpperCase())) {
    throw new Error(`Invalid action: ${action}. Allowed: ${validActions.join(', ')}`);
  }

  const validProtocols = ['TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'ANY'];
  if (!validProtocols.includes(protocol.toUpperCase())) {
    throw new Error(`Invalid protocol: ${protocol}. Allowed: ${validProtocols.join(', ')}`);
  }

  const id = `fwr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const profilesJson = Array.isArray(profiles) ? JSON.stringify(profiles) : profiles;

  const insert = db.prepare(`
    INSERT INTO firewall_rules (
      id, name, description, direction, action, protocol,
      local_ports, remote_ports, local_addresses, remote_addresses,
      profiles_json, program_path, service_name, target_group_id,
      enabled, priority, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `);

  insert.run(
    id,
    name.trim(),
    description,
    direction.toUpperCase(),
    action.toUpperCase(),
    protocol.toUpperCase(),
    local_ports.trim(),
    remote_ports.trim(),
    local_addresses.trim(),
    remote_addresses.trim(),
    profilesJson,
    program_path.trim(),
    service_name.trim(),
    target_group_id,
    enabled ? 1 : 0,
    Number(priority) || 100
  );

  return getRule(db, id);
}

/**
 * Get firewall rule by ID
 */
export function getRule(db, id) {
  const row = db.prepare(`
    SELECT r.*, g.name AS target_group_name
    FROM firewall_rules r
    LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
    WHERE r.id = ?
  `).get(id);

  if (!row) return null;

  try { row.profiles = JSON.parse(row.profiles_json || '[]'); } catch (_) { row.profiles = []; }
  return row;
}

/**
 * List all firewall rules with optional filters
 */
export function getRules(db, options = {}) {
  let query = `
    SELECT r.*, g.name AS target_group_name
    FROM firewall_rules r
    LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
    WHERE 1=1
  `;
  const params = [];

  if (options.direction) {
    query += ' AND r.direction = ?';
    params.push(options.direction.toUpperCase());
  }

  if (options.action) {
    query += ' AND r.action = ?';
    params.push(options.action.toUpperCase());
  }

  if (options.target_group_id) {
    query += ' AND r.target_group_id = ?';
    params.push(options.target_group_id);
  }

  if (options.enabled !== undefined) {
    query += ' AND r.enabled = ?';
    params.push(options.enabled ? 1 : 0);
  }

  query += ' ORDER BY r.priority ASC, r.created_at DESC';

  const rows = db.prepare(query).all(...params);
  return rows.map(r => {
    try { r.profiles = JSON.parse(r.profiles_json || '[]'); } catch (_) { r.profiles = []; }
    return r;
  });
}

/**
 * Update an existing firewall rule
 */
export function updateRule(db, id, updates) {
  const existing = getRule(db, id);
  if (!existing) return null;

  const validDirections = ['INBOUND', 'OUTBOUND'];
  const validActions = ['ALLOW', 'BLOCK'];
  const validProtocols = ['TCP', 'UDP', 'ICMPv4', 'ICMPv6', 'ANY'];

  if (updates.direction && !validDirections.includes(updates.direction.toUpperCase())) {
    throw new Error(`Invalid direction: ${updates.direction}`);
  }
  if (updates.action && !validActions.includes(updates.action.toUpperCase())) {
    throw new Error(`Invalid action: ${updates.action}`);
  }
  if (updates.protocol && !validProtocols.includes(updates.protocol.toUpperCase())) {
    throw new Error(`Invalid protocol: ${updates.protocol}`);
  }

  const name = updates.name !== undefined ? updates.name.trim() : existing.name;
  const description = updates.description !== undefined ? updates.description : existing.description;
  const direction = updates.direction !== undefined ? updates.direction.toUpperCase() : existing.direction;
  const action = updates.action !== undefined ? updates.action.toUpperCase() : existing.action;
  const protocol = updates.protocol !== undefined ? updates.protocol.toUpperCase() : existing.protocol;
  const local_ports = updates.local_ports !== undefined ? updates.local_ports : existing.local_ports;
  const remote_ports = updates.remote_ports !== undefined ? updates.remote_ports : existing.remote_ports;
  const local_addresses = updates.local_addresses !== undefined ? updates.local_addresses : existing.local_addresses;
  const remote_addresses = updates.remote_addresses !== undefined ? updates.remote_addresses : existing.remote_addresses;
  const profilesJson = updates.profiles !== undefined
    ? (Array.isArray(updates.profiles) ? JSON.stringify(updates.profiles) : updates.profiles)
    : existing.profiles_json;
  const program_path = updates.program_path !== undefined ? updates.program_path : existing.program_path;
  const service_name = updates.service_name !== undefined ? updates.service_name : existing.service_name;
  const target_group_id = updates.target_group_id !== undefined ? updates.target_group_id : existing.target_group_id;
  const enabled = updates.enabled !== undefined ? (updates.enabled ? 1 : 0) : existing.enabled;
  const priority = updates.priority !== undefined ? Number(updates.priority) : existing.priority;

  db.prepare(`
    UPDATE firewall_rules
    SET name = ?, description = ?, direction = ?, action = ?, protocol = ?,
        local_ports = ?, remote_ports = ?, local_addresses = ?, remote_addresses = ?,
        profiles_json = ?, program_path = ?, service_name = ?, target_group_id = ?,
        enabled = ?, priority = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    name, description, direction, action, protocol,
    local_ports, remote_ports, local_addresses, remote_addresses,
    profilesJson, program_path, service_name, target_group_id,
    enabled, priority, id
  );

  return getRule(db, id);
}

/**
 * Delete a firewall rule
 */
export function deleteRule(db, id) {
  const existing = getRule(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM firewall_rules WHERE id = ?').run(id);
  return true;
}

/**
 * Get all effective firewall rules for a device based on its dynamic groups
 */
export function getEffectiveRulesForDevice(db, deviceId) {
  // 1. Get assigned groups for this device
  const memberships = db.prepare(`
    SELECT group_id FROM group_memberships WHERE device_id = ?
  `).all(deviceId).map(m => m.group_id);

  const groupIds = ['grp-all', ...memberships];
  const placeholders = groupIds.map(() => '?').join(',');

  const rows = db.prepare(`
    SELECT r.*, g.name AS target_group_name
    FROM firewall_rules r
    LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
    WHERE r.enabled = 1 AND r.target_group_id IN (${placeholders})
    ORDER BY r.priority ASC, r.created_at DESC
  `).all(...groupIds);

  return rows.map(r => {
    try { r.profiles = JSON.parse(r.profiles_json || '[]'); } catch (_) { r.profiles = []; }
    return r;
  });
}

/**
 * Ingest and record device firewall status & profile state
 */
export function saveDeviceFirewallStatus(db, deviceId, payload) {
  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) {
    throw new Error(`Device not found: ${deviceId}`);
  }

  const domainEnabled = payload.domain_profile_enabled !== undefined ? (payload.domain_profile_enabled ? 1 : 0) : 1;
  const privateEnabled = payload.private_profile_enabled !== undefined ? (payload.private_profile_enabled ? 1 : 0) : 1;
  const publicEnabled = payload.public_profile_enabled !== undefined ? (payload.public_profile_enabled ? 1 : 0) : 1;

  const domainInbound = payload.domain_inbound_action || 'Block';
  const privateInbound = payload.private_inbound_action || 'Block';
  const publicInbound = payload.public_inbound_action || 'Block';
  const stealthMode = payload.stealth_mode_enabled !== undefined ? (payload.stealth_mode_enabled ? 1 : 0) : 1;
  const activeRulesCount = Number(payload.active_rules_count || 0);

  // Compliance evaluation
  let complianceStatus = 'COMPLIANT';
  const driftReasons = [];

  if (domainEnabled === 0) driftReasons.push('Domain profile is disabled');
  if (privateEnabled === 0) driftReasons.push('Private profile is disabled');
  if (publicEnabled === 0) driftReasons.push('Public profile is disabled');
  if (publicInbound.toLowerCase() === 'allow') driftReasons.push('Public inbound action is Allow (should be Block)');

  if (driftReasons.length > 0) {
    complianceStatus = 'NON_COMPLIANT';
    logSecurityEvent(db, {
      deviceId,
      eventType: 'FIREWALL_PROFILE_DISABLED',
      severity: 'HIGH',
      summary: `Windows Firewall drift detected on ${device.hostname}: ${driftReasons.join(', ')}`,
      payload: { drift_reasons: driftReasons, profiles: { domain: domainEnabled, private: privateEnabled, public: publicEnabled } }
    });
  }

  const existing = db.prepare('SELECT id FROM device_firewall_status WHERE device_id = ?').get(deviceId);
  const driftJson = JSON.stringify({ reasons: driftReasons });

  if (existing) {
    db.prepare(`
      UPDATE device_firewall_status
      SET domain_profile_enabled = ?, private_profile_enabled = ?, public_profile_enabled = ?,
          domain_inbound_action = ?, private_inbound_action = ?, public_inbound_action = ?,
          stealth_mode_enabled = ?, active_rules_count = ?, compliance_status = ?,
          drift_summary_json = ?, last_audit_at = DATETIME('now'), updated_at = DATETIME('now')
      WHERE device_id = ?
    `).run(
      domainEnabled, privateEnabled, publicEnabled,
      domainInbound, privateInbound, publicInbound,
      stealthMode, activeRulesCount, complianceStatus,
      driftJson, deviceId
    );
  } else {
    const id = `dfs-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    db.prepare(`
      INSERT INTO device_firewall_status (
        id, device_id, domain_profile_enabled, private_profile_enabled, public_profile_enabled,
        domain_inbound_action, private_inbound_action, public_inbound_action, stealth_mode_enabled,
        active_rules_count, compliance_status, drift_summary_json, last_audit_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))
    `).run(
      id, deviceId, domainEnabled, privateEnabled, publicEnabled,
      domainInbound, privateInbound, publicInbound, stealthMode,
      activeRulesCount, complianceStatus, driftJson
    );
  }

  return getDeviceFirewallStatus(db, deviceId);
}

/**
 * Get device firewall status
 */
export function getDeviceFirewallStatus(db, deviceId) {
  const row = db.prepare(`
    SELECT s.*, d.hostname, d.friendly_name
    FROM device_firewall_status s
    JOIN devices d ON s.device_id = d.id
    WHERE s.device_id = ?
  `).get(deviceId);

  if (!row) return null;
  try { row.drift_summary = JSON.parse(row.drift_summary_json || '{}'); } catch (_) { row.drift_summary = {}; }
  return row;
}

/**
 * Ingest and record open listening TCP/UDP ports from node agent
 */
export function saveDeviceListeningPorts(db, deviceId, ports = []) {
  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) {
    throw new Error(`Device not found: ${deviceId}`);
  }

  // Delete older listening ports for this device to refresh state
  db.prepare('DELETE FROM device_listening_ports WHERE device_id = ?').run(deviceId);

  const insert = db.prepare(`
    INSERT OR REPLACE INTO device_listening_ports (
      id, device_id, protocol, local_address, local_port,
      owning_process_id, process_name, service_name, risk_level,
      status, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))
  `);

  const results = [];
  let rogueExposedFound = false;

  for (const p of ports) {
    const portNum = Number(p.local_port);
    if (!portNum || isNaN(portNum)) continue;

    const protocol = (p.protocol || 'TCP').toUpperCase();
    const localAddress = (p.local_address || '0.0.0.0').trim();
    const isPublicBinding = localAddress === '0.0.0.0' || localAddress === '::' || localAddress === '*';
    const isLoopback = localAddress === '127.0.0.1' || localAddress === '::1' || localAddress.startsWith('127.');

    let riskLevel = 'LOW';
    let status = 'AUTHORIZED';

    if (HIGH_RISK_PORTS.has(portNum)) {
      if (isPublicBinding) {
        riskLevel = 'CRITICAL';
        status = 'EXPOSED_PUBLIC';
        rogueExposedFound = true;
      } else if (!isLoopback) {
        riskLevel = 'HIGH';
        status = 'SUSPICIOUS';
      }
    } else if (MEDIUM_RISK_PORTS.has(portNum)) {
      if (isPublicBinding) {
        riskLevel = 'MEDIUM';
        status = 'EXPOSED_PUBLIC';
      }
    }

    const id = `dlp-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    insert.run(
      id,
      deviceId,
      protocol,
      localAddress,
      portNum,
      p.owning_process_id ? Number(p.owning_process_id) : null,
      p.process_name || 'System',
      p.service_name || null,
      riskLevel,
      status
    );

    results.push({
      id,
      device_id: deviceId,
      protocol,
      local_address: localAddress,
      local_port: portNum,
      owning_process_id: p.owning_process_id,
      process_name: p.process_name,
      risk_level: riskLevel,
      status
    });
  }

  if (rogueExposedFound) {
    logSecurityEvent(db, {
      deviceId,
      eventType: 'ROGUE_PORT_DETECTED',
      severity: 'CRITICAL',
      summary: `High-risk open network port exposed publicly on ${device.hostname}`,
      payload: { exposed_ports: results.filter(r => r.risk_level === 'CRITICAL') }
    });
  }

  return results;
}

/**
 * Get listening ports for a device
 */
export function getDeviceListeningPorts(db, deviceId) {
  return db.prepare(`
    SELECT * FROM device_listening_ports
    WHERE device_id = ?
    ORDER BY risk_level = 'CRITICAL' DESC, risk_level = 'HIGH' DESC, local_port ASC
  `).all(deviceId);
}

/**
 * Get fleet-wide firewall and perimeter statistics
 */
export function getFleetFirewallStats(db) {
  const totalRules = db.prepare('SELECT COUNT(*) AS c FROM firewall_rules').get().c;
  const enabledRules = db.prepare('SELECT COUNT(*) AS c FROM firewall_rules WHERE enabled = 1').get().c;
  const monitoredDevices = db.prepare('SELECT COUNT(*) AS c FROM device_firewall_status').get().c;
  const compliantDevices = db.prepare("SELECT COUNT(*) AS c FROM device_firewall_status WHERE compliance_status = 'COMPLIANT'").get().c;
  const driftedDevices = db.prepare("SELECT COUNT(*) AS c FROM device_firewall_status WHERE compliance_status != 'COMPLIANT'").get().c;
  const totalOpenPorts = db.prepare('SELECT COUNT(*) AS c FROM device_listening_ports').get().c;
  const exposedHighRiskPorts = db.prepare("SELECT COUNT(*) AS c FROM device_listening_ports WHERE risk_level IN ('HIGH', 'CRITICAL')").get().c;

  return {
    total_rules: totalRules,
    enabled_rules: enabledRules,
    monitored_devices: monitoredDevices,
    compliant_devices: compliantDevices,
    drifted_devices: driftedDevices,
    total_open_ports: totalOpenPorts,
    exposed_high_risk_ports: exposedHighRiskPorts
  };
}

/**
 * Get fleet-wide open listening ports inventory
 */
export function getFleetListeningPorts(db, options = {}) {
  let query = `
    SELECT p.*, d.hostname, d.friendly_name
    FROM device_listening_ports p
    JOIN devices d ON p.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (options.risk_level) {
    query += ' AND p.risk_level = ?';
    params.push(options.risk_level.toUpperCase());
  }

  if (options.status) {
    query += ' AND p.status = ?';
    params.push(options.status.toUpperCase());
  }

  if (options.protocol) {
    query += ' AND p.protocol = ?';
    params.push(options.protocol.toUpperCase());
  }

  query += `
    ORDER BY 
      CASE p.risk_level 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        ELSE 4 
      END ASC,
      p.local_port ASC
  `;

  if (options.limit) {
    query += ' LIMIT ?';
    params.push(Number(options.limit));
  }

  return db.prepare(query).all(...params);
}
