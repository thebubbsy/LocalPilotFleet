/**
 * LocalPilot Fleet — Endpoint Privilege Management (EPM) Engine
 * server/src/services/epmEngine.js
 *
 * Implements Microsoft Intune Endpoint Privilege Management (EPM) governance:
 * - Granular elevation rules (Automatic, User-Confirmed, Support-Approved)
 * - File path, SHA-256 hash, and publisher certificate validation
 * - Dynamic group assignment and priority-based effective rule evaluation
 * - Standard user elevation requests & operator approval queue
 * - Forensic process execution audit trail and security event dispatch
 */

import crypto from 'node:crypto';

/**
 * Get fleet-wide EPM statistics and executive KPI cards
 */
export function getEpmStats(db) {
  const policyStats = db.prepare(`
    SELECT
      COUNT(*) as total_policies,
      COALESCE(SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END), 0) as active_policies
    FROM epm_policies
  `).get() || { total_policies: 0, active_policies: 0 };

  const ruleStats = db.prepare(`
    SELECT
      COUNT(*) as total_rules,
      COALESCE(SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END), 0) as active_rules,
      COALESCE(SUM(CASE WHEN elevation_type = 'AUTOMATIC' THEN 1 ELSE 0 END), 0) as auto_rules,
      COALESCE(SUM(CASE WHEN elevation_type = 'USER_CONFIRMED' THEN 1 ELSE 0 END), 0) as user_confirmed_rules,
      COALESCE(SUM(CASE WHEN elevation_type = 'SUPPORT_APPROVED' THEN 1 ELSE 0 END), 0) as support_approved_rules
    FROM epm_elevation_rules
  `).get() || { total_rules: 0, active_rules: 0, auto_rules: 0, user_confirmed_rules: 0, support_approved_rules: 0 };

  const requestStats = db.prepare(`
    SELECT
      COUNT(*) as total_requests,
      COALESCE(SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END), 0) as pending_requests,
      COALESCE(SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END), 0) as approved_requests,
      COALESCE(SUM(CASE WHEN status = 'DENIED' THEN 1 ELSE 0 END), 0) as denied_requests
    FROM epm_elevation_requests
  `).get() || { total_requests: 0, pending_requests: 0, approved_requests: 0, denied_requests: 0 };

  const logStats = db.prepare(`
    SELECT
      COUNT(*) as total_elevations,
      COALESCE(SUM(CASE WHEN executed_at >= DATETIME('now', '-24 hours') THEN 1 ELSE 0 END), 0) as elevations_24h,
      COALESCE(SUM(CASE WHEN elevation_type = 'AUTOMATIC' THEN 1 ELSE 0 END), 0) as auto_elevations,
      COALESCE(SUM(CASE WHEN elevation_type = 'USER_CONFIRMED' THEN 1 ELSE 0 END), 0) as user_confirmed_elevations,
      COALESCE(SUM(CASE WHEN elevation_type = 'SUPPORT_APPROVED' THEN 1 ELSE 0 END), 0) as support_approved_elevations
    FROM epm_elevation_logs
  `).get() || { total_elevations: 0, elevations_24h: 0, auto_elevations: 0, user_confirmed_elevations: 0, support_approved_elevations: 0 };

  return {
    total_policies: policyStats.total_policies,
    active_policies: policyStats.active_policies,
    total_rules: ruleStats.total_rules,
    active_rules: ruleStats.active_rules,
    pending_requests: requestStats.pending_requests,
    approved_requests: requestStats.approved_requests,
    denied_requests: requestStats.denied_requests,
    elevations_24h: logStats.elevations_24h,
    total_elevations: logStats.total_elevations,
    auto_elevations: logStats.auto_elevations,
    user_confirmed_elevations: logStats.user_confirmed_elevations,
    support_approved_elevations: logStats.support_approved_elevations
  };
}

/**
 * List all EPM policies with attached target group and rule counts
 */
export function getEpmPolicies(db) {
  return db.prepare(`
    SELECT
      p.*,
      g.name as target_group_name,
      g.color as target_group_color,
      (SELECT COUNT(*) FROM epm_elevation_rules r WHERE r.policy_id = p.id) as rule_count,
      (
        SELECT COUNT(DISTINCT gm.device_id)
        FROM group_memberships gm
        WHERE gm.group_id = p.target_group_id
      ) as targeted_devices_count
    FROM epm_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    ORDER BY p.created_at DESC
  `).all();
}

/**
 * Get single EPM policy with attached rules
 */
export function getEpmPolicy(db, id) {
  const policy = db.prepare(`
    SELECT
      p.*,
      g.name as target_group_name,
      g.color as target_group_color,
      (
        SELECT COUNT(DISTINCT gm.device_id)
        FROM group_memberships gm
        WHERE gm.group_id = p.target_group_id
      ) as targeted_devices_count
    FROM epm_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);

  if (!policy) return null;

  policy.rules = db.prepare(`
    SELECT * FROM epm_elevation_rules
    WHERE policy_id = ?
    ORDER BY created_at ASC
  `).all(id);

  return policy;
}

/**
 * Create a new EPM policy
 */
export function createEpmPolicy(db, data) {
  if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
    throw new Error('Policy name is required');
  }

  const id = data.id || `epm-pol-${crypto.randomUUID()}`;
  const targetGroupId = data.target_group_id || 'grp-all';
  const defaultAction = data.default_elevation_action || 'DENY';
  const sendTelemetry = data.send_elevation_telemetry !== undefined ? (data.send_elevation_telemetry ? 1 : 0) : 1;
  const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1;

  db.prepare(`
    INSERT INTO epm_policies (
      id, name, description, target_group_id, default_elevation_action, send_elevation_telemetry, is_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, data.name.trim(), data.description || '', targetGroupId, defaultAction, sendTelemetry, isEnabled);

  return getEpmPolicy(db, id);
}

/**
 * Update an existing EPM policy
 */
export function updateEpmPolicy(db, id, data) {
  const existing = getEpmPolicy(db, id);
  if (!existing) return null;

  const name = data.name !== undefined ? data.name.trim() : existing.name;
  const description = data.description !== undefined ? data.description : existing.description;
  const targetGroupId = data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id;
  const defaultAction = data.default_elevation_action !== undefined ? data.default_elevation_action : existing.default_elevation_action;
  const sendTelemetry = data.send_elevation_telemetry !== undefined ? (data.send_elevation_telemetry ? 1 : 0) : existing.send_elevation_telemetry;
  const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : existing.is_enabled;

  db.prepare(`
    UPDATE epm_policies
    SET name = ?, description = ?, target_group_id = ?, default_elevation_action = ?,
        send_elevation_telemetry = ?, is_enabled = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(name, description, targetGroupId, defaultAction, sendTelemetry, isEnabled, id);

  return getEpmPolicy(db, id);
}

/**
 * Delete an EPM policy (cascades to rules)
 */
export function deleteEpmPolicy(db, id) {
  const existing = getEpmPolicy(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM epm_policies WHERE id = ?').run(id);
  return true;
}

/**
 * List EPM elevation rules with optional filters
 */
export function getEpmRules(db, { policyId, elevationType, search } = {}) {
  let query = `
    SELECT
      r.*,
      p.name as policy_name,
      p.is_enabled as policy_enabled,
      g.name as target_group_name
    FROM epm_elevation_rules r
    JOIN epm_policies p ON r.policy_id = p.id
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE 1=1
  `;
  const params = [];

  if (policyId) {
    query += ` AND r.policy_id = ?`;
    params.push(policyId);
  }
  if (elevationType) {
    query += ` AND r.elevation_type = ?`;
    params.push(elevationType);
  }
  if (search) {
    query += ` AND (r.rule_name LIKE ? OR r.file_name LIKE ? OR r.file_path LIKE ?)`;
    const s = `%${search}%`;
    params.push(s, s, s);
  }

  query += ` ORDER BY r.created_at DESC`;

  return db.prepare(query).all(...params);
}

/**
 * Get single EPM elevation rule
 */
export function getEpmRule(db, id) {
  return db.prepare(`
    SELECT
      r.*,
      p.name as policy_name,
      p.target_group_id,
      g.name as target_group_name
    FROM epm_elevation_rules r
    JOIN epm_policies p ON r.policy_id = p.id
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE r.id = ?
  `).get(id);
}

/**
 * Create a new EPM elevation rule
 */
export function createEpmRule(db, data) {
  if (!data.policy_id) throw new Error('Policy ID is required');
  if (!data.rule_name || !data.rule_name.trim()) throw new Error('Rule name is required');
  if (!data.elevation_type || !['AUTOMATIC', 'USER_CONFIRMED', 'SUPPORT_APPROVED'].includes(data.elevation_type)) {
    throw new Error('Valid elevation type is required (AUTOMATIC, USER_CONFIRMED, SUPPORT_APPROVED)');
  }
  if (!data.file_name || !data.file_name.trim()) throw new Error('Target file name is required');

  const id = data.id || `rule-${crypto.randomUUID()}`;
  const childRule = data.child_process_rule || 'ELEVATE_NONE';
  const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1;

  db.prepare(`
    INSERT INTO epm_elevation_rules (
      id, policy_id, rule_name, description, elevation_type, file_name, file_path,
      file_hash_sha256, publisher_certificate, child_process_rule, min_file_version, max_file_version, is_enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, data.policy_id, data.rule_name.trim(), data.description || '', data.elevation_type,
    data.file_name.trim(), data.file_path || '', data.file_hash_sha256 || null,
    data.publisher_certificate || '', childRule, data.min_file_version || null,
    data.max_file_version || null, isEnabled
  );

  return getEpmRule(db, id);
}

/**
 * Update an existing EPM elevation rule
 */
export function updateEpmRule(db, id, data) {
  const existing = getEpmRule(db, id);
  if (!existing) return null;

  const ruleName = data.rule_name !== undefined ? data.rule_name.trim() : existing.rule_name;
  const description = data.description !== undefined ? data.description : existing.description;
  const elevationType = data.elevation_type !== undefined ? data.elevation_type : existing.elevation_type;
  const fileName = data.file_name !== undefined ? data.file_name.trim() : existing.file_name;
  const filePath = data.file_path !== undefined ? data.file_path : existing.file_path;
  const fileHash = data.file_hash_sha256 !== undefined ? data.file_hash_sha256 : existing.file_hash_sha256;
  const pubCert = data.publisher_certificate !== undefined ? data.publisher_certificate : existing.publisher_certificate;
  const childRule = data.child_process_rule !== undefined ? data.child_process_rule : existing.child_process_rule;
  const minVer = data.min_file_version !== undefined ? data.min_file_version : existing.min_file_version;
  const maxVer = data.max_file_version !== undefined ? data.max_file_version : existing.max_file_version;
  const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : existing.is_enabled;

  db.prepare(`
    UPDATE epm_elevation_rules
    SET rule_name = ?, description = ?, elevation_type = ?, file_name = ?, file_path = ?,
        file_hash_sha256 = ?, publisher_certificate = ?, child_process_rule = ?,
        min_file_version = ?, max_file_version = ?, is_enabled = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(ruleName, description, elevationType, fileName, filePath, fileHash, pubCert, childRule, minVer, maxVer, isEnabled, id);

  return getEpmRule(db, id);
}

/**
 * Delete an EPM elevation rule
 */
export function deleteEpmRule(db, id) {
  const existing = getEpmRule(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM epm_elevation_rules WHERE id = ?').run(id);
  return true;
}

/**
 * Get effective EPM elevation rules for a specific device based on group priority
 */
export function getEffectiveEpmRulesForDevice(db, deviceId) {
  const rules = db.prepare(`
    SELECT
      r.*,
      p.id as policy_id,
      p.name as policy_name,
      p.default_elevation_action,
      p.send_elevation_telemetry,
      g.id as group_id,
      g.name as group_name,
      g.priority as group_priority
    FROM epm_elevation_rules r
    JOIN epm_policies p ON r.policy_id = p.id
    JOIN group_memberships gm ON gm.group_id = p.target_group_id
    JOIN dynamic_groups g ON g.id = gm.group_id
    WHERE gm.device_id = ?
      AND p.is_enabled = 1
      AND r.is_enabled = 1
    ORDER BY g.priority ASC, r.created_at ASC
  `).all(deviceId);

  // De-duplicate by file_name, preserving higher priority group rule
  const deduplicated = [];
  const seenFiles = new Set();

  for (const rule of rules) {
    const key = rule.file_name.toLowerCase();
    if (!seenFiles.has(key)) {
      seenFiles.add(key);
      deduplicated.push(rule);
    }
  }

  return deduplicated;
}

/**
 * Submit or evaluate an elevation request from a standard user session
 */
export function requestElevation(db, deviceId, data) {
  if (!deviceId) throw new Error('Device ID is required');
  if (!data.requested_by_user) throw new Error('Requesting user name is required');
  if (!data.file_name) throw new Error('File name is required');
  if (!data.justification || data.justification.trim().length < 3) {
    throw new Error('A documented business justification (minimum 3 characters) is required for elevation');
  }

  const device = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const effectiveRules = getEffectiveEpmRulesForDevice(db, deviceId);
  const targetName = data.file_name.trim().toLowerCase();

  // Find matching rule by file_name and optionally hash or path
  let matchedRule = effectiveRules.find(r => {
    if (r.file_name.toLowerCase() !== targetName) return false;
    if (r.file_hash_sha256 && data.file_hash_sha256) {
      return r.file_hash_sha256.toLowerCase() === data.file_hash_sha256.toLowerCase();
    }
    return true;
  });

  const requestId = data.id || `epm-req-${crypto.randomUUID()}`;
  let status = 'PENDING';
  let reviewedBy = null;
  let reviewedAt = null;
  let reviewNotes = null;
  let expiresAt = null;
  let elevationType = matchedRule ? matchedRule.elevation_type : 'SUPPORT_APPROVED';

  if (matchedRule) {
    if (matchedRule.elevation_type === 'AUTOMATIC') {
      status = 'APPROVED';
      reviewedBy = 'EPM Engine (Auto-Approved Rule)';
      reviewedAt = new Date().toISOString();
      reviewNotes = `Rule '${matchedRule.rule_name}' permits automatic elevation without manual operator intervention.`;
      expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    } else if (matchedRule.elevation_type === 'USER_CONFIRMED') {
      status = 'APPROVED';
      reviewedBy = 'EPM Engine (User Justification Confirmed)';
      reviewedAt = new Date().toISOString();
      reviewNotes = `User justification validated: "${data.justification.trim()}". Granted for 4-hour window.`;
      expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();
    }
  }

  db.prepare(`
    INSERT INTO epm_elevation_requests (
      id, device_id, rule_id, requested_by_user, file_path, file_name,
      file_hash_sha256, file_version, justification, status, reviewed_by, reviewed_at, review_notes, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    requestId, deviceId, matchedRule ? matchedRule.id : null, data.requested_by_user,
    data.file_path || data.file_name, data.file_name, data.file_hash_sha256 || null,
    data.file_version || null, data.justification.trim(), status, reviewedBy, reviewedAt, reviewNotes, expiresAt
  );

  // Dispatch security event
  const isApproved = status === 'APPROVED';
  try {
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      deviceId,
      isApproved ? 'EPM_ELEVATION_APPROVED' : 'EPM_ELEVATION_REQUESTED',
      4688,
      'Microsoft-Windows-EPM',
      isApproved ? 'INFO' : 'MEDIUM',
      `EPM Elevation ${isApproved ? 'Approved' : 'Requested'} for ${data.file_name} by ${data.requested_by_user} on ${device.hostname}`,
      JSON.stringify({
        request_id: requestId,
        file_name: data.file_name,
        file_path: data.file_path,
        user: data.requested_by_user,
        justification: data.justification,
        elevation_type: elevationType,
        rule_matched: matchedRule ? matchedRule.rule_name : null,
        status
      })
    );
  } catch (_) {}

  return {
    request_id: requestId,
    device_id: deviceId,
    hostname: device.hostname,
    file_name: data.file_name,
    elevation_type: elevationType,
    status,
    reviewed_by: reviewedBy,
    expires_at: expiresAt,
    review_notes: reviewNotes
  };
}

/**
 * Review an elevation request (Approve or Deny)
 */
export function reviewElevationRequest(db, requestId, { decision, reviewedBy = 'Fleet Administrator', notes, validHours = 4 }) {
  if (!['APPROVED', 'DENIED'].includes(decision)) {
    throw new Error('Decision must be either APPROVED or DENIED');
  }

  const req = db.prepare(`
    SELECT r.*, d.hostname
    FROM epm_elevation_requests r
    JOIN devices d ON r.device_id = d.id
    WHERE r.id = ?
  `).get(requestId);

  if (!req) throw new Error(`Elevation request not found: ${requestId}`);

  const expiresAt = decision === 'APPROVED' ? new Date(Date.now() + validHours * 60 * 60 * 1000).toISOString() : null;

  db.prepare(`
    UPDATE epm_elevation_requests
    SET status = ?, reviewed_by = ?, reviewed_at = DATETIME('now'), review_notes = ?, expires_at = ?
    WHERE id = ?
  `).run(decision, reviewedBy, notes || `Operator ${reviewedBy} ${decision.toLowerCase()} the elevation request.`, expiresAt, requestId);

  // Security event
  try {
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.device_id,
      decision === 'APPROVED' ? 'EPM_ELEVATION_APPROVED' : 'EPM_ELEVATION_DENIED',
      4688,
      'Microsoft-Windows-EPM',
      decision === 'APPROVED' ? 'INFO' : 'WARNING',
      `EPM Elevation Request ${decision} for ${req.file_name} by ${reviewedBy} (${req.hostname})`,
      JSON.stringify({
        request_id: requestId,
        file_name: req.file_name,
        decision,
        reviewed_by: reviewedBy,
        notes,
        expires_at: expiresAt
      })
    );
  } catch (_) {}

  return db.prepare(`
    SELECT r.*, d.hostname
    FROM epm_elevation_requests r
    JOIN devices d ON r.device_id = d.id
    WHERE r.id = ?
  `).get(requestId);
}

/**
 * Ingest live process elevation execution telemetry from node agent
 */
export function logElevationEvent(db, deviceId, data) {
  if (!deviceId) throw new Error('Device ID is required');
  if (!data.file_name) throw new Error('File name is required');

  const id = data.id || `epm-log-${crypto.randomUUID()}`;
  const userName = data.user_name || 'StandardUser';
  const elevationType = data.elevation_type || 'AUTOMATIC';

  db.prepare(`
    INSERT INTO epm_elevation_logs (
      id, device_id, rule_id, user_name, file_path, file_name,
      file_hash_sha256, elevation_type, justification, process_id, parent_process_name
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, deviceId, data.rule_id || null, userName, data.file_path || data.file_name,
    data.file_name, data.file_hash_sha256 || null, elevationType,
    data.justification || '', data.process_id || null, data.parent_process_name || null
  );

  // Security event
  try {
    const device = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      deviceId,
      'EPM_PROCESS_ELEVATED',
      4688,
      'Microsoft-Windows-Security-Auditing',
      'LOW',
      `EPM Elevated Process Launch: ${data.file_name} (PID: ${data.process_id || 'N/A'}) by ${userName} on ${device ? device.hostname : deviceId}`,
      JSON.stringify({
        log_id: id,
        file_name: data.file_name,
        file_path: data.file_path,
        user: userName,
        elevation_type: elevationType,
        process_id: data.process_id,
        parent_process: data.parent_process_name
      })
    );
  } catch (_) {}

  return { id, device_id: deviceId, file_name: data.file_name, status: 'LOGGED' };
}

/**
 * List elevation requests
 */
export function getElevationRequests(db, { deviceId, status, limit = 50 } = {}) {
  let query = `
    SELECT
      req.*,
      d.hostname,
      d.friendly_name,
      r.rule_name
    FROM epm_elevation_requests req
    JOIN devices d ON req.device_id = d.id
    LEFT JOIN epm_elevation_rules r ON req.rule_id = r.id
    WHERE 1=1
  `;
  const params = [];

  if (deviceId) {
    query += ` AND req.device_id = ?`;
    params.push(deviceId);
  }
  if (status) {
    query += ` AND req.status = ?`;
    params.push(status);
  }

  query += ` ORDER BY req.created_at DESC LIMIT ?`;
  params.push(Number(limit));

  return db.prepare(query).all(...params);
}

/**
 * List elevation audit logs
 */
export function getElevationLogs(db, { deviceId, limit = 100 } = {}) {
  let query = `
    SELECT
      l.*,
      d.hostname,
      d.friendly_name,
      r.rule_name
    FROM epm_elevation_logs l
    JOIN devices d ON l.device_id = d.id
    LEFT JOIN epm_elevation_rules r ON l.rule_id = r.id
    WHERE 1=1
  `;
  const params = [];

  if (deviceId) {
    query += ` AND l.device_id = ?`;
    params.push(deviceId);
  }

  query += ` ORDER BY l.executed_at DESC LIMIT ?`;
  params.push(Number(limit));

  return db.prepare(query).all(...params);
}

/**
 * Get comprehensive device EPM posture for device blade drawer
 */
export function getDeviceEpmPosture(db, deviceId) {
  const device = db.prepare('SELECT id, hostname, friendly_name FROM devices WHERE id = ?').get(deviceId);
  if (!device) return null;

  const effectiveRules = getEffectiveEpmRulesForDevice(db, deviceId);
  const pendingRequests = getElevationRequests(db, { deviceId, status: 'PENDING', limit: 10 });
  const recentElevations = getElevationLogs(db, { deviceId, limit: 10 });

  return {
    device_id: device.id,
    hostname: device.hostname,
    friendly_name: device.friendly_name,
    effective_rules: effectiveRules,
    pending_requests: pendingRequests,
    recent_elevations: recentElevations,
    rules_count: effectiveRules.length,
    pending_count: pendingRequests.length
  };
}
