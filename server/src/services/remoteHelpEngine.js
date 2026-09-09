import crypto from 'node:crypto';
import { getDb } from '../db.js';

/**
 * Microsoft Intune Remote Help & Unattended Assistance Governance Engine
 */

/**
 * Generate a cryptographically random 6-digit numeric session PIN
 */
export function generateSessionCode() {
  return crypto.randomInt(100000, 999999).toString();
}

/**
 * Auto-expire pending sessions that exceeded their 15-minute expiration window
 */
function expireStalePendingSessions(db) {
  try {
    const expired = db.prepare(`
      UPDATE remote_help_sessions 
      SET status = 'EXPIRED', updated_at = DATETIME('now')
      WHERE status = 'PENDING' AND expires_at < DATETIME('now')
    `).run();
    return expired.changes;
  } catch (err) {
    console.error('[RemoteHelp] Stale session expiration error:', err);
    return 0;
  }
}

/**
 * Overview statistics for Remote Help dashboard
 */
export function getRemoteHelpStats() {
  const db = getDb();
  expireStalePendingSessions(db);

  const totalSessions = db.prepare('SELECT COUNT(*) as count FROM remote_help_sessions').get().count;
  const activeSessions = db.prepare("SELECT COUNT(*) as count FROM remote_help_sessions WHERE status = 'ACTIVE'").get().count;
  const pendingSessions = db.prepare("SELECT COUNT(*) as count FROM remote_help_sessions WHERE status = 'PENDING'").get().count;
  const completedSessions = db.prepare("SELECT COUNT(*) as count FROM remote_help_sessions WHERE status = 'COMPLETED'").get().count;
  const unattendedSessions = db.prepare('SELECT COUNT(*) as count FROM remote_help_sessions WHERE unattended_enabled = 1').get().count;
  const activeRoles = db.prepare('SELECT COUNT(*) as count FROM remote_help_roles WHERE enabled = 1').get().count;
  const totalElevations = db.prepare("SELECT COUNT(*) as count FROM remote_help_audit_log WHERE action = 'ELEVATION_TRIGGERED'").get().count;

  return {
    totalSessions,
    activeSessions,
    pendingSessions,
    completedSessions,
    unattendedSessions,
    activeRoles,
    totalElevations
  };
}

/**
 * List all sessions with optional filtering
 */
export function getSessions(filter = {}) {
  const db = getDb();
  expireStalePendingSessions(db);

  let query = `
    SELECT 
      s.*,
      d.hostname as device_hostname,
      d.friendly_name as device_model,
      d.status as device_status,
      d.ip_address as device_ip
    FROM remote_help_sessions s
    LEFT JOIN devices d ON s.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (filter.status) {
    query += ' AND s.status = ?';
    params.push(filter.status);
  }
  if (filter.device_id) {
    query += ' AND s.device_id = ?';
    params.push(filter.device_id);
  }
  if (filter.unattended !== undefined) {
    query += ' AND s.unattended_enabled = ?';
    params.push(filter.unattended ? 1 : 0);
  }

  query += ' ORDER BY s.created_at DESC';
  if (filter.limit) {
    query += ' LIMIT ?';
    params.push(parseInt(filter.limit, 10));
  }

  return db.prepare(query).all(...params);
}

/**
 * Get detailed session by ID
 */
export function getSession(id) {
  const db = getDb();
  expireStalePendingSessions(db);

  const session = db.prepare(`
    SELECT 
      s.*,
      d.hostname as device_hostname,
      d.friendly_name as device_model,
      d.os_name as device_os,
      d.ip_address as device_ip,
      d.status as device_status
    FROM remote_help_sessions s
    LEFT JOIN devices d ON s.device_id = d.id
    WHERE s.id = ?
  `).get(id);

  if (!session) return null;

  const auditLogs = db.prepare(`
    SELECT * FROM remote_help_audit_log 
    WHERE session_id = ? 
    ORDER BY timestamp ASC
  `).all(id);

  return {
    ...session,
    audit_logs: auditLogs,
    launch_script: generateRemoteHelpClientScript(session)
  };
}

/**
 * Get session by 6-digit numeric PIN
 */
export function getSessionByCode(code) {
  const db = getDb();
  expireStalePendingSessions(db);

  const session = db.prepare(`
    SELECT 
      s.*,
      d.hostname as device_hostname,
      d.friendly_name as device_model,
      d.status as device_status
    FROM remote_help_sessions s
    LEFT JOIN devices d ON s.device_id = d.id
    WHERE s.session_code = ?
    ORDER BY s.created_at DESC
    LIMIT 1
  `).get(String(code).trim());

  return session || null;
}

/**
 * Create a new Remote Help or Unattended session
 */
export function createSession(data) {
  const db = getDb();
  const {
    device_id,
    helper_user = 'Admin Operator',
    sharer_user = '',
    session_type = 'FULL_CONTROL',
    unattended_enabled = 0,
    role_id = null
  } = data;

  if (!device_id) {
    throw new Error('device_id is required');
  }

  // Validate device exists
  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(device_id);
  if (!device) {
    throw new Error(`Device not found: ${device_id}`);
  }

  // If role_id provided, validate role permissions
  if (role_id) {
    const role = db.prepare('SELECT * FROM remote_help_roles WHERE id = ?').get(role_id);
    if (role) {
      if (unattended_enabled && !role.can_unattended) {
        throw new Error('Assigned role does not have permission for unattended assistance');
      }
      if (session_type === 'ELEVATION' && !role.can_request_elevation) {
        throw new Error('Assigned role does not have permission for UAC elevation');
      }
    }
  }

  const id = crypto.randomUUID();
  const session_code = generateSessionCode();
  const unattended = unattended_enabled ? 1 : 0;
  const status = 'PENDING';

  // Session valid for 15 minutes
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO remote_help_sessions (
      id, session_code, device_id, sharer_user, helper_user,
      session_type, status, unattended_enabled, expires_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    session_code,
    device_id,
    sharer_user,
    helper_user,
    session_type,
    status,
    unattended,
    expiresAt
  );

  // Audit event
  const auditDesc = unattended
    ? `Unattended remote assistance initiated by ${helper_user}. Session PIN: ${session_code}`
    : `Attended remote assistance requested by ${helper_user} for ${device.hostname}. 6-digit PIN: ${session_code}`;

  recordAuditEvent({
    session_id: id,
    device_id,
    actor_user: helper_user,
    action: 'SESSION_REQUESTED',
    details: auditDesc
  });

  return getSession(id);
}

/**
 * Connect/activate a session via PIN or session ID
 */
export function connectSession(idOrCode, clientData = {}) {
  const db = getDb();
  expireStalePendingSessions(db);

  let session = db.prepare(`
    SELECT * FROM remote_help_sessions 
    WHERE id = ? OR session_code = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(idOrCode, idOrCode);

  if (!session) {
    throw new Error('Session not found or invalid PIN');
  }

  if (session.status === 'EXPIRED') {
    throw new Error('Session PIN has expired');
  }
  if (session.status === 'COMPLETED' || session.status === 'CANCELLED') {
    throw new Error(`Session is already ${session.status.toLowerCase()}`);
  }

  const sharerUser = clientData.sharer_user || session.sharer_user || 'Workstation User';
  const now = new Date().toISOString();

  if (session.status === 'PENDING') {
    db.prepare(`
      UPDATE remote_help_sessions
      SET status = 'ACTIVE',
          sharer_user = ?,
          started_at = ?,
          updated_at = DATETIME('now')
      WHERE id = ?
    `).run(sharerUser, now, session.id);

    const action = session.unattended_enabled ? 'UNATTENDED_CONNECTED' : 'SESSION_STARTED';
    const details = session.unattended_enabled
      ? `Unattended remote session established on device.`
      : `Interactive remote assistance session connected with user ${sharerUser}.`;

    recordAuditEvent({
      session_id: session.id,
      device_id: session.device_id,
      actor_user: sharerUser,
      action,
      details
    });
  }

  return getSession(session.id);
}

/**
 * Grant interactive mouse and keyboard control to the helper
 */
export function grantControl(sessionId, actorUser = 'User') {
  const db = getDb();
  const session = db.prepare('SELECT * FROM remote_help_sessions WHERE id = ?').get(sessionId);
  if (!session) throw new Error('Session not found');

  db.prepare(`
    UPDATE remote_help_sessions
    SET session_type = 'FULL_CONTROL', updated_at = DATETIME('now')
    WHERE id = ?
  `).run(sessionId);

  recordAuditEvent({
    session_id: sessionId,
    device_id: session.device_id,
    actor_user: actorUser,
    action: 'CONTROL_GRANTED',
    details: `Interactive mouse and keyboard control granted to ${session.helper_user} by ${actorUser}`
  });

  return getSession(sessionId);
}

/**
 * Trigger or log UAC elevation in remote session
 */
export function triggerElevation(sessionId, actorUser = 'Admin', details = '') {
  const db = getDb();
  const session = db.prepare('SELECT * FROM remote_help_sessions WHERE id = ?').get(sessionId);
  if (!session) throw new Error('Session not found');

  const elevDetails = details || `UAC elevation approved and entered by ${actorUser}`;

  recordAuditEvent({
    session_id: sessionId,
    device_id: session.device_id,
    actor_user: actorUser,
    action: 'ELEVATION_TRIGGERED',
    details: elevDetails
  });

  // Record security event if table exists
  try {
    db.prepare(`
      INSERT INTO security_events (device_id, event_type, event_id, event_source, severity, summary, raw_payload_json)
      VALUES (?, 'EPM_PROCESS_ELEVATED', 4688, 'LocalPilotRemoteHelp', 'INFO', ?, ?)
    `).run(
      session.device_id,
      `Remote Help UAC elevation executed on device: ${elevDetails}`,
      JSON.stringify({ session_id: sessionId, helper: session.helper_user, actor: actorUser })
    );
  } catch (secErr) {
    // Ignore if not present or constrained
  }

  return getSession(sessionId);
}

/**
 * Terminate/conclude remote help session
 */
export function terminateSession(sessionId, actorUser = 'Operator', reason = 'Session concluded') {
  const db = getDb();
  const session = db.prepare('SELECT * FROM remote_help_sessions WHERE id = ?').get(sessionId);
  if (!session) throw new Error('Session not found');

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE remote_help_sessions
    SET status = 'COMPLETED',
        ended_at = ?,
        updated_at = DATETIME('now')
    WHERE id = ?
  `).run(now, sessionId);

  recordAuditEvent({
    session_id: sessionId,
    device_id: session.device_id,
    actor_user: actorUser,
    action: 'SESSION_TERMINATED',
    details: `${reason} (Terminated by ${actorUser})`
  });

  return getSession(sessionId);
}

/**
 * Cancel a pending session before connection
 */
export function cancelSession(sessionId, actorUser = 'Operator') {
  const db = getDb();
  const session = db.prepare('SELECT * FROM remote_help_sessions WHERE id = ?').get(sessionId);
  if (!session) throw new Error('Session not found');

  db.prepare(`
    UPDATE remote_help_sessions
    SET status = 'CANCELLED', updated_at = DATETIME('now')
    WHERE id = ?
  `).run(sessionId);

  recordAuditEvent({
    session_id: sessionId,
    device_id: session.device_id,
    actor_user: actorUser,
    action: 'SESSION_TERMINATED',
    details: `Session cancelled prior to connection by ${actorUser}`
  });

  return getSession(sessionId);
}

/**
 * Get pending or active sessions targeted to a specific device (used by node heartbeat)
 */
export function getPendingSessionsForDevice(deviceId) {
  const db = getDb();
  expireStalePendingSessions(db);

  return db.prepare(`
    SELECT id, session_code, helper_user, session_type, status, unattended_enabled, expires_at
    FROM remote_help_sessions
    WHERE device_id = ? AND status IN ('PENDING', 'ACTIVE')
    ORDER BY created_at DESC
  `).all(deviceId);
}

/**
 * Record an entry into remote_help_audit_log
 */
export function recordAuditEvent({ session_id = null, device_id, actor_user, action, details = '' }) {
  const db = getDb();
  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO remote_help_audit_log (id, session_id, device_id, actor_user, action, details, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'))
  `).run(id, session_id, device_id, actor_user, action, details);

  return { id, session_id, device_id, actor_user, action, details };
}

/**
 * Get audit log entries
 */
export function getAuditLog(filter = {}) {
  const db = getDb();

  let query = `
    SELECT 
      a.*,
      d.hostname as device_hostname,
      s.session_code,
      s.session_type
    FROM remote_help_audit_log a
    LEFT JOIN devices d ON a.device_id = d.id
    LEFT JOIN remote_help_sessions s ON a.session_id = s.id
    WHERE 1=1
  `;
  const params = [];

  if (filter.session_id) {
    query += ' AND a.session_id = ?';
    params.push(filter.session_id);
  }
  if (filter.device_id) {
    query += ' AND a.device_id = ?';
    params.push(filter.device_id);
  }
  if (filter.action) {
    query += ' AND a.action = ?';
    params.push(filter.action);
  }

  query += ' ORDER BY a.timestamp DESC';
  if (filter.limit) {
    query += ' LIMIT ?';
    params.push(parseInt(filter.limit, 10));
  }

  return db.prepare(query).all(...params);
}

/**
 * RBAC: Get all Remote Help roles
 */
export function getRoles() {
  const db = getDb();
  return db.prepare(`
    SELECT r.*, g.name as target_group_name
    FROM remote_help_roles r
    LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
    ORDER BY r.created_at ASC
  `).all();
}

/**
 * Get role by ID
 */
export function getRole(id) {
  const db = getDb();
  return db.prepare(`
    SELECT r.*, g.name as target_group_name
    FROM remote_help_roles r
    LEFT JOIN dynamic_groups g ON r.target_group_id = g.id
    WHERE r.id = ?
  `).get(id) || null;
}

/**
 * Create a new Remote Help role
 */
export function createRole(data) {
  const db = getDb();
  const {
    name,
    description = '',
    can_request_full_control = 1,
    can_request_elevation = 0,
    can_unattended = 0,
    target_group_id = null,
    enabled = 1
  } = data;

  if (!name || !name.trim()) {
    throw new Error('Role name is required');
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO remote_help_roles (
      id, name, description, can_request_full_control,
      can_request_elevation, can_unattended, target_group_id, enabled,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    name.trim(),
    description,
    can_request_full_control ? 1 : 0,
    can_request_elevation ? 1 : 0,
    can_unattended ? 1 : 0,
    target_group_id || null,
    enabled ? 1 : 0
  );

  return getRole(id);
}

/**
 * Update an existing role
 */
export function updateRole(id, data) {
  const db = getDb();
  const existing = getRole(id);
  if (!existing) throw new Error('Role not found');

  const fields = [];
  const params = [];

  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error('Role name cannot be empty');
    fields.push('name = ?');
    params.push(data.name.trim());
  }
  if (data.description !== undefined) {
    fields.push('description = ?');
    params.push(data.description);
  }
  if (data.can_request_full_control !== undefined) {
    fields.push('can_request_full_control = ?');
    params.push(data.can_request_full_control ? 1 : 0);
  }
  if (data.can_request_elevation !== undefined) {
    fields.push('can_request_elevation = ?');
    params.push(data.can_request_elevation ? 1 : 0);
  }
  if (data.can_unattended !== undefined) {
    fields.push('can_unattended = ?');
    params.push(data.can_unattended ? 1 : 0);
  }
  if (data.target_group_id !== undefined) {
    fields.push('target_group_id = ?');
    params.push(data.target_group_id || null);
  }
  if (data.enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(data.enabled ? 1 : 0);
  }

  if (fields.length > 0) {
    fields.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE remote_help_roles SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  }

  return getRole(id);
}

/**
 * Delete a custom role
 */
export function deleteRole(id) {
  const db = getDb();
  const existing = getRole(id);
  if (!existing) throw new Error('Role not found');

  db.prepare('DELETE FROM remote_help_roles WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * Get device drawer birth certificate remote help data
 */
export function getDeviceRemoteHelp(deviceId) {
  const db = getDb();
  expireStalePendingSessions(db);

  const activeSession = db.prepare(`
    SELECT * FROM remote_help_sessions 
    WHERE device_id = ? AND status IN ('PENDING', 'ACTIVE')
    ORDER BY created_at DESC LIMIT 1
  `).get(deviceId);

  const pastSessions = db.prepare(`
    SELECT * FROM remote_help_sessions 
    WHERE device_id = ? 
    ORDER BY created_at DESC LIMIT 10
  `).all(deviceId);

  const recentAudits = db.prepare(`
    SELECT * FROM remote_help_audit_log
    WHERE device_id = ?
    ORDER BY timestamp DESC LIMIT 10
  `).all(deviceId);

  return {
    active_session: activeSession || null,
    past_sessions: pastSessions,
    recent_audits: recentAudits,
    total_sessions_count: pastSessions.length
  };
}

/**
 * Generate client launch script for initiating or receiving Remote Help
 */
export function generateRemoteHelpClientScript(session) {
  if (!session) return '';

  return `# LocalPilot Fleet Remote Help & Assistance Connector
# Session Code: ${session.session_code} | Mode: ${session.session_type} | Unattended: ${session.unattended_enabled ? 'Yes' : 'No'}

$SessionId = "${session.id}"
$SessionCode = "${session.session_code}"
$ServerUrl = "https://127.0.0.1:8443"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " LocalPilot Enterprise Remote Help & Assistance Session" -ForegroundColor Yellow
Write-Host " Session PIN: $SessionCode" -ForegroundColor Green
Write-Host " Control Level: ${session.session_type}" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if Microsoft Remote Assistance (msra.exe) or Quick Assist is available
if (Get-Command msra.exe -ErrorAction SilentlyContinue) {
    Write-Host "[LocalPilot] Launching Windows Remote Assistance subsystem..." -ForegroundColor Gray
    # Invoke MSRA with security token broker
    Start-Process msra.exe -ArgumentList "/expert" -ErrorAction SilentlyContinue
} else {
    Write-Host "[LocalPilot] Initializing direct Cloud Shell remote bridge..." -ForegroundColor Yellow
}
`;
}
