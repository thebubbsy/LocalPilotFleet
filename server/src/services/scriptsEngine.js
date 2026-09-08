/**
 * LocalPilot Fleet — Microsoft Intune Windows PowerShell Scripts Governance Engine
 * server/src/services/scriptsEngine.js
 *
 * Provides enterprise PowerShell script management, execution policy governance,
 * target group resolution, execution log archiving, and real-time dispatching.
 */

import crypto from 'node:crypto';
import { broadcastEvent } from '../routes/events.js';

function genId(prefix = 'ps') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
}

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
      5000,
      'Microsoft-Windows-PowerShell-Intune',
      severity,
      summary,
      JSON.stringify(payload)
    );
  } catch (err) {
    console.warn('[ScriptsEngine] Failed to log security event:', err.message);
  }
}

/**
 * Create a new enterprise PowerShell script
 */
export function createScript(db, payload) {
  const {
    name,
    description = '',
    script_content,
    run_as_account = 'SYSTEM',
    run_as_32bit = 0,
    enforce_signature_check = 0,
    timeout_seconds = 60,
    target_group_id = 'grp-all',
    assignment_intent = 'ASSIGNED',
    run_frequency = 'ONCE',
    schedule_cron = null,
    enabled = 1
  } = payload;

  if (!name || !name.trim()) {
    throw new Error('Script name is required');
  }
  if (!script_content || !script_content.trim()) {
    throw new Error('script_content is required');
  }
  if (!['SYSTEM', 'USER'].includes(run_as_account)) {
    throw new Error('run_as_account must be SYSTEM or USER');
  }
  if (timeout_seconds < 5 || timeout_seconds > 3600) {
    throw new Error('timeout_seconds must be between 5 and 3600');
  }
  if (!['ASSIGNED', 'AVAILABLE'].includes(assignment_intent)) {
    throw new Error('assignment_intent must be ASSIGNED or AVAILABLE');
  }
  if (!['ONCE', 'SCHEDULED', 'ON_DEMAND'].includes(run_frequency)) {
    throw new Error('run_frequency must be ONCE, SCHEDULED, or ON_DEMAND');
  }

  const id = payload.id && payload.id.trim() ? payload.id.trim() : genId('ps');

  const stmt = db.prepare(`
    INSERT INTO device_scripts (
      id, name, description, script_content, run_as_account, run_as_32bit,
      enforce_signature_check, timeout_seconds, target_group_id, assignment_intent,
      run_frequency, schedule_cron, enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `);

  stmt.run(
    id,
    name.trim(),
    description.trim(),
    script_content,
    run_as_account,
    run_as_32bit ? 1 : 0,
    enforce_signature_check ? 1 : 0,
    Number(timeout_seconds),
    target_group_id || 'grp-all',
    assignment_intent,
    run_frequency,
    schedule_cron,
    enabled ? 1 : 0
  );

  broadcastEvent('script_created', { id, name });
  return getScript(db, id);
}

/**
 * Fetch a script by ID with run statistics
 */
export function getScript(db, id) {
  const script = db.prepare(`
    SELECT ds.*, dg.name as target_group_name
    FROM device_scripts ds
    LEFT JOIN dynamic_groups dg ON ds.target_group_id = dg.id
    WHERE ds.id = ?
  `).get(id);

  if (!script) return null;

  const stats = db.prepare(`
    SELECT
      COUNT(*) as total_runs,
      SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_runs,
      SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_runs,
      MAX(executed_at) as last_executed_at
    FROM device_script_runs
    WHERE script_id = ?
  `).get(id);

  return {
    ...script,
    enabled: Boolean(script.enabled),
    run_as_32bit: Boolean(script.run_as_32bit),
    enforce_signature_check: Boolean(script.enforce_signature_check),
    total_runs: stats.total_runs || 0,
    success_runs: stats.success_runs || 0,
    failed_runs: stats.failed_runs || 0,
    last_executed_at: stats.last_executed_at
  };
}

/**
 * Query all scripts with filters
 */
export function getScripts(db, filters = {}) {
  const { search, target_group_id, enabled, run_frequency, run_as_account } = filters;
  let sql = `
    SELECT ds.*, dg.name as target_group_name,
      (SELECT COUNT(*) FROM device_script_runs WHERE script_id = ds.id) as total_runs,
      (SELECT COUNT(*) FROM device_script_runs WHERE script_id = ds.id AND status = 'SUCCESS') as success_runs,
      (SELECT COUNT(*) FROM device_script_runs WHERE script_id = ds.id AND status = 'FAILED') as failed_runs,
      (SELECT MAX(executed_at) FROM device_script_runs WHERE script_id = ds.id) as last_executed_at
    FROM device_scripts ds
    LEFT JOIN dynamic_groups dg ON ds.target_group_id = dg.id
    WHERE 1=1
  `;
  const params = [];

  if (search && search.trim()) {
    sql += ` AND (ds.name LIKE ? OR ds.description LIKE ?)`;
    const q = `%${search.trim()}%`;
    params.push(q, q);
  }

  if (target_group_id) {
    sql += ` AND ds.target_group_id = ?`;
    params.push(target_group_id);
  }

  if (enabled !== undefined && enabled !== '') {
    sql += ` AND ds.enabled = ?`;
    params.push(enabled === 'true' || enabled === 1 || enabled === '1' ? 1 : 0);
  }

  if (run_frequency) {
    sql += ` AND ds.run_frequency = ?`;
    params.push(run_frequency);
  }

  if (run_as_account) {
    sql += ` AND ds.run_as_account = ?`;
    params.push(run_as_account);
  }

  sql += ` ORDER BY ds.created_at DESC`;

  const rows = db.prepare(sql).all(...params);
  return rows.map(r => ({
    ...r,
    enabled: Boolean(r.enabled),
    run_as_32bit: Boolean(r.run_as_32bit),
    enforce_signature_check: Boolean(r.enforce_signature_check)
  }));
}

/**
 * Update an existing script
 */
export function updateScript(db, id, updates) {
  const existing = getScript(db, id);
  if (!existing) {
    throw new Error(`Script not found: ${id}`);
  }

  const fields = [];
  const params = [];

  if (updates.name !== undefined) {
    if (!updates.name.trim()) throw new Error('Script name cannot be empty');
    fields.push('name = ?');
    params.push(updates.name.trim());
  }
  if (updates.description !== undefined) {
    fields.push('description = ?');
    params.push(updates.description.trim());
  }
  if (updates.script_content !== undefined) {
    if (!updates.script_content.trim()) throw new Error('script_content cannot be empty');
    fields.push('script_content = ?');
    params.push(updates.script_content);
  }
  if (updates.run_as_account !== undefined) {
    if (!['SYSTEM', 'USER'].includes(updates.run_as_account)) {
      throw new Error('run_as_account must be SYSTEM or USER');
    }
    fields.push('run_as_account = ?');
    params.push(updates.run_as_account);
  }
  if (updates.run_as_32bit !== undefined) {
    fields.push('run_as_32bit = ?');
    params.push(updates.run_as_32bit ? 1 : 0);
  }
  if (updates.enforce_signature_check !== undefined) {
    fields.push('enforce_signature_check = ?');
    params.push(updates.enforce_signature_check ? 1 : 0);
  }
  if (updates.timeout_seconds !== undefined) {
    const t = Number(updates.timeout_seconds);
    if (t < 5 || t > 3600) throw new Error('timeout_seconds must be between 5 and 3600');
    fields.push('timeout_seconds = ?');
    params.push(t);
  }
  if (updates.target_group_id !== undefined) {
    fields.push('target_group_id = ?');
    params.push(updates.target_group_id || 'grp-all');
  }
  if (updates.assignment_intent !== undefined) {
    if (!['ASSIGNED', 'AVAILABLE'].includes(updates.assignment_intent)) {
      throw new Error('assignment_intent must be ASSIGNED or AVAILABLE');
    }
    fields.push('assignment_intent = ?');
    params.push(updates.assignment_intent);
  }
  if (updates.run_frequency !== undefined) {
    if (!['ONCE', 'SCHEDULED', 'ON_DEMAND'].includes(updates.run_frequency)) {
      throw new Error('run_frequency must be ONCE, SCHEDULED, or ON_DEMAND');
    }
    fields.push('run_frequency = ?');
    params.push(updates.run_frequency);
  }
  if (updates.schedule_cron !== undefined) {
    fields.push('schedule_cron = ?');
    params.push(updates.schedule_cron);
  }
  if (updates.enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(updates.enabled ? 1 : 0);
  }

  if (!fields.length) return existing;

  fields.push("updated_at = DATETIME('now')");
  params.push(id);

  db.prepare(`UPDATE device_scripts SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  broadcastEvent('script_updated', { id });
  return getScript(db, id);
}

/**
 * Delete a script
 */
export function deleteScript(db, id) {
  const existing = getScript(db, id);
  if (!existing) {
    throw new Error(`Script not found: ${id}`);
  }

  db.prepare('DELETE FROM device_scripts WHERE id = ?').run(id);
  broadcastEvent('script_deleted', { id, name: existing.name });
  return { success: true, id };
}

/**
 * Resolve effective assigned scripts for a device
 */
export function getAssignedScriptsForDevice(db, deviceId) {
  // 1. Get group memberships for the device
  const groupRows = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
  const groupIds = new Set(groupRows.map(r => r.group_id));
  groupIds.add('grp-all'); // always include catch-all

  // 2. Fetch all enabled assigned scripts
  const allScripts = db.prepare(`
    SELECT * FROM device_scripts WHERE enabled = 1 AND assignment_intent = 'ASSIGNED'
  `).all();

  const assigned = [];
  for (const s of allScripts) {
    if (!s.target_group_id || groupIds.has(s.target_group_id)) {
      // Check if this script was already executed successfully on this device
      // Check if this ONCE script has EVER succeeded on this device
      const priorRun = db.prepare(`
        SELECT id, status, exit_code, executed_at
        FROM device_script_runs
        WHERE device_id = ? AND script_id = ?
        ORDER BY executed_at DESC LIMIT 1
      `).get(deviceId, s.id);

      const anySuccess = db.prepare(`
        SELECT id FROM device_script_runs
        WHERE device_id = ? AND script_id = ? AND status = 'SUCCESS'
        LIMIT 1
      `).get(deviceId, s.id);

      const hasSucceeded = Boolean(anySuccess);
      const isDue = s.run_frequency !== 'ONCE' || !hasSucceeded;

      assigned.push({
        id: s.id,
        name: s.name,
        description: s.description,
        script_content: s.script_content,
        run_as_account: s.run_as_account,
        run_as_32bit: Boolean(s.run_as_32bit),
        enforce_signature_check: Boolean(s.enforce_signature_check),
        timeout_seconds: s.timeout_seconds,
        run_frequency: s.run_frequency,
        is_due: isDue,
        last_run_status: priorRun ? priorRun.status : null,
        last_executed_at: priorRun ? priorRun.executed_at : null
      });
    }
  }

  return assigned;
}

/**
 * Record a script execution result from a node
 */
export function saveScriptRunResult(db, payload) {
  const {
    deviceId,
    scriptId,
    runMode = 'ASSIGNED',
    exitCode = 0,
    stdout = '',
    stderr = '',
    executionTimeMs = 0
  } = payload;

  const runId = genId('dsr');
  const status = Number(exitCode) === 0 ? 'SUCCESS' : 'FAILED';

  const stmt = db.prepare(`
    INSERT INTO device_script_runs (
      id, device_id, script_id, run_mode, status, exit_code,
      stdout, stderr, execution_time_ms, executed_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))
  `);

  stmt.run(
    runId,
    deviceId,
    scriptId,
    runMode,
    status,
    Number(exitCode),
    String(stdout ?? ''),
    String(stderr ?? ''),
    Number(executionTimeMs || 0)
  );

  // If failed, log security event
  if (status === 'FAILED') {
    const script = db.prepare('SELECT name FROM device_scripts WHERE id = ?').get(scriptId);
    const scriptName = script ? script.name : scriptId;
    logSecurityEvent(db, {
      deviceId,
      eventType: 'SCRIPT_EXECUTION_FAILED',
      severity: 'MEDIUM',
      summary: `PowerShell script '${scriptName}' failed with exit code ${exitCode}`,
      payload: { script_id: scriptId, exit_code: exitCode, stderr: String(stderr).slice(0, 500) }
    });
  }

  broadcastEvent('script_run_completed', {
    run_id: runId,
    device_id: deviceId,
    script_id: scriptId,
    status,
    exit_code: exitCode
  });

  return db.prepare('SELECT * FROM device_script_runs WHERE id = ?').get(runId);
}

/**
 * Dispatch an on-demand script run to a device
 */
export function dispatchScriptRun(db, { deviceId, scriptId, initiatedBy = 'LocalPilot Administrator' }) {
  const script = getScript(db, scriptId);
  if (!script) throw new Error(`Script not found: ${scriptId}`);

  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const runId = genId('dsr');
  const commandId = crypto.randomUUID();

  // 1. Record pending script run
  db.prepare(`
    INSERT INTO device_script_runs (
      id, device_id, script_id, run_mode, status, executed_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'ON_DEMAND', 'PENDING', DATETIME('now'), DATETIME('now'), DATETIME('now'))
  `).run(runId, deviceId, scriptId);

  // 2. Queue as a device_command for immediate execution via heartbeat/agent
  db.prepare(`
    INSERT INTO device_commands (
      id, device_id, command_text, created_by, status, created_at
    ) VALUES (?, ?, ?, ?, 'PENDING', DATETIME('now'))
  `).run(commandId, deviceId, script.script_content, initiatedBy);

  // 3. Log security event
  logSecurityEvent(db, {
    deviceId,
    eventType: 'SCRIPT_DISPATCHED',
    severity: 'INFO',
    summary: `On-demand PowerShell script '${script.name}' dispatched to ${device.hostname}`,
    payload: { script_id: scriptId, run_id: runId, command_id: commandId }
  });

  broadcastEvent('script_dispatched', {
    run_id: runId,
    command_id: commandId,
    device_id: deviceId,
    script_id: scriptId
  });

  return {
    run_id: runId,
    command_id: commandId,
    device_id: deviceId,
    script_id: scriptId,
    status: 'PENDING'
  };
}

/**
 * Query historical script run logs with pagination and filters
 */
export function getScriptRuns(db, filters = {}) {
  const { device_id, script_id, status, limit = 50, offset = 0 } = filters;
  let sql = `
    SELECT dsr.*, ds.name as script_name, d.hostname, d.friendly_name
    FROM device_script_runs dsr
    JOIN device_scripts ds ON dsr.script_id = ds.id
    JOIN devices d ON dsr.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (device_id) {
    sql += ` AND dsr.device_id = ?`;
    params.push(device_id);
  }
  if (script_id) {
    sql += ` AND dsr.script_id = ?`;
    params.push(script_id);
  }
  if (status) {
    sql += ` AND dsr.status = ?`;
    params.push(status);
  }

  sql += ` ORDER BY dsr.executed_at DESC LIMIT ? OFFSET ?`;
  params.push(Number(limit), Number(offset));

  const runs = db.prepare(sql).all(...params);
  return {
    count: runs.length,
    runs
  };
}

/**
 * Executive KPI summary stats
 */
export function getScriptStats(db) {
  const totalScripts = db.prepare('SELECT COUNT(*) as count FROM device_scripts').get().count;
  const activeScripts = db.prepare('SELECT COUNT(*) as count FROM device_scripts WHERE enabled = 1').get().count;
  
  const runStats = db.prepare(`
    SELECT
      COUNT(*) as total_runs,
      SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as success_runs,
      SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_runs,
      COUNT(DISTINCT device_id) as targeted_devices
    FROM device_script_runs
  `).get();

  const totalRuns = runStats.total_runs || 0;
  const successRuns = runStats.success_runs || 0;
  const successRate = totalRuns > 0 ? Math.round((successRuns / totalRuns) * 100) : 100;

  return {
    total_scripts: totalScripts,
    active_scripts: activeScripts,
    total_runs: totalRuns,
    successful_runs: successRuns,
    failed_runs: runStats.failed_runs || 0,
    success_rate_percent: successRate,
    covered_devices: runStats.targeted_devices || 0
  };
}

/**
 * Get device script execution posture
 */
export function getDeviceScriptStatus(db, deviceId) {
  const assigned = getAssignedScriptsForDevice(db, deviceId);
  const recentRuns = db.prepare(`
    SELECT dsr.*, ds.name as script_name
    FROM device_script_runs dsr
    JOIN device_scripts ds ON dsr.script_id = ds.id
    WHERE dsr.device_id = ?
    ORDER BY dsr.executed_at DESC LIMIT 20
  `).all(deviceId);

  return {
    device_id: deviceId,
    assigned_scripts_count: assigned.length,
    assigned_scripts: assigned,
    recent_runs: recentRuns
  };
}
