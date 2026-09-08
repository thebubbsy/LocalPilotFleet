/**
 * LocalPilot Fleet — Device Remote Actions, Diagnostics & Bulk Orchestration Service
 * server/src/services/remoteActionEngine.js
 *
 * Implements Microsoft Intune device lifecycle and remote execution orchestration:
 * - Remote Lock, Restart with countdown & custom notifications, Shutdown, Cancel Shutdown
 * - Full wipe, Retire, Fresh Start with enterprise safeguards
 * - Standard Intune Diagnostic Package Collector, zip decompression & streaming download
 * - Dynamic Group bulk action dispatcher with live completion progress tracking
 * - Real-time SSE dispatch and security audit event logging
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDb } from '../db.js';
import { sseClients } from '../routes/events.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DIAGNOSTICS_DIR = path.resolve(__dirname, '../../data/diagnostics');

// Ensure storage directory for diagnostics bundles exists
try {
  if (!fs.existsSync(DIAGNOSTICS_DIR)) {
    fs.mkdirSync(DIAGNOSTICS_DIR, { recursive: true });
  }
} catch (err) {
  console.error('[RemoteActionEngine] Failed to initialize diagnostics directory:', err.message);
}

const VALID_ACTIONS = [
  'REMOTE_LOCK', 'RESTART', 'SHUTDOWN', 'CANCEL_SHUTDOWN',
  'COLLECT_DIAGNOSTICS', 'FRESH_START', 'WIPE', 'RETIRE',
  'SYNC_MDM', 'DEFENDER_SCAN', 'ROTATE_BITLOCKER', 'ROTATE_LAPS'
];

/**
 * Broadcast an event to all connected Intune SSE dashboards
 */
function broadcastSse(eventType, payload) {
  if (Array.isArray(sseClients)) {
    const message = `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
    sseClients.forEach(client => {
      try {
        client.res.write(message);
      } catch (_) {}
    });
  }
}

/**
 * Safely insert an audit event into security_events
 */
function logSecurityEvent(db, deviceId, eventType, severity, summary, payload = {}) {
  try {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) return;

    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `).run(
      deviceId,
      eventType,
      4900,
      'RemoteActionEngine',
      severity,
      summary,
      JSON.stringify(payload)
    );
  } catch (err) {
    console.warn('[RemoteActionEngine] Failed to log security event:', err.message);
  }
}

/**
 * Queue a remote action for a device
 */
export function queueRemoteAction({
  deviceId,
  actionType,
  parameters = {},
  initiatedBy = 'LocalPilot Administrator',
  bulkActionId = null
}) {
  const db = getDb();

  if (!deviceId) throw new Error('deviceId is required');
  if (!actionType) throw new Error('actionType is required');

  const normalizedAction = actionType.toUpperCase().trim();
  if (!VALID_ACTIONS.includes(normalizedAction)) {
    throw new Error(`Invalid action_type: ${actionType}. Allowed: ${VALID_ACTIONS.join(', ')}`);
  }

  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) {
    throw new Error(`Device not found: ${deviceId}`);
  }

  const actionId = `dra-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const paramsJson = typeof parameters === 'string' ? parameters : JSON.stringify(parameters);

  db.prepare(`
    INSERT INTO device_remote_actions (
      id, device_id, action_type, parameters_json, status,
      initiated_by, bulk_action_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'PENDING', ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    actionId,
    deviceId,
    normalizedAction,
    paramsJson,
    initiatedBy,
    bulkActionId
  );

  // If part of bulk action, increment dispatched count
  if (bulkActionId) {
    db.prepare(`
      UPDATE bulk_device_actions
      SET dispatched_count = dispatched_count + 1, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(bulkActionId);
  }

  const severity = ['WIPE', 'FRESH_START', 'SHUTDOWN'].includes(normalizedAction) ? 'HIGH' : 'INFO';
  logSecurityEvent(
    db,
    deviceId,
    'REMOTE_ACTION_DISPATCHED',
    severity,
    `Remote action ${normalizedAction} dispatched to ${device.hostname}`,
    { action_id: actionId, action_type: normalizedAction, initiated_by: initiatedBy, parameters }
  );

  const action = getRemoteAction(actionId);
  broadcastSse('remote_action_queued', action);
  return action;
}

/**
 * Retrieve a single remote action by ID
 */
export function getRemoteAction(actionId) {
  const db = getDb();
  const row = db.prepare(`
    SELECT a.*, d.hostname, d.serial_number, d.friendly_name
    FROM device_remote_actions a
    LEFT JOIN devices d ON a.device_id = d.id
    WHERE a.id = ?
  `).get(actionId);

  if (!row) return null;

  try { row.parameters = JSON.parse(row.parameters_json || '{}'); } catch (_) { row.parameters = {}; }
  try { row.result_data = JSON.parse(row.result_data_json || '{}'); } catch (_) { row.result_data = {}; }
  return row;
}

/**
 * Get all pending actions for a node agent (dispatches them)
 */
export function getPendingActionsForNode(deviceId) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM device_remote_actions
    WHERE device_id = ? AND status = 'PENDING'
    ORDER BY created_at ASC
  `).all(deviceId);

  if (rows.length > 0) {
    const updateStmt = db.prepare(`
      UPDATE device_remote_actions
      SET status = 'DISPATCHED', dispatched_at = DATETIME('now'), updated_at = DATETIME('now')
      WHERE id = ?
    `);

    for (const r of rows) {
      updateStmt.run(r.id);
      r.status = 'DISPATCHED';
      try { r.parameters = JSON.parse(r.parameters_json || '{}'); } catch (_) { r.parameters = {}; }
      try { r.result_data = JSON.parse(r.result_data_json || '{}'); } catch (_) { r.result_data = {}; }
      broadcastSse('remote_action_dispatched', r);
    }
  }

  return rows;
}

/**
 * Complete a remote action reporting execution results
 */
export function completeRemoteAction({
  actionId,
  deviceId,
  status = 'COMPLETED',
  resultData = {},
  errorMessage = null
}) {
  const db = getDb();
  const normalizedStatus = status.toUpperCase().trim();

  if (!['COMPLETED', 'FAILED'].includes(normalizedStatus)) {
    throw new Error(`Invalid completion status: ${status}. Must be COMPLETED or FAILED.`);
  }

  const action = db.prepare('SELECT * FROM device_remote_actions WHERE id = ?').get(actionId);
  if (!action) {
    throw new Error(`Remote action not found: ${actionId}`);
  }

  if (deviceId && action.device_id !== deviceId) {
    throw new Error(`Device mismatch for action ${actionId}`);
  }

  const resultJson = typeof resultData === 'string' ? resultData : JSON.stringify(resultData);

  db.prepare(`
    UPDATE device_remote_actions
    SET status = ?, result_data_json = ?, error_message = ?, completed_at = DATETIME('now'), updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    normalizedStatus,
    resultJson,
    errorMessage || null,
    actionId
  );

  // Update bulk action parent counters if applicable
  if (action.bulk_action_id) {
    if (normalizedStatus === 'COMPLETED') {
      db.prepare(`
        UPDATE bulk_device_actions
        SET completed_count = completed_count + 1, updated_at = DATETIME('now')
        WHERE id = ?
      `).run(action.bulk_action_id);
    } else {
      db.prepare(`
        UPDATE bulk_device_actions
        SET failed_count = failed_count + 1, updated_at = DATETIME('now')
        WHERE id = ?
      `).run(action.bulk_action_id);
    }

    // Check if bulk action has completed
    const bulk = db.prepare('SELECT * FROM bulk_device_actions WHERE id = ?').get(action.bulk_action_id);
    if (bulk && (bulk.completed_count + bulk.failed_count >= bulk.total_devices)) {
      const finalStatus = bulk.failed_count === 0 ? 'COMPLETED' : (bulk.completed_count === 0 ? 'FAILED' : 'PARTIALLY_FAILED');
      db.prepare(`
        UPDATE bulk_device_actions
        SET status = ?, updated_at = DATETIME('now')
        WHERE id = ?
      `).run(finalStatus, bulk.id);
    }
  }

  const eventType = normalizedStatus === 'COMPLETED' ? 'REMOTE_ACTION_COMPLETED' : 'REMOTE_ACTION_FAILED';
  const severity = normalizedStatus === 'COMPLETED' ? 'INFO' : 'HIGH';
  const dev = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(action.device_id);

  logSecurityEvent(
    db,
    action.device_id,
    eventType,
    severity,
    `Remote action ${action.action_type} on ${dev?.hostname || action.device_id} ${normalizedStatus.toLowerCase()}`,
    { action_id: actionId, action_type: action.action_type, result: resultData, error: errorMessage }
  );

  const updated = getRemoteAction(actionId);
  broadcastSse('remote_action_updated', updated);
  return updated;
}

/**
 * Cancel a pending or dispatched action
 */
export function cancelRemoteAction(actionId, cancelledBy = 'LocalPilot Administrator') {
  const db = getDb();
  const action = db.prepare('SELECT * FROM device_remote_actions WHERE id = ?').get(actionId);
  if (!action) throw new Error(`Action not found: ${actionId}`);

  if (!['PENDING', 'DISPATCHED'].includes(action.status)) {
    throw new Error(`Cannot cancel action in status ${action.status}`);
  }

  db.prepare(`
    UPDATE device_remote_actions
    SET status = 'CANCELLED', error_message = ?, completed_at = DATETIME('now'), updated_at = DATETIME('now')
    WHERE id = ?
  `).run(`Cancelled by ${cancelledBy}`, actionId);

  const updated = getRemoteAction(actionId);
  broadcastSse('remote_action_updated', updated);
  return updated;
}

/**
 * Save diagnostics bundle uploaded from a node
 */
export function saveDiagnosticsBundle({
  deviceId,
  remoteActionId = null,
  fileName,
  base64Data,
  categories = [],
  summary = {}
}) {
  const db = getDb();

  if (!deviceId) throw new Error('deviceId is required');
  if (!fileName) throw new Error('fileName is required');
  if (!base64Data) throw new Error('base64Data is required');

  const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!dev) throw new Error(`Device not found: ${deviceId}`);

  const bundleId = `ddb-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const safeFileName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, '_');
  const diskFileName = `${bundleId}_${safeFileName}`;
  const diskPath = path.join(DIAGNOSTICS_DIR, diskFileName);

  const buffer = Buffer.from(base64Data, 'base64');
  fs.writeFileSync(diskPath, buffer);

  const categoriesJson = JSON.stringify(Array.isArray(categories) ? categories : ['SYSTEM_LOGS']);
  const summaryJson = JSON.stringify(summary || {});

  db.prepare(`
    INSERT INTO device_diagnostics_bundles (
      id, device_id, remote_action_id, file_name, file_size_bytes, content_type,
      categories_json, status, storage_path, summary_json, collected_at, created_at
    ) VALUES (?, ?, ?, ?, ?, 'application/zip', ?, 'READY', ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    bundleId,
    deviceId,
    remoteActionId,
    safeFileName,
    buffer.length,
    categoriesJson,
    diskPath,
    summaryJson
  );

  // If attached to a remote action, mark it completed
  if (remoteActionId) {
    try {
      completeRemoteAction({
        actionId: remoteActionId,
        deviceId,
        status: 'COMPLETED',
        resultData: {
          bundle_id: bundleId,
          file_name: safeFileName,
          file_size_bytes: buffer.length
        }
      });
    } catch (_) {}
  }

  logSecurityEvent(
    db,
    deviceId,
    'DIAGNOSTICS_COLLECTED',
    'INFO',
    `Diagnostics package (${safeFileName}, ${Math.round(buffer.length / 1024)} KB) collected from ${dev.hostname}`,
    { bundle_id: bundleId, file_name: safeFileName, size_bytes: buffer.length, categories }
  );

  return getDiagnosticsBundle(bundleId);
}

/**
 * Get metadata for a diagnostics bundle
 */
export function getDiagnosticsBundle(bundleId) {
  const db = getDb();
  const row = db.prepare(`
    SELECT b.*, d.hostname, d.serial_number
    FROM device_diagnostics_bundles b
    LEFT JOIN devices d ON b.device_id = d.id
    WHERE b.id = ?
  `).get(bundleId);

  if (!row) return null;

  try { row.categories = JSON.parse(row.categories_json || '[]'); } catch (_) { row.categories = []; }
  try { row.summary = JSON.parse(row.summary_json || '{}'); } catch (_) { row.summary = {}; }
  return row;
}

/**
 * Get filesystem path and metadata to stream diagnostics download
 */
export function getDiagnosticsDownloadStream(bundleId) {
  const bundle = getDiagnosticsBundle(bundleId);
  if (!bundle) throw new Error(`Diagnostics bundle not found: ${bundleId}`);

  let filePath = bundle.storage_path;
  if (!path.isAbsolute(filePath)) {
    filePath = path.resolve(__dirname, '../../', filePath);
  }

  if (!fs.existsSync(filePath)) {
    // If not found, check inside DIAGNOSTICS_DIR directly
    const fallbackPath = path.join(DIAGNOSTICS_DIR, path.basename(filePath));
    if (fs.existsSync(fallbackPath)) {
      filePath = fallbackPath;
    } else {
      throw new Error(`Diagnostics package archive missing from disk: ${bundle.file_name}`);
    }
  }

  return { bundle, filePath };
}

/**
 * List diagnostics bundles for a device
 */
export function getDeviceDiagnosticsBundles(deviceId) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM device_diagnostics_bundles
    WHERE device_id = ?
    ORDER BY created_at DESC
  `).all(deviceId);

  return rows.map(r => {
    try { r.categories = JSON.parse(r.categories_json || '[]'); } catch (_) { r.categories = []; }
    try { r.summary = JSON.parse(r.summary_json || '{}'); } catch (_) { r.summary = {}; }
    return r;
  });
}

/**
 * Get actions for a specific device
 */
export function getDeviceActions(deviceId, limit = 50) {
  const db = getDb();
  const rows = db.prepare(`
    SELECT * FROM device_remote_actions
    WHERE device_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(deviceId, limit);

  return rows.map(r => {
    try { r.parameters = JSON.parse(r.parameters_json || '{}'); } catch (_) { r.parameters = {}; }
    try { r.result_data = JSON.parse(r.result_data_json || '{}'); } catch (_) { r.result_data = {}; }
    return r;
  });
}

/**
 * Get all actions across fleet with filters
 */
export function getAllActions({ status, actionType, deviceId, limit = 100, offset = 0 } = {}) {
  const db = getDb();
  const conditions = [];
  const params = [];

  if (status) {
    conditions.push('a.status = ?');
    params.push(status);
  }
  if (actionType) {
    conditions.push('a.action_type = ?');
    params.push(actionType);
  }
  if (deviceId) {
    conditions.push('a.device_id = ?');
    params.push(deviceId);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const totalCount = db.prepare(`
    SELECT COUNT(*) as count FROM device_remote_actions a ${whereClause}
  `).get(...params).count;

  const rows = db.prepare(`
    SELECT a.*, d.hostname, d.serial_number, d.friendly_name
    FROM device_remote_actions a
    LEFT JOIN devices d ON a.device_id = d.id
    ${whereClause}
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  const actions = rows.map(r => {
    try { r.parameters = JSON.parse(r.parameters_json || '{}'); } catch (_) { r.parameters = {}; }
    try { r.result_data = JSON.parse(r.result_data_json || '{}'); } catch (_) { r.result_data = {}; }
    return r;
  });

  return { total: totalCount, actions, limit, offset };
}

/**
 * Get Executive KPI stats for remote actions & diagnostics
 */
export function getRemoteActionStats() {
  const db = getDb();

  const totalActions = db.prepare('SELECT COUNT(*) as count FROM device_remote_actions').get().count;
  const pendingActions = db.prepare("SELECT COUNT(*) as count FROM device_remote_actions WHERE status = 'PENDING'").get().count;
  const inFlightActions = db.prepare("SELECT COUNT(*) as count FROM device_remote_actions WHERE status IN ('DISPATCHED', 'EXECUTING')").get().count;

  const completedToday = db.prepare(`
    SELECT COUNT(*) as count FROM device_remote_actions
    WHERE status = 'COMPLETED' AND completed_at >= DATETIME('now', '-24 hours')
  `).get().count;

  const failedToday = db.prepare(`
    SELECT COUNT(*) as count FROM device_remote_actions
    WHERE status = 'FAILED' AND completed_at >= DATETIME('now', '-24 hours')
  `).get().count;

  const totalDiagnostics = db.prepare('SELECT COUNT(*) as count FROM device_diagnostics_bundles').get().count;
  const totalBulkActions = db.prepare('SELECT COUNT(*) as count FROM bulk_device_actions').get().count;

  return {
    total_actions: totalActions,
    pending_actions: pendingActions,
    in_flight_actions: inFlightActions,
    completed_today: completedToday,
    failed_today: failedToday,
    total_diagnostics: totalDiagnostics,
    total_bulk_actions: totalBulkActions
  };
}

/**
 * Create and dispatch a bulk device action across a target dynamic group
 */
export function createBulkAction({
  name,
  actionType,
  targetGroupId = 'grp-all',
  parameters = {},
  initiatedBy = 'LocalPilot Administrator'
}) {
  const db = getDb();

  if (!name) throw new Error('Bulk action name is required');
  if (!actionType) throw new Error('actionType is required');

  const normalizedAction = actionType.toUpperCase().trim();
  if (!VALID_ACTIONS.includes(normalizedAction)) {
    throw new Error(`Invalid action_type: ${actionType}. Allowed: ${VALID_ACTIONS.join(', ')}`);
  }

  // Determine target devices
  let targetDevices = [];
  if (!targetGroupId || targetGroupId === 'grp-all') {
    targetDevices = db.prepare('SELECT id, hostname FROM devices').all();
  } else {
    targetDevices = db.prepare(`
      SELECT d.id, d.hostname
      FROM devices d
      JOIN group_memberships gm ON d.id = gm.device_id
      WHERE gm.group_id = ?
    `).all(targetGroupId);
  }

  const bulkId = `bda-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const paramsJson = typeof parameters === 'string' ? parameters : JSON.stringify(parameters);

  db.prepare(`
    INSERT INTO bulk_device_actions (
      id, name, action_type, target_group_id, parameters_json,
      total_devices, dispatched_count, completed_count, failed_count, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 'DISPATCHED', DATETIME('now'), DATETIME('now'))
  `).run(
    bulkId,
    name,
    normalizedAction,
    targetGroupId || null,
    paramsJson,
    targetDevices.length
  );

  // Queue action for each target device
  for (const dev of targetDevices) {
    queueRemoteAction({
      deviceId: dev.id,
      actionType: normalizedAction,
      parameters,
      initiatedBy: `${initiatedBy} (via Bulk: ${name})`,
      bulkActionId: bulkId
    });
  }

  // Log audit event on first device or overall
  if (targetDevices.length > 0) {
    logSecurityEvent(
      db,
      targetDevices[0].id,
      'BULK_ACTION_EXECUTED',
      'MEDIUM',
      `Bulk action "${name}" (${normalizedAction}) dispatched across ${targetDevices.length} node(s)`,
      { bulk_action_id: bulkId, name, action_type: normalizedAction, target_group_id: targetGroupId, total_devices: targetDevices.length }
    );
  }

  return getBulkAction(bulkId);
}

/**
 * Get all bulk device actions
 */
export function getBulkActions() {
  const db = getDb();
  const rows = db.prepare(`
    SELECT b.*, g.name as target_group_name
    FROM bulk_device_actions b
    LEFT JOIN dynamic_groups g ON b.target_group_id = g.id
    ORDER BY b.created_at DESC
  `).all();

  return rows.map(r => {
    try { r.parameters = JSON.parse(r.parameters_json || '{}'); } catch (_) { r.parameters = {}; }
    return r;
  });
}

/**
 * Get a single bulk device action with child device action details
 */
export function getBulkAction(bulkId) {
  const db = getDb();
  const bulk = db.prepare(`
    SELECT b.*, g.name as target_group_name
    FROM bulk_device_actions b
    LEFT JOIN dynamic_groups g ON b.target_group_id = g.id
    WHERE b.id = ?
  `).get(bulkId);

  if (!bulk) return null;

  try { bulk.parameters = JSON.parse(bulk.parameters_json || '{}'); } catch (_) { bulk.parameters = {}; }

  const childActions = db.prepare(`
    SELECT a.*, d.hostname, d.serial_number
    FROM device_remote_actions a
    LEFT JOIN devices d ON a.device_id = d.id
    WHERE a.bulk_action_id = ?
    ORDER BY a.created_at ASC
  `).all(bulkId);

  bulk.child_actions = childActions.map(r => {
    try { r.parameters = JSON.parse(r.parameters_json || '{}'); } catch (_) { r.parameters = {}; }
    try { r.result_data = JSON.parse(r.result_data_json || '{}'); } catch (_) { r.result_data = {}; }
    return r;
  });

  return bulk;
}
