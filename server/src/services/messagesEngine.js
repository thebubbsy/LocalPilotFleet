/**
 * LocalPilot Fleet — Organizational Messages & Toast Notifications Engine
 * server/src/services/messagesEngine.js
 *
 * Implements Microsoft Intune Organizational Messages:
 * - Native Windows Toast Notifications
 * - Taskbar Pin & System Notification Area Alerts
 * - Full-Screen Modal Security Notices
 * - Dynamic Group Scoping & Delivery Frequency Governance (ONCE, DAILY, EVERY_HEARTBEAT)
 */

import { broadcastEvent } from '../routes/events.js';

function genId(prefix = 'msg') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
}

const VALID_SURFACES = new Set(['TOAST', 'TASKBAR', 'MODAL']);
const VALID_THEMES = new Set(['INFO', 'WARNING', 'CRITICAL', 'UPDATE', 'ONBOARDING']);
const VALID_FREQUENCIES = new Set(['ONCE', 'DAILY', 'EVERY_HEARTBEAT']);

/**
 * Get all organizational messages with delivery statistics
 */
export function getMessages(db, filters = {}) {
  const { enabled, surface, theme } = filters;
  let sql = `
    SELECT om.*,
           COALESCE(dg.name, 'All Devices') as target_group_name,
           (SELECT COUNT(*) FROM device_message_deliveries WHERE message_id = om.id) as total_deliveries,
           (SELECT COUNT(*) FROM device_message_deliveries WHERE message_id = om.id AND status IN ('DELIVERED', 'ACTIONED')) as delivered_count,
           (SELECT COUNT(*) FROM device_message_deliveries WHERE message_id = om.id AND status = 'ACTIONED') as actioned_count
    FROM organizational_messages om
    LEFT JOIN dynamic_groups dg ON om.target_group_id = dg.id
    WHERE 1=1
  `;
  const params = [];

  if (enabled !== undefined) {
    sql += ' AND om.enabled = ?';
    params.push(enabled ? 1 : 0);
  }
  if (surface) {
    sql += ' AND om.surface = ?';
    params.push(surface);
  }
  if (theme) {
    sql += ' AND om.theme = ?';
    params.push(theme);
  }

  sql += ' ORDER BY om.created_at DESC';
  const rows = db.prepare(sql).all(...params);
  return rows.map(r => ({
    ...r,
    enabled: Boolean(r.enabled)
  }));
}

/**
 * Get a single organizational message by ID
 */
export function getMessage(db, id) {
  const msg = db.prepare(`
    SELECT om.*,
           COALESCE(dg.name, 'All Devices') as target_group_name,
           (SELECT COUNT(*) FROM device_message_deliveries WHERE message_id = om.id) as total_deliveries,
           (SELECT COUNT(*) FROM device_message_deliveries WHERE message_id = om.id AND status = 'ACTIONED') as actioned_count
    FROM organizational_messages om
    LEFT JOIN dynamic_groups dg ON om.target_group_id = dg.id
    WHERE om.id = ?
  `).get(id);

  if (!msg) return null;
  return {
    ...msg,
    enabled: Boolean(msg.enabled)
  };
}

/**
 * Create a new organizational message
 */
export function createMessage(db, payload) {
  const {
    title,
    messageBody,
    surface = 'TOAST',
    theme = 'INFO',
    targetGroupId = 'grp-all',
    actionUrl = '',
    actionLabel = '',
    startDate,
    endDate,
    frequency = 'ONCE',
    enabled = true
  } = payload;

  if (!title || typeof title !== 'string' || !title.trim()) {
    throw new Error('Message title is required');
  }
  if (!messageBody || typeof messageBody !== 'string' || !messageBody.trim()) {
    throw new Error('Message body is required');
  }
  if (!VALID_SURFACES.has(surface)) {
    throw new Error(`Invalid surface: ${surface}. Must be one of: ${[...VALID_SURFACES].join(', ')}`);
  }
  if (!VALID_THEMES.has(theme)) {
    throw new Error(`Invalid theme: ${theme}. Must be one of: ${[...VALID_THEMES].join(', ')}`);
  }
  if (!VALID_FREQUENCIES.has(frequency)) {
    throw new Error(`Invalid frequency: ${frequency}. Must be one of: ${[...VALID_FREQUENCIES].join(', ')}`);
  }

  const id = genId('msg');
  const stmt = db.prepare(`
    INSERT INTO organizational_messages (
      id, title, message_body, surface, theme, target_group_id,
      action_url, action_label, start_date, end_date, frequency, enabled,
      created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, DATE('now')), ?, ?, ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    title.trim(),
    messageBody.trim(),
    surface,
    theme,
    targetGroupId || 'grp-all',
    actionUrl ? actionUrl.trim() : '',
    actionLabel ? actionLabel.trim() : '',
    startDate || null,
    endDate || null,
    frequency,
    enabled ? 1 : 0
  );

  broadcastEvent('organizational_message_created', { id, title });
  return getMessage(db, id);
}

/**
 * Update an existing organizational message
 */
export function updateMessage(db, id, updates) {
  const existing = getMessage(db, id);
  if (!existing) throw new Error(`Organizational message not found: ${id}`);

  const fields = [];
  const params = [];

  if (updates.title !== undefined) {
    if (!updates.title.trim()) throw new Error('Title cannot be empty');
    fields.push('title = ?');
    params.push(updates.title.trim());
  }
  if (updates.message_body !== undefined || updates.messageBody !== undefined) {
    const b = updates.message_body || updates.messageBody;
    if (!b.trim()) throw new Error('Message body cannot be empty');
    fields.push('message_body = ?');
    params.push(b.trim());
  }
  if (updates.surface !== undefined) {
    if (!VALID_SURFACES.has(updates.surface)) throw new Error('Invalid surface');
    fields.push('surface = ?');
    params.push(updates.surface);
  }
  if (updates.theme !== undefined) {
    if (!VALID_THEMES.has(updates.theme)) throw new Error('Invalid theme');
    fields.push('theme = ?');
    params.push(updates.theme);
  }
  if (updates.target_group_id !== undefined || updates.targetGroupId !== undefined) {
    fields.push('target_group_id = ?');
    params.push(updates.target_group_id || updates.targetGroupId || 'grp-all');
  }
  if (updates.action_url !== undefined || updates.actionUrl !== undefined) {
    fields.push('action_url = ?');
    params.push(updates.action_url !== undefined ? updates.action_url : updates.actionUrl);
  }
  if (updates.action_label !== undefined || updates.actionLabel !== undefined) {
    fields.push('action_label = ?');
    params.push(updates.action_label !== undefined ? updates.action_label : updates.actionLabel);
  }
  if (updates.frequency !== undefined) {
    if (!VALID_FREQUENCIES.has(updates.frequency)) throw new Error('Invalid frequency');
    fields.push('frequency = ?');
    params.push(updates.frequency);
  }
  if (updates.enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(updates.enabled ? 1 : 0);
  }

  if (fields.length > 0) {
    fields.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE organizational_messages SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  }

  return getMessage(db, id);
}

/**
 * Delete an organizational message
 */
export function deleteMessage(db, id) {
  const existing = getMessage(db, id);
  if (!existing) throw new Error(`Organizational message not found: ${id}`);
  db.prepare('DELETE FROM organizational_messages WHERE id = ?').run(id);
  broadcastEvent('organizational_message_deleted', { id });
  return { success: true, id };
}

/**
 * Evaluate and retrieve pending messages due for delivery to a specific node
 */
export function getPendingMessagesForDevice(db, deviceId) {
  try {
    // 1. Resolve target groups
    const groupRows = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
    const groupIds = new Set(groupRows.map(r => r.group_id));
    groupIds.add('grp-all');

    // 2. Query active messages in target groups
    const messages = db.prepare(`
      SELECT * FROM organizational_messages
      WHERE enabled = 1
        AND (start_date IS NULL OR start_date <= DATE('now'))
        AND (end_date IS NULL OR end_date >= DATE('now'))
      ORDER BY created_at DESC
    `).all();

    const pending = [];

    for (const msg of messages) {
      if (!groupIds.has(msg.target_group_id)) continue;

      // 3. Frequency suppression evaluation
      if (msg.frequency === 'ONCE') {
        const delivered = db.prepare(`
          SELECT id FROM device_message_deliveries
          WHERE message_id = ? AND device_id = ? AND status IN ('DELIVERED', 'ACTIONED', 'DISMISSED')
          LIMIT 1
        `).get(msg.id, deviceId);
        if (delivered) continue;
      } else if (msg.frequency === 'DAILY') {
        const deliveredToday = db.prepare(`
          SELECT id FROM device_message_deliveries
          WHERE message_id = ? AND device_id = ?
            AND (delivered_at >= DATETIME('now', '-1 day') OR created_at >= DATETIME('now', '-1 day'))
          LIMIT 1
        `).get(msg.id, deviceId);
        if (deliveredToday) continue;
      }

      pending.push({
        id: msg.id,
        title: msg.title,
        message_body: msg.message_body,
        message: msg.message_body,
        surface: msg.surface,
        theme: msg.theme,
        action_url: msg.action_url,
        action_label: msg.action_label,
        frequency: msg.frequency
      });
    }

    return pending;
  } catch (err) {
    return [];
  }
}

/**
 * Record message delivery or user interaction from agent
 */
export function recordDeliveryStatus(db, payload) {
  const { messageId, deviceId, status = 'DELIVERED', interactedAt } = payload;
  if (!messageId || !deviceId) throw new Error('messageId and deviceId are required');

  const existing = db.prepare(`
    SELECT id FROM device_message_deliveries
    WHERE message_id = ? AND device_id = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(messageId, deviceId);

  if (existing) {
    db.prepare(`
      UPDATE device_message_deliveries
      SET status = ?,
          delivered_at = COALESCE(delivered_at, DATETIME('now')),
          interacted_at = CASE WHEN ? = 1 THEN DATETIME('now') ELSE interacted_at END
      WHERE id = ?
    `).run(status, interactedAt ? 1 : 0, existing.id);
  } else {
    const id = genId('dmd');
    db.prepare(`
      INSERT INTO device_message_deliveries (
        id, message_id, device_id, status, delivered_at, interacted_at, created_at
      ) VALUES (
        ?, ?, ?, ?, DATETIME('now'), CASE WHEN ? = 1 THEN DATETIME('now') ELSE NULL END, DATETIME('now')
      )
    `).run(id, messageId, deviceId, status, interactedAt ? 1 : 0);
  }

  broadcastEvent('device_message_status_updated', { message_id: messageId, device_id: deviceId, status });
  return { success: true, messageId, deviceId, status };
}

/**
 * Dispatch an urgent, targeted toast notification immediately to a single device
 */
export function dispatchUrgentToast(db, payload) {
  const { deviceId, title, messageBody, theme = 'WARNING', actionUrl = '', actionLabel = '' } = payload;
  if (!deviceId) throw new Error('deviceId is required');
  if (!title || !messageBody) throw new Error('title and messageBody are required');

  const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const msgId = genId('msg-instant');
  db.prepare(`
    INSERT INTO organizational_messages (
      id, title, message_body, surface, theme, target_group_id,
      action_url, action_label, start_date, frequency, enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, 'TOAST', ?, 'grp-all', ?, ?, DATE('now'), 'ONCE', 1, DATETIME('now'), DATETIME('now')
    )
  `).run(msgId, title, messageBody, theme, actionUrl, actionLabel);

  const deliveryId = genId('dmd');
  db.prepare(`
    INSERT INTO device_message_deliveries (
      id, message_id, device_id, status, created_at
    ) VALUES (?, ?, ?, 'PENDING', DATETIME('now'))
  `).run(deliveryId, msgId, deviceId);

  broadcastEvent('urgent_toast_dispatched', { device_id: deviceId, message_id: msgId, title });
  return { success: true, message_id: msgId, delivery_id: deliveryId };
}

/**
 * Get fleet-wide aggregate statistics for organizational messaging
 */
export function getMessageStats(db) {
  const total = db.prepare('SELECT COUNT(*) as c FROM organizational_messages').get().c;
  const active = db.prepare('SELECT COUNT(*) as c FROM organizational_messages WHERE enabled = 1').get().c;
  const deliveries = db.prepare('SELECT COUNT(*) as c FROM device_message_deliveries').get().c;
  const delivered = db.prepare("SELECT COUNT(*) as c FROM device_message_deliveries WHERE status IN ('DELIVERED', 'ACTIONED')").get().c;
  const actioned = db.prepare("SELECT COUNT(*) as c FROM device_message_deliveries WHERE status = 'ACTIONED'").get().c;

  const engagementRate = deliveries > 0 ? Math.round((actioned / deliveries) * 100) : 0;

  return {
    total_messages: total,
    active_messages: active,
    total_deliveries: deliveries,
    delivered_count: delivered,
    actioned_count: actioned,
    engagement_rate_percent: engagementRate
  };
}

/**
 * Get historical message deliveries
 */
export function getMessageDeliveries(db, filters = {}) {
  const { device_id, message_id, limit = 50 } = filters;
  let sql = `
    SELECT dmd.*,
           d.hostname,
           om.title as message_title,
           om.surface,
           om.theme
    FROM device_message_deliveries dmd
    JOIN devices d ON dmd.device_id = d.id
    JOIN organizational_messages om ON dmd.message_id = om.id
    WHERE 1=1
  `;
  const params = [];

  if (device_id) {
    sql += ' AND dmd.device_id = ?';
    params.push(device_id);
  }
  if (message_id) {
    sql += ' AND dmd.message_id = ?';
    params.push(message_id);
  }

  sql += ' ORDER BY dmd.created_at DESC LIMIT ?';
  params.push(Number(limit) || 50);

  return db.prepare(sql).all(...params);
}
