/**
 * LocalPilot Fleet — Enterprise Real-Time Push Transport & Scalability Engine
 * server/src/services/realtimePushEngine.js
 *
 * Dimension 2: Transport, Real-Time Push & Scalability
 * Provides persistent bi-directional push streaming (WebSocket / SSE Duplex),
 * sub-3-second emergency command dispatch (Wipe, Lock, Isolate, Policy Sync),
 * message delivery queueing, TTL expiration, and mathematical latency SLA calculation.
 */

import crypto from 'node:crypto';

// In-memory registry of active live streams (nodeId -> Set of HTTP streaming response objects)
const activeNodeStreams = new Map();

export function attachClientStream(nodeId, res) {
  if (!activeNodeStreams.has(nodeId)) {
    activeNodeStreams.set(nodeId, new Set());
  }
  activeNodeStreams.get(nodeId).add(res);

  res.on('close', () => {
    detachClientStream(nodeId, res);
  });
}

export function detachClientStream(nodeId, res) {
  if (activeNodeStreams.has(nodeId)) {
    const set = activeNodeStreams.get(nodeId);
    set.delete(res);
    if (set.size === 0) {
      activeNodeStreams.delete(nodeId);
    }
  }
}

export function broadcastToNode(nodeId, topic, data) {
  if (!activeNodeStreams.has(nodeId)) return 0;
  const set = activeNodeStreams.get(nodeId);
  const payloadStr = JSON.stringify(data);
  const sseChunk = `event: ${topic}\ndata: ${payloadStr}\n\n`;

  let sent = 0;
  for (const res of set) {
    try {
      res.write(sseChunk);
      sent++;
    } catch {
      set.delete(res);
    }
  }
  return sent;
}

export function getPushStats(db) {
  const totalChannels = db.prepare('SELECT COUNT(*) as c FROM realtime_push_channels').get().c;
  const activeChannels = db.prepare("SELECT COUNT(*) as c FROM realtime_push_channels WHERE status = 'ACTIVE'").get().c;
  const disconnectedChannels = db.prepare("SELECT COUNT(*) as c FROM realtime_push_channels WHERE status = 'DISCONNECTED'").get().c;

  const totalMessages = db.prepare('SELECT COUNT(*) as c FROM realtime_push_messages').get().c;
  const ackedMessages = db.prepare("SELECT COUNT(*) as c FROM realtime_push_messages WHERE status = 'ACKNOWLEDGED'").get().c;
  const queuedMessages = db.prepare("SELECT COUNT(*) as c FROM realtime_push_messages WHERE status = 'QUEUED'").get().c;
  const failedMessages = db.prepare("SELECT COUNT(*) as c FROM realtime_push_messages WHERE status = 'FAILED' OR status = 'EXPIRED'").get().c;

  // Latency metrics for acknowledged messages
  const latencyStats = db.prepare(`
    SELECT 
      AVG(latency_ms) as mean_latency,
      MIN(latency_ms) as min_latency,
      MAX(latency_ms) as max_latency,
      COUNT(CASE WHEN latency_ms <= 3000 THEN 1 END) as sub_3s_count,
      COUNT(*) as total_ack_count
    FROM realtime_push_messages
    WHERE status = 'ACKNOWLEDGED' AND latency_ms IS NOT NULL
  `).get();

  const meanLatency = latencyStats && latencyStats.mean_latency !== null
    ? Math.round(latencyStats.mean_latency * 10) / 10
    : 0;
  const minLatency = latencyStats && latencyStats.min_latency !== null
    ? Math.round(latencyStats.min_latency * 10) / 10
    : 0;
  const maxLatency = latencyStats && latencyStats.max_latency !== null
    ? Math.round(latencyStats.max_latency * 10) / 10
    : 0;

  const sub3sSlaPercent = latencyStats && latencyStats.total_ack_count > 0
    ? Math.round((latencyStats.sub_3s_count / latencyStats.total_ack_count) * 1000) / 10
    : 100.0;

  const transports = db.prepare(`
    SELECT transport_type, COUNT(*) as count
    FROM realtime_push_channels
    WHERE status = 'ACTIVE'
    GROUP BY transport_type
  `).all();

  const topics = db.prepare(`
    SELECT topic, COUNT(*) as count
    FROM realtime_push_messages
    GROUP BY topic
  `).all();

  return {
    total_channels: totalChannels,
    active_channels: activeChannels,
    disconnected_channels: disconnectedChannels,
    total_messages: totalMessages,
    acknowledged_messages: ackedMessages,
    queued_messages: queuedMessages,
    failed_messages: failedMessages,
    mean_latency_ms: meanLatency,
    min_latency_ms: minLatency,
    max_latency_ms: maxLatency,
    sub_3s_sla_percent: sub3sSlaPercent,
    transports_active: transports.reduce((acc, r) => { acc[r.transport_type] = r.count; return acc; }, {}),
    messages_by_topic: topics.reduce((acc, r) => { acc[r.topic] = r.count; return acc; }, {}),
    live_memory_streams: Array.from(activeNodeStreams.values()).reduce((sum, set) => sum + set.size, 0),
    status: activeChannels > 0 || totalChannels === 0 ? 'OPERATIONAL' : 'DEGRADED'
  };
}

export function getActiveChannels(db, { nodeId = null, status = null } = {}) {
  let sql = `
    SELECT c.*, d.hostname, d.friendly_name, d.status as device_status
    FROM realtime_push_channels c
    LEFT JOIN devices d ON c.node_id = d.id
  `;
  const conditions = [];
  const params = [];

  if (nodeId) {
    conditions.push('c.node_id = ?');
    params.push(nodeId);
  }
  if (status) {
    conditions.push('c.status = ?');
    params.push(status);
  }

  if (conditions.length > 0) {
    sql += ' WHERE ' + conditions.join(' AND ');
  }
  sql += ' ORDER BY c.status ASC, c.last_ping_at DESC';

  return db.prepare(sql).all(...params);
}

export function registerChannel(db, {
  id = null,
  nodeId,
  transportType = 'WEBSOCKET',
  protocolVersion = 'v1.0',
  clientIp = '',
  userAgent = ''
}) {
  const channelId = id || `chan-${crypto.randomBytes(6).toString('hex')}`;

  // Deactivate any existing active channels for this node
  db.prepare(`
    UPDATE realtime_push_channels
    SET status = 'DISCONNECTED', disconnected_at = DATETIME('now')
    WHERE node_id = ? AND status = 'ACTIVE'
  `).run(nodeId);

  db.prepare(`
    INSERT INTO realtime_push_channels (
      id, node_id, transport_type, protocol_version, connected_at, last_ping_at, status, client_ip, user_agent
    ) VALUES (?, ?, ?, ?, DATETIME('now'), DATETIME('now'), 'ACTIVE', ?, ?)
  `).run(
    channelId,
    nodeId,
    transportType,
    protocolVersion,
    clientIp,
    userAgent
  );

  return db.prepare('SELECT * FROM realtime_push_channels WHERE id = ?').get(channelId);
}

export function heartbeatChannel(db, channelId) {
  const res = db.prepare(`
    UPDATE realtime_push_channels
    SET last_ping_at = DATETIME('now'), status = 'ACTIVE'
    WHERE id = ?
  `).run(channelId);

  return res.changes > 0;
}

export function closeChannel(db, channelId) {
  const res = db.prepare(`
    UPDATE realtime_push_channels
    SET status = 'DISCONNECTED', disconnected_at = DATETIME('now')
    WHERE id = ?
  `).run(channelId);

  return res.changes > 0;
}

export function pruneStaleChannels(db, timeoutSec = 120) {
  const res = db.prepare(`
    UPDATE realtime_push_channels
    SET status = 'DISCONNECTED', disconnected_at = DATETIME('now')
    WHERE status = 'ACTIVE'
      AND (JULIANDAY('now') - JULIANDAY(last_ping_at)) * 86400 > ?
  `).run(timeoutSec);

  return res.changes;
}

export function dispatchPushMessage(db, {
  nodeId,
  topic,
  payload = {},
  priority = 'HIGH',
  ttlSeconds = 300
}) {
  const messageId = `msg-${crypto.randomBytes(8).toString('hex')}`;
  const payloadJson = typeof payload === 'string' ? payload : JSON.stringify(payload);

  // Check if node has active channel or active memory stream
  const activeChan = db.prepare(`
    SELECT id, transport_type
    FROM realtime_push_channels
    WHERE node_id = ? AND status = 'ACTIVE'
    LIMIT 1
  `).get(nodeId);

  const hasLiveStream = activeNodeStreams.has(nodeId) && activeNodeStreams.get(nodeId).size > 0;
  const isImmediatelyDeliverable = Boolean(activeChan || hasLiveStream);

  const initialStatus = isImmediatelyDeliverable ? 'SENT' : 'QUEUED';
  const deliveredAt = isImmediatelyDeliverable ? new Date().toISOString() : null;

  db.prepare(`
    INSERT INTO realtime_push_messages (
      id, node_id, topic, payload_json, priority, status, ttl_seconds, dispatched_at, delivered_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'), ?)
  `).run(
    messageId,
    nodeId,
    topic,
    payloadJson,
    priority,
    initialStatus,
    ttlSeconds,
    deliveredAt
  );

  const message = db.prepare('SELECT * FROM realtime_push_messages WHERE id = ?').get(messageId);

  // If live stream exists, push immediately over SSE/Socket
  if (isImmediatelyDeliverable) {
    broadcastToNode(nodeId, topic, {
      message_id: messageId,
      topic,
      priority,
      payload: typeof payload === 'string' ? JSON.parse(payload) : payload,
      dispatched_at: message.dispatched_at
    });
  }

  return message;
}

export function acknowledgePushMessage(db, {
  messageId,
  nodeId = null,
  clientTimestamp = null,
  latencyMs = null,
  errorMessage = null
}) {
  const msg = db.prepare('SELECT * FROM realtime_push_messages WHERE id = ?').get(messageId);
  if (!msg) {
    return { error: 'Push message not found', code: 'MESSAGE_NOT_FOUND' };
  }

  let finalLatency = latencyMs;
  if (finalLatency === null || finalLatency === undefined) {
    const dispatched = new Date(msg.dispatched_at).getTime();
    const ackTime = clientTimestamp ? new Date(clientTimestamp).getTime() : Date.now();
    finalLatency = Math.max(1, ackTime - dispatched);
  }

  const finalStatus = errorMessage ? 'FAILED' : 'ACKNOWLEDGED';

  db.prepare(`
    UPDATE realtime_push_messages
    SET status = ?,
        acknowledged_at = DATETIME('now'),
        latency_ms = ?,
        error_message = ?
    WHERE id = ?
  `).run(
    finalStatus,
    finalLatency,
    errorMessage || null,
    messageId
  );

  return db.prepare('SELECT * FROM realtime_push_messages WHERE id = ?').get(messageId);
}

export function getPushMessages(db, {
  nodeId = null,
  status = null,
  topic = null,
  limit = 50,
  offset = 0
} = {}) {
  let sql = `
    SELECT m.*, d.hostname, d.friendly_name
    FROM realtime_push_messages m
    LEFT JOIN devices d ON m.node_id = d.id
  `;
  const conditions = [];
  const params = [];

  if (nodeId) {
    conditions.push('m.node_id = ?');
    params.push(nodeId);
  }
  if (status) {
    conditions.push('m.status = ?');
    params.push(status);
  }
  if (topic) {
    conditions.push('m.topic = ?');
    params.push(topic);
  }

  if (conditions.length > 0) {
    sql += ' WHERE ' + conditions.join(' AND ');
  }
  sql += ' ORDER BY m.dispatched_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  return db.prepare(sql).all(...params);
}

export function getPendingMessagesForNode(db, nodeId) {
  // Prune expired messages first
  db.prepare(`
    UPDATE realtime_push_messages
    SET status = 'EXPIRED'
    WHERE node_id = ? AND status IN ('QUEUED', 'SENT')
      AND (JULIANDAY('now') - JULIANDAY(dispatched_at)) * 86400 > ttl_seconds
  `).run(nodeId);

  return db.prepare(`
    SELECT *
    FROM realtime_push_messages
    WHERE node_id = ? AND status IN ('QUEUED', 'SENT')
    ORDER BY 
      CASE priority
        WHEN 'URGENT' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'NORMAL' THEN 3
        ELSE 4
      END,
      dispatched_at ASC
  `).all(nodeId);
}
