/**
 * LocalPilot Fleet — Event Stream & Audit Feed Routes
 * server/src/routes/events.js
 */

import { getDb } from '../db.js';
import { requireFleetKey } from '../utils/auth.js';
import { sendJson } from '../utils/router.js';

export const sseClients = new Set();

let pingInterval = null;

export function broadcastEvent(eventType, data) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

function startPingInterval() {
  if (pingInterval) return;
  pingInterval = setInterval(() => {
    for (const client of sseClients) {
      try {
        client.write(': ping\n\n');
      } catch {
        sseClients.delete(client);
      }
    }
  }, 15000);
  if (pingInterval.unref) pingInterval.unref();
}

export function registerEventRoutes(router) {
  startPingInterval();

  const handleSse = (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    res.write(`event: connected\ndata: ${JSON.stringify({ server_time: new Date().toISOString() })}\n\n`);
    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
  };

  router.get('/api/v1/events/stream', handleSse);
  router.get('/api/v1/fleet/events/stream', handleSse);

  const handleEventsList = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const { severity, acknowledged, device_id, limit = 50, offset = 0 } = req.query;

      const conditions = [];
      const params = [];

      if (severity) {
        conditions.push('e.severity = ?');
        params.push(severity);
      }

      if (acknowledged !== undefined && acknowledged !== '') {
        const ackVal = (acknowledged === 'true' || acknowledged === '1') ? 1 : 0;
        conditions.push('e.acknowledged = ?');
        params.push(ackVal);
      }

      if (device_id) {
        conditions.push('e.device_id = ?');
        params.push(device_id);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const query = `
        SELECT 
          e.id,
          e.device_id,
          d.hostname,
          d.friendly_name,
          e.event_type,
          e.event_id,
          e.event_source,
          e.severity,
          e.summary,
          e.raw_payload_json,
          e.acknowledged,
          e.acknowledged_at,
          e.acknowledged_by,
          e.created_at
        FROM security_events e
        LEFT JOIN devices d ON e.device_id = d.id
        ${whereClause}
        ORDER BY e.created_at DESC
        LIMIT ? OFFSET ?
      `;

      params.push(Number(limit) || 50, Number(offset) || 0);

      const events = db.prepare(query).all(...params);

      // Parse raw_payload_json for convenience
      const enriched = events.map(e => {
        let details = {};
        try {
          details = JSON.parse(e.raw_payload_json || '{}');
        } catch {}
        return {
          ...e,
          details
        };
      });

      const countQuery = `SELECT COUNT(*) as total FROM security_events e ${whereClause}`;
      const totalCount = db.prepare(countQuery).get(...params.slice(0, conditions.length)).total;

      sendJson(res, 200, {
        events: enriched,
        total_count: totalCount,
        limit: Number(limit),
        offset: Number(offset)
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DB_ERROR', message: err.message });
    }
  };

  router.get('/api/v1/fleet/events', handleEventsList);
  router.get('/api/v1/events/history', handleEventsList);

  const handleAck = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const eventId = Number(req.params.id);
      const ackBy = req.body.acknowledged_by || 'Fleet Admin';
      const now = new Date().toISOString();

      const stmt = db.prepare(`
        UPDATE security_events
        SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
        WHERE id = ?
      `);
      const result = stmt.run(now, ackBy, eventId);

      if (result.changes === 0) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Event ${eventId} not found` });
        return;
      }

      broadcastEvent('alert_acknowledged', {
        event_id: eventId,
        acknowledged_by: ackBy,
        acknowledged_at: now
      });

      sendJson(res, 200, {
        success: true,
        acknowledged_at: now,
        acknowledged_by: ackBy
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DB_ERROR', message: err.message });
    }
  };

  router.post('/api/v1/fleet/events/:id/ack', handleAck);
  router.post('/api/v1/events/:id/ack', handleAck);
}

export default registerEventRoutes;
