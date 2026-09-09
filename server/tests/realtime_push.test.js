import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, seedDatabase } from '../src/db.js';
import * as pushEngine from '../src/services/realtimePushEngine.js';

describe('Real-Time Push Transport & Scalability Engine (Dimension 2)', () => {
  let db;

  beforeEach(() => {
    db = initDb(':memory:', { seed: false });
    seedDatabase(db);
  });

  test('PUSH-01: should initialize push tables and retrieve initial push stats', () => {
    const stats = pushEngine.getPushStats(db);
    assert.ok(stats);
    assert.strictEqual(typeof stats.total_channels, 'number');
    assert.strictEqual(typeof stats.active_channels, 'number');
    assert.strictEqual(typeof stats.total_messages, 'number');
    assert.strictEqual(typeof stats.sub_3s_sla_percent, 'number');
    assert.strictEqual(stats.status, 'OPERATIONAL');
  });

  test('PUSH-02: should register a persistent WebSocket channel for a node', () => {
    const chan = pushEngine.registerChannel(db, {
      nodeId: 'dev-daddy-pc',
      transportType: 'WEBSOCKET',
      protocolVersion: 'v1.0',
      clientIp: '192.168.1.50',
      userAgent: 'LocalPilot-Agent/1.0.0'
    });

    assert.ok(chan);
    assert.strictEqual(chan.node_id, 'dev-daddy-pc');
    assert.strictEqual(chan.transport_type, 'WEBSOCKET');
    assert.strictEqual(chan.status, 'ACTIVE');
    assert.strictEqual(chan.client_ip, '192.168.1.50');
  });

  test('PUSH-03: should update last_ping_at during channel heartbeat', () => {
    const chan = pushEngine.registerChannel(db, { nodeId: 'dev-daddy-pc' });
    const ok = pushEngine.heartbeatChannel(db, chan.id);
    assert.strictEqual(ok, true);

    const updated = db.prepare('SELECT * FROM realtime_push_channels WHERE id = ?').get(chan.id);
    assert.strictEqual(updated.status, 'ACTIVE');
    assert.ok(updated.last_ping_at);
  });

  test('PUSH-04: should close a channel and set status to DISCONNECTED', () => {
    const chan = pushEngine.registerChannel(db, { nodeId: 'dev-daddy-pc' });
    const ok = pushEngine.closeChannel(db, chan.id);
    assert.strictEqual(ok, true);

    const updated = db.prepare('SELECT * FROM realtime_push_channels WHERE id = ?').get(chan.id);
    assert.strictEqual(updated.status, 'DISCONNECTED');
    assert.ok(updated.disconnected_at);
  });

  test('PUSH-05: should prune stale channels that exceeded inactivity timeout', () => {
    const chan = pushEngine.registerChannel(db, { nodeId: 'dev-sarah-laptop' });
    // Manually age the channel's last_ping_at
    db.prepare("UPDATE realtime_push_channels SET last_ping_at = DATETIME('now', '-300 seconds') WHERE id = ?").run(chan.id);

    const prunedCount = pushEngine.pruneStaleChannels(db, 120);
    assert.ok(prunedCount >= 1);

    const updated = db.prepare('SELECT * FROM realtime_push_channels WHERE id = ?').get(chan.id);
    assert.strictEqual(updated.status, 'DISCONNECTED');
  });

  test('PUSH-06: should dispatch an urgent push message (LOCK) and calculate initial status', () => {
    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'LOCK',
      payload: { action: 'REMOTE_LOCK', delay_sec: 0 },
      priority: 'URGENT',
      ttlSeconds: 120
    });

    assert.ok(msg);
    assert.strictEqual(msg.node_id, 'dev-daddy-pc');
    assert.strictEqual(msg.topic, 'LOCK');
    assert.strictEqual(msg.priority, 'URGENT');
    assert.ok(['SENT', 'QUEUED'].includes(msg.status));
  });

  test('PUSH-07: should queue a push message when node has no active channel', () => {
    // Ensure node has no active channels
    db.prepare("UPDATE realtime_push_channels SET status = 'DISCONNECTED' WHERE node_id = 'dev-livingroom-pc'").run();

    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-livingroom-pc',
      topic: 'POLICY_SYNC',
      payload: { scope: 'DELTA' },
      priority: 'HIGH'
    });

    assert.ok(msg);
    assert.strictEqual(msg.status, 'QUEUED');
    assert.strictEqual(msg.delivered_at, null);
  });

  test('PUSH-08: should set status to SENT when node has an active channel', () => {
    pushEngine.registerChannel(db, { nodeId: 'dev-sarah-laptop' });

    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-sarah-laptop',
      topic: 'COMMAND',
      payload: { command_id: 'cmd-01', command_text: 'Get-Service' },
      priority: 'HIGH'
    });

    assert.ok(msg);
    assert.strictEqual(msg.status, 'SENT');
    assert.ok(msg.delivered_at);
  });

  test('PUSH-09: should acknowledge a push message and calculate latency_ms', () => {
    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'COMMAND',
      payload: { command_id: 'cmd-ack-01' }
    });

    const acked = pushEngine.acknowledgePushMessage(db, {
      messageId: msg.id,
      nodeId: 'dev-daddy-pc',
      latencyMs: 84.5
    });

    assert.strictEqual(acked.status, 'ACKNOWLEDGED');
    assert.strictEqual(acked.latency_ms, 84.5);
    assert.ok(acked.acknowledged_at);
  });

  test('PUSH-10: should verify sub-3-second SLA calculation on low-latency delivery', () => {
    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'PING',
      payload: { ping: true }
    });

    pushEngine.acknowledgePushMessage(db, {
      messageId: msg.id,
      latencyMs: 120.0
    });

    const stats = pushEngine.getPushStats(db);
    assert.strictEqual(stats.sub_3s_sla_percent, 100.0);
    assert.ok(stats.mean_latency_ms > 0);
  });

  test('PUSH-11: should handle failed push message delivery with error message', () => {
    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'COMMAND',
      payload: { command_id: 'fail-01' }
    });

    const failed = pushEngine.acknowledgePushMessage(db, {
      messageId: msg.id,
      errorMessage: 'Socket write failed: Connection reset by peer'
    });

    assert.strictEqual(failed.status, 'FAILED');
    assert.strictEqual(failed.error_message, 'Socket write failed: Connection reset by peer');
  });

  test('PUSH-12: should query active channels with device metadata join', () => {
    pushEngine.registerChannel(db, { nodeId: 'dev-daddy-pc' });
    const channels = pushEngine.getActiveChannels(db, { status: 'ACTIVE' });
    assert.ok(channels.length > 0);

    const daddyChan = channels.find(c => c.node_id === 'dev-daddy-pc');
    assert.ok(daddyChan);
    assert.strictEqual(daddyChan.hostname, 'DADDY-RIG');
  });

  test('PUSH-13: should filter push messages by status and topic', () => {
    pushEngine.dispatchPushMessage(db, { nodeId: 'dev-daddy-pc', topic: 'WIPE', priority: 'URGENT' });
    const wipeMsgs = pushEngine.getPushMessages(db, { topic: 'WIPE' });
    assert.ok(wipeMsgs.length > 0);
    assert.strictEqual(wipeMsgs[0].topic, 'WIPE');
  });

  test('PUSH-14: should retrieve pending messages ordered by priority (URGENT > HIGH > NORMAL)', () => {
    db.prepare("UPDATE realtime_push_channels SET status = 'DISCONNECTED' WHERE node_id = 'dev-sarah-laptop'").run();

    pushEngine.dispatchPushMessage(db, { nodeId: 'dev-sarah-laptop', topic: 'POLICY_SYNC', priority: 'NORMAL' });
    pushEngine.dispatchPushMessage(db, { nodeId: 'dev-sarah-laptop', topic: 'LOCK', priority: 'URGENT' });
    pushEngine.dispatchPushMessage(db, { nodeId: 'dev-sarah-laptop', topic: 'COMMAND', priority: 'HIGH' });

    const pending = pushEngine.getPendingMessagesForNode(db, 'dev-sarah-laptop');
    assert.ok(pending.length >= 3);
    assert.strictEqual(pending[0].priority, 'URGENT');
    assert.strictEqual(pending[1].priority, 'HIGH');
    assert.strictEqual(pending[2].priority, 'NORMAL');
  });

  test('PUSH-15: should expire pending messages when ttl_seconds has elapsed', () => {
    db.prepare("UPDATE realtime_push_channels SET status = 'DISCONNECTED' WHERE node_id = 'dev-livingroom-pc'").run();

    const msg = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-livingroom-pc',
      topic: 'PING',
      ttlSeconds: 10
    });

    // Artificially age the message past TTL
    db.prepare("UPDATE realtime_push_messages SET dispatched_at = DATETIME('now', '-20 seconds') WHERE id = ?").run(msg.id);

    const pending = pushEngine.getPendingMessagesForNode(db, 'dev-livingroom-pc');
    const expiredMsg = pending.find(m => m.id === msg.id);
    assert.strictEqual(expiredMsg, undefined); // should be expired and excluded

    const dbMsg = db.prepare('SELECT status FROM realtime_push_messages WHERE id = ?').get(msg.id);
    assert.strictEqual(dbMsg.status, 'EXPIRED');
  });

  test('PUSH-16: should attach and detach in-memory client streaming response objects', () => {
    const mockRes = {
      write: () => true,
      on: (ev, cb) => { mockRes._onClose = cb; }
    };

    pushEngine.attachClientStream('dev-test-node', mockRes);
    const statsBefore = pushEngine.getPushStats(db);
    assert.ok(statsBefore.live_memory_streams >= 1);

    pushEngine.detachClientStream('dev-test-node', mockRes);
    const statsAfter = pushEngine.getPushStats(db);
    assert.strictEqual(statsAfter.live_memory_streams, statsBefore.live_memory_streams - 1);
  });

  test('PUSH-17: should broadcast message payload over active memory stream', () => {
    let writtenChunk = '';
    const mockRes = {
      write: (chunk) => { writtenChunk += chunk; return true; },
      on: () => {}
    };

    pushEngine.attachClientStream('dev-stream-node', mockRes);
    const sent = pushEngine.broadcastToNode('dev-stream-node', 'EMERGENCY_LOCK', { locked: true });

    assert.strictEqual(sent, 1);
    assert.ok(writtenChunk.includes('event: EMERGENCY_LOCK'));
    assert.ok(writtenChunk.includes('"locked":true'));

    pushEngine.detachClientStream('dev-stream-node', mockRes);
  });

  test('PUSH-18: should support emergency WIPE and ISOLATE topic dispatches', () => {
    const wipe = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'WIPE',
      payload: { preserve_user_data: false },
      priority: 'URGENT'
    });
    assert.strictEqual(wipe.topic, 'WIPE');
    assert.strictEqual(wipe.priority, 'URGENT');

    const isolate = pushEngine.dispatchPushMessage(db, {
      nodeId: 'dev-daddy-pc',
      topic: 'ISOLATE',
      payload: { allow_fleet_traffic: true },
      priority: 'URGENT'
    });
    assert.strictEqual(isolate.topic, 'ISOLATE');
  });

  test('PUSH-19: should calculate mean, min, and max delivery latency metrics', () => {
    const stats = pushEngine.getPushStats(db);
    assert.strictEqual(typeof stats.mean_latency_ms, 'number');
    assert.strictEqual(typeof stats.min_latency_ms, 'number');
    assert.strictEqual(typeof stats.max_latency_ms, 'number');
    assert.ok(stats.max_latency_ms >= stats.min_latency_ms);
  });

  test('PUSH-20: should deactivate previous channel when node reconnects with a new channel', () => {
    const c1 = pushEngine.registerChannel(db, { nodeId: 'dev-daddy-pc', clientIp: '10.0.0.1' });
    assert.strictEqual(c1.status, 'ACTIVE');

    const c2 = pushEngine.registerChannel(db, { nodeId: 'dev-daddy-pc', clientIp: '10.0.0.2' });
    assert.strictEqual(c2.status, 'ACTIVE');

    const oldC1 = db.prepare('SELECT status FROM realtime_push_channels WHERE id = ?').get(c1.id);
    assert.strictEqual(oldC1.status, 'DISCONNECTED');
  });
});
