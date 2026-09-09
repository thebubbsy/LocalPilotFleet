/**
 * LocalPilot Fleet — Organizational Messages & Toast Notifications QA
 * server/tests/messages.test.js
 *
 * Tests: Message catalog CRUD, surface/theme validation,
 * heartbeat delivery, ONCE/DAILY frequency suppression,
 * delivery/interaction acknowledgements, instant urgent toasts,
 * and engagement metrics.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Microsoft Intune Organizational Messages & Toast Notifications QA (messages.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-messages-qa';
  let testDeviceId;
  let testNodeToken;
  let createdMessageId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'QA-TOAST-WORKSTATION',
        serial_number: 'SN-MSG-TEST-001',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26200',
        total_ram_bytes: 34359738368,
        primary_user: 'qa-toast-admin'
      })
    });
    assert.equal(enrollRes.status, 201);
    const enrollData = await enrollRes.json();
    testDeviceId = enrollData.device_id;
    testNodeToken = enrollData.node_token;
  });

  after(async () => {
    if (app) await app.cleanup();
  });

  async function api(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Fleet-Key': FLEET_KEY,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  async function nodeApi(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  // ── STATS & CRUD TESTS ───────────────────────────────────────────────────

  it('MSG-01: GET /api/v1/fleet/messages/stats returns correct numeric KPIs', async () => {
    const res = await api('/api/v1/fleet/messages/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_messages === 'number');
    assert.ok(typeof res.body.active_messages === 'number');
    assert.ok(typeof res.body.total_deliveries === 'number');
    assert.ok(typeof res.body.engagement_rate_percent === 'number');
    assert.ok(res.body.total_messages >= 3, 'Should include at least 3 seeded messages');
  });

  it('MSG-02: POST /api/v1/fleet/messages creates new message (201)', async () => {
    const res = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Emergency Maintenance Tonight at 10 PM',
        messageBody: 'Fleet-wide zero-day patching is taking place. Please save your work.',
        surface: 'TOAST',
        theme: 'WARNING',
        targetGroupId: 'grp-all',
        actionUrl: 'https://status.localpilot.corp',
        actionLabel: 'Check Status',
        frequency: 'ONCE'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.title, 'Emergency Maintenance Tonight at 10 PM');
    assert.equal(res.body.surface, 'TOAST');
    assert.equal(res.body.theme, 'WARNING');
    createdMessageId = res.body.id;
  });

  it('MSG-03: POST /api/v1/fleet/messages rejects missing title or body (400)', async () => {
    const res1 = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({ messageBody: 'No title' })
    });
    assert.equal(res1.status, 400);

    const res2 = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({ title: 'No body' })
    });
    assert.equal(res2.status, 400);
  });

  it('MSG-04: POST /api/v1/fleet/messages rejects invalid surface or theme (400)', async () => {
    const res1 = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Bad surface',
        messageBody: 'test',
        surface: 'HOLOGRAM'
      })
    });
    assert.equal(res1.status, 400);

    const res2 = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Bad theme',
        messageBody: 'test',
        theme: 'PARTY'
      })
    });
    assert.equal(res2.status, 400);
  });

  it('MSG-05: GET /api/v1/fleet/messages returns seeded and created messages', async () => {
    const res = await api('/api/v1/fleet/messages');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.messages));
    assert.ok(res.body.messages.length >= 4);
    const found = res.body.messages.find(m => m.id === createdMessageId);
    assert.ok(found, 'Created message should be listed');
  });

  it('MSG-06: GET /api/v1/fleet/messages/:id returns single message', async () => {
    const res = await api(`/api/v1/fleet/messages/${createdMessageId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdMessageId);
    assert.equal(res.body.title, 'Emergency Maintenance Tonight at 10 PM');
  });

  it('MSG-07: GET /api/v1/fleet/messages/:id returns 404 for unknown message', async () => {
    const res = await api('/api/v1/fleet/messages/msg-unknown-999');
    assert.equal(res.status, 404);
  });

  it('MSG-08: PATCH /api/v1/fleet/messages/:id updates message fields', async () => {
    const res = await api(`/api/v1/fleet/messages/${createdMessageId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        title: 'Emergency Maintenance Tonight at 11 PM (Rescheduled)',
        theme: 'CRITICAL'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.title, 'Emergency Maintenance Tonight at 11 PM (Rescheduled)');
    assert.equal(res.body.theme, 'CRITICAL');
  });

  it('MSG-09: PATCH /api/v1/fleet/messages/:id rejects invalid frequency (400)', async () => {
    const res = await api(`/api/v1/fleet/messages/${createdMessageId}`, {
      method: 'PATCH',
      body: JSON.stringify({ frequency: 'EVERY_SECOND' })
    });
    assert.equal(res.status, 400);
  });

  it('MSG-10: DELETE /api/v1/fleet/messages/:id deletes message, then returns 404', async () => {
    const del = await api(`/api/v1/fleet/messages/${createdMessageId}`, { method: 'DELETE' });
    assert.equal(del.status, 200);
    assert.equal(del.body.success, true);

    const getAgain = await api(`/api/v1/fleet/messages/${createdMessageId}`);
    assert.equal(getAgain.status, 404);
  });

  // ── HEARTBEAT DELIVERY & INTERACTION TELEMETRY ────────────────────────────

  it('MSG-11: POST /api/v1/nodes/heartbeat includes pending_messages array', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        ip_address: '192.168.1.155',
        metrics: { cpu_usage_percent: 15, memory_used_bytes: 4000000 }
      })
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.pending_messages), 'Heartbeat must contain pending_messages');
    assert.ok(res.body.pending_messages.length >= 1, 'Should deliver active seeded messages');
  });

  it('MSG-12: POST /api/v1/nodes/:id/messages/:messageId/ack records delivery (200)', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/messages/msg-reboot-reminder/ack`, {
      method: 'POST',
      body: JSON.stringify({ status: 'DELIVERED', interacted: false })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.status, 'DELIVERED');
  });

  it('MSG-13: POST /api/v1/nodes/:id/messages/:messageId/ack records interaction (ACTIONED)', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/messages/msg-reboot-reminder/ack`, {
      method: 'POST',
      body: JSON.stringify({ status: 'ACTIONED', interacted: true })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ACTIONED');
  });

  it('MSG-14: POST /api/v1/nodes/:id/messages/:messageId/ack rejects invalid auth (401)', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/messages/msg-reboot-reminder/ack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer bad-token' },
      body: JSON.stringify({ status: 'DELIVERED' })
    });
    assert.equal(res.status, 401);
  });

  it('MSG-15: Frequency ONCE suppression: actioned message is omitted on next heartbeat', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId, metrics: {} })
    });
    assert.equal(res.status, 200);
    const hasRebootMsg = res.body.pending_messages.some(m => m.id === 'msg-reboot-reminder');
    assert.equal(hasRebootMsg, false, 'ONCE message should be suppressed after delivery/action');
  });

  it('MSG-16: GET /api/v1/fleet/messages/deliveries lists delivery history with hostname', async () => {
    const res = await api('/api/v1/fleet/messages/deliveries');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.deliveries));
    assert.ok(res.body.deliveries.length >= 1);
    const d = res.body.deliveries.find(item => item.device_id === testDeviceId);
    assert.ok(d, 'Should find delivery for test device');
    assert.equal(d.hostname, 'QA-TOAST-WORKSTATION');
    assert.equal(d.status, 'ACTIONED');
  });

  // ── INSTANT URGENT TOAST DISPATCH ─────────────────────────────────────────

  it('MSG-17: POST /api/v1/fleet/devices/:id/toast dispatches urgent toast (202)', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/toast`, {
      method: 'POST',
      body: JSON.stringify({
        title: 'Urgent Security Intervention',
        message: 'Malicious process activity blocked on your workstation.',
        theme: 'CRITICAL',
        action_url: 'windowsdefender:',
        action_label: 'View Defender Alert'
      })
    });
    assert.equal(res.status, 202);
    assert.ok(res.body.message_id);
    assert.ok(res.body.delivery_id);

    // Heartbeat should now receive this urgent toast
    const hbRes = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId, metrics: {} })
    });
    const urgentMsg = hbRes.body.pending_messages.find(m => m.id === res.body.message_id);
    assert.ok(urgentMsg, 'Urgent toast must be present in heartbeat pending_messages');
    assert.equal(urgentMsg.title, 'Urgent Security Intervention');
  });

  it('MSG-18: POST /api/v1/fleet/devices/:id/toast returns 404 for unknown device', async () => {
    const res = await api('/api/v1/fleet/devices/non-existent-device-xyz/toast', {
      method: 'POST',
      body: JSON.stringify({ title: 'Test', message: 'Test' })
    });
    assert.equal(res.status, 404);
  });

  it('MSG-19: Message stats reflect deliveries and interaction rate', async () => {
    const res = await api('/api/v1/fleet/messages/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_deliveries >= 1);
    assert.ok(res.body.actioned_count >= 1);
  });

  it('MSG-20: Group targeting: message for another group is not delivered to test device', async () => {
    const createRes = await api('/api/v1/fleet/messages', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Strictly for Win11 Modern Group',
        messageBody: 'Targeted message',
        targetGroupId: 'grp-win11-modern',
        surface: 'TOAST'
      })
    });
    assert.equal(createRes.status, 201);
    const targetMsgId = createRes.body.id;

    // Device not in grp-win11-modern should not receive it
    const hbRes = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId, metrics: {} })
    });
    const delivered = hbRes.body.pending_messages.some(m => m.id === targetMsgId);
    assert.equal(delivered, false, 'Should not deliver message targeted to other groups');
  });
});
