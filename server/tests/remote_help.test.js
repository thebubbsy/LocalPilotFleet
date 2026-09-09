/**
 * LocalPilot Fleet — Microsoft Intune Remote Help & Unattended Assistance QA Tests
 * server/tests/remote_help.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as remoteHelpEngine from '../src/services/remoteHelpEngine.js';

describe('Intune Remote Help & Unattended Assistance QA (remote_help.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-remote-help-qa';
  let testDeviceId;
  let testNodeToken;

  let createdSessionId;
  let createdSessionCode;
  let customRoleId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test workstation
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': FLEET_KEY
      },
      body: JSON.stringify({
        hostname: 'CAD-WORKSTATION-01',
        friendly_name: 'Engineering CAD Workstation',
        serial_number: 'RH-TEST-SN-112233',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '23H2',
        total_ram_bytes: 34359738368
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

  // ── 1. Statistics & Baseline Seeds ──
  it('RH-01: GET /api/v1/fleet/remote-help/stats should return baseline stats', async () => {
    const res = await api('/api/v1/fleet/remote-help/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.totalSessions === 'number');
    assert.ok(typeof res.body.activeRoles === 'number');
    assert.ok(res.body.activeRoles >= 3, 'Should have at least 3 seed roles');
  });

  it('RH-02: GET /api/v1/fleet/remote-help/roles should return default seed roles', async () => {
    const res = await api('/api/v1/fleet/remote-help/roles');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.roles));
    const roleIds = res.body.roles.map(r => r.id);
    assert.ok(roleIds.includes('rh-role-tier1'));
    assert.ok(roleIds.includes('rh-role-tier2-admin'));
    assert.ok(roleIds.includes('rh-role-unattended-ops'));

    const tier1 = res.body.roles.find(r => r.id === 'rh-role-tier1');
    assert.equal(tier1.can_request_full_control, 1);
    assert.equal(tier1.can_request_elevation, 0);
    assert.equal(tier1.can_unattended, 0);
  });

  it('RH-03: POST /api/v1/fleet/remote-help/roles should create custom role', async () => {
    const res = await api('/api/v1/fleet/remote-help/roles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Custom Tier 3 Escalation',
        description: 'Senior escalations with full control and elevation',
        can_request_full_control: 1,
        can_request_elevation: 1,
        can_unattended: 0
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, 'Custom Tier 3 Escalation');
    assert.equal(res.body.can_request_elevation, 1);
    customRoleId = res.body.id;
  });

  it('RH-04: PATCH /api/v1/fleet/remote-help/roles/:id should update role permissions', async () => {
    const res = await api(`/api/v1/fleet/remote-help/roles/${customRoleId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        can_unattended: 1,
        description: 'Updated senior escalations with unattended access'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.can_unattended, 1);
    assert.equal(res.body.description, 'Updated senior escalations with unattended access');
  });

  it('RH-05: DELETE /api/v1/fleet/remote-help/roles/:id should delete custom role', async () => {
    const res = await api(`/api/v1/fleet/remote-help/roles/${customRoleId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.deleted_id, customRoleId);

    const check = await api(`/api/v1/fleet/remote-help/roles/${customRoleId}`);
    assert.equal(check.status, 404);
  });

  // ── 2. Session Lifecycle & Remote Control ──
  it('RH-06: POST /api/v1/fleet/remote-help/sessions should create attended session with 6-digit PIN', async () => {
    const res = await api('/api/v1/fleet/remote-help/sessions', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        helper_user: 'Alice Admin',
        sharer_user: 'Bob User',
        session_type: 'VIEW_ONLY',
        unattended_enabled: 0
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.status, 'PENDING');
    assert.equal(res.body.session_type, 'VIEW_ONLY');
    assert.match(res.body.session_code, /^\d{6}$/);

    createdSessionId = res.body.id;
    createdSessionCode = res.body.session_code;
  });

  it('RH-07: POST /api/v1/fleet/remote-help/sessions should reject invalid device_id with 400', async () => {
    const res = await api('/api/v1/fleet/remote-help/sessions', {
      method: 'POST',
      body: JSON.stringify({
        device_id: 'non-existent-device-id',
        helper_user: 'Alice Admin'
      })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  it('RH-08: GET /api/v1/fleet/remote-help/sessions/:id should return details and launch script', async () => {
    const res = await api(`/api/v1/fleet/remote-help/sessions/${createdSessionId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdSessionId);
    assert.equal(res.body.session_code, createdSessionCode);
    assert.ok(res.body.launch_script.includes(createdSessionCode));
    assert.ok(Array.isArray(res.body.audit_logs));
    assert.ok(res.body.audit_logs.length >= 1);
  });

  it('RH-09: POST /api/v1/fleet/remote-help/sessions/:id/connect should transition status to ACTIVE', async () => {
    const res = await api(`/api/v1/fleet/remote-help/sessions/${createdSessionId}/connect`, {
      method: 'POST',
      body: JSON.stringify({
        sharer_user: 'Bob Verified'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ACTIVE');
    assert.ok(res.body.started_at);
  });

  it('RH-10: POST /api/v1/fleet/remote-help/sessions/:id/control should grant FULL_CONTROL', async () => {
    const res = await api(`/api/v1/fleet/remote-help/sessions/${createdSessionId}/control`, {
      method: 'POST',
      body: JSON.stringify({
        actor_user: 'Bob Verified'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.session_type, 'FULL_CONTROL');
  });

  it('RH-11: POST /api/v1/fleet/remote-help/sessions/:id/elevation should record elevation event', async () => {
    const res = await api(`/api/v1/fleet/remote-help/sessions/${createdSessionId}/elevation`, {
      method: 'POST',
      body: JSON.stringify({
        actor_user: 'Alice Admin',
        details: 'Elevating to install diagnostic patch'
      })
    });
    assert.equal(res.status, 200);
    const hasElevationLog = res.body.audit_logs.some(l => l.action === 'ELEVATION_TRIGGERED');
    assert.ok(hasElevationLog);
  });

  it('RH-12: POST /api/v1/fleet/remote-help/sessions/:id/terminate should complete session', async () => {
    const res = await api(`/api/v1/fleet/remote-help/sessions/${createdSessionId}/terminate`, {
      method: 'POST',
      body: JSON.stringify({
        actor_user: 'Alice Admin',
        reason: 'Support ticket resolved successfully'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'COMPLETED');
    assert.ok(res.body.ended_at);
  });

  it('RH-13: POST /api/v1/fleet/remote-help/sessions should create unattended assistance session', async () => {
    const res = await api('/api/v1/fleet/remote-help/sessions', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        helper_user: 'Ops Engineer',
        session_type: 'FULL_CONTROL',
        unattended_enabled: 1
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.unattended_enabled, 1);
    assert.equal(res.body.status, 'PENDING');
  });

  // ── 3. Node Agent Integration & Heartbeat ──
  it('RH-14: POST /api/v1/nodes/heartbeat should include pending_remote_help_sessions', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        hostname: 'CAD-WORKSTATION-01'
      })
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.pending_remote_help_sessions));
    assert.ok(res.body.pending_remote_help_sessions.length >= 1, 'Should include unattended session from RH-13');
  });

  it('RH-15: POST /api/v1/nodes/:id/remote-help/connect should connect using PIN', async () => {
    // Create fresh session via engine
    const sess = remoteHelpEngine.createSession({
      device_id: testDeviceId,
      helper_user: 'Helpdesk Node Tester'
    });

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/remote-help/connect`, {
      method: 'POST',
      body: JSON.stringify({
        session_code: sess.session_code,
        sharer_user: 'Node User'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ACTIVE');
  });

  it('RH-16: POST /api/v1/nodes/:id/remote-help/event should record remote audit event', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/remote-help/event`, {
      method: 'POST',
      body: JSON.stringify({
        actor_user: 'Node Agent',
        action: 'CONTROL_GRANTED',
        details: 'User clicked Accept Remote Control'
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.action, 'CONTROL_GRANTED');
  });

  it('RH-17: POST /api/v1/nodes/:id/remote-help/disconnect should conclude session', async () => {
    const sess = remoteHelpEngine.createSession({
      device_id: testDeviceId,
      helper_user: 'Disconnector Tester'
    });
    remoteHelpEngine.connectSession(sess.id);

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/remote-help/disconnect`, {
      method: 'POST',
      body: JSON.stringify({
        session_id: sess.id,
        actor_user: 'Node User',
        reason: 'User closed assistance window'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'COMPLETED');
  });

  // ── 4. Audit Trail, Drawer & Security ──
  it('RH-18: GET /api/v1/fleet/remote-help/audit-log should return audit trail with hostname', async () => {
    const res = await api('/api/v1/fleet/remote-help/audit-log');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.audit_log));
    assert.ok(res.body.audit_log.length > 0);
    const entry = res.body.audit_log[0];
    assert.ok(entry.action);
    assert.ok(entry.actor_user);
  });

  it('RH-19: GET /api/v1/fleet/devices/:id/remote-help should return drawer data', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/remote-help`);
    assert.equal(res.status, 200);
    assert.ok('active_session' in res.body);
    assert.ok(Array.isArray(res.body.past_sessions));
    assert.ok(Array.isArray(res.body.recent_audits));
  });

  it('RH-20: Security rejection — request without valid fleet key returns 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-help/stats`, {
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': 'invalid-key'
      }
    });
    assert.equal(res.status, 401);
  });
});
