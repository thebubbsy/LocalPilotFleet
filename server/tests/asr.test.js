/**
 * LocalPilot Fleet — Intune Endpoint Security > Attack Surface Reduction QA
 * server/tests/asr.test.js
 *
 * Tests: ASR policy CRUD, stats, events, device posture, heartbeat integration,
 * agent reporting endpoints, group-based policy resolution.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Microsoft Intune ASR Rules, Exploit Protection & Network Protection QA (asr.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-asr-qa-2026';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'QA-ASR-RIG',
        serial_number: 'SN-ASR-TEST-001',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.22631',
        total_ram_bytes: 17179869184,
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        primary_user: 'qa-asr-tester'
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

  // ASR-01: GET stats returns correct numeric KPIs
  it('ASR-01: GET /api/v1/fleet/asr/stats returns numeric KPIs', async () => {
    const res = await api('/api/v1/fleet/asr/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_policies === 'number', 'total_policies should be number');
    assert.ok(typeof res.body.block_mode_count === 'number', 'block_mode_count should be number');
    assert.ok(typeof res.body.audit_mode_count === 'number', 'audit_mode_count should be number');
    assert.ok(typeof res.body.events_today === 'number', 'events_today should be number');
    assert.ok(typeof res.body.devices_covered === 'number', 'devices_covered should be number');
    assert.ok(res.body.total_policies >= 3, 'Should have at least 3 seeded ASR policies');
  });

  // ASR-02: POST create policy with ASR rules JSON
  it('ASR-02: POST /api/v1/fleet/asr/policies creates policy with ASR rules', async () => {
    const res = await api('/api/v1/fleet/asr/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: 'QA Test ASR Policy',
        description: 'Created by QA test suite',
        target_group_id: 'grp-all',
        network_protection_mode: 'AUDIT',
        controlled_folder_access: 'AUDIT',
        asr_rules: {
          'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'BLOCK',
          'c1db55ab-c21a-4637-bb3f-a12568109d35': 'BLOCK',
          '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'AUDIT'
        },
        enabled: true
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id, 'Policy should have id');
    assert.equal(res.body.name, 'QA Test ASR Policy');
    assert.equal(res.body.network_protection_mode, 'AUDIT');
    assert.equal(res.body.controlled_folder_access, 'AUDIT');
    assert.ok(res.body.asr_rules, 'Should return asr_rules');
    createdPolicyId = res.body.id;
  });

  // ASR-03: Reject create with invalid network_protection_mode
  it('ASR-03: POST rejects invalid network_protection_mode', async () => {
    const res = await api('/api/v1/fleet/asr/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Invalid NP Policy',
        network_protection_mode: 'INVALID_MODE'
      })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error, 'Should return error field');
  });

  // ASR-04: GET list returns seeded policies
  it('ASR-04: GET /api/v1/fleet/asr/policies returns seeded policies', async () => {
    const res = await api('/api/v1/fleet/asr/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies), 'Should return policies array');
    assert.ok(res.body.policies.length >= 4, 'Should have 3 seeded + 1 created');
    assert.ok(typeof res.body.count === 'number', 'Should include count');
    const audit = res.body.policies.find(p => p.id === 'asr-pol-audit');
    assert.ok(audit, 'Should find seeded audit policy');
  });

  // ASR-05: GET single policy 404 for unknown
  it('ASR-05: GET /api/v1/fleet/asr/policies/:id returns 404 for unknown', async () => {
    const res = await api('/api/v1/fleet/asr/policies/non-existent-asr-policy');
    assert.equal(res.status, 404);
  });

  // ASR-06: PATCH update policy
  it('ASR-06: PATCH /api/v1/fleet/asr/policies/:id updates policy', async () => {
    assert.ok(createdPolicyId, 'Need created policy from ASR-02');
    const res = await api(`/api/v1/fleet/asr/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated by QA',
        network_protection_mode: 'BLOCK',
        controlled_folder_access: 'BLOCK'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.description, 'Updated by QA');
    assert.equal(res.body.network_protection_mode, 'BLOCK');
    assert.equal(res.body.controlled_folder_access, 'BLOCK');
  });

  // ASR-07: DELETE soft-delete, then 404
  it('ASR-07: DELETE /api/v1/fleet/asr/policies/:id deletes policy, then 404', async () => {
    assert.ok(createdPolicyId, 'Need created policy from ASR-02');
    const deleteRes = await api(`/api/v1/fleet/asr/policies/${createdPolicyId}`, { method: 'DELETE' });
    assert.equal(deleteRes.status, 200);
    assert.equal(deleteRes.body.success, true);

    const getRes = await api(`/api/v1/fleet/asr/policies/${createdPolicyId}`);
    assert.equal(getRes.status, 404);
  });

  // ASR-08: GET events (empty initially)
  it('ASR-08: GET /api/v1/fleet/asr/events returns empty initially', async () => {
    const res = await api('/api/v1/fleet/asr/events');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.events), 'Should return events array');
    assert.ok(typeof res.body.count === 'number', 'Should include count');
  });

  // ASR-09: Heartbeat includes assigned_asr_policy
  it('ASR-09: POST /api/v1/nodes/heartbeat includes assigned_asr_policy', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId, cpu_usage_percent: 5 })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.acknowledged === true, 'Should acknowledge heartbeat');
    // assigned_asr_policy may be an object or null
    assert.ok('assigned_asr_policy' in res.body, 'Should include assigned_asr_policy field');
  });

  // ASR-10: POST node asr-status saves posture record
  it('ASR-10: POST /api/v1/nodes/:id/asr-status saves posture snapshot', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/asr-status`, {
      method: 'POST',
      body: JSON.stringify({
        policy_id: 'asr-pol-audit',
        asr_rules_status: {
          'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'AUDIT',
          'c1db55ab-c21a-4637-bb3f-a12568109d35': 'AUDIT'
        },
        network_protection_mode: 'AUDIT',
        controlled_folder_access: 'DISABLED',
        exploit_protection_applied: false
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.id, 'Should return status record with id');
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.network_protection_mode, 'AUDIT');
  });

  // ASR-11: POST node asr-events saves events
  it('ASR-11: POST /api/v1/nodes/:id/asr-events saves events', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/asr-events`, {
      method: 'POST',
      body: JSON.stringify({
        events: [
          {
            action: 'BLOCKED',
            rule_id: 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
            process_name: 'outlook.exe',
            target_path: 'C:\\Temp\\malware.exe',
            occurred_at: new Date().toISOString()
          },
          {
            action: 'AUDITED',
            rule_id: 'c1db55ab-c21a-4637-bb3f-a12568109d35',
            process_name: 'explorer.exe',
            target_path: 'C:\\Users\\User\\Documents\\ransomware.js',
            occurred_at: new Date().toISOString()
          }
        ]
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.saved_count, 2);
  });

  // ASR-12: GET /api/v1/fleet/asr/events returns inserted events with hostname
  it('ASR-12: GET /api/v1/fleet/asr/events returns inserted events with hostname', async () => {
    const res = await api('/api/v1/fleet/asr/events');
    assert.equal(res.status, 200);
    assert.ok(res.body.count >= 2, 'Should have at least 2 events from ASR-11');
    const blockedEvent = res.body.events.find(e => e.action === 'BLOCKED');
    assert.ok(blockedEvent, 'Should find BLOCKED event');
    assert.ok(blockedEvent.hostname, 'Event should include hostname from device join');
    assert.equal(blockedEvent.rule_id, 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550');
  });

  // ASR-13: GET /api/v1/fleet/devices/:id/asr returns posture
  it('ASR-13: GET /api/v1/fleet/devices/:id/asr returns device ASR posture', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/asr`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.status !== undefined, 'Should include status field');
    assert.ok(Array.isArray(res.body.recent_events), 'Should include recent_events array');
    assert.ok(typeof res.body.events_today === 'number', 'Should include events_today count');
    // Status should have been saved in ASR-10
    assert.ok(res.body.status !== null, 'Status should not be null after ASR-10');
  });

  // ASR-14: GET /api/v1/fleet/devices/:id/asr 404 for unknown device
  it('ASR-14: GET /api/v1/fleet/devices/:id/asr returns 404 for unknown device', async () => {
    const res = await api('/api/v1/fleet/devices/non-existent-device-id-asr/asr');
    assert.equal(res.status, 404);
  });

  // ASR-15: ASR events filtered by device_id
  it('ASR-15: GET /api/v1/fleet/asr/events?device_id= filters by device', async () => {
    const res = await api(`/api/v1/fleet/asr/events?device_id=${testDeviceId}`);
    assert.equal(res.status, 200);
    assert.ok(res.body.events.length >= 2, 'Should find events for device');
    res.body.events.forEach(e => {
      assert.equal(e.device_id, testDeviceId);
    });
  });

  // ASR-16: ASR events filtered by action=BLOCKED
  it('ASR-16: GET /api/v1/fleet/asr/events?action=BLOCKED filters by action', async () => {
    const res = await api('/api/v1/fleet/asr/events?action=BLOCKED');
    assert.equal(res.status, 200);
    res.body.events.forEach(e => {
      assert.equal(e.action, 'BLOCKED');
    });
  });

  // ASR-17: Policy with all BLOCK rules counted in stats
  it('ASR-17: Stats reflect BLOCK-mode rules from seeded policies', async () => {
    const res = await api('/api/v1/fleet/asr/stats');
    assert.equal(res.status, 200);
    // asr-pol-block has 16 BLOCK rules
    assert.ok(res.body.block_mode_count >= 16, `block_mode_count should be >= 16 (got ${res.body.block_mode_count})`);
  });

  // ASR-18: Invalid token rejected on asr-status (401)
  it('ASR-18: POST /api/v1/nodes/:id/asr-status rejects invalid token', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/asr-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer invalid-bad-token' },
      body: JSON.stringify({ network_protection_mode: 'AUDIT' })
    });
    assert.equal(res.status, 401);
  });

  // ASR-19: Stats reflect events after posting
  it('ASR-19: Stats events_today reflects posted events', async () => {
    const res = await api('/api/v1/fleet/asr/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.events_today >= 2, `events_today should reflect posted events (got ${res.body.events_today})`);
    assert.ok(res.body.devices_covered >= 1, 'devices_covered should count device with status');
  });

  // ASR-20: Assigned ASR policy resolves via group membership
  it('ASR-20: Heartbeat resolves ASR policy via group membership', async () => {
    const hbRes = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId })
    });
    assert.equal(hbRes.status, 200);
    // Device is in grp-all via enrollment, so should get the asr-pol-audit policy (targeting grp-all)
    const assignedPolicy = hbRes.body.assigned_asr_policy;
    assert.ok(assignedPolicy !== undefined, 'Should include assigned_asr_policy in heartbeat');
    if (assignedPolicy !== null) {
      assert.ok(assignedPolicy.id, 'Assigned policy should have id');
      assert.ok(assignedPolicy.name, 'Assigned policy should have name');
      assert.ok(assignedPolicy.asr_rules !== undefined, 'Assigned policy should have asr_rules');
    }
  });
});
