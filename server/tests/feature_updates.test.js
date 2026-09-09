/**
 * LocalPilot Fleet — Microsoft Intune Feature Update Profiles & Expedited Updates QA Tests
 * server/tests/feature_updates.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as featureEngine from '../src/services/featureUpdateEngine.js';

describe('Intune Feature Updates & Expedited Quality Updates QA (feature_updates.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-feature-updates-qa';
  let testDeviceId;
  let testNodeToken;

  let createdPolicyId;
  let createdExpeditedId;

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
        hostname: 'EXEC-LAPTOP-01',
        friendly_name: 'Executive ThinkPad X1',
        serial_number: 'FEAT-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Pro',
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

  // FEAT-01: Engine OS Target Version Parsing
  it('FEAT-01: parseOsTargetVersion parses Windows 10 and 11 version strings correctly', () => {
    const w11 = featureEngine.parseOsTargetVersion('Windows 11, version 23H2');
    assert.equal(w11.product, 'Windows 11');
    assert.equal(w11.version, '23H2');

    const w10 = featureEngine.parseOsTargetVersion('Windows 10, version 22H2');
    assert.equal(w10.product, 'Windows 10');
    assert.equal(w10.version, '22H2');

    const w11Next = featureEngine.parseOsTargetVersion('Windows 11 24H2 Canary');
    assert.equal(w11Next.product, 'Windows 11');
    assert.equal(w11Next.version, '24H2');
  });

  // FEAT-02: Engine Registry Script Generation
  it('FEAT-02: generateFeatureRegistryScript builds correct PowerShell WUfB version lock script', () => {
    const script = featureEngine.generateFeatureRegistryScript({
      name: 'Lock to 23H2',
      target_os_version: 'Windows 11, version 23H2',
      safeguard_holds_enabled: 1
    });

    assert.match(script, /TargetReleaseVersion.*-Value 1/);
    assert.match(script, /TargetReleaseVersionInfo.*-Value "23H2"/);
    assert.match(script, /ProductVersion.*-Value "Windows 11"/);
    assert.match(script, /DisableWUfBSafeguards.*-Value 0/);
  });

  // FEAT-03: Engine Expedited Hotfix Script Generation
  it('FEAT-03: generateExpeditedRegistryScript constructs USO client hotfix command', () => {
    const script = featureEngine.generateExpeditedRegistryScript({
      name: 'Emergency Kernel Zero-Day',
      target_kb_number: 'KB5044284',
      cve_reference: 'CVE-2024-43573',
      days_until_forced_reboot: 1
    });

    assert.match(script, /KB5044284/);
    assert.match(script, /CVE-2024-43573/);
    assert.match(script, /usoclient\.exe.*StartScan/);
    assert.match(script, /usoclient\.exe.*StartInstall/);
  });

  // FEAT-04: GET /api/v1/fleet/feature-updates/stats
  it('FEAT-04: GET /api/v1/fleet/feature-updates/stats returns overview metrics', async () => {
    const { status, body } = await api('/api/v1/fleet/feature-updates/stats');
    assert.equal(status, 200);
    assert.ok(body.stats);
    assert.ok(typeof body.stats.totalFeaturePolicies === 'number');
    assert.ok(typeof body.stats.totalExpeditedUpdates === 'number');
    assert.ok(typeof body.stats.totalMonitoredDevices === 'number');
  });

  // FEAT-05: GET /api/v1/fleet/feature-updates/policies
  it('FEAT-05: GET /api/v1/fleet/feature-updates/policies returns seeded feature update policies', async () => {
    const { status, body } = await api('/api/v1/fleet/feature-updates/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.policies));
    assert.ok(body.policies.length >= 2);
    const pinPol = body.policies.find(p => p.id === 'feat-pol-w11-23h2-pin');
    assert.ok(pinPol);
    assert.equal(pinPol.target_os_version, 'Windows 11, version 23H2');
  });

  // FEAT-06: POST /api/v1/fleet/feature-updates/policies creates a new policy
  it('FEAT-06: POST /api/v1/fleet/feature-updates/policies creates a new custom feature version lock policy', async () => {
    const payload = {
      name: 'Global Enterprise Windows 11 23H2 Rollout',
      description: 'Standard enterprise feature lock across all production divisions',
      target_os_version: 'Windows 11, version 23H2',
      rollout_type: 'IMMEDIATELY',
      safeguard_holds_enabled: 1,
      enabled: 1
    };

    const { status, body } = await api('/api/v1/fleet/feature-updates/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    assert.equal(status, 201);
    assert.ok(body.policy);
    assert.equal(body.policy.name, payload.name);
    assert.equal(body.policy.target_os_version, payload.target_os_version);
    assert.ok(body.policy.registry_script.includes('23H2'));
    createdPolicyId = body.policy.id;
  });

  // FEAT-07: POST /api/v1/fleet/feature-updates/policies validates required fields
  it('FEAT-07: POST /api/v1/fleet/feature-updates/policies validates required fields', async () => {
    const { status: s1 } = await api('/api/v1/fleet/feature-updates/policies', {
      method: 'POST',
      body: JSON.stringify({ name: '' })
    });
    assert.equal(s1, 400);

    const { status: s2 } = await api('/api/v1/fleet/feature-updates/policies', {
      method: 'POST',
      body: JSON.stringify({ name: 'Valid Name', target_os_version: '' })
    });
    assert.equal(s2, 400);
  });

  // FEAT-08: GET /api/v1/fleet/feature-updates/policies/:id returns details
  it('FEAT-08: GET /api/v1/fleet/feature-updates/policies/:id returns policy with generated script', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/policies/${createdPolicyId}`);
    assert.equal(status, 200);
    assert.ok(body.policy);
    assert.equal(body.policy.id, createdPolicyId);
    assert.ok(body.policy.registry_script);
  });

  // FEAT-09: PUT /api/v1/fleet/feature-updates/policies/:id updates policy
  it('FEAT-09: PUT /api/v1/fleet/feature-updates/policies/:id updates policy properties', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/policies/${createdPolicyId}`, {
      method: 'PUT',
      body: JSON.stringify({
        name: 'Updated Enterprise W11 23H2 Rollout',
        safeguard_holds_enabled: 0
      })
    });

    assert.equal(status, 200);
    assert.equal(body.policy.name, 'Updated Enterprise W11 23H2 Rollout');
    assert.equal(body.policy.safeguard_holds_enabled, 0);
  });

  // FEAT-10: DELETE /api/v1/fleet/feature-updates/policies/:id deletes policy
  it('FEAT-10: DELETE /api/v1/fleet/feature-updates/policies/:id deletes policy', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/policies/${createdPolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.equal(body.success, true);

    const check = await api(`/api/v1/fleet/feature-updates/policies/${createdPolicyId}`);
    assert.equal(check.status, 404);
  });

  // FEAT-11: GET /api/v1/fleet/feature-updates/expedited
  it('FEAT-11: GET /api/v1/fleet/feature-updates/expedited returns seeded expedited hotfixes', async () => {
    const { status, body } = await api('/api/v1/fleet/feature-updates/expedited');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.expedited_updates));
    assert.ok(body.expedited_updates.length >= 1);
    const seedExp = body.expedited_updates.find(e => e.id === 'exp-update-zero-day');
    assert.ok(seedExp);
    assert.equal(seedExp.target_kb_number, 'KB5044284');
  });

  // FEAT-12: POST /api/v1/fleet/feature-updates/expedited creates a new expedited update
  it('FEAT-12: POST /api/v1/fleet/feature-updates/expedited creates an expedited quality update campaign', async () => {
    const payload = {
      name: 'Emergency RPC Zero-Day Hotfix',
      description: 'Expedite installation of out-of-band security patch',
      target_kb_number: 'KB5044300',
      cve_reference: 'CVE-2024-99999',
      days_until_forced_reboot: 2,
      override_active_hours: 1,
      status: 'ACTIVE'
    };

    const { status, body } = await api('/api/v1/fleet/feature-updates/expedited', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    assert.equal(status, 201);
    assert.ok(body.expedited_update);
    assert.equal(body.expedited_update.target_kb_number, 'KB5044300');
    assert.ok(body.expedited_update.expedite_script.includes('KB5044300'));
    createdExpeditedId = body.expedited_update.id;
  });

  // FEAT-13: POST /api/v1/fleet/feature-updates/expedited validates required fields
  it('FEAT-13: POST /api/v1/fleet/feature-updates/expedited validates required fields', async () => {
    const { status: s1 } = await api('/api/v1/fleet/feature-updates/expedited', {
      method: 'POST',
      body: JSON.stringify({ name: '' })
    });
    assert.equal(s1, 400);

    const { status: s2 } = await api('/api/v1/fleet/feature-updates/expedited', {
      method: 'POST',
      body: JSON.stringify({ name: 'Expedite Name', target_kb_number: '' })
    });
    assert.equal(s2, 400);
  });

  // FEAT-14: GET /api/v1/fleet/feature-updates/expedited/:id returns campaign details
  it('FEAT-14: GET /api/v1/fleet/feature-updates/expedited/:id returns details with expedite script', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/expedited/${createdExpeditedId}`);
    assert.equal(status, 200);
    assert.ok(body.expedited_update);
    assert.equal(body.expedited_update.id, createdExpeditedId);
    assert.ok(body.expedited_update.expedite_script);
  });

  // FEAT-15: PUT /api/v1/fleet/feature-updates/expedited/:id updates campaign
  it('FEAT-15: PUT /api/v1/fleet/feature-updates/expedited/:id updates campaign status/properties', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/expedited/${createdExpeditedId}`, {
      method: 'PUT',
      body: JSON.stringify({
        status: 'PAUSED',
        days_until_forced_reboot: 3
      })
    });

    assert.equal(status, 200);
    assert.equal(body.expedited_update.status, 'PAUSED');
    assert.equal(body.expedited_update.days_until_forced_reboot, 3);
  });

  // FEAT-16: DELETE /api/v1/fleet/feature-updates/expedited/:id deletes campaign
  it('FEAT-16: DELETE /api/v1/fleet/feature-updates/expedited/:id deletes campaign', async () => {
    const { status, body } = await api(`/api/v1/fleet/feature-updates/expedited/${createdExpeditedId}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.equal(body.success, true);

    const check = await api(`/api/v1/fleet/feature-updates/expedited/${createdExpeditedId}`);
    assert.equal(check.status, 404);
  });

  // FEAT-17: POST /api/v1/nodes/:id/feature-status ingests node status
  it('FEAT-17: POST /api/v1/nodes/:id/feature-status ingests node feature and expedited patch posture', async () => {
    const nodeRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/feature-status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testNodeToken}`
      },
      body: JSON.stringify({
        current_os_version: 'Windows 11 Enterprise',
        current_os_build: '22631.3007',
        target_os_version: 'Windows 11, version 23H2',
        feature_update_status: 'UP_TO_DATE',
        expedited_install_status: 'COMPLETED',
        safeguard_hold_reasons: ''
      })
    });

    assert.equal(nodeRes.status, 200);
    const nodeData = await nodeRes.json();
    assert.ok(nodeData.status);
    assert.equal(nodeData.status.device_id, testDeviceId);
    assert.equal(nodeData.status.feature_update_status, 'UP_TO_DATE');
    assert.equal(nodeData.status.expedited_install_status, 'COMPLETED');
  });

  // FEAT-18: GET /api/v1/nodes/:id/feature-policy returns effective policy & expedited config
  it('FEAT-18: GET /api/v1/nodes/:id/feature-policy returns effective policy and expedited instructions', async () => {
    const nodeRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/feature-policy`, {
      headers: {
        'Authorization': `Bearer ${testNodeToken}`
      }
    });

    assert.equal(nodeRes.status, 200);
    const nodeData = await nodeRes.json();
    assert.ok(nodeData.effective_feature_policy);
    assert.ok(nodeData.registry_script);
    assert.match(nodeData.registry_script, /TargetReleaseVersion/);
  });

  // FEAT-19: POST /api/v1/nodes/heartbeat includes active feature policy & expedited update
  it('FEAT-19: POST /api/v1/nodes/heartbeat response delivers active feature policy & expedited update', async () => {
    const hbRes = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testNodeToken}`
      },
      body: JSON.stringify({
        device_id: testDeviceId,
        status: 'online',
        uptime_seconds: 7200
      })
    });

    assert.equal(hbRes.status, 200);
    const hbData = await hbRes.json();
    assert.ok(hbData.active_feature_policy);
    assert.ok(hbData.active_feature_policy.target_os_version);
    assert.ok(hbData.active_expedited_update);
    assert.equal(hbData.active_expedited_update.target_kb_number, 'KB5044284');
  });

  // FEAT-20: Device drawer feature posture & Unauthenticated rejection
  it('FEAT-20: GET /api/v1/fleet/devices/:id/feature-updates returns device posture; unauthenticated returns 401', async () => {
    // 1. Drawer data fetch
    const { status, body } = await api(`/api/v1/fleet/devices/${testDeviceId}/feature-updates`);
    assert.equal(status, 200);
    assert.ok(body.status);
    assert.equal(body.status.device_id, testDeviceId);
    assert.equal(body.status.feature_update_status, 'UP_TO_DATE');
    assert.ok(body.effective_feature_policy);

    // 2. Unauthenticated fleet routes rejection
    const unauthRes = await fetch(`${app.baseUrl}/api/v1/fleet/feature-updates/stats`);
    assert.equal(unauthRes.status, 401);
  });
});
