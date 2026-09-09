/**
 * LocalPilot Fleet — Delivery Optimization & Peer-to-Peer Cache Governance QA
 * server/tests/delivery_optimization.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateRegistryScript } from '../src/services/deliveryOptimizationEngine.js';

describe('Delivery Optimization & Peer-to-Peer Cache Governance QA (delivery_optimization.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-do-qa';
  let testDeviceId;
  let testNodeToken;
  let createdLanPolicyId;
  let createdGroupPolicyId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'DO-TEST-WORKSTATION',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26100',
        total_ram_bytes: 34359738368,
        mac_address: '00:15:5D:AA:BB:CC',
        serial_number: 'VMware-AA-BB-CC'
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

  it('DO-01: GET /api/v1/fleet/delivery-optimization/stats should return baseline DO statistics', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_policies >= 3);
    assert.ok(res.body.active_policies >= 3);
    assert.equal(typeof res.body.fleet_p2p_efficiency_pct, 'number');
    assert.equal(res.body.total_audited_devices, 0);
  });

  it('DO-02: GET /api/v1/fleet/delivery-optimization/policies should return seed policies with assigned device count', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    const ids = res.body.policies.map(p => p.id);
    assert.ok(ids.includes('do-corp-lan-peer'));
    assert.ok(ids.includes('do-branch-office-restricted'));
    assert.ok(ids.includes('do-developer-bypass'));
  });

  it('DO-03: POST /api/v1/fleet/delivery-optimization/policies should create a LAN peering policy', async () => {
    const payload = {
      name: 'QA Test LAN Peering Rule',
      description: 'Test rule for peer caching on LAN',
      target_group_id: 'grp-all',
      download_mode: 'LAN_PEER',
      max_cache_size_pct: 25,
      cache_retention_days: 10,
      monthly_upload_cap_gb: 80
    };

    const res = await api('/api/v1/fleet/delivery-optimization/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    createdLanPolicyId = res.body.id;
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.download_mode, 'LAN_PEER');
    assert.equal(res.body.max_cache_size_pct, 25);
    assert.ok(res.body.powershell_script.includes('DODownloadMode'));
  });

  it('DO-04: POST /api/v1/fleet/delivery-optimization/policies should reject missing name with 400', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/policies', {
      method: 'POST',
      body: JSON.stringify({ download_mode: 'LAN_PEER' })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'DO_POLICY_CREATE_ERROR');
  });

  it('DO-05: POST /api/v1/fleet/delivery-optimization/policies should create a Group Peering policy with GroupID GUID', async () => {
    const payload = {
      name: 'Branch Site Group Peering',
      description: 'Domain and site boundary peering',
      target_group_id: 'grp-workstations',
      download_mode: 'GROUP_PEER',
      group_id_guid: '9a369888-9d7e-46f3-9999-7ef827dc7f93',
      max_upload_bandwidth_kbps: 10240,
      max_background_download_pct: 50
    };

    const res = await api('/api/v1/fleet/delivery-optimization/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    createdGroupPolicyId = res.body.id;
    assert.equal(res.body.group_id_guid, payload.group_id_guid);
    assert.ok(res.body.powershell_script.includes('DOGroupId'));
    assert.ok(res.body.powershell_script.includes('9a369888-9d7e-46f3-9999-7ef827dc7f93'));
  });

  it('DO-06: GET /api/v1/fleet/delivery-optimization/policies/:id should return details with powershell script', async () => {
    const res = await api(`/api/v1/fleet/delivery-optimization/policies/${createdLanPolicyId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.policy.id, createdLanPolicyId);
    assert.ok(res.body.powershell_script.includes('DOMaxCacheSize'));
  });

  it('DO-07: GET /api/v1/fleet/delivery-optimization/policies/:id should return 404 for unknown policy', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/policies/do-non-existent-999');
    assert.equal(res.status, 404);
  });

  it('DO-08: generateRegistryScript should configure correct registry paths and mode values', () => {
    const scriptBypass = generateRegistryScript({
      id: 'test-bypass',
      name: 'Bypass Script',
      download_mode: 'BYPASS',
      max_cache_size_pct: 10,
      cache_retention_days: 2
    });
    assert.ok(scriptBypass.includes('DODownloadMode'));
    assert.ok(scriptBypass.includes('Value 100'));

    const scriptGroup = generateRegistryScript({
      id: 'test-grp',
      name: 'Group Script',
      download_mode: 'GROUP_PEER',
      group_id_guid: '11111111-2222-3333-4444-555555555555',
      max_background_download_pct: 35
    });
    assert.ok(scriptGroup.includes('Value 2'));
    assert.ok(scriptGroup.includes('DOGroupId'));
    assert.ok(scriptGroup.includes('DOMaxBackgroundDownloadBandwidth'));
  });

  it('DO-09: PATCH /api/v1/fleet/delivery-optimization/policies/:id should update policy fields', async () => {
    const res = await api(`/api/v1/fleet/delivery-optimization/policies/${createdLanPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        max_cache_size_pct: 40,
        monthly_upload_cap_gb: 150
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.max_cache_size_pct, 40);
    assert.equal(res.body.monthly_upload_cap_gb, 150);
  });

  it('DO-10: PATCH /api/v1/fleet/delivery-optimization/policies/:id should reject empty name with 400', async () => {
    const res = await api(`/api/v1/fleet/delivery-optimization/policies/${createdLanPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: '' })
    });
    assert.equal(res.status, 400);
  });

  it('DO-11: POST /api/v1/nodes/heartbeat should include delivery_optimization_policy in payload', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 15,
        ram_usage_percent: 45
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.acknowledged);
    assert.ok(res.body.delivery_optimization_policy !== undefined);
  });

  it('DO-12: POST /api/v1/nodes/:id/delivery-optimization-status should record workstation DO posture', async () => {
    const payload = {
      download_mode_active: 'LAN_PEER',
      bytes_downloaded_http: 104857600, // 100 MB
      bytes_downloaded_p2p: 419430400,  // 400 MB
      bytes_uploaded_p2p: 209715200,    // 200 MB
      active_peers_count: 3,
      cache_size_bytes: 524288000,
      cache_file_count: 12
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/delivery-optimization-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'SAVED');
    // 400 / 500 = 80.0%
    assert.equal(res.body.p2p_efficiency_pct, 80.0);
  });

  it('DO-13: POST /api/v1/nodes/:id/delivery-optimization-status should handle zero bytes download safely', async () => {
    const payload = {
      download_mode_active: 'LAN_PEER',
      bytes_downloaded_http: 0,
      bytes_downloaded_p2p: 0,
      bytes_uploaded_p2p: 0
    };

    const res = await api(`/api/v1/nodes/${testDeviceId}/delivery-optimization-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.p2p_efficiency_pct, 0.0);
  });

  it('DO-14: POST /api/v1/nodes/:id/delivery-optimization-status should reject unauthenticated request with 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/delivery-optimization-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ download_mode_active: 'LAN_PEER' })
    });
    assert.equal(res.status, 401);
  });

  it('DO-15: POST /api/v1/nodes/:id/delivery-optimization-log should record package transfer event in content log', async () => {
    const payload = {
      file_hash: 'sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      content_type: 'WINDOWS_UPDATE',
      file_size_bytes: 83886080,
      bytes_from_peers: 75497472, // 90% from peers
      bytes_from_http: 8388608,
      peer_source_ip: '10.1.1.150',
      duration_ms: 1250
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/delivery-optimization-log`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.status, 'RECORDED');
    assert.equal(res.body.content_type, 'WINDOWS_UPDATE');
  });

  it('DO-16: GET /api/v1/nodes/:id/delivery-optimization-policy should allow node to fetch assigned policy', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/delivery-optimization-policy`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.policy !== null);
  });

  it('DO-17: GET /api/v1/fleet/delivery-optimization/inventory should return audited workstations', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    assert.equal(res.body.inventory.length, 1);
    assert.equal(res.body.inventory[0].device_id, testDeviceId);
    assert.equal(res.body.inventory[0].hostname, 'DO-TEST-WORKSTATION');
    assert.equal(res.body.inventory[0].download_mode_active, 'LAN_PEER');
  });

  it('DO-18: GET /api/v1/fleet/delivery-optimization/content-log should return package transfer events', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/content-log');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.content_log));
    assert.ok(res.body.content_log.length >= 1);
    assert.equal(res.body.content_log[0].content_type, 'WINDOWS_UPDATE');
    assert.equal(res.body.content_log[0].peer_source_ip, '10.1.1.150');
  });

  it('DO-19: DELETE /api/v1/fleet/delivery-optimization/policies/:id should delete custom policy', async () => {
    const res = await api(`/api/v1/fleet/delivery-optimization/policies/${createdLanPolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    const getRes = await api(`/api/v1/fleet/delivery-optimization/policies/${createdLanPolicyId}`);
    assert.equal(getRes.status, 404);
  });

  it('DO-20: GET /api/v1/fleet/delivery-optimization/stats should reflect updated audit totals and peering metrics', async () => {
    const res = await api('/api/v1/fleet/delivery-optimization/stats');
    assert.equal(res.status, 200);
    assert.equal(res.body.total_audited_devices, 1);
    assert.equal(res.body.peering_devices_count, 1);
    assert.equal(res.body.total_content_transfers, 1);
  });
});
