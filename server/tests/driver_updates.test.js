/**
 * LocalPilot Fleet — Windows Driver & Firmware Update Profiles (WUfB) QA Tests
 * server/tests/driver_updates.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateDriverRegistryScript } from '../src/services/driverUpdateEngine.js';

describe('Windows Driver & Firmware Update Profiles (WUfB) QA (driver_updates.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-drivers-qa';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;

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
        serial_number: 'DRV-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Pro for Workstations',
        os_version: '23H2',
        total_ram_bytes: 68719476736
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
  it('DRV-01: GET /api/v1/fleet/drivers/stats should return driver & firmware statistics', async () => {
    const res = await api('/api/v1/fleet/drivers/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_policies >= 3, 'Should have at least 3 seed policies');
    assert.ok(res.body.total_catalog_drivers >= 4, 'Should have at least 4 catalog drivers');
    assert.equal(typeof res.body.approved_drivers_count, 'number');
    assert.equal(typeof res.body.pending_review_drivers_count, 'number');
    assert.equal(typeof res.body.total_devices_in_fleet, 'number');
  });

  it('DRV-02: GET /api/v1/fleet/drivers/policies should list default seed policies', async () => {
    const res = await api('/api/v1/fleet/drivers/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    const ids = res.body.policies.map(p => p.id);
    assert.ok(ids.includes('drv-pol-recommended'));
    assert.ok(ids.includes('drv-pol-conservative'));
    assert.ok(ids.includes('drv-pol-canary'));
  });

  it('DRV-03: GET /api/v1/fleet/drivers/policies/:id should return policy and PowerShell registry script', async () => {
    const res = await api('/api/v1/fleet/drivers/policies/drv-pol-recommended');
    assert.equal(res.status, 200);
    assert.equal(res.body.policy.approval_method, 'AUTOMATIC');
    assert.ok(res.body.script.includes('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'));
    assert.ok(res.body.script.includes('DriverUpdateApprovalMode'));
  });

  // ── 2. Policy Management (CRUD) ──
  it('DRV-04: POST /api/v1/fleet/drivers/policies should create a new driver policy', async () => {
    const res = await api('/api/v1/fleet/drivers/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: 'High Performance GPU Driver Policy',
        description: 'Enforces automatic rollout with 3-day buffer for workstation GPUs',
        target_group_id: 'grp-all',
        approval_method: 'AUTOMATIC',
        automatic_approval_delay_days: 3,
        allow_optional_drivers: 1,
        enabled: 1
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, 'High Performance GPU Driver Policy');
    assert.equal(res.body.automatic_approval_delay_days, 3);
    createdPolicyId = res.body.id;
  });

  it('DRV-05: PATCH /api/v1/fleet/drivers/policies/:id should update policy configuration', async () => {
    const res = await api(`/api/v1/fleet/drivers/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        approval_method: 'MANUAL',
        automatic_approval_delay_days: 0,
        allow_optional_drivers: 0
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.approval_method, 'MANUAL');
    assert.equal(res.body.automatic_approval_delay_days, 0);
    assert.equal(res.body.allow_optional_drivers, 0);
  });

  it('DRV-06: DELETE /api/v1/fleet/drivers/policies/:id should delete policy cleanly', async () => {
    const res = await api(`/api/v1/fleet/drivers/policies/${createdPolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.deleted_id, createdPolicyId);

    // Verify 404 after deletion
    const verifyRes = await api(`/api/v1/fleet/drivers/policies/${createdPolicyId}`);
    assert.equal(verifyRes.status, 404);
  });

  // ── 3. Catalog & Approval Workflow ──
  it('DRV-07: GET /api/v1/fleet/drivers/catalog should list seed catalog drivers', async () => {
    const res = await api('/api/v1/fleet/drivers/catalog');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.catalog));
    const ids = res.body.catalog.map(c => c.id);
    assert.ok(ids.includes('drv-intel-wifi'));
    assert.ok(ids.includes('drv-nvidia-display'));
    assert.ok(ids.includes('drv-realtek-audio'));
    assert.ok(ids.includes('drv-dell-firmware'));
  });

  it('DRV-08: GET /api/v1/fleet/drivers/catalog?driver_class=DISPLAY should filter by driver class', async () => {
    const res = await api('/api/v1/fleet/drivers/catalog?driver_class=DISPLAY');
    assert.equal(res.status, 200);
    assert.ok(res.body.catalog.length >= 1);
    for (const d of res.body.catalog) {
      assert.equal(d.driver_class, 'DISPLAY');
    }
  });

  it('DRV-09: GET /api/v1/fleet/drivers/catalog?approval_status=APPROVED should filter by status', async () => {
    const res = await api('/api/v1/fleet/drivers/catalog?approval_status=APPROVED');
    assert.equal(res.status, 200);
    assert.ok(res.body.catalog.length >= 1);
    for (const d of res.body.catalog) {
      assert.equal(d.approval_status, 'APPROVED');
    }
  });

  it('DRV-10: PATCH /api/v1/fleet/drivers/catalog/:id/approval should approve a pending driver', async () => {
    const res = await api('/api/v1/fleet/drivers/catalog/drv-realtek-audio/approval', {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'APPROVED',
        approved_by: 'Fleet SecOps Engineer'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.approval_status, 'APPROVED');
    assert.equal(res.body.approved_by, 'Fleet SecOps Engineer');
    assert.ok(res.body.approved_at);
  });

  it('DRV-11: PATCH /api/v1/fleet/drivers/catalog/:id/approval should decline or suspend a driver', async () => {
    const res = await api('/api/v1/fleet/drivers/catalog/drv-dell-firmware/approval', {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'DECLINED',
        approved_by: 'QA Release Manager'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.approval_status, 'DECLINED');
  });

  // ── 4. Node Ingestion & Device Driver Inventory ──
  it('DRV-12: POST /api/v1/nodes/:id/drivers/inventory should ingest driver telemetry', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/drivers/inventory`, {
      method: 'POST',
      body: JSON.stringify({
        drivers: [
          {
            driver_name: 'NVIDIA RTX 4090 DCH Driver',
            driver_class: 'DISPLAY',
            driver_provider: 'NVIDIA',
            driver_version: '31.0.15.5186',
            driver_date: '2025-01-15',
            hardware_id: 'PCI\\VEN_10DE&DEV_2684&SUBSYS_168710DE',
            install_status: 'INSTALLED'
          },
          {
            driver_name: 'Intel(R) Wi-Fi 7 BE200 320MHz',
            driver_class: 'NET',
            driver_provider: 'Intel',
            driver_version: '23.40.0.4',
            driver_date: '2025-02-10',
            hardware_id: 'PCI\\VEN_8086&DEV_272B&SUBSYS_00908086',
            install_status: 'INSTALLED'
          },
          {
            driver_name: 'Samsung NVMe Controller Driver',
            driver_class: 'STORAGE',
            driver_provider: 'Samsung',
            driver_version: '3.3.0.2003',
            driver_date: '2024-09-01',
            hardware_id: 'PCI\\VEN_144D&DEV_A80A',
            install_status: 'NEEDS_UPDATE'
          }
        ]
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.drivers_ingested, 3);
  });

  it('DRV-13: GET /api/v1/nodes/:id/driver-policy should return effective driver policy and script', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/driver-policy`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.policy);
    assert.ok(res.body.registry_script);
  });

  it('DRV-14: GET /api/v1/nodes/:id/drivers should return device driver inventory', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/drivers`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(Array.isArray(res.body.drivers));
    assert.equal(res.body.drivers.length, 3);

    const storageDrv = res.body.drivers.find(d => d.driver_class === 'STORAGE');
    assert.ok(storageDrv);
    assert.equal(storageDrv.install_status, 'NEEDS_UPDATE');
  });

  it('DRV-15: POST /api/v1/nodes/heartbeat should include driver_policy in response', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 12.5,
        ram_usage_percent: 45.0
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.driver_policy !== undefined, 'driver_policy should be present in heartbeat payload');
    assert.equal(typeof res.body.driver_policy, 'object');
  });

  // ── 5. Fleet Admin Driver Inventory & Device Linkage ──
  it('DRV-16: GET /api/v1/fleet/drivers/inventory should return fleet overview metrics', async () => {
    const res = await api('/api/v1/fleet/drivers/inventory');
    assert.equal(res.status, 200);
    assert.ok(res.body.inventory);
    const row = res.body.inventory.find(i => i.device_id === testDeviceId);
    assert.ok(row, 'Our enrolled test workstation should appear in fleet driver inventory');
    assert.equal(row.total_drivers, 3);
    assert.equal(row.needs_update_count, 1);
  });

  it('DRV-17: GET /api/v1/fleet/devices/:id/drivers should return workstation driver inventory for admin', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/drivers`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(Array.isArray(res.body.drivers));
    assert.equal(res.body.drivers.length, 3);
  });

  // ── 6. Dynamic Group Evaluation & Priority Fallback ──
  it('DRV-18: should evaluate group-targeted driver update policy when assigned', async () => {
    const res = await api('/api/v1/fleet/drivers/policies/drv-pol-conservative');
    assert.equal(res.status, 200);
    assert.equal(res.body.policy.approval_method, 'MANUAL');
    assert.equal(res.body.policy.target_group_id, 'grp-workstations');
  });

  it('DRV-19: generateDriverRegistryScript should correctly configure manual vs automatic approval', () => {
    const scriptAuto = generateDriverRegistryScript({
      id: 'test-auto',
      approval_method: 'AUTOMATIC',
      automatic_approval_delay_days: 7,
      allow_optional_drivers: 1,
      enabled: 1
    });
    assert.ok(scriptAuto.includes("'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 0"));
    assert.ok(scriptAuto.includes("'DriverUpdateApprovalMode' -Type DWord -Value 1"));
    assert.ok(scriptAuto.includes("'DriverDeferralPeriodInDays' -Type DWord -Value 7"));

    const scriptManual = generateDriverRegistryScript({
      id: 'test-manual',
      approval_method: 'MANUAL',
      automatic_approval_delay_days: 0,
      allow_optional_drivers: 0,
      enabled: 1
    });
    assert.ok(scriptManual.includes("'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 0"));
    assert.ok(scriptManual.includes("'DriverUpdateApprovalMode' -Type DWord -Value 0"));

    const scriptDisabled = generateDriverRegistryScript({
      id: 'test-disabled',
      approval_method: 'MANUAL',
      enabled: 0
    });
    assert.ok(scriptDisabled.includes("'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1"));
  });

  it('DRV-20: should reject node inventory ingestion without valid token or fleet key', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/drivers/inventory`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ drivers: [] })
    });
    assert.equal(res.status, 401);
  });
});
