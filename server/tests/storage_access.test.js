/**
 * LocalPilot Fleet — Removable Storage Access Control QA
 * server/tests/storage_access.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateRegistryScript } from '../src/services/storageAccessEngine.js';

describe('Removable Storage Access Control QA (storage_access.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-storage-qa';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;
  let createdAirgapId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'STORAGE-TEST-WORKSTATION',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26100',
        total_ram_bytes: 34359738368,
        mac_address: '00:15:5D:88:99:AA',
        serial_number: 'VMware-88-99-AA'
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

  it('STO-01: GET /api/v1/fleet/storage-access/stats should return baseline storage statistics', async () => {
    const res = await api('/api/v1/fleet/storage-access/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_policies === 'number');
    assert.ok(res.body.total_policies >= 3);
    assert.ok(res.body.active_policies >= 3);
    assert.ok(typeof res.body.bitlocker_to_go_enforced_count === 'number');
  });

  it('STO-02: GET /api/v1/fleet/storage-access/policies should return seed policies with assigned device count', async () => {
    const res = await api('/api/v1/fleet/storage-access/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    assert.ok(res.body.policies.length >= 3);
    const bde = res.body.policies.find(p => p.id === 'stor-corp-bitlocker-to-go');
    assert.ok(bde);
    assert.equal(bde.removable_disk_access, 'DENY_UNENCRYPTED');
    assert.equal(bde.require_bitlocker_to_go, true);
    assert.ok(bde.assigned_devices_count >= 1);
  });

  it('STO-03: POST /api/v1/fleet/storage-access/policies should create a BitLocker To Go policy', async () => {
    const payload = {
      name: 'Financial Audit Secure USB Policy',
      description: 'Strict BitLocker To Go requirement for all financial auditors and external USB keys',
      target_group_id: 'grp-all',
      removable_disk_access: 'DENY_UNENCRYPTED',
      require_bitlocker_to_go: true,
      block_wpd_devices: true,
      block_bluetooth: false
    };
    const res = await api('/api/v1/fleet/storage-access/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.removable_disk_access, 'DENY_UNENCRYPTED');
    assert.equal(res.body.block_wpd_devices, true);
    assert.ok(res.body.powershell_script.includes('RDVDenyWriteAccess'));
    createdPolicyId = res.body.id;
  });

  it('STO-04: POST /api/v1/fleet/storage-access/policies should reject missing name with 400', async () => {
    const res = await api('/api/v1/fleet/storage-access/policies', {
      method: 'POST',
      body: JSON.stringify({ description: 'Nameless policy' })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  it('STO-05: POST /api/v1/fleet/storage-access/policies should create an Air-Gap lockdown policy with allowed hardware IDs', async () => {
    const payload = {
      name: 'SCIF Air-Gap Restricted USB Policy',
      description: 'Total deny except for whitelisted hardware IDs',
      target_group_id: 'grp-workstations',
      removable_disk_access: 'DENY_ALL',
      require_bitlocker_to_go: true,
      block_wpd_devices: true,
      block_bluetooth: true,
      allowed_hardware_ids: ['USB\\VID_0951&PID_1666', 'USB\\VID_0781&PID_5583']
    };
    const res = await api('/api/v1/fleet/storage-access/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.removable_disk_access, 'DENY_ALL');
    assert.equal(res.body.allowed_hardware_ids.length, 2);
    createdAirgapId = res.body.id;
  });

  it('STO-06: GET /api/v1/fleet/storage-access/policies/:id should return details with powershell script', async () => {
    const res = await api(`/api/v1/fleet/storage-access/policies/${createdPolicyId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdPolicyId);
    assert.ok(res.body.powershell_script.includes('RemovableStorageDevices'));
    assert.ok(res.body.powershell_script.includes('RDVDenyWriteAccess'));
  });

  it('STO-07: GET /api/v1/fleet/storage-access/policies/:id should return 404 for unknown policy', async () => {
    const res = await api('/api/v1/fleet/storage-access/policies/storage-non-existent-999');
    assert.equal(res.status, 404);
  });

  it('STO-08: generateRegistryScript should configure correct registry paths for DENY_ALL and DENY_WRITE', () => {
    const denyAllScript = generateRegistryScript({
      id: 'test-deny-all',
      name: 'Deny All Test',
      removable_disk_access: 'DENY_ALL',
      require_bitlocker_to_go: 1,
      block_wpd_devices: 1
    });
    assert.ok(denyAllScript.includes('Deny_All'));
    assert.ok(denyAllScript.includes('-Value 1'));
    assert.ok(denyAllScript.includes('RDVDenyWriteAccess'));
    assert.ok(denyAllScript.includes('{6AC27878-A6FA-4155-BA85-F98F491D4F33}'));

    const readOnlyScript = generateRegistryScript({
      id: 'test-readonly',
      name: 'Read Only Test',
      removable_disk_access: 'READ_ONLY',
      require_bitlocker_to_go: 0,
      block_wpd_devices: 0
    });
    assert.ok(readOnlyScript.includes('Deny_Write'));
  });

  it('STO-09: PATCH /api/v1/fleet/storage-access/policies/:id should update policy fields', async () => {
    const res = await api(`/api/v1/fleet/storage-access/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: 'Financial Audit Secure USB Policy v2',
        block_bluetooth: true,
        enabled: false
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'Financial Audit Secure USB Policy v2');
    assert.equal(res.body.block_bluetooth, true);
    assert.equal(res.body.enabled, false);
  });

  it('STO-10: PATCH /api/v1/fleet/storage-access/policies/:id should reject empty name with 400', async () => {
    const res = await api(`/api/v1/fleet/storage-access/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: '   ' })
    });
    assert.equal(res.status, 400);
  });

  it('STO-11: POST /api/v1/nodes/heartbeat should include storage_access_policy in payload', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 15.0,
        ram_usage_percent: 42.0
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.storage_access_policy !== undefined);
  });

  it('STO-12: POST /api/v1/nodes/:id/storage-status should record workstation removable storage posture', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/storage-status`, {
      method: 'POST',
      body: JSON.stringify({
        connected_removable_drives: [
          {
            drive_letter: 'E:',
            volume_name: 'SECURE_DATA',
            bus_type: 'USB',
            size_bytes: 32000000000,
            is_bitlocker_protected: true,
            serial_number: 'KINGSTON1234'
          }
        ],
        active_usb_devices: [
          { name: 'Kingston DataTraveler 3.0 USB Device', class: 'DiskDrive' }
        ],
        write_access_denied: false
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.connected_removable_drives.length, 1);
    assert.equal(res.body.compliance_status, 'COMPLIANT');
  });

  it('STO-13: POST /api/v1/nodes/:id/storage-status should flag unencrypted USB drive as UNENCRYPTED_USB_DETECTED', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/storage-status`, {
      method: 'POST',
      body: JSON.stringify({
        connected_removable_drives: [
          {
            drive_letter: 'F:',
            volume_name: 'UNENCRYPTED_USB',
            bus_type: 'USB',
            size_bytes: 16000000000,
            is_bitlocker_protected: false,
            serial_number: 'SANDISK9999'
          }
        ],
        active_usb_devices: [
          { name: 'SanDisk Cruzer Glide USB Device', class: 'DiskDrive' }
        ],
        write_access_denied: true
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.compliance_status, 'UNENCRYPTED_USB_DETECTED');
    assert.equal(res.body.write_access_denied, true);
  });

  it('STO-14: POST /api/v1/nodes/:id/storage-status should reject unauthenticated request with 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/storage-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connected_removable_drives: [] })
    });
    assert.equal(res.status, 401);
  });

  it('STO-15: POST /api/v1/nodes/:id/storage-event should record USB insertion event in audit ledger', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/storage-event`, {
      method: 'POST',
      body: JSON.stringify({
        event_type: 'UNENCRYPTED_DRIVE_INSERTED',
        drive_letter: 'F:',
        volume_name: 'UNENCRYPTED_USB',
        hardware_id: 'USB\\VID_0781&PID_5575',
        is_encrypted: false,
        action_taken: 'ENFORCED_READ_ONLY'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.event_type, 'UNENCRYPTED_DRIVE_INSERTED');
    assert.equal(res.body.action_taken, 'ENFORCED_READ_ONLY');
  });

  it('STO-16: GET /api/v1/nodes/:id/storage-policy should allow node to fetch assigned policy', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/storage-policy`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.policy !== undefined);
  });

  it('STO-17: GET /api/v1/fleet/storage-access/inventory should return audited workstations', async () => {
    const res = await api('/api/v1/fleet/storage-access/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    const deviceEntry = res.body.inventory.find(i => i.device_id === testDeviceId);
    assert.ok(deviceEntry);
    assert.equal(deviceEntry.hostname, 'STORAGE-TEST-WORKSTATION');
    assert.equal(deviceEntry.connected_removable_drives.length, 1);
  });

  it('STO-18: GET /api/v1/fleet/storage-access/events should return audit event ledger', async () => {
    const res = await api('/api/v1/fleet/storage-access/events');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.events));
    const evt = res.body.events.find(e => e.device_id === testDeviceId);
    assert.ok(evt);
    assert.equal(evt.drive_letter, 'F:');
    assert.equal(evt.action_taken, 'ENFORCED_READ_ONLY');
  });

  it('STO-19: DELETE /api/v1/fleet/storage-access/policies/:id should delete custom policy', async () => {
    const res = await api(`/api/v1/fleet/storage-access/policies/${createdAirgapId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    const getRes = await api(`/api/v1/fleet/storage-access/policies/${createdAirgapId}`);
    assert.equal(getRes.status, 404);
  });

  it('STO-20: GET /api/v1/fleet/storage-access/stats should reflect updated audit totals and alerts', async () => {
    const res = await api('/api/v1/fleet/storage-access/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_audited_workstations >= 1);
    assert.ok(res.body.connected_removable_drives_count >= 1);
    assert.ok(res.body.unencrypted_usb_alerts_count >= 1);
    assert.ok(res.body.total_storage_events_count >= 1);
  });
});
