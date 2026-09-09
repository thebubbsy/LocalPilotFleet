/**
 * LocalPilot Fleet — Device Firmware Configuration Interface (DFCI) & UEFI Security QA Tests
 * server/tests/dfci.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateRegistryScript } from '../src/services/dfciEngine.js';

describe('Device Firmware Configuration Interface (DFCI) & UEFI Security QA (dfci.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-dfci-qa';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;
  let createdKioskPolicyId;

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
        hostname: 'WORKSTATION-SECURE-01',
        serial_number: 'SN-DFCI-TEST-001',
        os_name: 'Microsoft Windows 11 Enterprise',
        total_ram_bytes: 34359738368,
        tpm_present: 1,
        tpm_version: '2.0',
        secure_boot_enabled: 1
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

  it('DFCI-01: GET /api/v1/fleet/dfci/stats should return baseline DFCI statistics', async () => {
    const res = await api('/api/v1/fleet/dfci/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_policies >= 3, 'Should have at least 3 seed policies');
    assert.equal(typeof res.body.total_audited_devices, 'number');
    assert.equal(typeof res.body.secure_boot_enabled_devices, 'number');
    assert.equal(typeof res.body.tpm2_verified_devices, 'number');
    assert.equal(typeof res.body.average_hardware_readiness_score, 'number');
  });

  it('DFCI-02: GET /api/v1/fleet/dfci/policies should return seed policies with assigned device count', async () => {
    const res = await api('/api/v1/fleet/dfci/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    const zeroTrust = res.body.policies.find(p => p.id === 'dfci-zero-trust-hardened');
    assert.ok(zeroTrust, 'Zero-Trust hardened seed policy must exist');
    assert.equal(zeroTrust.require_secure_boot, true);
    assert.equal(zeroTrust.require_tpm2, true);
    assert.equal(typeof zeroTrust.assigned_devices_count, 'number');
  });

  it('DFCI-03: POST /api/v1/fleet/dfci/policies should create a custom Zero-Trust hardware baseline policy', async () => {
    const payload = {
      name: 'Custom High-Assurance Firmware Baseline',
      description: 'Enforces strict UEFI lock and kernel DMA protection',
      target_group_id: 'grp-all',
      cameras_enabled: 1,
      microphones_enabled: 1,
      radios_enabled: 1,
      external_media_boot_enabled: 0,
      network_adapter_boot_enabled: 0,
      prevent_user_bios_changes: 1,
      require_secure_boot: 1,
      require_tpm2: 1,
      require_kernel_dma: 1,
      require_vbs: 1,
      uefi_password_protection: 'ADMIN_PASSWORD'
    };

    const res = await api('/api/v1/fleet/dfci/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    createdPolicyId = res.body.id;
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.external_media_boot_enabled, false);
    assert.equal(res.body.prevent_user_bios_changes, true);
    assert.equal(res.body.require_kernel_dma, true);
    assert.ok(res.body.powershell_script.includes('ExternalMediaBootEnabled'));
  });

  it('DFCI-04: POST /api/v1/fleet/dfci/policies should reject missing name with 400', async () => {
    const res = await api('/api/v1/fleet/dfci/policies', {
      method: 'POST',
      body: JSON.stringify({ description: 'No name provided' })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'DFCI_POLICY_CREATE_ERROR');
  });

  it('DFCI-05: POST /api/v1/fleet/dfci/policies should create a Kiosk hardware isolation policy', async () => {
    const payload = {
      name: 'Air-Gap Kiosk Hardware Isolation',
      description: 'Disables cameras, mics, and radios at motherboard layer',
      target_group_id: 'grp-all',
      cameras_enabled: 0,
      microphones_enabled: 0,
      radios_enabled: 0,
      external_media_boot_enabled: 0,
      network_adapter_boot_enabled: 0,
      prevent_user_bios_changes: 1
    };

    const res = await api('/api/v1/fleet/dfci/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    createdKioskPolicyId = res.body.id;
    assert.equal(res.body.cameras_enabled, false);
    assert.equal(res.body.microphones_enabled, false);
    assert.equal(res.body.radios_enabled, false);
  });

  it('DFCI-06: GET /api/v1/fleet/dfci/policies/:id should return details with powershell script', async () => {
    const res = await api(`/api/v1/fleet/dfci/policies/${createdPolicyId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.policy.id, createdPolicyId);
    assert.ok(res.body.powershell_script.includes('Set-ItemProperty'));
    assert.ok(res.body.powershell_script.includes('Confirm-SecureBootUEFI'));
  });

  it('DFCI-07: GET /api/v1/fleet/dfci/policies/:id should return 404 for unknown policy', async () => {
    const res = await api('/api/v1/fleet/dfci/policies/dfci-nonexistent-999');
    assert.equal(res.status, 404);
  });

  it('DFCI-08: generateRegistryScript should configure correct registry paths and firmware settings', () => {
    const script = generateRegistryScript({
      id: 'dfci-mock',
      name: 'Mock Script Test',
      target_group_id: 'grp-all',
      cameras_enabled: false,
      microphones_enabled: false,
      radios_enabled: false,
      external_media_boot_enabled: false,
      network_adapter_boot_enabled: false,
      prevent_user_bios_changes: true,
      require_kernel_dma: true,
      require_vbs: true
    });

    assert.ok(script.includes('HKLM:\\SOFTWARE\\Policies\\Microsoft\\DFCI'));
    assert.ok(script.includes('CamerasEnabled'));
    assert.ok(script.includes('KernelDmaProtection'));
    assert.ok(script.includes('EnableVirtualizationBasedSecurity'));
  });

  it('DFCI-09: PATCH /api/v1/fleet/dfci/policies/:id should update policy fields', async () => {
    const res = await api(`/api/v1/fleet/dfci/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated description for hardware baseline',
        cameras_enabled: 0
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.description, 'Updated description for hardware baseline');
    assert.equal(res.body.cameras_enabled, false);
  });

  it('DFCI-10: PATCH /api/v1/fleet/dfci/policies/:id should reject empty name with 400', async () => {
    const res = await api(`/api/v1/fleet/dfci/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: '   ' })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'DFCI_POLICY_UPDATE_ERROR');
  });

  it('DFCI-11: POST /api/v1/nodes/heartbeat should include dfci_policy in payload', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 15.0,
        ram_usage_percent: 45.0
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.dfci_policy, 'Heartbeat payload must include dfci_policy');
    assert.ok(res.body.dfci_policy.name, 'Policy must have a valid name');
  });

  it('DFCI-12: POST /api/v1/nodes/:id/dfci-status should record workstation UEFI, TPM 2.0 & Secure Boot posture', async () => {
    const payload = {
      bios_vendor: 'American Megatrends Inc.',
      bios_version: 'ALDER-2.10.4',
      bios_release_date: '2026-03-15',
      uefi_version: '2.8',
      secure_boot_enabled: 1,
      tpm_present: 1,
      tpm_version: '2.0',
      tpm_ready: 1,
      tpm_manufacturer: 'INTC',
      kernel_dma_protection: 1,
      vbs_status: 'RUNNING',
      hvci_status: 'RUNNING',
      cameras_state: 'ENABLED',
      microphones_state: 'ENABLED',
      radios_state: 'ENABLED',
      external_boot_state: 'DISABLED',
      network_boot_state: 'DISABLED'
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/dfci-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status.bios_vendor, 'American Megatrends Inc.');
    assert.equal(res.body.status.secure_boot_enabled, true);
    assert.equal(res.body.status.tpm_present, true);
    assert.equal(res.body.status.tpm_ready, true);
    assert.equal(res.body.status.kernel_dma_protection, true);
    assert.equal(res.body.status.hardware_readiness_score, 100);
    assert.equal(res.body.status.compliance_status, 'COMPLIANT');
  });

  it('DFCI-13: POST /api/v1/nodes/:id/dfci-status should detect disabled Secure Boot and flag compliance', async () => {
    const payload = {
      bios_vendor: 'American Megatrends Inc.',
      secure_boot_enabled: 0,
      tpm_present: 1,
      tpm_version: '2.0',
      tpm_ready: 1
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/dfci-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status.secure_boot_enabled, false);
    assert.equal(res.body.status.compliance_status, 'SECUREBOOT_DISABLED');
    assert.ok(res.body.status.hardware_readiness_score < 100);
  });

  it('DFCI-14: POST /api/v1/nodes/:id/dfci-status should reject unauthenticated request with 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/dfci-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bios_vendor: 'Injected' })
    });
    assert.equal(res.status, 401);
  });

  it('DFCI-15: POST /api/v1/nodes/:id/dfci-event should record firmware change event in audit log', async () => {
    const eventPayload = {
      event_type: 'FIRMWARE_AUDIT',
      setting_name: 'ExternalMediaBoot',
      old_value: 'ENABLED',
      new_value: 'DISABLED',
      details: 'Agent disabled USB boot via motherboard WMI interface'
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/dfci-event`, {
      method: 'POST',
      body: JSON.stringify(eventPayload)
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.event_type, 'FIRMWARE_AUDIT');
    assert.equal(res.body.setting_name, 'ExternalMediaBoot');
  });

  it('DFCI-16: POST /api/v1/nodes/:id/dfci-event should trigger critical security event on SECUREBOOT_VIOLATION', async () => {
    const violationPayload = {
      event_type: 'SECUREBOOT_VIOLATION',
      setting_name: 'SecureBootState',
      old_value: 'ENABLED',
      new_value: 'DISABLED',
      details: 'Pre-boot rootkit or unauthorized BIOS operator disabled Secure Boot'
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/dfci-event`, {
      method: 'POST',
      body: JSON.stringify(violationPayload)
    });
    assert.equal(res.status, 201);

    // Verify security alert was created in master security_events table
    const secEventsRes = await api(`/api/v1/fleet/devices/${testDeviceId}`);
    assert.equal(secEventsRes.status, 200);
    const hasViolation = secEventsRes.body.security_events?.some(e => e.event_type === 'SECUREBOOT_DISABLED');
    assert.ok(hasViolation, 'Must log master SECUREBOOT_DISABLED security event');
  });

  it('DFCI-17: GET /api/v1/nodes/:id/dfci-policy should allow node to fetch assigned policy', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/dfci-policy`);
    assert.equal(res.status, 200);
    assert.ok(res.body.policy, 'Must return policy object');
  });

  it('DFCI-18: GET /api/v1/fleet/dfci/inventory should return audited workstations', async () => {
    const res = await api('/api/v1/fleet/dfci/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    assert.ok(res.body.inventory.length >= 1, 'Should include at least 1 audited workstation');
    const node = res.body.inventory.find(d => d.device_id === testDeviceId);
    assert.ok(node, 'Enrolled device must be present in inventory');
  });

  it('DFCI-19: GET /api/v1/fleet/dfci/audit-log should return firmware change audit events', async () => {
    const res = await api('/api/v1/fleet/dfci/audit-log');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.logs));
    assert.ok(res.body.logs.length >= 2, 'Should have logged at least 2 audit events');
  });

  it('DFCI-20: DELETE /api/v1/fleet/dfci/policies/:id should delete custom policy', async () => {
    const res = await api(`/api/v1/fleet/dfci/policies/${createdKioskPolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    const getRes = await api(`/api/v1/fleet/dfci/policies/${createdKioskPolicyId}`);
    assert.equal(getRes.status, 404);
  });
});
