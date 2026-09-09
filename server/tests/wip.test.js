/**
 * LocalPilot Fleet — Windows Information Protection (WIP) & Data Loss Prevention (DLP) QA Tests
 * server/tests/wip.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateWipRegistryScript } from '../src/services/wipEngine.js';

describe('Windows Information Protection (WIP) & DLP QA (wip.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-wip-qa';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;
  let createdOverridePolicyId;

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
        hostname: 'SECURE-CORP-PC',
        friendly_name: 'Executive Finance Laptop',
        serial_number: 'WIP-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '23H2',
        total_ram_bytes: 34359738368,
        tpm_present: 1,
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

  // Helper for admin fleet API
  async function api(path, options = {}) {
    const url = `${app.baseUrl}${path}`;
    const headers = {
      'Content-Type': 'application/json',
      'X-Fleet-Key': FLEET_KEY,
      ...(options.headers || {})
    };
    const res = await fetch(url, { ...options, headers });
    let body = null;
    try {
      body = await res.json();
    } catch {}
    return { status: res.status, body };
  }

  // Helper for node agent API
  async function nodeApi(path, options = {}) {
    const url = `${app.baseUrl}${path}`;
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`,
      ...(options.headers || {})
    };
    const res = await fetch(url, { ...options, headers });
    let body = null;
    try {
      body = await res.json();
    } catch {}
    return { status: res.status, body };
  }

  it('WIP-01: GET /api/v1/fleet/wip/stats should return baseline WIP statistics', async () => {
    const res = await api('/api/v1/fleet/wip/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_policies === 'number');
    assert.ok(res.body.total_policies >= 3, 'Should include at least 3 seed policies');
    assert.ok(typeof res.body.total_devices_in_fleet === 'number');
    assert.ok(typeof res.body.total_protected_files === 'number');
    assert.ok(typeof res.body.compliance_pct === 'number');
  });

  it('WIP-02: GET /api/v1/fleet/wip/policies should return seed policies with assigned device count', async () => {
    const res = await api('/api/v1/fleet/wip/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    assert.ok(res.body.policies.length >= 3);

    const hardened = res.body.policies.find(p => p.id === 'wip-corp-block-hardened');
    assert.ok(hardened, 'wip-corp-block-hardened seed policy must exist');
    assert.equal(hardened.enforcement_level, 'BLOCK');
    assert.equal(hardened.enterprise_domain, 'localpilot.internal');
    assert.ok(Array.isArray(hardened.protected_apps));
    assert.ok(hardened.protected_apps.length >= 3);
  });

  it('WIP-03: POST /api/v1/fleet/wip/policies should create a custom BLOCK enforcement policy', async () => {
    const newPolicy = {
      name: 'Finance & Legal Strict DLP Boundary',
      description: 'Zero-tolerance data protection preventing exfiltration to USB or consumer cloud drives.',
      target_group_id: 'grp-all',
      enforcement_level: 'BLOCK',
      enterprise_domain: 'corp.localpilot.internal',
      protected_apps: [
        { name: 'Microsoft Excel', binary: 'excel.exe', allowed: true },
        { name: 'Accounting Suite', binary: 'quickbooks.exe', allowed: true }
      ],
      network_boundaries: [
        { name: 'Secure Accounting Subnet', domain: '10.50.0.0/16', type: 'IPV4_RANGE' }
      ],
      allow_user_decryption: false,
      show_wip_overlays: true,
      revoke_on_unenroll: true
    };

    const res = await api('/api/v1/fleet/wip/policies', {
      method: 'POST',
      body: JSON.stringify(newPolicy)
    });

    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, 'Finance & Legal Strict DLP Boundary');
    assert.equal(res.body.enforcement_level, 'BLOCK');
    assert.equal(res.body.enterprise_domain, 'corp.localpilot.internal');
    assert.equal(res.body.allow_user_decryption, false);
    assert.equal(res.body.show_wip_overlays, true);
    createdPolicyId = res.body.id;
  });

  it('WIP-04: POST /api/v1/fleet/wip/policies should reject missing name with 400', async () => {
    const invalid = {
      description: 'Missing name',
      enforcement_level: 'BLOCK'
    };
    const res = await api('/api/v1/fleet/wip/policies', {
      method: 'POST',
      body: JSON.stringify(invalid)
    });
    assert.equal(res.status, 400);
  });

  it('WIP-05: POST /api/v1/fleet/wip/policies should create an OVERRIDE policy with protected apps list', async () => {
    const overridePolicy = {
      name: 'Contractor Audited Override Policy',
      description: 'Allows contractors to copy text with recorded audit reason.',
      enforcement_level: 'OVERRIDE',
      enterprise_domain: 'contractor.localpilot.internal',
      protected_apps: [
        { name: 'Edge', binary: 'msedge.exe', allowed: true }
      ],
      allow_user_decryption: true
    };

    const res = await api('/api/v1/fleet/wip/policies', {
      method: 'POST',
      body: JSON.stringify(overridePolicy)
    });

    assert.equal(res.status, 201);
    assert.equal(res.body.enforcement_level, 'OVERRIDE');
    assert.equal(res.body.allow_user_decryption, true);
    createdOverridePolicyId = res.body.id;
  });

  it('WIP-06: GET /api/v1/fleet/wip/policies/:id should return details with powershell script', async () => {
    const res = await api(`/api/v1/fleet/wip/policies/${createdPolicyId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdPolicyId);
    assert.ok(res.body.powershell_script);
    assert.ok(res.body.powershell_script.includes('DataProtection'));
    assert.ok(res.body.powershell_script.includes('corp.localpilot.internal'));
  });

  it('WIP-07: GET /api/v1/fleet/wip/policies/:id should return 404 for unknown policy', async () => {
    const res = await api('/api/v1/fleet/wip/policies/wip-unknown-999');
    assert.equal(res.status, 404);
  });

  it('WIP-08: generateWipRegistryScript should configure correct registry paths and enforcement level', () => {
    const script = generateWipRegistryScript({
      name: 'Unit Test Policy',
      id: 'wip-test-unit',
      enforcement_level: 'BLOCK',
      enterprise_domain: 'secure.localpilot.internal',
      allow_user_decryption: false,
      show_wip_overlays: true,
      revoke_on_unenroll: true,
      protected_apps: [{ name: 'Test App', binary: 'test.exe' }]
    });

    assert.ok(script.includes("Status' -Value 3")); // 3 = BLOCK
    assert.ok(script.includes("PrimaryDomainName' -Value 'secure.localpilot.internal'"));
    assert.ok(script.includes("AllowUserDecryption' -Value 0"));
    assert.ok(script.includes("ShowIconOverlay' -Value 1"));
    assert.ok(script.includes("test.exe"));
  });

  it('WIP-09: PATCH /api/v1/fleet/wip/policies/:id should update policy fields', async () => {
    const res = await api(`/api/v1/fleet/wip/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: 'Finance & Legal Strict DLP Boundary (Updated)',
        enforcement_level: 'OVERRIDE',
        allow_user_decryption: true
      })
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'Finance & Legal Strict DLP Boundary (Updated)');
    assert.equal(res.body.enforcement_level, 'OVERRIDE');
    assert.equal(res.body.allow_user_decryption, true);
  });

  it('WIP-10: PATCH /api/v1/fleet/wip/policies/:id should reject empty name with 400', async () => {
    const res = await api(`/api/v1/fleet/wip/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: '' })
    });
    assert.equal(res.status, 400);
  });

  it('WIP-11: POST /api/v1/nodes/heartbeat should include wip_policy in payload', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        status: 'online',
        uptime_seconds: 3600
      })
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.wip_policy, 'Heartbeat must return assigned wip_policy');
    assert.ok(res.body.wip_policy.enterprise_domain);
  });

  it('WIP-12: POST /api/v1/nodes/:id/wip-status should record workstation corporate data files and encrypted bytes', async () => {
    const statusPayload = {
      enforcement_active: 'BLOCK',
      protected_files_count: 142,
      encrypted_bytes: 524288000, // 500 MB
      managed_apps_count: 5,
      clipboard_violations_24h: 0,
      cloud_exfiltration_attempts_24h: 0
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/wip-status`, {
      method: 'POST',
      body: JSON.stringify(statusPayload)
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.status.enforcement_active, 'BLOCK');
    assert.equal(res.body.status.protected_files_count, 142);
    assert.equal(res.body.status.compliance_status, 'COMPLIANT');
  });

  it('WIP-13: POST /api/v1/nodes/:id/wip-status should detect exfiltration attempts and flag NON_COMPLIANT', async () => {
    const statusPayload = {
      enforcement_active: 'BLOCK',
      protected_files_count: 142,
      encrypted_bytes: 524288000,
      managed_apps_count: 5,
      clipboard_violations_24h: 12,
      cloud_exfiltration_attempts_24h: 3
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/wip-status`, {
      method: 'POST',
      body: JSON.stringify(statusPayload)
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.status.compliance_status, 'NON_COMPLIANT');
  });

  it('WIP-14: POST /api/v1/nodes/:id/wip-status should reject unauthenticated request with 401', async () => {
    const unauthRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/wip-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ protected_files_count: 10 })
    });
    assert.equal(unauthRes.status, 401);
  });

  it('WIP-15: POST /api/v1/nodes/:id/wip-event should record data boundary access in audit log', async () => {
    const eventPayload = {
      event_type: 'ENTERPRISE_FILE_ACCESSED',
      app_name: 'msedge.exe',
      target_location: 'https://sharepoint.corp/finance.xlsx',
      file_name: 'finance.xlsx',
      details: 'Enterprise encrypted file opened in protected application context'
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/wip-event`, {
      method: 'POST',
      body: JSON.stringify(eventPayload)
    });

    assert.equal(res.status, 201);
    assert.equal(res.body.event_type, 'ENTERPRISE_FILE_ACCESSED');
    assert.equal(res.body.file_name, 'finance.xlsx');
  });

  it('WIP-16: POST /api/v1/nodes/:id/wip-event should trigger master security event on EXFILTRATION_ATTEMPT', async () => {
    const violationPayload = {
      event_type: 'EXFILTRATION_ATTEMPT',
      app_name: 'dropbox.exe',
      target_location: 'C:\Users\User\Dropbox\Personal',
      file_name: 'Q3_Payroll_Records.xlsx',
      user_justification: 'Attempted sync to personal cloud storage',
      details: 'WIP blocked transfer from enterprise domain localpilot.internal to unmanaged application dropbox.exe'
    };

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/wip-event`, {
      method: 'POST',
      body: JSON.stringify(violationPayload)
    });
    assert.equal(res.status, 201);

    // Verify security alert was created in master security_events table
    const devRes = await api(`/api/v1/fleet/devices/${testDeviceId}`);
    assert.equal(devRes.status, 200);
    const hasViolation = devRes.body.security_events?.some(e => e.event_source === 'WIP_SUBSYSTEM');
    assert.ok(hasViolation, 'Must log master WIP_SUBSYSTEM security event');
  });

  it('WIP-17: GET /api/v1/nodes/:id/wip-policy should allow node to fetch assigned policy', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/wip-policy`);
    assert.equal(res.status, 200);
    assert.ok(res.body.policy);
    assert.equal(res.body.device_id, testDeviceId);
  });

  it('WIP-18: GET /api/v1/fleet/wip/inventory should return audited workstations', async () => {
    const res = await api('/api/v1/fleet/wip/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    assert.ok(res.body.inventory.length >= 1);
    const node = res.body.inventory.find(d => d.device_id === testDeviceId);
    assert.ok(node, 'Enrolled device must be present in inventory');
  });

  it('WIP-19: GET /api/v1/fleet/wip/audit-log should return data protection audit log events', async () => {
    const res = await api('/api/v1/fleet/wip/audit-log');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.logs));
    assert.ok(res.body.logs.length >= 2, 'Should have logged at least 2 WIP events');
  });

  it('WIP-20: DELETE /api/v1/fleet/wip/policies/:id should delete custom policy', async () => {
    const res = await api(`/api/v1/fleet/wip/policies/${createdOverridePolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    const getRes = await api(`/api/v1/fleet/wip/policies/${createdOverridePolicyId}`);
    assert.equal(getRes.status, 404);
  });
});
