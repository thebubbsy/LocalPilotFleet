/**
 * LocalPilot Fleet — Windows Hello for Business (WHfB) & FIDO2 Passwordless Authentication QA Tests
 * server/tests/whfb.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateWhfbRegistryScript } from '../src/services/whfbEngine.js';

describe('Windows Hello for Business (WHfB) & FIDO2 Passwordless QA (whfb.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-whfb-qa';
  let testDeviceId;
  let testNodeToken;
  let createdPolicyId;
  let createdDeveloperPolicyId;

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
        hostname: 'SECURE-WHFB-RIG',
        friendly_name: 'Executive Workstation Rig',
        serial_number: 'WHFB-TEST-SN-778899',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '23H2',
        total_ram_bytes: 34359738368,
        tpm_present: 1,
        tpm_version: '2.0'
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
  it('WHFB-01: GET /api/v1/fleet/whfb/stats should return baseline WHfB statistics', async () => {
    const res = await api('/api/v1/fleet/whfb/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_policies >= 3, 'Should have at least 3 seed policies');
    assert.equal(typeof res.body.total_audited_devices, 'number');
    assert.equal(typeof res.body.enrolled_devices_count, 'number');
    assert.equal(typeof res.body.tpm_attested_devices_count, 'number');
  });

  it('WHFB-02: GET /api/v1/fleet/whfb/policies should list default seed policies', async () => {
    const res = await api('/api/v1/fleet/whfb/policies');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.policies));
    const ids = res.body.policies.map(p => p.id);
    assert.ok(ids.includes('whfb-corp-strict'));
    assert.ok(ids.includes('whfb-standard-workstation'));
    assert.ok(ids.includes('whfb-kiosk-disallowed'));
  });

  it('WHFB-03: should verify corporate strict policy mandates TPM and PIN length >= 8', async () => {
    const res = await api('/api/v1/fleet/whfb/policies/whfb-corp-strict');
    assert.equal(res.status, 200);
    const p = res.body.policy;
    assert.equal(p.state, 'ENABLED');
    assert.equal(p.min_pin_length, 8);
    assert.equal(p.use_tpm_only, 1);
    assert.equal(p.require_enhanced_anti_spoofing, 1);
    assert.equal(p.allow_fido2_security_keys, 1);
    assert.ok(res.body.script.includes('PassportForWork'));
  });

  // ── 2. Policy Creation & Validation ──
  it('WHFB-04: POST /api/v1/fleet/whfb/policies should create a custom WHfB policy', async () => {
    const payload = {
      name: 'Developer FIDO2 Fast-Track',
      description: 'Allows biometrics and FIDO2 keys with 6-digit PIN',
      target_group_id: 'grp-all',
      state: 'ENABLED',
      min_pin_length: 6,
      max_pin_length: 64,
      allow_biometrics: 1,
      require_enhanced_anti_spoofing: 0,
      use_tpm_only: 0,
      allow_fido2_security_keys: 1
    };
    const res = await api('/api/v1/fleet/whfb/policies', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.use_tpm_only, 0);
    createdPolicyId = res.body.id;
  });

  it('WHFB-05: GET /api/v1/fleet/whfb/policies/:id should return created policy and PowerShell script', async () => {
    const res = await api(`/api/v1/fleet/whfb/policies/${createdPolicyId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.policy.id, createdPolicyId);
    assert.ok(res.body.script.includes('EnableFIDODeviceLogon'));
    assert.ok(res.body.script.includes('MinimumPINLength'));
  });

  it('WHFB-06: PATCH /api/v1/fleet/whfb/policies/:id should update policy parameters', async () => {
    const res = await api(`/api/v1/fleet/whfb/policies/${createdPolicyId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        min_pin_length: 10,
        pin_expiration_days: 60
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.min_pin_length, 10);
    assert.equal(res.body.pin_expiration_days, 60);
  });

  it('WHFB-07: POST /api/v1/fleet/whfb/policies should create another policy for deletion testing', async () => {
    const res = await api('/api/v1/fleet/whfb/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Temporary Lab Policy',
        state: 'DISABLED',
        min_pin_length: 4
      })
    });
    assert.equal(res.status, 201);
    createdDeveloperPolicyId = res.body.id;
  });

  it('WHFB-08: DELETE /api/v1/fleet/whfb/policies/:id should delete custom policy', async () => {
    const res = await api(`/api/v1/fleet/whfb/policies/${createdDeveloperPolicyId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);

    const getRes = await api(`/api/v1/fleet/whfb/policies/${createdDeveloperPolicyId}`);
    assert.equal(getRes.status, 404);
  });

  // ── 3. Node Heartbeat & Effective Policy Resolution ──
  it('WHFB-09: Node heartbeat should include whfb_policy in response', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        cpu_usage_percent: 14.5,
        ram_used_bytes: 16000000000,
        uptime_seconds: 3600
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.whfb_policy, 'Heartbeat must return effective WHfB policy');
    assert.ok(res.body.whfb_policy.id);
  });

  it('WHFB-10: GET /api/v1/nodes/:id/whfb-policy should return effective assigned policy', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-policy`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.policy);
  });

  // ── 4. Ingestion of Node WHfB Status ──
  it('WHFB-11: POST /api/v1/nodes/:id/whfb-status should ingest non-enrolled device status', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-status`, {
      method: 'POST',
      body: JSON.stringify({
        whfb_enrolled: 0,
        tpm_present: 1,
        tpm_ready: 1,
        biometrics_available: 1
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.whfb_status.whfb_enrolled, 0);
    assert.equal(res.body.whfb_status.compliance_status, 'NOT_ENROLLED');
  });

  it('WHFB-12: POST /api/v1/nodes/:id/whfb-status should ingest enrolled compliant status', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-status`, {
      method: 'POST',
      body: JSON.stringify({
        whfb_enrolled: 1,
        whfb_provisioning_state: 'ENROLLED',
        tpm_present: 1,
        tpm_ready: 1,
        biometrics_available: 1,
        face_auth_configured: 1,
        anti_spoofing_active: 1,
        pin_complexity_compliant: 1,
        fido2_keys_count: 1
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.whfb_status.whfb_enrolled, 1);
    assert.equal(res.body.whfb_status.compliance_status, 'COMPLIANT');
    assert.equal(res.body.whfb_status.fido2_keys_count, 1);
  });

  it('WHFB-13: should evaluate to NON_COMPLIANT when PIN complexity fails', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-status`, {
      method: 'POST',
      body: JSON.stringify({
        whfb_enrolled: 1,
        pin_complexity_compliant: 0
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.whfb_status.compliance_status, 'NON_COMPLIANT');
  });

  // ── 5. Audit Logging & Security Event Escalation ──
  it('WHFB-14: POST /api/v1/nodes/:id/whfb-event should record normal PIN event', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-event`, {
      method: 'POST',
      body: JSON.stringify({
        event_type: 'PIN_PROVISIONED',
        credential_type: 'PIN',
        user_name: 'Tony',
        status: 'SUCCESS',
        details: 'User successfully created alphanumeric PIN'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.event_type, 'PIN_PROVISIONED');
  });

  it('WHFB-15: POST /api/v1/nodes/:id/whfb-event should record biometric spoof attempt and trigger security alert', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/whfb-event`, {
      method: 'POST',
      body: JSON.stringify({
        event_type: 'SPOOF_ATTEMPT_BLOCKED',
        credential_type: 'FACE',
        user_name: 'Tony',
        status: 'BLOCKED',
        details: '2D photograph spoofing attempt detected and blocked by infrared depth sensor'
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.status, 'BLOCKED');

    // Verify security alert escalated to fleet security events
    const secRes = await api('/api/v1/fleet/events');
    assert.equal(secRes.status, 200);
    const events = secRes.body.events || secRes.body;
    const alert = (Array.isArray(events) ? events : []).find(e => e.event_source === 'WHFB_SUBSYSTEM');
    assert.ok(alert, 'Must escalate biometric spoof attempt to security_events');
    assert.equal(alert.severity, 'CRITICAL');
  });

  // ── 6. Fleet Inventory & Workstation Drilldown ──
  it('WHFB-16: GET /api/v1/fleet/whfb/inventory should return fleet workstation WHfB posture', async () => {
    const res = await api('/api/v1/fleet/whfb/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    const dev = res.body.inventory.find(i => i.device_id === testDeviceId);
    assert.ok(dev, 'Enrolled test device must appear in WHfB inventory');
    assert.equal(dev.hostname, 'SECURE-WHFB-RIG');
    assert.ok(dev.policy_name);
  });

  it('WHFB-17: GET /api/v1/fleet/whfb/audit-log should return audit records with hostname', async () => {
    const res = await api('/api/v1/fleet/whfb/audit-log');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.audit_log));
    assert.ok(res.body.audit_log.length >= 2);
    const item = res.body.audit_log.find(l => l.device_id === testDeviceId);
    assert.ok(item);
    assert.equal(item.hostname, 'SECURE-WHFB-RIG');
  });

  it('WHFB-18: GET /api/v1/fleet/devices/:id/whfb should return device WHfB birth certificate card data', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/whfb`);
    assert.equal(res.status, 200);
    assert.ok(res.body.status);
    assert.equal(res.body.status.device_id, testDeviceId);
    assert.ok(Array.isArray(res.body.recent_events));
  });

  // ── 7. Script Generator & Security Rejections ──
  it('WHFB-19: Registry script generator should properly map complexity and registry paths', () => {
    const script = generateWhfbRegistryScript({
      id: 'test-gen',
      name: 'Generator Test',
      state: 'ENABLED',
      min_pin_length: 8,
      max_pin_length: 127,
      pin_uppercase: 'REQUIRED',
      pin_lowercase: 'REQUIRED',
      pin_special_chars: 'ALLOWED',
      pin_digits: 'REQUIRED',
      pin_expiration_days: 90,
      pin_history_count: 5,
      allow_biometrics: 1,
      require_enhanced_anti_spoofing: 1,
      use_tpm_only: 1,
      allow_fido2_security_keys: 1
    });
    assert.ok(script.includes("Set-ItemProperty -Path $pinKey -Name 'MinimumPINLength' -Type DWord -Value 8"));
    assert.ok(script.includes("Set-ItemProperty -Path $passportKey -Name 'RequireSecurityDevice' -Type DWord -Value 1"));
    assert.ok(script.includes("Set-ItemProperty -Path $bioKey -Name 'FacialFeaturesUseEnhancedAntiSpoofing' -Type DWord -Value 1"));
  });

  it('WHFB-20: Security rejection — request with missing or invalid fleet key returns 401', async () => {
    const res = await api('/api/v1/fleet/whfb/stats', {
      headers: { 'X-Fleet-Key': 'invalid-key' }
    });
    assert.equal(res.status, 401);
  });
});
