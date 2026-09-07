/**
 * LocalPilot Fleet — Device Compliance Policies & Conditional Access QA Tests
 * server/tests/compliance.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Device Compliance Policies & Conditional Access QA (compliance.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-secret-qa';
  const authHeader = { 'X-Fleet-Key': FLEET_KEY };
  const jsonHeader = { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY };

  before(async () => {
    app = await createTestApp({
      fleetKey: FLEET_KEY,
      seed: true
    });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. Fleet Compliance Policies API', () => {
    it('GET /api/v1/fleet/compliance/policies returns seed policies with statistics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.policies));
      assert.ok(data.policies.length >= 3);

      const baseline = data.policies.find(p => p.id === 'pol-enterprise-baseline');
      assert.ok(baseline);
      assert.equal(baseline.name, 'Windows 11 Enterprise Zero-Trust Compliance Policy');
      assert.equal(baseline.require_bitlocker, 1);
      assert.equal(baseline.require_tpm, 1);
      assert.equal(baseline.grace_period_days, 3);
      assert.equal(baseline.non_compliance_action, 'MARK_NON_COMPLIANT');
      assert.ok(baseline.stats);
    });

    it('GET /api/v1/fleet/compliance/stats returns fleet compliance breakdown', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_policies >= 3);
      assert.ok(stats.total_devices >= 2);
      assert.ok(typeof stats.compliant_devices === 'number');
      assert.ok(typeof stats.in_grace_period_devices === 'number');
      assert.ok(typeof stats.compliance_rate_percent === 'number');
    });

    it('GET /api/v1/fleet/compliance/policies/:id returns details and evaluated devices', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies/pol-enterprise-baseline`, { headers: authHeader });
      assert.equal(res.status, 200);
      const policy = await res.json();
      assert.equal(policy.id, 'pol-enterprise-baseline');
      assert.ok(Array.isArray(policy.evaluations));
      assert.ok(policy.stats);
    });

    it('POST /api/v1/fleet/compliance/policies creates a new compliance policy', async () => {
      const newPolicy = {
        name: 'Executive Laptop Strict Compliance',
        description: 'Requires BitLocker, Secure Boot, and Defender RTP with 24h grace period',
        target_group_id: 'grp-workstations',
        platform: 'Windows11',
        min_os_build: '10.0.22631',
        require_bitlocker: 1,
        require_secure_boot: 1,
        require_tpm: 1,
        require_defender_rtp: 1,
        require_firewall: 1,
        grace_period_days: 1,
        non_compliance_action: 'QUARANTINE'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPolicy)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.equal(created.name, newPolicy.name);
      assert.equal(created.min_os_build, '10.0.22631');
      assert.equal(created.grace_period_days, 1);
      assert.equal(created.non_compliance_action, 'QUARANTINE');
    });

    it('PATCH /api/v1/fleet/compliance/policies/:id updates policy rules and actions', async () => {
      const patchData = {
        grace_period_days: 5,
        non_compliance_action: 'ALERT_ONLY'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies/pol-homelab-relaxed`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify(patchData)
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.grace_period_days, 5);
      assert.equal(updated.non_compliance_action, 'ALERT_ONLY');
    });

    it('GET /api/v1/fleet/devices/:id/compliance returns device compliance evaluations', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/compliance`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.device_id, 'dev-daddy-pc');
      assert.ok(Array.isArray(data.evaluations));
    });

    it('POST /api/v1/fleet/devices/:id/evaluate-compliance runs on-demand audit', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/evaluate-compliance`, {
        method: 'POST',
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(Array.isArray(data.results));
    });
  });

  describe('2. Node Agent Compliance Ingest & Quarantine Actions', () => {
    it('GET /api/v1/nodes/:id/compliance-policies returns assigned policies for node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/compliance-policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.policies));
      assert.ok(data.policies.length >= 2);
    });

    it('POST /api/v1/nodes/:id/compliance-report evaluates COMPLIANT when all rules pass', async () => {
      const auditPayload = {
        os_build: '10.0.22631',
        bitlocker_status: 'FullyEncrypted',
        secure_boot_enabled: 1,
        tpm_present: 1,
        tpm_enabled: 1,
        defender_rtp_enabled: 1,
        firewall_enabled: 1
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/compliance-report`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(auditPayload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.ok(Array.isArray(result.evaluations));

      const baseEval = result.evaluations.find(e => e.policy_id === 'pol-enterprise-baseline');
      assert.ok(baseEval);
      assert.equal(baseEval.compliance_status, 'COMPLIANT');
      assert.equal(baseEval.rules_passed, baseEval.rules_evaluated);
    });

    it('POST /api/v1/nodes/:id/compliance-report enforces QUARANTINE on zero-tolerance breach', async () => {
      // Daddy PC belongs to grp-workstations which has pol-strict-quarantine (0-day grace period)
      const auditPayload = {
        os_build: '10.0.22000',
        bitlocker_status: 'Disabled',
        secure_boot_enabled: 0,
        tpm_present: 0,
        tpm_enabled: 0,
        defender_rtp_enabled: 0,
        firewall_enabled: 0
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/compliance-report`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(auditPayload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);

      // Verify device was transitioned to quarantined
      const devRes = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc`, { headers: authHeader });
      const dev = await devRes.json();
      assert.equal(dev.status, 'quarantined');
    });

    it('POST /api/v1/nodes/heartbeat includes compliance_policies in response', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: 'dev-daddy-pc',
          cpu_usage_percent: 10,
          ram_used_bytes: 4000000000,
          ram_free_bytes: 4000000000
        })
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.acknowledged, true);
      assert.ok(Array.isArray(data.compliance_policies));
      assert.ok(data.compliance_policies.length >= 2);
    });
  });

  describe('3. Compliance Policy Deletion & Cascade Clean-up', () => {
    it('DELETE /api/v1/fleet/compliance/policies/:id deletes policy and cascade evals', async () => {
      // Create temporary policy
      const createRes = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Disposable QA Compliance Policy'
        })
      });
      const created = await createRes.json();

      // Delete
      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies/${created.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      // Verify 404
      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/compliance/policies/${created.id}`, { headers: authHeader });
      assert.equal(getRes.status, 404);
    });
  });
});
