/**
 * LocalPilot Fleet — Windows LAPS (Local Administrator Password Solution) QA Tests
 * server/tests/laps.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { lapsEngine } from '../src/services/lapsEngine.js';

describe('Windows LAPS Password Solution & Vault QA (laps.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-laps-qa';
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

  describe('1. LAPS Policy Management Endpoints', () => {
    it('GET /api/v1/fleet/laps/policies returns seed policies with targeted device counts', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.policies));
      assert.ok(data.policies.length >= 3);

      const baseline = data.policies.find(p => p.id === 'laps-enterprise-baseline');
      assert.ok(baseline);
      assert.equal(baseline.admin_account_name, 'Administrator');
      assert.equal(baseline.password_complexity, 'COMPLEX');
      assert.equal(baseline.password_length, 16);
      assert.equal(baseline.password_age_days, 30);
      assert.equal(baseline.is_enabled, true);
      assert.ok(baseline.targeted_devices_count >= 1);
    });

    it('GET /api/v1/fleet/laps/policies/:id returns specific policy', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/policies/laps-workstations-strict`, { headers: authHeader });
      assert.equal(res.status, 200);
      const policy = await res.json();
      assert.equal(policy.id, 'laps-workstations-strict');
      assert.equal(policy.password_length, 24);
      assert.equal(policy.post_auth_reset_enabled, true);
    });

    it('POST /api/v1/fleet/laps/policies creates a new custom LAPS policy', async () => {
      const newPolicy = {
        name: 'Lab Server Extended LAPS',
        description: '90-day rotation for lab servers',
        target_group_id: 'grp-win11-modern',
        admin_account_name: 'LabAdmin',
        password_complexity: 'COMPLEX',
        password_length: 20,
        password_age_days: 90,
        auto_enable_account: true,
        post_auth_reset_enabled: false
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPolicy)
      });
      assert.equal(res.status, 201);
      const created = await res.json();
      assert.ok(created.id);
      assert.equal(created.name, 'Lab Server Extended LAPS');
      assert.equal(created.admin_account_name, 'LabAdmin');
      assert.equal(created.password_length, 20);
      assert.equal(created.password_age_days, 90);
    });

    it('PATCH /api/v1/fleet/laps/policies/:id updates policy parameters', async () => {
      const updateData = {
        password_length: 32,
        password_age_days: 14
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/policies/laps-enterprise-baseline`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify(updateData)
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.password_length, 32);
      assert.equal(updated.password_age_days, 14);
    });

    it('DELETE /api/v1/fleet/laps/policies/:id deletes policy', async () => {
      const tempPolicy = lapsEngine.createPolicy(app.db, {
        name: 'Temporary Deletable LAPS Policy',
        target_group_id: 'grp-all'
      });

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/policies/${tempPolicy.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);

      const check = lapsEngine.getPolicyById(app.db, tempPolicy.id);
      assert.equal(check, null);
    });
  });

  describe('2. Password Generation & Cryptographic Vault', () => {
    it('lapsEngine generates compliant passwords for all complexity tiers', () => {
      const complex = lapsEngine.generatePassword(18, 'COMPLEX');
      assert.equal(complex.length, 18);
      assert.match(complex, /[A-Z]/);
      assert.match(complex, /[a-z]/);
      assert.match(complex, /[0-9]/);
      assert.match(complex, /[!@#$%^&*()_+~|}{[\]:;?><,./\-=]/);

      const alphaNum = lapsEngine.generatePassword(14, 'ALPHANUMERIC');
      assert.equal(alphaNum.length, 14);
      assert.match(alphaNum, /^[A-Za-z0-9]+$/);

      const alpha = lapsEngine.generatePassword(12, 'ALPHABETICAL');
      assert.equal(alpha.length, 12);
      assert.match(alpha, /^[A-Za-z]+$/);

      const numeric = lapsEngine.generatePassword(16, 'NUMERIC');
      assert.equal(numeric.length, 16);
      assert.match(numeric, /^[0-9]+$/);
    });

    it('lapsEngine encrypts and decrypts passwords with AES-256-GCM correctly', () => {
      const original = 'P@ssw0rd_Test_123456789!#';
      const encrypted = lapsEngine.encryptPassword(original);
      assert.ok(encrypted.includes(':'));
      assert.notEqual(encrypted, original);

      const decrypted = lapsEngine.decryptPassword(encrypted);
      assert.equal(decrypted, original);
    });
  });

  describe('3. Zero-Trust Masked Password Queries', () => {
    it('GET /api/v1/fleet/laps/passwords returns masked credentials without exposing secrets', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/passwords`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.passwords));
      assert.ok(data.passwords.length >= 1);

      for (const p of data.passwords) {
        assert.ok(p.password_masked);
        assert.ok(p.password_masked.includes('•'));
        assert.equal(p.password, undefined); // Raw password must NEVER be exposed
        assert.ok(p.account_name);
        assert.ok(p.hostname);
        assert.ok(p.health_status);
        assert.ok(['HEALTHY', 'EXPIRING_SOON', 'EXPIRED', 'ROTATION_PENDING'].includes(p.health_status));
      }
    });

    it('GET /api/v1/fleet/devices/:id/laps returns device LAPS posture and history', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/laps`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.device_id, 'dev-daddy-pc');
      assert.ok(data.active_credential);
      assert.ok(data.active_credential.password_masked.includes('•'));
      assert.equal(data.active_credential.password, undefined);
      assert.ok(data.effective_policy);
    });
  });

  describe('4. Audited Password Reveal Protocol', () => {
    it('POST /api/v1/fleet/devices/:id/laps/reveal rejects requests with missing/short reason', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/laps/reveal`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ accessed_by: 'Admin', access_reason: 'no' })
      });
      assert.equal(res.status, 400);
      const err = await res.json();
      assert.ok(err.error);
      assert.match(err.message, /minimum 5 characters/i);
    });

    it('POST /api/v1/fleet/devices/:id/laps/reveal returns plaintext password and logs audit paper trail', async () => {
      const revealPayload = {
        accessed_by: 'Matthew Bubb (Lead Admin)',
        access_reason: 'Emergency server recovery & console debugging session'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/laps/reveal`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(revealPayload)
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.device_id, 'dev-daddy-pc');
      assert.ok(data.password); // Unmasked
      assert.ok(data.audit_record_id);
      assert.ok(data.revealed_at);

      // Verify audit trail recorded in database
      const auditRes = await fetch(`${app.baseUrl}/api/v1/fleet/laps/audit`, { headers: authHeader });
      assert.equal(auditRes.status, 200);
      const auditData = await auditRes.json();
      assert.ok(auditData.audit_logs.length > 0);

      const match = auditData.audit_logs.find(a => a.id === data.audit_record_id);
      assert.ok(match);
      assert.equal(match.accessed_by, 'Matthew Bubb (Lead Admin)');
      assert.equal(match.action, 'REVEAL');
      assert.equal(match.access_reason, 'Emergency server recovery & console debugging session');
    });
  });

  describe('5. Node Escrow & Historical Password Archive', () => {
    it('POST /api/v1/nodes/:id/laps-escrow rotates password and archives previous into history', async () => {
      const deviceId = 'dev-daddy-pc';
      const newPassword = lapsEngine.generatePassword(24, 'COMPLEX');

      const escrowPayload = {
        account_name: 'Administrator',
        password: newPassword,
        password_length: 24,
        complexity_level: 'COMPLEX',
        rotation_reason: 'SCHEDULED_EXPIRATION'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${deviceId}/laps-escrow`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(escrowPayload)
      });
      assert.equal(res.status, 201);
      const escrowRes = await res.json();
      assert.equal(escrowRes.device_id, deviceId);
      assert.equal(escrowRes.password_length, 24);
      assert.equal(escrowRes.rotation_status, 'ACTIVE');

      // Verify history now contains the retired previous password
      const posture = lapsEngine.getDeviceLapsPosture(app.db, deviceId);
      assert.ok(posture.history.length >= 1);
      const archived = posture.history[0];
      assert.ok(archived.id);
      assert.equal(archived.rotation_reason, 'SCHEDULED_EXPIRATION');

      // Test historical password reveal
      const histRevealRes = await fetch(`${app.baseUrl}/api/v1/fleet/laps/history/${archived.id}/reveal`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          accessed_by: 'Forensic Investigator',
          access_reason: 'Restoring backup volume from 3 days ago'
        })
      });
      assert.equal(histRevealRes.status, 200);
      const histData = await histRevealRes.json();
      assert.equal(histData.history_id, archived.id);
      assert.ok(histData.password);
    });

    it('GET /api/v1/nodes/:id/laps-policy returns effective policy for device', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/laps-policy`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.policy);
      assert.ok(data.policy.admin_account_name);
    });
  });

  describe('6. Remote Rotation Command Dispatch & Fleet KPIs', () => {
    it('POST /api/v1/fleet/devices/:id/laps/rotate queues remote rotation command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/laps/rotate`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ requested_by: 'Operator' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'ROTATION_PENDING');
      assert.ok(data.command_id);

      // Verify command in database
      const cmd = app.db.prepare('SELECT * FROM device_commands WHERE id = ?').get(data.command_id);
      assert.ok(cmd);
      assert.equal(cmd.command_text, 'Invoke-LapsRotation -Force');
    });

    it('GET /api/v1/fleet/laps/stats returns complete fleet LAPS metrics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/laps/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_devices >= 1);
      assert.ok(stats.managed_devices >= 1);
      assert.ok(stats.coverage_percent >= 0);
      assert.ok(stats.total_audit_events >= 1);
      assert.ok(stats.total_historical_passwords >= 1);
      assert.ok(stats.active_policies_count >= 1);
    });
  });
});
