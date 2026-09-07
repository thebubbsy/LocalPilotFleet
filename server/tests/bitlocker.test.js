/**
 * LocalPilot Fleet — BitLocker Drive Encryption & Recovery Vault QA Tests
 * server/tests/bitlocker.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('BitLocker Drive Encryption & Recovery Vault QA (bitlocker.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-bitlocker-qa';
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

  describe('1. BitLocker Policy Endpoints', () => {
    it('GET /api/v1/fleet/bitlocker/policies returns seed policies with targeted device counts', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.policies));
      assert.ok(data.policies.length >= 2);

      const baseline = data.policies.find(p => p.id === 'bit-baseline-enterprise');
      assert.ok(baseline);
      assert.equal(baseline.encryption_method_os, 'XtsAes128');
      assert.equal(baseline.require_tpm, true);
      assert.equal(baseline.silent_encryption_enabled, true);
      assert.ok(baseline.targeted_devices_count >= 1);
    });

    it('GET /api/v1/fleet/bitlocker/policies/:id returns policy details', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies/bit-high-security`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.policy.id, 'bit-high-security');
      assert.equal(data.policy.encryption_method_os, 'XtsAes256');
      assert.equal(data.policy.require_tpm, true);
    });

    it('POST /api/v1/fleet/bitlocker/policies creates a new custom BitLocker policy', async () => {
      const newPolicy = {
        name: 'Family Laptop BitLocker Standard',
        description: 'Standard XTS-AES 128-bit encryption for portable family laptops',
        target_group_id: 'grp-family-laptops',
        encryption_method_os: 'XtsAes128',
        encryption_method_fixed: 'XtsAes128',
        require_tpm: true,
        recovery_key_rotation: true,
        hide_recovery_options_in_wizard: true,
        silent_encryption_enabled: true
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPolicy)
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.policy.id.startsWith('bit-'));
      assert.equal(data.policy.name, 'Family Laptop BitLocker Standard');
      assert.equal(data.policy.require_tpm, true);
    });

    it('PATCH /api/v1/fleet/bitlocker/policies/:id updates policy settings', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies/bit-baseline-enterprise`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          description: 'Updated enterprise description for full compliance audit',
          encryption_method_os: 'XtsAes256'
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.policy.description, 'Updated enterprise description for full compliance audit');
      assert.equal(data.policy.encryption_method_os, 'XtsAes256');
    });

    it('DELETE /api/v1/fleet/bitlocker/policies/:id removes a policy', async () => {
      // Create transient policy to delete
      const createRes = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ name: 'Transient Policy to Delete' })
      });
      const created = await createRes.json();

      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies/${created.policy.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/policies/${created.policy.id}`, { headers: authHeader });
      assert.equal(getRes.status, 404);
    });
  });

  describe('2. BitLocker Recovery Vault & Key Escrow', () => {
    it('GET /api/v1/fleet/bitlocker/keys returns list of escrowed recovery keys with masked passwords', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/keys`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.keys));
      assert.ok(data.keys.length >= 2);

      const key = data.keys.find(k => k.id === 'key-daddy-c');
      assert.ok(key);
      assert.equal(key.volume_mount_point, 'C:');
      assert.equal(key.device_id, 'dev-daddy-pc');
      assert.ok(key.key_id_short);
      assert.ok(key.recovery_password_masked.includes('••••••'));
      assert.ok(!key.recovery_password_masked.includes('182940')); // Verifies secret is properly masked
    });

    it('GET /api/v1/fleet/bitlocker/keys?query=daddy searches by device hostname', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/keys?query=daddy`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.keys.length >= 1);
      assert.ok(data.keys.every(k => k.hostname.toLowerCase().includes('daddy') || k.friendly_name.toLowerCase().includes('dad')));
    });

    it('POST /api/v1/fleet/bitlocker/keys/:id/reveal unmasks the recovery password and logs audit record', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/keys/key-daddy-c/reveal`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          accessed_by: 'IT Specialist Bob',
          access_reason: 'Blue Screen of Death recovery unlock'
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.id, 'key-daddy-c');
      assert.equal(data.recovery_password, '419204-182940-582910-384910-184920-582910-482910-582910');
      assert.ok(data.audit_record_id);

      // Verify audit log has the new record
      const auditRes = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/audit`, { headers: authHeader });
      assert.equal(auditRes.status, 200);
      const auditData = await auditRes.json();
      const latestAudit = auditData.audit_logs.find(a => a.id === data.audit_record_id);
      assert.ok(latestAudit);
      assert.equal(latestAudit.accessed_by, 'IT Specialist Bob');
      assert.equal(latestAudit.access_reason, 'Blue Screen of Death recovery unlock');
    });

    it('POST /api/v1/fleet/bitlocker/keys/:id/reveal returns 404 for invalid key', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/keys/key-nonexistent/reveal`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ accessed_by: 'Admin' })
      });
      assert.equal(res.status, 404);
    });
  });

  describe('3. Fleet BitLocker KPI Stats & Device Posture', () => {
    it('GET /api/v1/fleet/bitlocker/stats returns comprehensive fleet encryption metrics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bitlocker/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_devices >= 3);
      assert.ok(stats.encrypted_devices >= 1);
      assert.ok(stats.encryption_rate_percent >= 0 && stats.encryption_rate_percent <= 100);
      assert.ok(stats.total_volumes >= 3);
      assert.ok(stats.protected_volumes >= 2);
      assert.ok(stats.total_escrowed_keys >= 2);
      assert.ok(stats.ciphers_breakdown);
      assert.ok(stats.ciphers_breakdown.XtsAes128 >= 1);
    });

    it('GET /api/v1/fleet/devices/:id/bitlocker returns full posture and volumes for a device', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/bitlocker`, { headers: authHeader });
      assert.equal(res.status, 200);
      const posture = await res.json();
      assert.equal(posture.device_id, 'dev-daddy-pc');
      assert.ok(Array.isArray(posture.volumes));
      assert.ok(posture.volumes.length >= 2); // C: and D:

      const osVol = posture.volumes.find(v => v.mount_point === 'C:');
      assert.ok(osVol);
      assert.equal(osVol.protection_status, 'On');
      assert.equal(osVol.volume_status, 'FullyEncrypted');
      assert.equal(osVol.encryption_percentage, 100);
      assert.equal(osVol.has_recovery_key, 1);
      assert.ok(osVol.key_protectors.includes('Tpm'));
      assert.ok(osVol.key_protectors.includes('RecoveryPassword'));

      assert.ok(Array.isArray(posture.recovery_keys));
      assert.ok(posture.recovery_keys.length >= 2);
      assert.ok(posture.effective_policy);
    });
  });

  describe('4. Remote BitLocker Command Execution', () => {
    it('POST /api/v1/fleet/devices/:id/bitlocker/rotate-keys queues key rotation in device_commands', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/bitlocker/rotate-keys`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ mount_point: 'C:' })
      });
      assert.equal(res.status, 200);
      const result = await res.json();
      assert.ok(result.command_id);
      assert.equal(result.command_type, 'ROTATE_BITLOCKER_KEY');
      assert.equal(result.status, 'PENDING');

      const cmd = app.db.prepare('SELECT * FROM device_commands WHERE id = ?').get(result.command_id);
      assert.ok(cmd);
      assert.ok(cmd.command_text.includes('Add-BitLockerKeyProtector'));
      assert.ok(cmd.command_text.includes('Remove-BitLockerKeyProtector'));
    });

    it('POST /api/v1/fleet/devices/:id/bitlocker/enable queues silent drive encryption command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-livingroom-pc/bitlocker/enable`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ mount_point: 'C:', encryption_method: 'XtsAes128' })
      });
      assert.equal(res.status, 200);
      const result = await res.json();
      assert.ok(result.command_id);
      assert.equal(result.command_type, 'ENABLE_BITLOCKER');
      assert.equal(result.encryption_method, 'XtsAes128');

      const cmd = app.db.prepare('SELECT * FROM device_commands WHERE id = ?').get(result.command_id);
      assert.ok(cmd);
      assert.ok(cmd.command_text.includes('Enable-BitLocker'));
      assert.ok(cmd.command_text.includes('XtsAes128'));
    });

    it('POST /api/v1/fleet/devices/:id/bitlocker/backup-keys queues force escrow command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/bitlocker/backup-keys`, {
        method: 'POST',
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const result = await res.json();
      assert.ok(result.command_id);
      assert.equal(result.command_type, 'ESCROW_BITLOCKER_KEYS');
    });
  });

  describe('5. Node Agent Telemetry & Escrow Ingestion', () => {
    it('GET /api/v1/nodes/:id/bitlocker-policy delivers effective policy to node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/bitlocker-policy`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.policy);
      assert.equal(data.policy.require_tpm, true);
    });

    it('POST /api/v1/nodes/:id/bitlocker-status records volume status and updates devices.bitlocker_status', async () => {
      const payload = {
        mount_point: 'C:',
        volume_type: 'OperatingSystem',
        protection_status: 'On',
        volume_status: 'FullyEncrypted',
        encryption_percentage: 100.0,
        encryption_method: 'XtsAes256',
        lock_status: 'Unlocked',
        key_protector_types: ['Tpm', 'RecoveryPassword']
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-livingroom-pc/bitlocker-status`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.mount_point, 'C:');
      assert.equal(data.protection_status, 'On');
      assert.equal(data.volume_status, 'FullyEncrypted');
      assert.equal(data.encryption_method, 'XtsAes256');

      // Verify devices table was updated
      const dev = app.db.prepare('SELECT bitlocker_status FROM devices WHERE id = ?').get('dev-livingroom-pc');
      assert.equal(dev.bitlocker_status, 'FullyEncrypted');
    });

    it('POST /api/v1/nodes/:id/bitlocker-escrow vaults a 48-digit recovery password', async () => {
      const keyPayload = {
        volume_mount_point: 'C:',
        volume_type: 'OperatingSystem',
        key_protector_id: '{F4982103-891A-4821-B491-019284019284}',
        key_protector_type: 'RecoveryPassword',
        recovery_password: '519204-182940-384910-582910-184920-629104-482910-182940',
        encryption_method: 'XtsAes256'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-livingroom-pc/bitlocker-escrow`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(keyPayload)
      });
      assert.equal(res.status, 201);
      const result = await res.json();
      assert.ok(result.id);
      assert.equal(result.key_id_short, 'F4982103');
      assert.ok(result.recovery_password_masked.includes('••••••'));

      // Confirm row was persisted in bitlocker_recovery_keys
      const row = app.db.prepare('SELECT * FROM bitlocker_recovery_keys WHERE id = ?').get(result.id);
      assert.ok(row);
      assert.equal(row.recovery_password, '519204-182940-384910-582910-184920-629104-482910-182940');
      assert.equal(row.encryption_method, 'XtsAes256');
    });
  });
});
