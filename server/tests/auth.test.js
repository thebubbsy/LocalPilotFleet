/**
 * LocalPilot Fleet — Dual-Tier Authentication & Isolation QA Tests
 * server/tests/auth.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createTestApp } from './helpers/testServer.js';

describe('Dual-Tier Authentication & Isolation QA (auth.test.js)', () => {
  let app;
  const MASTER_KEY = 'secret-fleet-key-999';

  before(async () => {
    app = await createTestApp({ fleetKey: MASTER_KEY, seed: false });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. Master FleetKey (X-Fleet-Key) Authorization', () => {
    it('rejects /api/v1/fleet/stats with 401 when X-Fleet-Key is missing', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/stats`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.ok(body.error, 'Should return error object');
    });

    it('rejects /api/v1/fleet/stats with 401 when X-Fleet-Key is invalid', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/stats`, {
        headers: { 'X-Fleet-Key': 'completely-wrong-key' }
      });
      assert.equal(res.status, 401);
    });

    it('accepts /api/v1/fleet/stats with 200 when X-Fleet-Key is valid', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/stats`, {
        headers: { 'X-Fleet-Key': MASTER_KEY }
      });
      assert.equal(res.status, 200);
    });

    it('rejects /api/v1/nodes/enroll with 401 when X-Fleet-Key is missing', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: 'UNAUTH-PC' })
      });
      assert.equal(res.status, 401);
    });
  });

  describe('2. Node Token (Bearer) Authorization & Plaintext Storage Prevention', () => {
    let enrolledDeviceId;
    let enrolledNodeToken;

    before(async () => {
      // Enroll a test device
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Fleet-Key': MASTER_KEY
        },
        body: JSON.stringify({
          hostname: 'AUTH-TEST-NODE',
          serial_number: 'SN-AUTH-001',
          os_name: 'Windows 11 Pro',
          os_version: '10.0.22631',
          total_ram_bytes: 17179869184
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      enrolledDeviceId = data.device_id;
      enrolledNodeToken = data.node_token;
      assert.ok(enrolledNodeToken.startsWith('lp_node_'));
    });

    it('never stores plaintext node_token in SQLite; stores SHA-256 hash', () => {
      const devRow = app.db.prepare('SELECT node_token_hash FROM devices WHERE id = ?').get(enrolledDeviceId);
      assert.ok(devRow, 'Device row must exist');
      assert.notEqual(devRow.node_token_hash, enrolledNodeToken, 'Plaintext token must NOT be in DB');

      const expectedHash = crypto.createHash('sha256').update(enrolledNodeToken).digest('hex');
      assert.equal(devRow.node_token_hash, expectedHash, 'Database must store SHA-256 digest of token');
    });

    it('rejects /api/v1/nodes/heartbeat with 401 when Authorization header is missing', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: enrolledDeviceId })
      });
      assert.equal(res.status, 401);
    });

    it('rejects /api/v1/nodes/heartbeat with 401 when Bearer token is invalid', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer lp_node_fake_token_12345'
        },
        body: JSON.stringify({ device_id: enrolledDeviceId })
      });
      assert.equal(res.status, 401);
    });

    it('accepts /api/v1/nodes/heartbeat with 200 when Bearer token is valid', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${enrolledNodeToken}`
        },
        body: JSON.stringify({
          device_id: enrolledDeviceId,
          cpu_usage_percent: 10.0,
          ram_used_bytes: 8000000000,
          ram_free_bytes: 8000000000,
          ram_usage_percent: 50.0
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.acknowledged, true);
    });
  });

  describe('3. Cross-Device Isolation Enforcement', () => {
    let nodeA;
    let nodeB;

    before(async () => {
      // Enroll Node A
      const resA = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': MASTER_KEY },
        body: JSON.stringify({
          hostname: 'NODE-A', serial_number: 'SN-A-01', os_name: 'Win11', total_ram_bytes: 16000000000
        })
      });
      nodeA = await resA.json();

      // Enroll Node B
      const resB = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': MASTER_KEY },
        body: JSON.stringify({
          hostname: 'NODE-B', serial_number: 'SN-B-01', os_name: 'Win11', total_ram_bytes: 16000000000
        })
      });
      nodeB = await resB.json();
    });

    it('Node A cannot query Node B policy using Node A token (returns 401 or 403)', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${nodeB.device_id}/policy`, {
        headers: { 'Authorization': `Bearer ${nodeA.node_token}` }
      });
      assert.ok([401, 403].includes(res.status), `Cross-device policy query must be rejected; got ${res.status}`);
    });

    it('Node A can query Node A policy using Node A token (returns 200)', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${nodeA.device_id}/policy`, {
        headers: { 'Authorization': `Bearer ${nodeA.node_token}` }
      });
      assert.equal(res.status, 200);
    });

    it('Master FleetKey can query any node policy (returns 200)', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${nodeB.device_id}/policy`, {
        headers: { 'X-Fleet-Key': MASTER_KEY }
      });
      assert.equal(res.status, 200);
    });
  });
});
