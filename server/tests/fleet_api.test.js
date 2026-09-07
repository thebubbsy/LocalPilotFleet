/**
 * LocalPilot Fleet — Fleet Command Center API QA Tests
 * server/tests/fleet_api.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Fleet Command Center API QA (fleet_api.test.js)', () => {
  let app;
  const FLEET_KEY = 'fleet-admin-key-2026';
  const authHeader = { 'X-Fleet-Key': FLEET_KEY };
  const jsonHeader = { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY };

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. GET /api/v1/fleet/stats (Executive KPI)', () => {
    it('returns aggregate fleet statistics accurately', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();

      assert.ok('total_devices' in stats);
      assert.ok('online' in stats);
      assert.ok('offline' in stats);
      assert.ok('drifted' in stats);
      assert.ok('critical_alerts' in stats);
      assert.ok('total_fleet_ram_gb' in stats);
      assert.ok(stats.total_devices >= 0);
    });
  });

  describe('2. GET /api/v1/fleet/devices (Inventory & Filtering)', () => {
    before(() => {
      // Seed two test devices
      app.db.prepare(`
        INSERT OR REPLACE INTO devices (
          id, hostname, friendly_name, serial_number, os_name, os_version, total_ram_bytes, status, ip_address, connection_route, node_token_hash, agent_version
        ) VALUES 
        ('node-flt-01', 'OFFICE-DESKTOP', 'Office PC', 'SN-FLT-1', 'Win 11', '10.0', 34359738368, 'online', '10.0.0.45', 'LAN', 'h1', '1.0'),
        ('node-flt-02', 'TRAVEL-LAPTOP', 'Mom Laptop', 'SN-FLT-2', 'Win 11', '10.0', 17179869184, 'offline', '192.168.2.10', 'Cloudflare', 'h2', '1.0')
      `).run();
    });

    it('returns all devices when no filter provided', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.devices));
      assert.ok(data.devices.length >= 2);
    });

    it('filters devices by hostname search', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices?search=TRAVEL`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.devices.length, 1);
      assert.equal(data.devices[0].hostname, 'TRAVEL-LAPTOP');
    });

    it('filters devices by status', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices?status=offline`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      const hosts = data.devices.map(d => d.hostname);
      assert.ok(hosts.includes('TRAVEL-LAPTOP'));
      assert.ok(!hosts.includes('OFFICE-DESKTOP'));
    });

    it('filters devices by connection route', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices?route=Cloudflare`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.devices.every(d => d.connection_route === 'Cloudflare'));
    });
  });

  describe('3. Device Birth Certificate & Lifecycle CRUD', () => {
    it('GET /api/v1/fleet/devices/:id returns deep inspection payload', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/node-flt-01`, { headers: authHeader });
      assert.equal(res.status, 200);
      const dev = await res.json();
      assert.equal(dev.id, 'node-flt-01');
      assert.equal(dev.hostname, 'OFFICE-DESKTOP');
      assert.ok('total_ram_gb' in dev);
    });

    it('PATCH /api/v1/fleet/devices/:id updates metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/node-flt-01`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({ friendly_name: 'Studio Workstation', tags: ['work', 'studio'] })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.friendly_name, 'Studio Workstation');
    });

    it('DELETE /api/v1/fleet/devices/:id removes device and cascades data', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/node-flt-02`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);

      // Verify 404 on subsequent get
      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/devices/node-flt-02`, { headers: authHeader });
      assert.equal(getRes.status, 404);
    });
  });

  describe('4. Dynamic Groups CRUD & Dry-Run Evaluation', () => {
    const testGroupId = 'grp-test-devs';

    it('POST /api/v1/fleet/groups creates dynamic group and evaluates members', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/groups`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          id: testGroupId,
          name: 'High RAM Fleet',
          description: 'Nodes with at least 32GB RAM',
          rule_syntax: 'Device.TotalRAM_GB -ge 32',
          color: '#10B981',
          icon: 'cpu'
        })
      });
      assert.equal(res.status, 201);
      const group = await res.json();
      assert.equal(group.id, testGroupId);
      assert.ok(group.member_count >= 1);
    });

    it('POST /api/v1/fleet/groups/evaluate tests rule without saving', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/groups/evaluate`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ rule_syntax: "Device.Hostname -like '*OFFICE*'" })
      });
      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.valid, true);
      assert.ok(result.total_matches >= 1);
    });

    it('DELETE /api/v1/fleet/groups/:id removes group', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/groups/${testGroupId}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);
    });
  });

  describe('5. Security Events Feed & Alert Acknowledgment', () => {
    let testEventId;

    before(() => {
      const res = app.db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_source, severity, summary, raw_payload_json, acknowledged
        ) VALUES ('node-flt-01', 'USER_CREATED', 'Security', 'CRITICAL', 'Test alert user', '{}', 0)
      `).run();
      testEventId = res.lastInsertRowid;
    });

    it('GET /api/v1/fleet/events returns filtered events', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/events?severity=CRITICAL`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.events));
      assert.ok(data.events.some(e => e.id === Number(testEventId)));
    });

    it('POST /api/v1/fleet/events/:id/ack acknowledges critical alert', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/events/${testEventId}/ack`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ acknowledged_by: 'Fleet Admin' })
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);

      // Verify DB
      const evt = app.db.prepare('SELECT acknowledged, acknowledged_by FROM security_events WHERE id = ?').get(testEventId);
      assert.equal(evt.acknowledged, 1);
      assert.equal(evt.acknowledged_by, 'Fleet Admin');
    });
  });

  describe('6. Fleet Settings Management & Secret Masking', () => {
    it('GET /api/v1/fleet/settings masks secret keys', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/settings`, { headers: authHeader });
      assert.equal(res.status, 200);
      const settings = await res.json();
      assert.ok('fleet_enrollment_key' in settings);
      // Secrets must be masked with asterisks or not revealed in plaintext
      assert.notEqual(settings.fleet_enrollment_key, FLEET_KEY, 'Secret enrollment key must be masked in API output');
    });

    it('PUT /api/v1/fleet/settings updates non-secret settings', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/settings`, {
        method: 'PUT',
        headers: jsonHeader,
        body: JSON.stringify({ fleet_name: 'HQ Central Command' })
      });
      assert.equal(res.status, 200);

      const val = app.db.prepare("SELECT value FROM fleet_settings WHERE key = 'fleet_name'").get();
      assert.equal(val.value, 'HQ Central Command');
    });
  });

  describe('7. Intune Remote Script Runner & Command History', () => {
    it('POST /api/v1/fleet/devices/:id/run-script queues command and GET /api/v1/fleet/commands/:id inspects it', async () => {
      const dev = app.db.prepare('SELECT id FROM devices LIMIT 1').get();
      assert.ok(dev);

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/${dev.id}/run-script`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ script: 'Get-Service spooler' })
      });
      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.command_id);
      assert.equal(data.status, 'PENDING');

      // Inspect via GET /commands/:id
      const cmdRes = await fetch(`${app.baseUrl}/api/v1/fleet/commands/${data.command_id}`, { headers: authHeader });
      assert.equal(cmdRes.status, 200);
      const cmd = await cmdRes.json();
      assert.equal(cmd.command_text, 'Get-Service spooler');
      assert.equal(cmd.device_id, dev.id);

      // List device command history
      const listRes = await fetch(`${app.baseUrl}/api/v1/fleet/devices/${dev.id}/commands`, { headers: authHeader });
      assert.equal(listRes.status, 200);
      const list = await listRes.json();
      assert.ok(Array.isArray(list.commands));
      assert.ok(list.commands.some(c => c.id === data.command_id));
    });
  });
});
