/**
 * LocalPilot Fleet — Node Agent Ingest & Policy API QA Tests
 * server/tests/nodes_api.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Node Agent Endpoints API QA (nodes_api.test.js)', () => {
  let app;
  const FLEET_KEY = 'm1-test-fleet-key-2026';
  let activeDeviceId;
  let activeNodeToken;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. POST /api/v1/nodes/enroll', () => {
    it('returns 400 Bad Request when required fields are missing', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
        body: JSON.stringify({ friendly_name: 'No Hostname PC' })
      });
      assert.equal(res.status, 400);
    });

    it('enrolls new device successfully with 201 Created and returns token & groups', async () => {
      const payload = {
        hostname: 'LIVINGROOM-RIG',
        serial_number: 'SN-LV-9923',
        uuid: '4C4C4544-0050-4E10-8043-B2C04F343832',
        mac_address: '00:1A:2B:3C:4D:5E',
        friendly_name: 'Living Room PC',
        tags: ['family', 'livingroom'],
        os_name: 'Microsoft Windows 11 Pro',
        os_version: '10.0.22631',
        total_ram_bytes: 34359738368, // 32 GB
        gpu_name: 'NVIDIA GeForce RTX 4080',
        has_battery: false,
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        agent_version: '1.0.0'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
        body: JSON.stringify(payload)
      });
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.status, 'enrolled');
      assert.ok(body.device_id);
      assert.ok(body.node_token);
      assert.ok(Array.isArray(body.assigned_groups));
      assert.ok(body.assigned_groups.includes('grp-all'));
      assert.ok(body.assigned_groups.includes('grp-workstations')); // >=32GB + NVIDIA + NoBattery

      activeDeviceId = body.device_id;
      activeNodeToken = body.node_token;
    });

    it('re-enrollment of existing serial number updates token and preserves device_id', async () => {
      const reEnrollPayload = {
        hostname: 'LIVINGROOM-RIG-RENAMED',
        serial_number: 'SN-LV-9923', // Same serial
        os_name: 'Microsoft Windows 11 Pro',
        os_version: '10.0.22631',
        total_ram_bytes: 34359738368
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
        body: JSON.stringify(reEnrollPayload)
      });
      assert.ok([200, 201].includes(res.status));
      const body = await res.json();
      assert.equal(body.device_id, activeDeviceId, 'Device ID must remain consistent across re-enrollment');
      assert.ok(body.node_token);

      // Update active token to new token
      activeNodeToken = body.node_token;
    });
  });

  describe('2. POST /api/v1/nodes/heartbeat', () => {
    it('updates last_seen_at, status, and route on valid heartbeat', async () => {
      const payload = {
        device_id: activeDeviceId,
        cpu_usage_percent: 18.5,
        ram_used_bytes: 12000000000,
        ram_free_bytes: 22000000000,
        ram_usage_percent: 35.0,
        battery_percent: 100.0,
        battery_charging: false,
        ip_address: '192.168.1.188',
        connection_route: 'LAN',
        uptime_seconds: 3600
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeNodeToken}`
        },
        body: JSON.stringify(payload)
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.acknowledged, true);

      // Verify DB record
      const dev = app.db.prepare('SELECT status, ip_address, connection_route FROM devices WHERE id = ?').get(activeDeviceId);
      assert.equal(dev.status, 'online');
      assert.equal(dev.ip_address, '192.168.1.188');
      assert.equal(dev.connection_route, 'LAN');
    });
  });

  describe('3. POST /api/v1/nodes/telemetry & Drift Detection', () => {
    it('ingests hardware, disks, users, and installed software; flags drift when prohibited app detected', async () => {
      const telemetryPayload = {
        device_id: activeDeviceId,
        timestamp: new Date().toISOString(),
        hardware: {
          cpu_usage_percent: 12.0,
          ram_used_bytes: 10000000000,
          ram_free_bytes: 24000000000,
          ram_usage_percent: 30.0,
          disks: [
            { drive: 'C:', total_gb: 1000, free_gb: 450, smart_healthy: true }
          ]
        },
        security: {
          local_users: [
            { username: 'Dad', is_admin: true },
            { username: 'GamerKid', is_admin: false }
          ]
        },
        installed_software: [
          { name: 'Google Chrome', winget_id: 'Google.Chrome', version: '122.0' },
          { name: '7-Zip', winget_id: '7zip.7zip', version: '23.01' },
          { name: 'uTorrent', winget_id: 'BitTorrent.uTorrent', version: '3.5.5' } // Prohibited!
        ]
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/telemetry`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeNodeToken}`
        },
        body: JSON.stringify(telemetryPayload)
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'processed');
      assert.equal(data.drift_detected, true, 'Should detect prohibited package uTorrent as drift');

      // Verify device status is updated to 'drifted' in database
      const dev = app.db.prepare('SELECT status FROM devices WHERE id = ?').get(activeDeviceId);
      assert.equal(dev.status, 'drifted');

      // Verify snapshot was created
      const snap = app.db.prepare('SELECT count(*) as c FROM telemetry_snapshots WHERE device_id = ?').get(activeDeviceId);
      assert.ok(snap.c >= 1);
    });
  });

  describe('4. POST /api/v1/nodes/events (Watchdog Event Ingest)', () => {
    it('records Security Event 4720 (User Created) and returns 202 Accepted', async () => {
      const eventPayload = {
        device_id: activeDeviceId,
        event_type: 'USER_CREATED',
        event_id: 4720,
        event_source: 'Security',
        severity: 'CRITICAL',
        summary: "New local Windows user account 'unauthorized_guest' created",
        timestamp: new Date().toISOString(),
        details: { TargetUserName: 'unauthorized_guest' }
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeNodeToken}`
        },
        body: JSON.stringify(eventPayload)
      });
      assert.equal(res.status, 202);
      const data = await res.json();
      assert.equal(data.status, 'dispatched');
      assert.ok(data.event_record_id);

      // Verify event in DB
      const evt = app.db.prepare('SELECT * FROM security_events WHERE id = ?').get(data.event_record_id);
      assert.equal(evt.event_type, 'USER_CREATED');
      assert.equal(evt.severity, 'CRITICAL');
      assert.equal(evt.acknowledged, 0);
    });
  });

  describe('5. GET /api/v1/nodes/:id/policy', () => {
    it('returns combined effective policies with prohibited precedence', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${activeDeviceId}/policy`, {
        headers: { 'Authorization': `Bearer ${activeNodeToken}` }
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.ok(body.policies);
      assert.ok(Array.isArray(body.policies.required));
      assert.ok(Array.isArray(body.policies.prohibited));

      // uTorrent must be in prohibited
      const prohibitedIds = body.policies.prohibited.map(p => p.winget_id);
      assert.ok(prohibitedIds.includes('BitTorrent.uTorrent'));

      // Chrome must be in required (from grp-all)
      const requiredIds = body.policies.required.map(p => p.winget_id);
      assert.ok(requiredIds.includes('Google.Chrome'));
    });
  });

  describe('6. Remote Command Execution & Result Ingest', () => {
    it('node receives pending command on heartbeat, executes, and posts result back', async () => {
      // 1. Queue a command via fleet endpoint
      const runRes = await fetch(`${app.baseUrl}/api/v1/fleet/devices/${activeDeviceId}/run-script`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Fleet-Key': app.fleetKey
        },
        body: JSON.stringify({ script: 'Get-Process | Select-Object -First 5' })
      });
      assert.equal(runRes.status, 201);
      const runData = await runRes.json();
      assert.ok(runData.command_id);
      const cmdId = runData.command_id;

      // 2. Node performs heartbeat with active_user reporting
      const hbRes = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeNodeToken}`
        },
        body: JSON.stringify({
          active_user: 'DOM\\Tony',
          cpu_usage_percent: 15.2,
          ram_usage_percent: 42.0
        })
      });
      assert.equal(hbRes.status, 200);
      const hbData = await hbRes.json();
      assert.equal(hbData.commands_pending, true);
      assert.ok(Array.isArray(hbData.pending_commands));
      assert.equal(hbData.pending_commands.length, 1);
      assert.equal(hbData.pending_commands[0].id, cmdId);

      // Verify device's primary_user was updated in DB
      const dev = app.db.prepare('SELECT primary_user FROM devices WHERE id = ?').get(activeDeviceId);
      assert.equal(dev.primary_user, 'DOM\\Tony');

      // 3. Node posts execution result back
      const resultRes = await fetch(`${app.baseUrl}/api/v1/nodes/${activeDeviceId}/command-result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${activeNodeToken}`
        },
        body: JSON.stringify({
          command_id: cmdId,
          status: 'COMPLETED',
          exit_code: 0,
          stdout: 'Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName\n-------  ------    -----      -----     ------     --  -- -----------',
          stderr: ''
        })
      });
      assert.equal(resultRes.status, 200);
      const resultData = await resultRes.json();
      assert.equal(resultData.success, true);
      assert.equal(resultData.status, 'COMPLETED');

      // Verify command in DB
      const cmdRecord = app.db.prepare('SELECT * FROM device_commands WHERE id = ?').get(cmdId);
      assert.equal(cmdRecord.status, 'COMPLETED');
      assert.equal(cmdRecord.exit_code, 0);
      assert.ok(cmdRecord.stdout.includes('Handles'));
      assert.ok(cmdRecord.completed_at);
    });
  });
});
