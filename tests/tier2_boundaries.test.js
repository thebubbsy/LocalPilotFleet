import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  setupTestEnvironment,
  teardownTestEnvironment,
  apiRequest,
  enrollTestDevice,
  getFleetKey,
  createEnrollPayload,
  createHeartbeatPayload,
  createTelemetryPayload,
  createEventPayload,
  evaluateRule
} from './harness/test_helper.js';

describe('Tier 2: Boundary & Corner Cases (Stress, Validation & Resiliency)', () => {
  before(async () => {
    await setupTestEnvironment();
  });

  after(async () => {
    await teardownTestEnvironment();
  });

  // --------------------------------------------------------------------------
  // B01 - B06: Authentication & Authorization Boundaries
  // --------------------------------------------------------------------------
  it('B01: should reject enrollment with completely missing X-Fleet-Key header with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      body: createEnrollPayload()
    });
    assert.equal(res.status, 401);
    assert.equal(res.data.error, 'INVALID_FLEET_KEY');
  });

  it('B02: should reject enrollment with empty string X-Fleet-Key header with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: '',
      body: createEnrollPayload()
    });
    assert.equal(res.status, 401);
  });

  it('B03: should reject enrollment with whitespace-only X-Fleet-Key with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: '     ',
      body: createEnrollPayload()
    });
    assert.equal(res.status, 401);
  });

  it('B04: should reject enrollment with SQL injection in X-Fleet-Key with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: "' OR 1=1 --",
      body: createEnrollPayload()
    });
    assert.equal(res.status, 401);
  });

  it('B05: should reject node heartbeat with missing Authorization header with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: createHeartbeatPayload()
    });
    assert.equal(res.status, 401);
  });

  it('B06: should reject node heartbeat with malformed Bearer prefix (Basic instead of Bearer) with 401', async () => {
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      headers: { 'Authorization': 'Basic dXNlcjpwYXNz' },
      body: createHeartbeatPayload()
    });
    assert.equal(res.status, 401);
  });

  // --------------------------------------------------------------------------
  // B07 - B12: Payload Malformation & Missing Properties
  // --------------------------------------------------------------------------
  it('B07: should reject enrollment with completely empty JSON object {} with 400', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {}
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'BAD_REQUEST');
  });

  it('B08: should reject enrollment missing hostname property with 400', async () => {
    const payload = createEnrollPayload();
    delete payload.hostname;

    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: payload
    });
    assert.equal(res.status, 400);
  });

  it('B09: should reject malformed JSON syntax with HTTP 400', async () => {
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: getFleetKey(),
      headers: { 'Content-Type': 'application/json' },
      body: '{"hostname": "broken-json", "missing_brace": '
    });
    assert.equal(res.status, 400);
  });

  it('B10: should reject security event missing event_type with 400', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: { severity: 'CRITICAL', summary: 'Missing event_type' }
    });
    assert.equal(res.status, 400);
  });

  it('B11: should reject security event missing severity with 400', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: { event_type: 'USER_CREATED', summary: 'Missing severity' }
    });
    assert.equal(res.status, 400);
  });

  it('B12: should handle security event with empty details object safely', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: {
        event_type: 'USER_CREATED',
        severity: 'INFO',
        summary: 'Empty details test',
        details: {}
      }
    });
    assert.equal(res.status, 202);
  });

  // --------------------------------------------------------------------------
  // B13 - B18: Extreme Numeric & Metric Values
  // --------------------------------------------------------------------------
  it('B13: should handle extreme RAM value: 0 bytes', async () => {
    const dev = await enrollTestDevice({ total_ram_bytes: 0 });
    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.device.total_ram_gb, 0);
  });

  it('B14: should handle extreme RAM value: 1 Petabyte (1,125,899,906,842,624 bytes)', async () => {
    const dev = await enrollTestDevice({ total_ram_bytes: 1125899906842624 });
    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.ok(res.data.device.total_ram_gb > 1000000);
  });

  it('B15: should handle heartbeat with 0.0% CPU and 100.0% RAM utilization', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload({ cpu_usage_percent: 0.0, ram_usage_percent: 100.0 })
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.acknowledged, true);
  });

  it('B16: should handle heartbeat with 100.0% CPU and 0.0% RAM utilization', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload({ cpu_usage_percent: 100.0, ram_usage_percent: 0.0 })
    });
    assert.equal(res.status, 200);
  });

  it('B17: should handle zero disk free space (0.0 GB disk free)', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id, {
      hardware: {
        cpu_usage_percent: 10,
        ram_usage_percent: 50,
        disks: [{ drive_letter: 'C:', total_gb: 500, free_gb: 0, smart_status: 'Critical' }]
      }
    });

    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });
    assert.equal(res.status, 200);
  });

  it('B18: should handle event_id boundaries (0 and large integer 65535)', async () => {
    const dev = await enrollTestDevice();
    const res0 = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ event_id: 0, summary: 'Boundary event 0' })
    });
    assert.equal(res0.status, 202);

    const resLarge = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ event_id: 65535, summary: 'Boundary event 65535' })
    });
    assert.equal(resLarge.status, 202);
  });

  // --------------------------------------------------------------------------
  // B19 - B24: String Injection, Escaping, and Unicode Resiliency
  // --------------------------------------------------------------------------
  it('B19: should safely store and return hostnames containing SQL injection characters', async () => {
    const sqlInjectionHostname = "HACKER'; DROP TABLE devices; --";
    const dev = await enrollTestDevice({ hostname: sqlInjectionHostname });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.device.hostname, sqlInjectionHostname);

    // Verify table was not dropped
    const statsRes = await apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() });
    assert.equal(statsRes.status, 200);
  });

  it('B20: should safely store and return strings containing XSS script tags without executing or corrupting', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    const dev = await enrollTestDevice({ primary_user: xssPayload });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.device.primary_user, xssPayload);
  });

  it('B21: should safely store and return international Unicode characters, emoji, and non-Latin scripts', async () => {
    const unicodeUsername = 'José Müller 💻 日本語 пользователя';
    const dev = await enrollTestDevice({ primary_user: unicodeUsername });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.device.primary_user, unicodeUsername);
  });

  it('B22: should handle very long string in event summary (2,000 characters)', async () => {
    const longSummary = 'A'.repeat(2000);
    const dev = await enrollTestDevice();

    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ summary: longSummary })
    });
    assert.equal(res.status, 202);
  });

  it('B23: should handle deeply nested JSON object in security event details', async () => {
    const nestedDetails = {
      level1: { level2: { level3: { level4: { key: 'deeply_nested_value', array: [1, 2, 3] } } } }
    };
    const dev = await enrollTestDevice();

    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ details: nestedDetails })
    });
    assert.equal(res.status, 202);
  });

  it('B24: should safely handle empty strings in optional enrollment properties', async () => {
    const dev = await enrollTestDevice({
      friendly_name: '',
      gpu_name: '',
      tpm_version: '',
      bitlocker_status: 'Disabled'
    });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.device.friendly_name, '');
  });

  // --------------------------------------------------------------------------
  // B25 - B30: Nonexistent Entities (HTTP 404 Boundaries)
  // --------------------------------------------------------------------------
  it('B25: should return HTTP 404 when querying Birth Certificate for nonexistent device_id', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/00000000-0000-0000-0000-000000000000', {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 404);
    assert.equal(res.data.error, 'NOT_FOUND');
  });

  it('B26: should return HTTP 404 when querying policy for nonexistent device_id', async () => {
    const res = await apiRequest('/api/v1/nodes/00000000-0000-0000-0000-000000000000/policy', {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 404);
  });

  it('B27: should return HTTP 404 when attempting to PATCH nonexistent device_id', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/00000000-0000-0000-0000-000000000000', {
      method: 'PATCH',
      fleetKey: getFleetKey(),
      body: { friendly_name: 'Ghost' }
    });
    assert.equal(res.status, 404);
  });

  it('B28: should return HTTP 404 when attempting to DELETE nonexistent device_id', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/00000000-0000-0000-0000-000000000000', {
      method: 'DELETE',
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 404);
  });

  it('B29: should return HTTP 404 when acknowledging nonexistent alert_id', async () => {
    const res = await apiRequest('/api/v1/fleet/events/99999999/ack', {
      method: 'POST',
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 404);
  });

  it('B30: should return HTTP 404 for unknown API path /api/v1/unknown/endpoint', async () => {
    const res = await apiRequest('/api/v1/unknown/endpoint', {
      fleetKey: getFleetKey()
    });
    assert.equal(res.status, 404);
  });

  // --------------------------------------------------------------------------
  // B31 - B36: Dynamic Group Rule Evaluator Edge Cases
  // --------------------------------------------------------------------------
  it('B31: should evaluate safely to false when rule checks property missing on device', () => {
    const ctx = { hostname: 'SIMPLE-PC' };
    const match = evaluateRule("Device.GPU -like '*NVIDIA*'", ctx);
    assert.equal(match, false);
  });

  it('B32: should evaluate safely to false when checking battery on non-battery desktop device', () => {
    const ctx = { hostname: 'DESKTOP-PC', has_battery: false };
    const match = evaluateRule("Device.HasBattery -eq true", ctx);
    assert.equal(match, false);
  });

  it('B33: should handle case-insensitive operator evaluation (-EQ, -Like, -And, -Or)', () => {
    const ctx = { hostname: 'LAPTOP-01', total_ram_gb: 16 };
    const match = evaluateRule("Device.Hostname -LIKE '*LAPTOP*' -AND Device.TotalRAM_GB -GE 16", ctx);
    assert.equal(match, true);
  });

  it('B34: should evaluate numeric comparison with quoted string value safely ("16" vs 16)', () => {
    const ctx = { total_ram_gb: 16 };
    const match = evaluateRule("Device.TotalRAM_GB -ge '16'", ctx);
    assert.equal(match, true);
  });

  it('B35: should evaluate empty array tags property without crashing', () => {
    const ctx = { tags: [] };
    const match = evaluateRule("Device.Tags -contains 'family'", ctx);
    assert.equal(match, false);
  });

  it('B36: should reject dynamic group rule creation with missing operand with 400', async () => {
    const res = await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        name: 'Broken Group',
        rule_syntax: 'Device.TotalRAM_GB -ge'
      }
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'INVALID_SYNTAX');
  });

  // --------------------------------------------------------------------------
  // B37 - B42: Telemetry Ingest Boundaries (Massive Inventory & Missing Hardware)
  // --------------------------------------------------------------------------
  it('B37: should ingest large software inventory with 200 packages without error or timeout', async () => {
    const dev = await enrollTestDevice();
    const softwareList = Array.from({ length: 200 }, (_, i) => ({
      name: `Software Package ${i}`,
      publisher: `Publisher ${i % 10}`,
      version: `1.${i}.0`,
      winget_id: `Vendor.App${i}`,
      install_type: 'Registry'
    }));

    const telePayload = createTelemetryPayload(dev.device_id, { installed_software: softwareList });
    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'processed');
  });

  it('B38: should handle telemetry with null/empty disks and network_adapters arrays', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id, {
      hardware: { disks: [], network_adapters: [] }
    });

    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });

    assert.equal(res.status, 200);
  });

  it('B39: should handle telemetry with empty local_users array', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id, {
      security: { local_users: [] }
    });

    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });

    assert.equal(res.status, 200);
  });

  it('B40: should handle duplicate enrollment with identical serial number by updating existing node', async () => {
    const serial = `SN-DUPLICATE-${crypto.randomBytes(4).toString('hex')}`;
    const dev1 = await enrollTestDevice({ serial_number: serial, hostname: 'ORIGINAL-NAME' });
    const dev2 = await enrollTestDevice({ serial_number: serial, hostname: 'RENAMED-NAME' });

    assert.equal(dev1.device_id, dev2.device_id, 'Duplicate serial must resolve to same device_id');

    const checkRes = await apiRequest(`/api/v1/fleet/devices/${dev1.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(checkRes.data.device.hostname, 'RENAMED-NAME');
  });

  // --------------------------------------------------------------------------
  // B41 - B45: High Concurrency Stress Boundaries
  // --------------------------------------------------------------------------
  it('B41: should handle 25 concurrent heartbeats from different devices simultaneously', async () => {
    // Enroll 5 devices
    const devices = await Promise.all(Array.from({ length: 5 }, () => enrollTestDevice()));

    // Fire 25 heartbeats simultaneously (5 per device)
    const promises = [];
    for (const dev of devices) {
      for (let i = 0; i < 5; i++) {
        promises.push(
          apiRequest('/api/v1/nodes/heartbeat', {
            method: 'POST',
            nodeToken: dev.node_token,
            body: createHeartbeatPayload({ cpu_usage_percent: 10 + i })
          })
        );
      }
    }

    const results = await Promise.all(promises);
    for (const r of results) {
      assert.equal(r.status, 200);
      assert.equal(r.data.acknowledged, true);
    }
  });

  it('B42: should handle 10 concurrent telemetry snapshots without SQLite lock contention', async () => {
    const devices = await Promise.all(Array.from({ length: 5 }, () => enrollTestDevice()));

    const promises = devices.flatMap(dev => [
      apiRequest('/api/v1/nodes/telemetry', {
        method: 'POST',
        nodeToken: dev.node_token,
        body: createTelemetryPayload(dev.device_id)
      }),
      apiRequest('/api/v1/nodes/telemetry', {
        method: 'POST',
        nodeToken: dev.node_token,
        body: createTelemetryPayload(dev.device_id)
      })
    ]);

    const results = await Promise.all(promises);
    for (const r of results) {
      assert.equal(r.status, 200);
      assert.equal(r.data.status, 'processed');
    }
  });

  it('B43: should handle 15 concurrent security event dispatches without dropping alerts', async () => {
    const dev = await enrollTestDevice();
    const promises = Array.from({ length: 15 }, (_, i) =>
      apiRequest('/api/v1/nodes/events', {
        method: 'POST',
        nodeToken: dev.node_token,
        body: createEventPayload({ summary: `Concurrent event ${i}` })
      })
    );

    const results = await Promise.all(promises);
    for (const r of results) {
      assert.equal(r.status, 202);
      assert.ok(r.data.event_record_id > 0);
    }
  });

  it('B44: should reject dynamic group creation with duplicate name with 400', async () => {
    const res = await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        name: 'All Devices', // Pre-existing default group
        rule_syntax: 'Device.Hostname -like "*"'
      }
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'DUPLICATE_GROUP');
  });

  it('B45: should handle duplicate software catalog package with 400', async () => {
    const res = await apiRequest('/api/v1/fleet/software', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        name: 'Google Chrome Duplicate',
        winget_id: 'Google.Chrome' // Pre-existing
      }
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'CATALOG_ERROR');
  });
});
