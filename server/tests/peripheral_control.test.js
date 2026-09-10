/**
 * Iteration 49: USB & Peripheral Device Control Test Suite
 * Module: server/tests/peripheral_control.test.js
 *
 * Validates:
 * 1. Removable storage and peripheral control policies CRUD
 * 2. Enforcement modes (ALLOW, READ_ONLY, BLOCK) and Bluetooth/printer postures
 * 3. Hardware exception whitelist (VID, PID, Serial, Interface GUIDs)
 * 4. Real-time forensic connection and write interception audit telemetry
 * 5. Automated HIGH severity security alert dispatch on unauthorized write attempts
 * 6. Node agent endpoints for peripheral telemetry ingestion
 * 7. PowerShell client configuration script synthesis (HKLM RemovableStorageDevices)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { PeripheralControlEngine } from '../src/services/peripheralControlEngine.js';

describe('Iteration 49: USB & Peripheral Device Control (peripheral_control.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-peripheral-49';
  const TEST_DEVICE_ID = 'dev-usb-test-01';
  let createdPolicyId;
  let createdExceptionId;

  const router = {
    routes: { GET: [], POST: [], PATCH: [], DELETE: [], PUT: [] },
    get(path, handler) { this.routes.GET.push({ path, handler }); },
    post(path, handler) { this.routes.POST.push({ path, handler }); },
    put(path, handler) { this.routes.PUT.push({ path, handler }); },
    patch(path, handler) { this.routes.PATCH.push({ path, handler }); },
    delete(path, handler) { this.routes.DELETE.push({ path, handler }); }
  };

  function matchRoute(method, urlPath) {
    const list = router.routes[method] || [];
    for (const r of list) {
      if (r.path === urlPath) return { handler: r.handler, params: {} };
      const rParts = r.path.split('/');
      const uParts = urlPath.split('/');
      if (rParts.length === uParts.length) {
        let match = true;
        const params = {};
        for (let i = 0; i < rParts.length; i++) {
          if (rParts[i].startsWith(':')) {
            params[rParts[i].slice(1)] = uParts[i];
          } else if (rParts[i] !== uParts[i]) {
            match = false;
            break;
          }
        }
        if (match) return { handler: r.handler, params };
      }
    }
    return null;
  }

  before(async () => {
    db = initDb(':memory:');
    setFleetKey(TEST_FLEET_KEY);
    registerFleetRoutes(router);
    registerNodeRoutes(router);

    // Create test device
    db.prepare(`
      INSERT OR REPLACE INTO devices (id, hostname, serial_number, os_name, os_version, total_ram_bytes, node_token_hash, agent_version)
      VALUES (?, 'DESKTOP-USB-01', 'SN-USB-49001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-usb-999', '2.5.0')
    `).run(TEST_DEVICE_ID);

    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      const route = matchRoute(req.method, url.pathname);
      if (!route) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NOT_FOUND', message: 'Route not found' }));
        return;
      }

      req.params = route.params;
      req.query = Object.fromEntries(url.searchParams.entries());

      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        if (body) {
          try { req.body = JSON.parse(body); } catch(e) { req.body = {}; }
        } else {
          req.body = {};
        }
        route.handler(req, res);
      });
    });

    await new Promise(resolve => server.listen(0, resolve));
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (server) {
      await new Promise(resolve => server.close(resolve));
    }
    closeDb();
  });

  const apiRequest = async (method, path, body = null, headers = {}) => {
    const finalHeaders = {
      'X-Fleet-Key': TEST_FLEET_KEY,
      'Content-Type': 'application/json',
      ...headers
    };
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: finalHeaders,
      body: body ? JSON.stringify(body) : undefined
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, data: json };
  };

  test('UDC-01: GET /api/v1/fleet/peripheral-control/stats returns baseline metrics', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/stats');
    assert.equal(status, 200);
    assert.ok(data.totalPolicies >= 2);
    assert.ok(data.activePolicies >= 2);
    assert.ok(data.totalExceptions >= 3);
    assert.ok(data.totalEvents >= 2);
    assert.equal(data.enforcementSla, true);
  });

  test('UDC-02: GET /api/v1/fleet/peripheral-control/policies returns seeded policies', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    assert.ok(data.length >= 2);
    const corp = data.find(p => p.id === 'usb-pol-corp-baseline');
    assert.ok(corp);
    assert.equal(corp.removable_storage_access, 'READ_ONLY');
    assert.equal(corp.bluetooth_mode, 'RESTRICTED');
  });

  test('UDC-03: POST /api/v1/fleet/peripheral-control/policies creates a custom policy', async () => {
    const newPolicy = {
      name: 'R&D Strict Airgap Policy',
      description: 'Zero removable storage and bluetooth tethering blocked',
      target_scope: 'ALL_FLEET',
      removable_storage_access: 'BLOCK',
      bluetooth_mode: 'DISABLED',
      printer_protection_mode: 'BLOCK',
      audit_level: 'DETAILED'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/policies', newPolicy);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newPolicy.name);
    assert.equal(data.policy.removable_storage_access, 'BLOCK');
    createdPolicyId = data.policy.id;
  });

  test('UDC-04: POST /api/v1/fleet/peripheral-control/policies rejects request missing name', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/policies', {
      description: 'Missing name'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('UDC-05: GET /api/v1/fleet/peripheral-control/policies/:id returns policy with exceptions', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/policies/usb-pol-corp-baseline');
    assert.equal(status, 200);
    assert.equal(data.id, 'usb-pol-corp-baseline');
    assert.ok(Array.isArray(data.exceptions));
    assert.ok(data.exceptions.length >= 2);
  });

  test('UDC-06: GET /api/v1/fleet/peripheral-control/policies/:id returns 404 for unknown ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/policies/usb-pol-nonexistent');
    assert.equal(status, 404);
    assert.equal(data.error, 'POLICY_NOT_FOUND');
  });

  test('UDC-07: PATCH /api/v1/fleet/peripheral-control/policies/:id updates attributes', async () => {
    const { status, data } = await apiRequest('PATCH', '/api/v1/fleet/peripheral-control/policies/usb-pol-airgap', {
      bluetooth_mode: 'RESTRICTED',
      audit_level: 'STANDARD'
    });
    assert.equal(status, 200);
    assert.equal(data.policy.bluetooth_mode, 'RESTRICTED');
    assert.equal(data.policy.audit_level, 'STANDARD');
  });

  test('UDC-08: DELETE /api/v1/fleet/peripheral-control/policies/:id deletes policy', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/peripheral-control/policies', {
      name: 'Temporary Policy to Delete',
      removable_storage_access: 'ALLOW'
    });
    const tempId = createRes.data.policy.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/peripheral-control/policies/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);

    const checkRes = await apiRequest('GET', `/api/v1/fleet/peripheral-control/policies/${tempId}`);
    assert.equal(checkRes.status, 404);
  });

  test('UDC-09: GET /api/v1/fleet/peripheral-control/exceptions returns hardware whitelist', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/exceptions');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    const yubi = data.find(e => e.friendly_name.includes('YubiKey'));
    assert.ok(yubi);
    assert.equal(yubi.action, 'ALLOW');
  });

  test('UDC-10: POST /api/v1/fleet/peripheral-control/exceptions creates a new whitelist rule', async () => {
    const newExc = {
      policy_id: 'usb-pol-corp-baseline',
      friendly_name: 'Executive Encrypted Samsung T7 SSD',
      vendor_id: '04e8',
      product_id: '4001',
      serial_number: 'S5R2NS0R800192A',
      action: 'ALLOW'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/exceptions', newExc);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.exception.vendor_id, '04e8');
    createdExceptionId = data.exception.id;
  });

  test('UDC-11: POST /api/v1/fleet/peripheral-control/exceptions rejects missing friendly_name', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/exceptions', {
      vendor_id: '1234'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('UDC-12: DELETE /api/v1/fleet/peripheral-control/exceptions/:id deletes exception', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/peripheral-control/exceptions', {
      friendly_name: 'Temp Flash to Delete',
      action: 'BLOCK'
    });
    const tempId = createRes.data.exception.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/peripheral-control/exceptions/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
  });

  test('UDC-13: GET /api/v1/fleet/peripheral-control/events lists peripheral connection logs', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/events');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    assert.ok(data.count >= 2);
  });

  test('UDC-14: POST /api/v1/fleet/peripheral-control/events logs an external device connect', async () => {
    const newEvent = {
      device_id: TEST_DEVICE_ID,
      event_type: 'USB_ATTACH',
      device_name: 'Corsair Voyager GTX USB 3.1',
      hardware_id: 'USB\\VID_1B1C&PID_1A0B',
      action_taken: 'ALLOWED',
      process_name: 'System'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/events', newEvent);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.event.device_name, 'Corsair Voyager GTX USB 3.1');
  });

  test('UDC-15: POST /api/v1/fleet/peripheral-control/events on WRITE_BLOCKED triggers security alert', async () => {
    const writeEvent = {
      device_id: TEST_DEVICE_ID,
      event_type: 'WRITE_BLOCKED',
      device_name: 'Generic Mass Storage',
      hardware_id: 'USB\\VID_0000&PID_0000',
      action_taken: 'BLOCKED',
      process_name: 'cmd.exe',
      file_path: 'E:\\customer_dump.sql'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/peripheral-control/events', writeEvent);
    assert.equal(status, 201);

    // Verify security alert was recorded in database
    const alert = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND event_type = 'MALWARE_THREAT_DETECTED'
      ORDER BY rowid DESC LIMIT 1
    `).get(TEST_DEVICE_ID);

    assert.ok(alert);
    assert.equal(alert.severity, 'HIGH');
  });

  test('UDC-16: POST /api/v1/nodes/:id/peripheral-control/events lets node agent log telemetry', async () => {
    // Generate valid node token in devices table
    const nodeRes = await fetch(`${baseUrl}/api/v1/nodes/${TEST_DEVICE_ID}/peripheral-control/events`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + TEST_FLEET_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        event_type: 'READ_ONLY_ENFORCED',
        device_name: 'Lexar JumpDrive',
        action_taken: 'BLOCKED'
      })
    });
    assert.equal(nodeRes.status, 201);
    const data = await nodeRes.json();
    assert.ok(data.success);
  });

  test('UDC-17: GET /api/v1/fleet/peripheral-control/events supports filtering by event_type', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/peripheral-control/events?event_type=WRITE_BLOCKED');
    assert.equal(status, 200);
    assert.ok(data.events.every(e => e.event_type === 'WRITE_BLOCKED'));
  });

  test('UDC-18: GET /api/v1/fleet/peripheral-control/script/:deviceId generates PowerShell enforcement script', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/peripheral-control/script/${TEST_DEVICE_ID}`, {
      headers: { 'X-Fleet-Key': TEST_FLEET_KEY }
    });
    assert.equal(res.status, 200);
    const script = await res.text();
    assert.ok(script.includes('RemovableStorageDevices'));
    assert.ok(script.includes('Deny_Write'));
    assert.ok(script.includes('auditpol'));
  });

  test('UDC-19: Exception rule correctly supports explicit BLOCK actions for rogue hardware', async () => {
    const exc = db.prepare("SELECT * FROM usb_device_exceptions WHERE action = 'BLOCK' LIMIT 1").get();
    assert.ok(exc);
    assert.equal(exc.action, 'BLOCK');
  });

  test('UDC-20: Concurrent peripheral event ingestion SLA under load (< 1000ms)', async () => {
    const start = Date.now();
    const promises = Array.from({ length: 15 }, (_, i) => {
      return apiRequest('POST', '/api/v1/fleet/peripheral-control/events', {
        device_id: TEST_DEVICE_ID,
        event_type: 'USB_ATTACH',
        device_name: 'Benchmark USB #' + i,
        action_taken: 'ALLOWED'
      });
    });

    const results = await Promise.all(promises);
    const duration = Date.now() - start;
    assert.ok(duration < 1000, `Duration was ${duration}ms, expected < 1000ms`);
    assert.ok(results.every(r => r.status === 201));
  });
});
