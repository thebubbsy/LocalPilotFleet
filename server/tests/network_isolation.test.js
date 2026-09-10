/**
 * Iteration 51: Network Isolation & Host Quarantine Governance Test Suite
 * Module: server/tests/network_isolation.test.js
 *
 * Validates:
 * 1. Network isolation policies CRUD & mode configurations (FULL_DISCONNECT, SELECTIVE_MANAGEMENT, HONEYPOT_REDIRECT)
 * 2. Protocol flags (DNS, DHCP, Fleet Telemetry) & honeypot redirect addresses
 * 3. Out-of-band SecOps exclusion endpoints (IP, CIDR, FQDN, Port ranges)
 * 4. Live host containment actions (/isolate/:deviceId and /release/:deviceId)
 * 5. Forensic transition audit logs and dropped packet telemetry
 * 6. Automated CRITICAL security alert dispatch upon host isolation
 * 7. Node agent endpoints for isolation packet drop reporting
 * 8. Native Windows PowerShell / netsh quarantine rule generator
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { NetworkIsolationEngine } from '../src/services/networkIsolationEngine.js';

describe('Iteration 51: Network Isolation & Host Quarantine (network_isolation.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-iso-51';
  const TEST_DEVICE_ID = 'dev-iso-test-01';

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
      VALUES (?, 'DESKTOP-ISO-01', 'SN-ISO-51001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-iso-999', '2.5.0')
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

  test('ISO-01: GET /api/v1/fleet/network-isolation/stats returns baseline isolation metrics', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/stats');
    assert.equal(status, 200);
    assert.ok(data.totalPolicies >= 2);
    assert.ok(data.activePolicies >= 2);
    assert.ok(data.totalExclusions >= 3);
    assert.ok(data.totalLogs >= 2);
    assert.equal(data.containmentSla, true);
  });

  test('ISO-02: GET /api/v1/fleet/network-isolation/policies returns seeded policies', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    assert.ok(data.length >= 2);
    const ent = data.find(p => p.id === 'nip-enterprise-containment');
    assert.ok(ent);
    assert.equal(ent.isolation_mode, 'SELECTIVE_MANAGEMENT');
    assert.equal(ent.allow_fleet_telemetry, 1);
  });

  test('ISO-03: POST /api/v1/fleet/network-isolation/policies creates custom isolation policy', async () => {
    const newPolicy = {
      name: 'Ransomware Blast Radius Quarantine',
      description: 'Zero inbound/outbound except local loopback fleet controller',
      target_scope: 'ALL_FLEET',
      isolation_mode: 'FULL_DISCONNECT',
      allow_dns: false,
      allow_dhcp: true,
      allow_fleet_telemetry: true
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/network-isolation/policies', newPolicy);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newPolicy.name);
    assert.equal(data.policy.isolation_mode, 'FULL_DISCONNECT');
  });

  test('ISO-04: POST /api/v1/fleet/network-isolation/policies rejects request missing name', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/network-isolation/policies', {
      description: 'Missing name'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('ISO-05: GET /api/v1/fleet/network-isolation/policies/:id returns policy with exclusions', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/policies/nip-enterprise-containment');
    assert.equal(status, 200);
    assert.equal(data.id, 'nip-enterprise-containment');
    assert.ok(Array.isArray(data.exclusions));
    assert.ok(data.exclusions.length >= 2);
  });

  test('ISO-06: GET /api/v1/fleet/network-isolation/policies/:id returns 404 for unknown ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/policies/nip-nonexistent');
    assert.equal(status, 404);
    assert.equal(data.error, 'POLICY_NOT_FOUND');
  });

  test('ISO-07: PATCH /api/v1/fleet/network-isolation/policies/:id updates policy attributes', async () => {
    const { status, data } = await apiRequest('PATCH', '/api/v1/fleet/network-isolation/policies/nip-airgap-lockdown', {
      isolation_mode: 'SELECTIVE_MANAGEMENT',
      allow_fleet_telemetry: true
    });
    assert.equal(status, 200);
    assert.equal(data.policy.isolation_mode, 'SELECTIVE_MANAGEMENT');
    assert.equal(data.policy.allow_fleet_telemetry, 1);
  });

  test('ISO-08: DELETE /api/v1/fleet/network-isolation/policies/:id deletes policy', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/network-isolation/policies', {
      name: 'Temp Policy to Delete',
      isolation_mode: 'FULL_DISCONNECT'
    });
    const tempId = createRes.data.policy.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/network-isolation/policies/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);

    const checkRes = await apiRequest('GET', `/api/v1/fleet/network-isolation/policies/${tempId}`);
    assert.equal(checkRes.status, 404);
  });

  test('ISO-09: GET /api/v1/fleet/network-isolation/exclusions returns exclusion endpoints', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/exclusions');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    const fleetServer = data.find(e => e.endpoint_value === '127.0.0.1');
    assert.ok(fleetServer);
    assert.equal(fleetServer.port, 8443);
  });

  test('ISO-10: POST /api/v1/fleet/network-isolation/exclusions creates new exclusion endpoint', async () => {
    const newExc = {
      policy_id: 'nip-enterprise-containment',
      friendly_name: 'Out-of-band SecOps Bastion',
      endpoint_type: 'IP_ADDRESS',
      endpoint_value: '10.250.0.15',
      direction: 'BOTH',
      port: 22
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/network-isolation/exclusions', newExc);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.exclusion.endpoint_value, '10.250.0.15');
  });

  test('ISO-11: POST /api/v1/fleet/network-isolation/exclusions rejects missing friendly_name', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/network-isolation/exclusions', {
      endpoint_value: '1.2.3.4'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('ISO-12: DELETE /api/v1/fleet/network-isolation/exclusions/:id deletes exclusion', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/network-isolation/exclusions', {
      friendly_name: 'Temp Exclusion',
      endpoint_value: '192.168.1.1'
    });
    const tempId = createRes.data.exclusion.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/network-isolation/exclusions/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
  });

  test('ISO-13: POST /api/v1/fleet/network-isolation/isolate/:deviceId isolates host and logs event', async () => {
    const { status, data } = await apiRequest('POST', `/api/v1/fleet/network-isolation/isolate/${TEST_DEVICE_ID}`, {
      reason: 'Active Cobalt Strike beaconing identified on host',
      initiated_by: 'Lead Threat Hunter'
    });
    assert.equal(status, 200);
    assert.ok(data.success);
    assert.equal(data.state.containment_status, 'CONTAINED');

    // Verify security alert was recorded
    const alert = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND event_source = 'NETWORK_ISOLATION_ENGINE'
      ORDER BY rowid DESC LIMIT 1
    `).get(TEST_DEVICE_ID);

    assert.ok(alert);
    assert.equal(alert.severity, 'CRITICAL');
  });

  test('ISO-14: POST /api/v1/fleet/network-isolation/release/:deviceId releases host back to network', async () => {
    const { status, data } = await apiRequest('POST', `/api/v1/fleet/network-isolation/release/${TEST_DEVICE_ID}`, {
      reason: 'Host successfully remediated and AV scanned clean',
      initiated_by: 'Incident Commander'
    });
    assert.equal(status, 200);
    assert.ok(data.success);
    assert.equal(data.state.containment_status, 'UNCONTAINED');
  });

  test('ISO-15: GET /api/v1/fleet/network-isolation/logs lists isolation audit history', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/network-isolation/logs');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.logs));
    assert.ok(data.count >= 2);
  });

  test('ISO-16: POST /api/v1/fleet/network-isolation/logs logs unauthorized packet drop', async () => {
    const newLog = {
      device_id: TEST_DEVICE_ID,
      transition_type: 'UNAUTHORIZED_TRAFFIC_DROPPED',
      reason: 'Egress connection blocked to untrusted external IP',
      packet_summary: 'TCP 10.0.1.20:51290 -> 45.33.32.156:443 [DROPPED]'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/network-isolation/logs', newLog);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.log.transition_type, 'UNAUTHORIZED_TRAFFIC_DROPPED');
  });

  test('ISO-17: POST /api/v1/nodes/:id/network-isolation/logs lets node agent report packet drop', async () => {
    const res = await fetch(`${baseUrl}/api/v1/nodes/${TEST_DEVICE_ID}/network-isolation/logs`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + TEST_FLEET_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        transition_type: 'UNAUTHORIZED_TRAFFIC_DROPPED',
        reason: 'Blocked outbound SMB port 445 packet'
      })
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.success);
  });

  test('ISO-18: GET /api/v1/fleet/network-isolation/script/:deviceId generates netsh WFP script', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/network-isolation/script/${TEST_DEVICE_ID}`, {
      headers: { 'X-Fleet-Key': TEST_FLEET_KEY }
    });
    assert.equal(res.status, 200);
    const script = await res.text();
    assert.ok(script.includes('LocalPilot-Isolation'));
    assert.ok(script.includes('netsh advfirewall'));
  });

  test('ISO-19: Honeypot redirect mode is supported by policy schema', async () => {
    const policy = NetworkIsolationEngine.createPolicy(db, {
      name: 'Honeypot Sandbox Redirect Policy',
      isolation_mode: 'HONEYPOT_REDIRECT',
      honeypot_redirect_ip: '10.99.99.1'
    });
    assert.equal(policy.isolation_mode, 'HONEYPOT_REDIRECT');
    assert.equal(policy.honeypot_redirect_ip, '10.99.99.1');
  });

  test('ISO-20: Concurrent isolation audit log ingestion SLA under load (< 1000ms)', async () => {
    const start = Date.now();
    const promises = Array.from({ length: 15 }, (_, i) => {
      return apiRequest('POST', '/api/v1/fleet/network-isolation/logs', {
        device_id: TEST_DEVICE_ID,
        transition_type: 'UNAUTHORIZED_TRAFFIC_DROPPED',
        reason: 'Stress packet drop #' + i
      });
    });

    const results = await Promise.all(promises);
    const duration = Date.now() - start;
    assert.ok(duration < 1000, `Duration was ${duration}ms, expected < 1000ms`);
    assert.ok(results.every(r => r.status === 201));
  });
});
