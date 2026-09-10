/**
 * Iteration 50: Endpoint Tamper Protection & Antivirus Exclusion Governance Test Suite
 * Module: server/tests/tamper_protection.test.js
 *
 * Validates:
 * 1. Tamper protection policies CRUD & state enforcement (ENFORCED, AUDIT_ONLY, DISABLED)
 * 2. Service locks, exclusion protection, and safe-mode bypass prevention flags
 * 3. Governed antivirus exclusions (PATH, FOLDER, EXTENSION, PROCESS) with risk tiers
 * 4. Forensic telemetry stream on unauthorized registry/service/exclusion tampering
 * 5. Automated CRITICAL security alert dispatch on tampering attempts
 * 6. Node agent endpoints for tamper telemetry reporting
 * 7. Native PowerShell client configuration script synthesis (Set-MpPreference & Feature registry)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { TamperProtectionEngine } from '../src/services/tamperProtectionEngine.js';

describe('Iteration 50: Endpoint Tamper Protection & Exclusion Governance (tamper_protection.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-tamper-50';
  const TEST_DEVICE_ID = 'dev-tamper-test-01';

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
      VALUES (?, 'DESKTOP-TAMPER-01', 'SN-TAMPER-50001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-tamper-999', '2.5.0')
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

  test('TP-01: GET /api/v1/fleet/tamper-protection/stats returns baseline tamper metrics', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/stats');
    assert.equal(status, 200);
    assert.ok(data.totalPolicies >= 2);
    assert.ok(data.activePolicies >= 2);
    assert.ok(data.totalExclusions >= 3);
    assert.ok(data.totalEvents >= 2);
    assert.equal(data.subSecondSweepSla, true);
  });

  test('TP-02: GET /api/v1/fleet/tamper-protection/policies returns seeded policies', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    assert.ok(data.length >= 2);
    const strict = data.find(p => p.id === 'tpp-enterprise-strict');
    assert.ok(strict);
    assert.equal(strict.tamper_protection_state, 'ENFORCED');
    assert.equal(strict.lock_security_services, 1);
  });

  test('TP-03: POST /api/v1/fleet/tamper-protection/policies creates a custom policy', async () => {
    const newPolicy = {
      name: 'High-Value Financial Workstation Tamper Policy',
      description: 'Strict Anti-Snooping with complete exclusion lockdown',
      target_scope: 'ALL_FLEET',
      tamper_protection_state: 'ENFORCED',
      lock_security_services: true,
      protect_antivirus_exclusions: true,
      prevent_safe_mode_bypass: true
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/policies', newPolicy);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newPolicy.name);
    assert.equal(data.policy.tamper_protection_state, 'ENFORCED');
  });

  test('TP-04: POST /api/v1/fleet/tamper-protection/policies rejects request missing name', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/policies', {
      description: 'Missing name'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('TP-05: GET /api/v1/fleet/tamper-protection/policies/:id returns policy with exclusions', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/policies/tpp-enterprise-strict');
    assert.equal(status, 200);
    assert.equal(data.id, 'tpp-enterprise-strict');
    assert.ok(Array.isArray(data.exclusions));
    assert.ok(data.exclusions.length >= 2);
  });

  test('TP-06: GET /api/v1/fleet/tamper-protection/policies/:id returns 404 for unknown ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/policies/tpp-nonexistent');
    assert.equal(status, 404);
    assert.equal(data.error, 'POLICY_NOT_FOUND');
  });

  test('TP-07: PATCH /api/v1/fleet/tamper-protection/policies/:id updates attributes', async () => {
    const { status, data } = await apiRequest('PATCH', '/api/v1/fleet/tamper-protection/policies/tpp-developer-monitored', {
      tamper_protection_state: 'ENFORCED',
      prevent_safe_mode_bypass: true
    });
    assert.equal(status, 200);
    assert.equal(data.policy.tamper_protection_state, 'ENFORCED');
    assert.equal(data.policy.prevent_safe_mode_bypass, 1);
  });

  test('TP-08: DELETE /api/v1/fleet/tamper-protection/policies/:id deletes policy', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/tamper-protection/policies', {
      name: 'Temporary Policy to Delete',
      tamper_protection_state: 'AUDIT_ONLY'
    });
    const tempId = createRes.data.policy.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/tamper-protection/policies/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);

    const checkRes = await apiRequest('GET', `/api/v1/fleet/tamper-protection/policies/${tempId}`);
    assert.equal(checkRes.status, 404);
  });

  test('TP-09: GET /api/v1/fleet/tamper-protection/exclusions returns governed exclusions', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/exclusions');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data));
    const git = data.find(e => e.exclusion_value.includes('git.exe'));
    assert.ok(git);
    assert.equal(git.risk_tier, 'LOW');
  });

  test('TP-10: POST /api/v1/fleet/tamper-protection/exclusions creates a new exclusion rule', async () => {
    const newExc = {
      policy_id: 'tpp-enterprise-strict',
      exclusion_type: 'PROCESS',
      exclusion_value: 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\dockerd.exe',
      risk_tier: 'LOW',
      justification: 'Container runtime daemon I/O overhead reduction',
      approved_by: 'Infrastructure Lead'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/exclusions', newExc);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.exclusion.exclusion_value, newExc.exclusion_value);
    assert.equal(data.exclusion.risk_tier, 'LOW');
  });

  test('TP-11: POST /api/v1/fleet/tamper-protection/exclusions rejects missing exclusion_value', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/exclusions', {
      exclusion_type: 'PATH'
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('TP-12: DELETE /api/v1/fleet/tamper-protection/exclusions/:id deletes exclusion rule', async () => {
    const createRes = await apiRequest('POST', '/api/v1/fleet/tamper-protection/exclusions', {
      exclusion_value: 'C:\\temp\\scratch_to_delete.log',
      exclusion_type: 'PATH',
      justification: 'Temp test'
    });
    const tempId = createRes.data.exclusion.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/tamper-protection/exclusions/${tempId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
  });

  test('TP-13: GET /api/v1/fleet/tamper-protection/events lists tamper event logs', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/events');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    assert.ok(data.count >= 2);
  });

  test('TP-14: POST /api/v1/fleet/tamper-protection/events logs a service tamper attempt', async () => {
    const newEvent = {
      device_id: TEST_DEVICE_ID,
      event_type: 'SERVICE_STOP_ATTEMPT',
      target_resource: 'WinDefend (Microsoft Defender Antivirus Service)',
      attacker_process: 'sc.exe stop WinDefend',
      action_taken: 'BLOCKED',
      details: { return_code: 5, error: 'ACCESS_DENIED_BY_TAMPER_PROTECTION' }
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/events', newEvent);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.event.event_type, 'SERVICE_STOP_ATTEMPT');
  });

  test('TP-15: POST /api/v1/fleet/tamper-protection/events triggers CRITICAL security alert', async () => {
    const tamperEvent = {
      device_id: TEST_DEVICE_ID,
      event_type: 'REGISTRY_TAMPER_ATTEMPT',
      target_resource: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware',
      attacker_process: 'malware_dropper.exe',
      action_taken: 'BLOCKED'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/tamper-protection/events', tamperEvent);
    assert.equal(status, 201);

    // Verify security alert was recorded in database
    const alert = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND event_source = 'TAMPER_PROTECTION_ENGINE'
      ORDER BY rowid DESC LIMIT 1
    `).get(TEST_DEVICE_ID);

    assert.ok(alert);
    assert.equal(alert.severity, 'CRITICAL');
  });

  test('TP-16: POST /api/v1/nodes/:id/tamper-protection/events lets node agent log tamper event', async () => {
    const res = await fetch(`${baseUrl}/api/v1/nodes/${TEST_DEVICE_ID}/tamper-protection/events`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + TEST_FLEET_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        event_type: 'DRIVER_UNLOAD_ATTEMPT',
        target_resource: 'WdFilter.sys',
        attacker_process: 'mimikatz.exe',
        action_taken: 'BLOCKED'
      })
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.success);
  });

  test('TP-17: GET /api/v1/fleet/tamper-protection/events supports filtering by event_type', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/tamper-protection/events?event_type=REGISTRY_TAMPER_ATTEMPT');
    assert.equal(status, 200);
    assert.ok(data.events.every(e => e.event_type === 'REGISTRY_TAMPER_ATTEMPT'));
  });

  test('TP-18: GET /api/v1/fleet/tamper-protection/script/:deviceId generates PowerShell enforcement script', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/tamper-protection/script/${TEST_DEVICE_ID}`, {
      headers: { 'X-Fleet-Key': TEST_FLEET_KEY }
    });
    assert.equal(res.status, 200);
    const script = await res.text();
    assert.ok(script.includes('TamperProtection'));
    assert.ok(script.includes('Set-MpPreference'));
    assert.ok(script.includes('Add-MpPreference'));
  });

  test('TP-19: High risk exclusion rules are correctly flagged in inventory', async () => {
    const highRisk = db.prepare("SELECT * FROM antivirus_exclusion_rules WHERE risk_tier = 'HIGH' LIMIT 1").get();
    assert.ok(highRisk);
    assert.equal(highRisk.risk_tier, 'HIGH');
  });

  test('TP-20: Concurrent tamper event ingestion SLA under load (< 1000ms)', async () => {
    const start = Date.now();
    const promises = Array.from({ length: 15 }, (_, i) => {
      return apiRequest('POST', '/api/v1/fleet/tamper-protection/events', {
        device_id: TEST_DEVICE_ID,
        event_type: 'REGISTRY_TAMPER_ATTEMPT',
        target_resource: 'HKLM\\Registry\\Key\\' + i,
        attacker_process: 'stress_agent.exe',
        action_taken: 'BLOCKED'
      });
    });

    const results = await Promise.all(promises);
    const duration = Date.now() - start;
    assert.ok(duration < 1000, `Duration was ${duration}ms, expected < 1000ms`);
    assert.ok(results.every(r => r.status === 201));
  });
});
