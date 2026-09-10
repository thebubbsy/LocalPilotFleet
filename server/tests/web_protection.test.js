/**
 * Iteration 48: Web Content Filtering & SmartScreen Test Suite
 * Module: server/tests/web_protection.test.js
 *
 * Validates:
 * 1. Web content filtering policies CRUD & category toggles
 * 2. SmartScreen enforcement modes (BLOCK, WARN, DISABLED)
 * 3. Custom domain, URL, and IP indicator overrides
 * 4. Real-time network intercept telemetry stream
 * 5. Automated CRITICAL security event dispatch on phishing attempts
 * 6. Node agent endpoints for web intercept logging
 * 7. PowerShell client configuration script synthesis
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { WebProtectionEngine } from '../src/services/webProtectionEngine.js';

describe('Iteration 48: Web Content Filtering & SmartScreen (web_protection.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-web-48';
  const TEST_DEVICE_ID = 'dev-web-test-01';
  let createdPolicyId;
  let createdIndicatorId;

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
      VALUES (?, 'DESKTOP-WEB-01', 'SN-WEB-48001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-web-999', '2.5.0')
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

  test('WCF-01: GET /api/v1/fleet/web-protection/stats returns baseline web protection metrics', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalPolicies, 'number');
    assert.equal(typeof data.activePolicies, 'number');
    assert.equal(typeof data.totalIndicators, 'number');
    assert.equal(typeof data.totalWebBlocks, 'number');
    assert.equal(data.subSecondSweepSla, true);
  });

  test('WCF-02: GET /api/v1/fleet/web-protection/policies returns seeded web filter baselines', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.policies));
    assert.ok(data.policies.length >= 2);
    const strict = data.policies.find(p => p.id === 'wcf-enterprise-strict');
    assert.ok(strict, 'Should find seeded enterprise strict policy');
    assert.equal(strict.smartscreen_mode, 'BLOCK');
  });

  test('WCF-03: POST /api/v1/fleet/web-protection/policies creates a new custom web filter policy', async () => {
    const newPolicy = {
      name: 'Executive Boardroom Restrictive Web Baseline',
      description: 'Strict web filtering preventing social media and unapproved high-liability categories',
      target_scope: 'ALL_FLEET',
      block_adult_content: true,
      block_high_liability: true,
      block_legal_liability: true,
      block_bandwidth_loss: true,
      smartscreen_mode: 'BLOCK',
      allow_user_bypass: false,
      network_protection_mode: 'BLOCK'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/policies', newPolicy);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newPolicy.name);
    assert.equal(data.policy.block_bandwidth_loss, 1);
    createdPolicyId = data.policy.id;
  });

  test('WCF-04: POST /api/v1/fleet/web-protection/policies rejects request with missing name with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/policies', { description: 'Missing name' });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('WCF-05: GET /api/v1/fleet/web-protection/policies/:id returns single policy with attached indicators', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/web-protection/policies/${createdPolicyId}`);
    assert.equal(status, 200);
    assert.equal(data.id, createdPolicyId);
    assert.ok(Array.isArray(data.indicators));
  });

  test('WCF-06: GET /api/v1/fleet/web-protection/policies/:id returns 404 for unknown policy ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/policies/non-existent-policy');
    assert.equal(status, 404);
    assert.equal(data.error, 'POLICY_NOT_FOUND');
  });

  test('WCF-07: PATCH /api/v1/fleet/web-protection/policies/:id updates policy attributes', async () => {
    const { status, data } = await apiRequest('PATCH', `/api/v1/fleet/web-protection/policies/${createdPolicyId}`, {
      description: 'Updated executive policy description',
      allow_user_bypass: true
    });
    assert.equal(status, 200);
    assert.ok(data.success);
    assert.equal(data.policy.description, 'Updated executive policy description');
    assert.equal(data.policy.allow_user_bypass, 1);
  });

  test('WCF-08: DELETE /api/v1/fleet/web-protection/policies/:id deletes policy and returns 200', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/web-protection/policies/${createdPolicyId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', `/api/v1/fleet/web-protection/policies/${createdPolicyId}`);
    assert.equal(check.status, 404);
  });

  test('WCF-09: GET /api/v1/fleet/web-protection/indicators returns custom indicator list', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/indicators');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.indicators));
    assert.ok(data.indicators.length >= 1);
  });

  test('WCF-10: POST /api/v1/fleet/web-protection/indicators creates a new domain block indicator', async () => {
    const newIndicator = {
      indicator_type: 'DOMAIN',
      indicator_value: 'malicious-cryptominer-pool.org',
      action: 'BLOCK',
      category: 'Cryptomining & Abuse'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/indicators', newIndicator);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.indicator.indicator_value, newIndicator.indicator_value);
    createdIndicatorId = data.indicator.id;
  });

  test('WCF-11: POST /api/v1/fleet/web-protection/indicators rejects missing indicator_value with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/indicators', { action: 'BLOCK' });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('WCF-12: DELETE /api/v1/fleet/web-protection/indicators/:id deletes indicator and returns 200', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/web-protection/indicators/${createdIndicatorId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
  });

  test('WCF-13: GET /api/v1/fleet/web-protection/events lists captured web protection events', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/events');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    assert.ok(data.events.length >= 1);
  });

  test('WCF-14: POST /api/v1/fleet/web-protection/events logs an intercepted connection', async () => {
    const intercept = {
      device_id: TEST_DEVICE_ID,
      hostname: 'DESKTOP-WEB-01',
      username: 'Sarah',
      event_type: 'URL_BLOCKED',
      url: 'https://torrent-unapproved-share.biz/download',
      domain: 'torrent-unapproved-share.biz',
      category: 'Bandwidth Loss & P2P',
      action_taken: 'BLOCKED',
      browser_process: 'msedge.exe',
      severity: 'LOW'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/events', intercept);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.event.domain, 'torrent-unapproved-share.biz');
  });

  test('WCF-15: POST /api/v1/fleet/web-protection/events automatically dispatches CRITICAL alert on phishing attempt', async () => {
    const phishEvent = {
      device_id: TEST_DEVICE_ID,
      hostname: 'DESKTOP-WEB-01',
      username: 'Tony',
      event_type: 'PHISHING_ATTEMPT_DETECTED',
      url: 'https://office365-credential-harvest.fake/auth',
      domain: 'office365-credential-harvest.fake',
      category: 'Phishing & Credential Theft',
      action_taken: 'BLOCKED',
      browser_process: 'chrome.exe',
      severity: 'CRITICAL'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/web-protection/events', phishEvent);
    assert.equal(status, 201);
    assert.ok(data.success);

    // Verify security_events audit record was created
    const sec = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND severity = 'CRITICAL' AND event_source = 'WEB_PROTECTION_ENGINE'
      ORDER BY id DESC LIMIT 1
    `).get(TEST_DEVICE_ID);
    assert.ok(sec, 'Security alert should be created for phishing detection');
    assert.ok(sec.summary.includes('Phishing connection blocked'));
  });

  test('WCF-16: POST /api/v1/nodes/:id/web-protection/events lets node agent log web intercept event', async () => {
    const nodeEvent = {
      event_type: 'SMARTSCREEN_WARNING_BYPASS',
      url: 'https://untrusted-software-dist.net/setup.exe',
      domain: 'untrusted-software-dist.net',
      category: 'Unrated Software',
      action_taken: 'USER_BYPASSED',
      browser_process: 'msedge.exe',
      severity: 'MEDIUM'
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/web-protection/events`, nodeEvent);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.event.action_taken, 'USER_BYPASSED');
  });

  test('WCF-17: GET /api/v1/fleet/web-protection/events filters events by action_taken and event_type', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/web-protection/events?action_taken=USER_BYPASSED');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    data.events.forEach(e => assert.equal(e.action_taken, 'USER_BYPASSED'));
  });

  test('WCF-18: GET /api/v1/fleet/web-protection/script/:deviceId generates PowerShell Defender Web Protection script', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/web-protection/script/${TEST_DEVICE_ID}`, {
      headers: { 'X-Fleet-Key': TEST_FLEET_KEY }
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/plain; charset=utf-8');
    const text = await res.text();
    assert.ok(text.includes('EnableNetworkProtection'));
    assert.ok(text.includes('SmartScreenPath'));
    assert.ok(text.includes('web_indicators.json'));
  });

  test('WCF-19: Custom Indicator rule correctly supports ALLOW and WARN overrides', async () => {
    const allowRule = WebProtectionEngine.createIndicatorRule(db, {
      indicator_type: 'DOMAIN',
      indicator_value: 'trusted-partner-portal.com',
      action: 'ALLOW',
      category: 'B2B Allowed Portal'
    });
    assert.equal(allowRule.action, 'ALLOW');

    const warnRule = WebProtectionEngine.createIndicatorRule(db, {
      indicator_type: 'DOMAIN',
      indicator_value: 'gaming-stream.tv',
      action: 'WARN',
      category: 'Bandwidth Warning'
    });
    assert.equal(warnRule.action, 'WARN');
  });

  test('WCF-20: Concurrent web telemetry aggregation SLA under load (< 1000ms)', async () => {
    const start = Date.now();
    const [stats, policies, indicators, events] = await Promise.all([
      apiRequest('GET', '/api/v1/fleet/web-protection/stats'),
      apiRequest('GET', '/api/v1/fleet/web-protection/policies'),
      apiRequest('GET', '/api/v1/fleet/web-protection/indicators'),
      apiRequest('GET', '/api/v1/fleet/web-protection/events')
    ]);
    const duration = Date.now() - start;
    assert.equal(stats.status, 200);
    assert.equal(policies.status, 200);
    assert.equal(indicators.status, 200);
    assert.equal(events.status, 200);
    assert.ok(duration < 1000, `Telemetry requests took ${duration}ms, expected < 1000ms`);
  });
});
