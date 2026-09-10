/**
 * Iteration 57: Data Loss Prevention & Sensitive Information Defense (DLP) Test Suite
 * Module: server/tests/dlp.test.js
 *
 * Validates:
 * 1. Aggregated DLP metrics and statistics (/dlp/stats)
 * 2. Fleet key authentication requirement
 * 3. Classification rules listing (/dlp/rules)
 * 4. Category-based rules filtering
 * 5. Single rule retrieval by ID
 * 6. 404 response on missing rule
 * 7. Creation of new classification rule
 * 8. Validation of regex compilability on rule creation
 * 9. Validation of missing required parameters
 * 10. Updating classification rule properties
 * 11. Deleting classification rule
 * 12. Querying sensitive file scan findings (/dlp/findings)
 * 13. Status-based findings filtering
 * 14. Recording a sensitive file discovery
 * 15. Updating finding remediation status
 * 16. Querying exfiltration incidents (/dlp/incidents)
 * 17. Logging an intercepted exfiltration attempt
 * 18. Validation error on missing required incident fields
 * 19. Fast in-memory regex text scanning (/dlp/scan-text)
 * 20. Node agent DLP endpoints (pull rules, report finding, report exfiltration)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { DlpEngine } from '../src/services/dlpEngine.js';

describe('Iteration 57: Data Loss Prevention & Exfiltration Guardrails (dlp.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-dlp-57';
  const TEST_DEVICE_ID = 'dev-dlp-test-01';

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
      VALUES (?, 'FINANCE-LAPTOP-01', 'SN-DLP-57001', 'Windows 11 Pro', '10.0.26100.1742', 17179869184, 'tokenhash-dlp-999', '2.5.0')
    `).run(TEST_DEVICE_ID);

    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      const route = matchRoute(req.method, url.pathname);
      if (!route) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'ROUTE_NOT_FOUND', path: url.pathname }));
        return;
      }

      req.query = Object.fromEntries(url.searchParams.entries());
      req.params = route.params;

      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        if (body) {
          try { req.body = JSON.parse(body); } catch { req.body = {}; }
        } else {
          req.body = {};
        }
        route.handler(req, res);
      });
    });

    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise(resolve => server.close(resolve));
    closeDb();
  });

  async function api(path, options = {}) {
    const url = `${baseUrl}${path}`;
    const headers = { ...(options.headers || {}) };
    if (!headers['x-fleet-key'] && !headers['Authorization'] && !options.noAuth) {
      headers['x-fleet-key'] = TEST_FLEET_KEY;
    }
    if (options.body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    const data = await res.json().catch(() => null);
    return { status: res.status, data };
  }

  test('1. GET /api/v1/fleet/dlp/stats returns valid metrics', async () => {
    const res = await api('/api/v1/fleet/dlp/stats');
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.ok(res.data.stats);
    assert.ok(res.data.stats.totalRules >= 4);
    assert.ok(res.data.stats.totalExposures >= 2);
    assert.equal(res.data.stats.dlpOperational, true);
  });

  test('2. GET /api/v1/fleet/dlp/stats rejects unauthenticated requests', async () => {
    const res = await api('/api/v1/fleet/dlp/stats', { noAuth: true });
    assert.equal(res.status, 401);
  });

  test('3. GET /api/v1/fleet/dlp/rules lists seeded classification rules', async () => {
    const res = await api('/api/v1/fleet/dlp/rules');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.rules));
    assert.ok(res.data.count >= 4);
  });

  test('4. GET /api/v1/fleet/dlp/rules?category=FINANCIAL_PCI filters rules by category', async () => {
    const res = await api('/api/v1/fleet/dlp/rules?category=FINANCIAL_PCI');
    assert.equal(res.status, 200);
    assert.ok(res.data.rules.length > 0);
    for (const r of res.data.rules) {
      assert.equal(r.category, 'FINANCIAL_PCI');
    }
  });

  test('5. GET /api/v1/fleet/dlp/rules/:id retrieves single rule', async () => {
    const res = await api('/api/v1/fleet/dlp/rules/dcr-01');
    assert.equal(res.status, 200);
    assert.equal(res.data.rule.id, 'dcr-01');
    assert.equal(res.data.rule.category, 'FINANCIAL_PCI');
  });

  test('6. GET /api/v1/fleet/dlp/rules/:id returns 404 for missing rule', async () => {
    const res = await api('/api/v1/fleet/dlp/rules/dcr-NON-EXISTENT');
    assert.equal(res.status, 404);
  });

  test('7. POST /api/v1/fleet/dlp/rules creates a new classification rule', async () => {
    const payload = {
      rule_name: 'GitHub Personal Access Token (PAT)',
      category: 'SECRETS_CREDENTIALS',
      severity: 'CRITICAL',
      pattern_regex: 'ghp_[A-Za-z0-9]{36}',
      confidence_threshold: 98.0,
      enforcement_action: 'BLOCK'
    };

    const res = await api('/api/v1/fleet/dlp/rules', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.rule.rule_name, 'GitHub Personal Access Token (PAT)');
    assert.equal(res.data.rule.severity, 'CRITICAL');
  });

  test('8. POST /api/v1/fleet/dlp/rules rejects invalid regex', async () => {
    const res = await api('/api/v1/fleet/dlp/rules', {
      method: 'POST',
      body: {
        rule_name: 'Broken Regex Rule',
        pattern_regex: '[unclosed-bracket'
      }
    });
    assert.equal(res.status, 400);
  });

  test('9. POST /api/v1/fleet/dlp/rules rejects missing required fields', async () => {
    const res = await api('/api/v1/fleet/dlp/rules', {
      method: 'POST',
      body: { rule_name: 'Missing pattern' }
    });
    assert.equal(res.status, 400);
  });

  test('10. PUT /api/v1/fleet/dlp/rules/:id updates rule attributes', async () => {
    const listRes = await api('/api/v1/fleet/dlp/rules');
    const target = listRes.data.rules.find(r => r.rule_name === 'GitHub Personal Access Token (PAT)');
    assert.ok(target);

    const res = await api(`/api/v1/fleet/dlp/rules/${target.id}`, {
      method: 'PUT',
      body: {
        enforcement_action: 'ENCRYPT',
        confidence_threshold: 99.5
      }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.rule.enforcement_action, 'ENCRYPT');
    assert.equal(res.data.rule.confidence_threshold, 99.5);
  });

  test('11. DELETE /api/v1/fleet/dlp/rules/:id removes classification rule', async () => {
    const listRes = await api('/api/v1/fleet/dlp/rules');
    const target = listRes.data.rules.find(r => r.rule_name === 'GitHub Personal Access Token (PAT)');
    assert.ok(target);

    const res = await api(`/api/v1/fleet/dlp/rules/${target.id}`, { method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);

    const check = await api(`/api/v1/fleet/dlp/rules/${target.id}`);
    assert.equal(check.status, 404);
  });

  test('12. GET /api/v1/fleet/dlp/findings retrieves file exposures', async () => {
    const res = await api('/api/v1/fleet/dlp/findings');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.findings));
    assert.ok(res.data.count >= 2);
  });

  test('13. GET /api/v1/fleet/dlp/findings?remediation_status=UNENCRYPTED_EXPOSURE filters by status', async () => {
    const res = await api('/api/v1/fleet/dlp/findings?remediation_status=UNENCRYPTED_EXPOSURE');
    assert.equal(res.status, 200);
    assert.ok(res.data.findings.length > 0);
    for (const f of res.data.findings) {
      assert.equal(f.remediation_status, 'UNENCRYPTED_EXPOSURE');
    }
  });

  test('14. POST /api/v1/fleet/dlp/findings records sensitive file finding', async () => {
    const payload = {
      device_id: TEST_DEVICE_ID,
      file_path: 'C:\\Users\\Bob\\Documents\\payroll_december.xlsx',
      file_size_bytes: 524288,
      classification_rule_id: 'dcr-02',
      match_count: 120
    };

    const res = await api('/api/v1/fleet/dlp/findings', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.finding.device_id, TEST_DEVICE_ID);
    assert.equal(res.data.finding.match_count, 120);
  });

  test('15. PUT /api/v1/fleet/dlp/findings/:id updates finding status to SECURED_ENCRYPTED', async () => {
    const findingsRes = await api(`/api/v1/fleet/dlp/findings?device_id=${TEST_DEVICE_ID}`);
    const target = findingsRes.data.findings[0];
    assert.ok(target);

    const res = await api(`/api/v1/fleet/dlp/findings/${target.id}`, {
      method: 'PUT',
      body: { status: 'SECURED_ENCRYPTED' }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.finding.remediation_status, 'SECURED_ENCRYPTED');
    assert.ok(res.data.finding.remediated_at);
  });

  test('16. GET /api/v1/fleet/dlp/incidents retrieves exfiltration telemetry', async () => {
    const res = await api('/api/v1/fleet/dlp/incidents');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.incidents));
    assert.ok(res.data.count >= 2);
  });

  test('17. POST /api/v1/fleet/dlp/incidents logs blocked USB transfer', async () => {
    const payload = {
      device_id: TEST_DEVICE_ID,
      channel: 'REMOVABLE_USB',
      file_or_data_name: 'D:\\SecretProject_SourceCode.zip',
      rule_name: 'Intellectual Property Protection',
      action_taken: 'BLOCKED',
      user_account: 'developer_dan',
      details: { usb_drive_letter: 'E:', serial_id: 'CORP-USB-101' }
    };

    const res = await api('/api/v1/fleet/dlp/incidents', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.incident.channel, 'REMOVABLE_USB');
    assert.equal(res.data.incident.action_taken, 'BLOCKED');
  });

  test('18. POST /api/v1/fleet/dlp/incidents rejects invalid fields', async () => {
    const res = await api('/api/v1/fleet/dlp/incidents', {
      method: 'POST',
      body: { device_id: TEST_DEVICE_ID }
    });
    assert.equal(res.status, 400);
  });

  test('19. POST /api/v1/fleet/dlp/scan-text detects sensitive patterns in text', async () => {
    const sampleText = 'Test payload with Visa: 4111222233334444 and AWS Key: AKIAIOSFODNN7EXAMPLE.';
    const res = await api('/api/v1/fleet/dlp/scan-text', {
      method: 'POST',
      body: { text: sampleText }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.ok(res.data.totalMatched >= 2);
    assert.ok(res.data.matches.some(m => m.category === 'FINANCIAL_PCI'));
    assert.ok(res.data.matches.some(m => m.category === 'SECRETS_CREDENTIALS'));
  });

  test('20. Node agent DLP endpoints operate correctly', async () => {
    // 1. Agent pulls rules
    const rulesRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/dlp/rules`);
    assert.equal(rulesRes.status, 200);
    assert.ok(Array.isArray(rulesRes.data.rules));

    // 2. Agent reports disk scan finding
    const findingRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/dlp/report-finding`, {
      method: 'POST',
      body: {
        file_path: 'C:\\temp\\unencrypted_keys.pem',
        classification_rule_id: 'dcr-03',
        file_size_bytes: 4096
      }
    });
    assert.equal(findingRes.status, 201);
    assert.equal(findingRes.data.success, true);

    // 3. Agent reports intercepted clipboard leak
    const exfilRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/dlp/report-exfiltration`, {
      method: 'POST',
      body: {
        channel: 'CLIPBOARD_PASTE',
        file_or_data_name: 'Clipboard -> Telegram.exe',
        action_taken: 'BLOCKED',
        user_account: 'bob_finance'
      }
    });
    assert.equal(exfilRes.status, 201);
    assert.equal(exfilRes.data.success, true);
  });
});
