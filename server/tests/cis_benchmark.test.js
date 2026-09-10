/**
 * Iteration 58: Endpoint Configuration Drift & CIS Benchmark Compliance Test Suite
 * Module: server/tests/cis_benchmark.test.js
 *
 * Validates:
 * 1. Aggregated CIS compliance metrics (/cis/stats)
 * 2. Fleet key authentication requirement
 * 3. CIS benchmark catalog rules listing (/cis/rules)
 * 4. Profile level filtering (LEVEL_1, LEVEL_2)
 * 5. Single rule retrieval with remediation script
 * 6. 404 response on missing rule
 * 7. Creation of new CIS benchmark rule
 * 8. Validation of missing required parameters
 * 9. Updating rule configuration
 * 10. Deleting rule from catalog
 * 11. Endpoint compliance audits listing (/cis/audits)
 * 12. Drift-based audits filtering
 * 13. Ingesting endpoint compliance audit scorecard
 * 14. Validation error on missing device_id
 * 15. Automated device compliance audit sweep (/cis/evaluate/:deviceId)
 * 16. Querying rule remediation script snippet
 * 17. Creating or updating surgical remediation script
 * 18. Dispatching remediation code to endpoint (/cis/apply-remediation)
 * 19. Error handling on missing remediation targets
 * 20. Node agent CIS endpoints (pull rules, report audit, request remediation)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { CisBenchmarkEngine } from '../src/services/cisBenchmarkEngine.js';

describe('Iteration 58: Endpoint Configuration Drift & CIS Compliance (cis_benchmark.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-cis-58';
  const TEST_DEVICE_ID = 'dev-cis-test-01';

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
      VALUES (?, 'CORP-HARDENED-01', 'SN-CIS-58001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-cis-999', '2.5.0')
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

  test('1. GET /api/v1/fleet/cis/stats returns valid metrics', async () => {
    const res = await api('/api/v1/fleet/cis/stats');
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.ok(res.data.stats);
    assert.ok(res.data.stats.totalRules >= 4);
    assert.ok(res.data.stats.level1Rules >= 3);
    assert.equal(res.data.stats.cisOperational, true);
  });

  test('2. GET /api/v1/fleet/cis/stats rejects unauthenticated requests', async () => {
    const res = await api('/api/v1/fleet/cis/stats', { noAuth: true });
    assert.equal(res.status, 401);
  });

  test('3. GET /api/v1/fleet/cis/rules lists seeded CIS benchmark rules', async () => {
    const res = await api('/api/v1/fleet/cis/rules');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.rules));
    assert.ok(res.data.count >= 4);
    assert.ok(res.data.rules[0].remediation !== undefined);
  });

  test('4. GET /api/v1/fleet/cis/rules?profile_level=LEVEL_1 filters by Level 1', async () => {
    const res = await api('/api/v1/fleet/cis/rules?profile_level=LEVEL_1');
    assert.equal(res.status, 200);
    assert.ok(res.data.rules.length > 0);
    for (const r of res.data.rules) {
      assert.equal(r.profile_level, 'LEVEL_1');
    }
  });

  test('5. GET /api/v1/fleet/cis/rules/:id retrieves single rule with remediation', async () => {
    const res = await api('/api/v1/fleet/cis/rules/cbr-01');
    assert.equal(res.status, 200);
    assert.equal(res.data.rule.id, 'cbr-01');
    assert.equal(res.data.rule.section_id, '18.9.4.1');
    assert.ok(res.data.rule.remediation);
  });

  test('6. GET /api/v1/fleet/cis/rules/:id returns 404 for missing rule', async () => {
    const res = await api('/api/v1/fleet/cis/rules/cbr-NON-EXISTENT');
    assert.equal(res.status, 404);
  });

  test('7. POST /api/v1/fleet/cis/rules creates a new benchmark rule', async () => {
    const payload = {
      section_id: '2.3.7.4',
      title: 'Ensure Interactive logon: Do not display last signed-in user is enabled',
      description: 'Hides previous username on the logon screen to prevent shoulder surfing',
      profile_level: 'LEVEL_1',
      check_type: 'REGISTRY_VALUE',
      target_path: 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
      target_key: 'DontDisplayLastUserName',
      expected_value: '1',
      remediation_impact: 'LOW'
    };

    const res = await api('/api/v1/fleet/cis/rules', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.rule.section_id, '2.3.7.4');
    assert.equal(res.data.rule.expected_value, '1');
  });

  test('8. POST /api/v1/fleet/cis/rules rejects missing required fields', async () => {
    const res = await api('/api/v1/fleet/cis/rules', {
      method: 'POST',
      body: { title: 'Missing Section ID' }
    });
    assert.equal(res.status, 400);
  });

  test('9. PUT /api/v1/fleet/cis/rules/:id updates rule properties', async () => {
    const listRes = await api('/api/v1/fleet/cis/rules');
    const target = listRes.data.rules.find(r => r.section_id === '2.3.7.4');
    assert.ok(target);

    const res = await api(`/api/v1/fleet/cis/rules/${target.id}`, {
      method: 'PUT',
      body: {
        remediation_impact: 'MEDIUM',
        expected_value: '1'
      }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.rule.remediation_impact, 'MEDIUM');
  });

  test('10. DELETE /api/v1/fleet/cis/rules/:id deletes rule from catalog', async () => {
    const listRes = await api('/api/v1/fleet/cis/rules');
    const target = listRes.data.rules.find(r => r.section_id === '2.3.7.4');
    assert.ok(target);

    const res = await api(`/api/v1/fleet/cis/rules/${target.id}`, { method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);

    const check = await api(`/api/v1/fleet/cis/rules/${target.id}`);
    assert.equal(check.status, 404);
  });

  test('11. GET /api/v1/fleet/cis/audits retrieves compliance evaluations', async () => {
    const res = await api('/api/v1/fleet/cis/audits');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.audits));
    assert.ok(res.data.count >= 1);
  });

  test('12. GET /api/v1/fleet/cis/audits?drift_detected=true filters drifted endpoints', async () => {
    const res = await api('/api/v1/fleet/cis/audits?drift_detected=true');
    assert.equal(res.status, 200);
    assert.ok(res.data.audits.length > 0);
    for (const a of res.data.audits) {
      assert.equal(a.drift_detected, 1);
    }
  });

  test('13. POST /api/v1/fleet/cis/audits ingests compliance scorecard', async () => {
    const payload = {
      device_id: TEST_DEVICE_ID,
      benchmark_name: 'CIS_WINDOWS_11_ENTERPRISE',
      total_rules_evaluated: 10,
      passed_rules_count: 9,
      failed_rules_count: 1,
      findings_summary: { failed: ['cbr-02'] }
    };

    const res = await api('/api/v1/fleet/cis/audits', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.audit.device_id, TEST_DEVICE_ID);
    assert.equal(res.data.audit.compliance_score_percent, 90.0);
    assert.equal(res.data.audit.drift_detected, 1);
  });

  test('14. POST /api/v1/fleet/cis/audits rejects missing device_id', async () => {
    const res = await api('/api/v1/fleet/cis/audits', {
      method: 'POST',
      body: { total_rules_evaluated: 5 }
    });
    assert.equal(res.status, 400);
  });

  test('15. POST /api/v1/fleet/cis/evaluate/:deviceId runs automated compliance sweep', async () => {
    const res = await api(`/api/v1/fleet/cis/evaluate/${TEST_DEVICE_ID}`, {
      method: 'POST'
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.ok(res.data.audit.total_rules_evaluated >= 4);
    assert.ok(res.data.audit.compliance_score_percent >= 50);
  });

  test('16. GET /api/v1/fleet/cis/remediations/:ruleId retrieves script snippet', async () => {
    const res = await api('/api/v1/fleet/cis/remediations/cbr-01');
    assert.equal(res.status, 200);
    assert.equal(res.data.remediation.rule_id, 'cbr-01');
    assert.ok(res.data.remediation.remediation_code.includes('EnableSmartScreen'));
  });

  test('17. POST /api/v1/fleet/cis/remediations creates or links remediation code', async () => {
    const payload = {
      rule_id: 'cbr-03',
      script_type: 'POWERSHELL',
      remediation_code: 'Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force',
      reboot_required: false
    };

    const res = await api('/api/v1/fleet/cis/remediations', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.remediation.rule_id, 'cbr-03');
  });

  test('18. POST /api/v1/fleet/cis/apply-remediation dispatches surgical code to endpoint', async () => {
    const res = await api('/api/v1/fleet/cis/apply-remediation', {
      method: 'POST',
      body: {
        device_id: TEST_DEVICE_ID,
        rule_id: 'cbr-01'
      }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.equal(res.data.result.dispatched, true);
    assert.ok(res.data.result.remediationCode);
  });

  test('19. POST /api/v1/fleet/cis/apply-remediation handles invalid IDs safely', async () => {
    const res = await api('/api/v1/fleet/cis/apply-remediation', {
      method: 'POST',
      body: {
        device_id: 'non-existent-device',
        rule_id: 'cbr-01'
      }
    });
    assert.equal(res.status, 400);
  });

  test('20. Node agent CIS endpoints operate correctly', async () => {
    // 1. Agent pulls rules
    const rulesRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/cis/benchmarks`);
    assert.equal(rulesRes.status, 200);
    assert.ok(Array.isArray(rulesRes.data.rules));

    // 2. Agent reports scorecard
    const auditRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/cis/report-audit`, {
      method: 'POST',
      body: {
        benchmark_name: 'CIS_WINDOWS_11_ENTERPRISE',
        total_rules_evaluated: 4,
        passed_rules_count: 4,
        failed_rules_count: 0
      }
    });
    assert.equal(auditRes.status, 201);
    assert.equal(auditRes.data.success, true);
    assert.equal(auditRes.data.audit.compliance_score_percent, 100.0);

    // 3. Agent requests remediation for a drifted rule
    const remRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/cis/request-remediation`, {
      method: 'POST',
      body: { rule_id: 'cbr-02' }
    });
    assert.equal(remRes.status, 200);
    assert.equal(remRes.data.success, true);
    assert.ok(remRes.data.result.remediationCode);
  });
});
