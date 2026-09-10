/**
 * Iteration 53: EDR Incident Correlation & Multi-Stage Attack Storyline Test Suite
 * Module: server/tests/incident_correlation.test.js
 *
 * Validates:
 * 1. Incident statistics & fleet-wide mean risk scores (/incidents/stats)
 * 2. Security Incident case management (CRUD, status, severity, classification)
 * 3. Cross-module alert aggregation & associations (M:N mappings)
 * 4. Chronological kill-chain attack timeline milestones & MITRE ATT&CK techniques
 * 5. Attack storyline process graph synthesis
 * 6. Automated cross-signal correlation engine synthesizing alerts into unified cases
 * 7. Incident closure, root cause attribution, and remediation audit records
 * 8. Node agent endpoints for incident queries and correlation sweeps
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { IncidentCorrelationEngine } from '../src/services/incidentCorrelationEngine.js';

describe('Iteration 53: EDR Incident Correlation (incident_correlation.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-inc-53';
  const TEST_DEVICE_ID = 'dev-inc-test-01';

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
      VALUES (?, 'DESKTOP-INC-01', 'SN-INC-53001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-inc-999', '2.5.0')
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
    if (server) await new Promise(resolve => server.close(resolve));
    closeDb();
  });

  async function apiRequest(endpoint, options = {}) {
    const url = `${baseUrl}${endpoint}`;
    const headers = {
      'x-fleet-key': TEST_FLEET_KEY,
      'content-type': 'application/json',
      ...(options.headers || {})
    };
    const res = await fetch(url, { ...options, headers });
    const isJson = res.headers.get('content-type')?.includes('application/json');
    const data = isJson ? await res.json() : await res.text();
    return { status: res.status, data };
  }

  // 1. GET /api/v1/fleet/incidents/stats
  test('1. GET /api/v1/fleet/incidents/stats returns aggregated metrics', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalIncidents, 'number');
    assert.equal(typeof data.activeIncidents, 'number');
    assert.equal(typeof data.totalAssociatedAlerts, 'number');
    assert.ok(data.meanRiskScore >= 0 && data.meanRiskScore <= 100);
  });

  // 2. GET /api/v1/fleet/incidents
  test('2. GET /api/v1/fleet/incidents retrieves list of incident cases', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.incidents));
    assert.ok(data.count >= 1);
    assert.ok(Array.isArray(data.incidents[0].attack_storyline));
  });

  // 3. POST /api/v1/fleet/incidents
  test('3. POST /api/v1/fleet/incidents creates a new incident case', async () => {
    const payload = {
      title: 'Active Ransomware Staging Attempt',
      description: 'Shadow copy deletion and bulk file rename operations detected',
      severity: 'CRITICAL',
      risk_score: 95,
      primary_device_id: TEST_DEVICE_ID,
      assigned_analyst: 'Tier 3 Hunter Bob',
      mitre_tactics: ['Impact', 'Defense Evasion']
    };
    const { status, data } = await apiRequest('/api/v1/fleet/incidents', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.incident.title, payload.title);
    assert.equal(data.incident.severity, 'CRITICAL');
    assert.equal(data.incident.risk_score, 95);
  });

  // 4. POST /api/v1/fleet/incidents validation error
  test('4. POST /api/v1/fleet/incidents returns 400 when title or device is missing', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents', {
      method: 'POST',
      body: JSON.stringify({ severity: 'HIGH' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 5. GET /api/v1/fleet/incidents/:id
  test('5. GET /api/v1/fleet/incidents/:id retrieves incident with alerts and timeline', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001');
    assert.equal(status, 200);
    assert.equal(data.id, 'inc-2026-001');
    assert.ok(Array.isArray(data.alerts));
    assert.ok(Array.isArray(data.timeline));
    assert.ok(data.alerts.length >= 3);
    assert.ok(data.timeline.length >= 4);
  });

  // 6. PATCH /api/v1/fleet/incidents/:id
  test('6. PATCH /api/v1/fleet/incidents/:id updates incident details', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001', {
      method: 'PATCH',
      body: JSON.stringify({ status: 'UNDER_INVESTIGATION', assigned_analyst: 'Senior Analyst Dave' })
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
    assert.equal(data.incident.status, 'UNDER_INVESTIGATION');
    assert.equal(data.incident.assigned_analyst, 'Senior Analyst Dave');
  });

  // 7. POST /api/v1/fleet/incidents/:id/close
  test('7. POST /api/v1/fleet/incidents/:id/close resolves incident and adds remediation milestone', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/close', {
      method: 'POST',
      body: JSON.stringify({
        resolution: 'RESOLVED',
        classification: 'TRUE_POSITIVE',
        rootCause: 'Phishing macro dropped Trojan neutralized and uninstalled',
        notes: 'Verified clean by SecOps team'
      })
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
    assert.equal(data.incident.status, 'RESOLVED');
    assert.equal(data.incident.classification, 'TRUE_POSITIVE');

    // Verify remediation milestone added
    const remMilestone = data.incident.timeline.find(m => m.phase_name === 'REMEDIATION');
    assert.ok(remMilestone);
  });

  // 8. GET /api/v1/fleet/incidents/:id/alerts
  test('8. GET /api/v1/fleet/incidents/:id/alerts retrieves associated alerts', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/alerts');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.alerts));
    assert.ok(data.count >= 3);
  });

  // 9. POST /api/v1/fleet/incidents/:id/alerts
  test('9. POST /api/v1/fleet/incidents/:id/alerts associates an alert', async () => {
    const payload = {
      alert_source: 'USB_CONTROL',
      alert_id: 'pae-usb-099',
      alert_summary: 'Blocked unauthorized USB mass storage insertion during active incident'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/alerts', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.association.alert_source, 'USB_CONTROL');
  });

  // 10. POST alerts validation error
  test('10. POST /api/v1/fleet/incidents/:id/alerts returns 400 on missing fields', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/alerts', {
      method: 'POST',
      body: JSON.stringify({ alert_source: 'USB_CONTROL' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 11. GET /api/v1/fleet/incidents/:id/timeline
  test('11. GET /api/v1/fleet/incidents/:id/timeline retrieves chronological milestones', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/timeline');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.timeline));
    assert.ok(data.count >= 4);
  });

  // 12. POST /api/v1/fleet/incidents/:id/timeline
  test('12. POST /api/v1/fleet/incidents/:id/timeline adds a kill-chain milestone', async () => {
    const payload = {
      phase_name: 'CREDENTIAL_ACCESS',
      milestone_title: 'LSASS Memory Dump Intercepted',
      details: 'ProcDump attempted against lsass.exe',
      evidence_artifact: 'procdump.exe',
      mitre_technique_id: 'T1003.001'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/timeline', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.milestone.phase_name, 'CREDENTIAL_ACCESS');
    assert.equal(data.milestone.mitre_technique_id, 'T1003.001');
  });

  // 13. POST timeline validation error
  test('13. POST /api/v1/fleet/incidents/:id/timeline returns 400 on missing fields', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/timeline', {
      method: 'POST',
      body: JSON.stringify({ phase_name: 'EXECUTION' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 14. GET /api/v1/fleet/incidents/:id/storyline
  test('14. GET /api/v1/fleet/incidents/:id/storyline synthesizes attack graph nodes', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/incidents/inc-2026-001/storyline');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.storyline));
    assert.ok(data.nodes >= 4);
    assert.ok(data.storyline[0].nodeId.startsWith('node-'));
  });

  // 15. POST /api/v1/fleet/incidents/correlate/:deviceId
  test('15. POST /api/v1/fleet/incidents/correlate/:deviceId correlates multi-signal alerts', async () => {
    // Seed an event for TEST_DEVICE_ID
    db.prepare(`
      INSERT INTO security_events (device_id, event_type, event_id, event_source, severity, summary, raw_payload_json)
      VALUES (?, 'MALWARE_THREAT_DETECTED', 9901, 'CORRELATION_TEST', 'HIGH', 'Test suspicious script activity', '{}')
    `).run(TEST_DEVICE_ID);

    const { status, data } = await apiRequest(`/api/v1/fleet/incidents/correlate/${TEST_DEVICE_ID}`, {
      method: 'POST'
    });
    assert.equal(status, 200);
    assert.equal(data.correlated, true);
    assert.ok(data.incident);
    assert.equal(data.incident.primary_device_id, TEST_DEVICE_ID);
  });

  // 16. GET /api/v1/nodes/:id/incidents
  test('16. GET /api/v1/nodes/:id/incidents retrieves incidents for node agent', async () => {
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/incidents`);
    assert.equal(status, 200);
    assert.equal(data.device_id, TEST_DEVICE_ID);
    assert.ok(Array.isArray(data.incidents));
  });

  // 17. POST /api/v1/nodes/:id/incidents/trigger-correlation
  test('17. POST /api/v1/nodes/:id/incidents/trigger-correlation allows agent sweep', async () => {
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/incidents/trigger-correlation`, {
      method: 'POST'
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
    assert.ok(data.result);
  });

  // 18. Filtering by severity and status
  test('18. IncidentCorrelationEngine.getIncidents filters by status and severity', () => {
    const criticals = IncidentCorrelationEngine.getIncidents(db, { severity: 'CRITICAL' });
    assert.ok(Array.isArray(criticals));
    for (const c of criticals) {
      assert.equal(c.severity, 'CRITICAL');
    }
  });

  // 19. False positive incident closure
  test('19. IncidentCorrelationEngine.closeIncident handles FALSE_POSITIVE classification', () => {
    const inc = IncidentCorrelationEngine.createIncident(db, {
      title: 'False Alarm Canary',
      primary_device_id: TEST_DEVICE_ID,
      severity: 'LOW'
    });
    const closed = IncidentCorrelationEngine.closeIncident(db, inc.id, {
      resolution: 'FALSE_POSITIVE',
      classification: 'FALSE_POSITIVE',
      notes: 'Benign backup utility triggered heuristic'
    });
    assert.equal(closed.status, 'FALSE_POSITIVE');
    assert.equal(closed.classification, 'FALSE_POSITIVE');
  });

  // 20. Automatic storyline synthesis contains node structure
  test('20. IncidentCorrelationEngine.generateAttackStorylineJson returns structured nodes', () => {
    const nodes = IncidentCorrelationEngine.generateAttackStorylineJson(db, 'inc-2026-001');
    assert.ok(Array.isArray(nodes));
    assert.ok(nodes.length > 0);
    assert.ok(nodes[0].phase);
    assert.ok(nodes[0].title);
  });
});
