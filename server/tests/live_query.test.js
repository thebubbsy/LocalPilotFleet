import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { LiveQueryEngine } from '../src/services/liveQueryEngine.js';

describe('Live Distributed Fleet Query (CMPivot / Tanium) QA (live_query.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-query-key-12345';

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

    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const routeMatch = matchRoute(req.method, url.pathname);
      if (!routeMatch) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NOT_FOUND' }));
        return;
      }
      req.params = routeMatch.params;
      req.query = Object.fromEntries(url.searchParams.entries());

      let bodyStr = '';
      req.on('data', chunk => { bodyStr += chunk; });
      req.on('end', () => {
        try {
          req.body = bodyStr ? JSON.parse(bodyStr) : {};
        } catch {
          req.body = {};
        }
        routeMatch.handler(req, res);
      });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) await new Promise(resolve => server.close(resolve));
    closeDb();
  });

  async function apiRequest(path, options = {}) {
    const headers = {
      'x-fleet-key': TEST_FLEET_KEY,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    const res = await fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: res.status, data };
  }

  test('QUERY-01: GET /api/v1/fleet/queries/stats returns baseline live query metrics', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/stats');
    assert.equal(res.status, 200);
    assert.ok(res.data.totalSessions >= 1);
    assert.ok(res.data.availableSensors >= 5);
    assert.equal(res.data.sub3SecondResponseGuarantee, true);
  });

  test('QUERY-02: GET /api/v1/fleet/queries/entities returns CMPivot sensor catalog', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/entities');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.entities));
    const names = res.data.entities.map(e => e.entity_name);
    assert.ok(names.includes('ProcessList'));
    assert.ok(names.includes('ServiceList'));
    assert.ok(names.includes('Registry'));
  });

  test('QUERY-03: Filtering entities by category returns matching sensors', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/entities?category=System%20Services');
    assert.equal(res.status, 200);
    assert.ok(res.data.entities.length >= 1);
    assert.equal(res.data.entities[0].category, 'System Services');
  });

  test('QUERY-04: POST /api/v1/fleet/queries/sessions dispatches a live query session', async () => {
    const payload = {
      query_text: 'ProcessList | where WorkingSetMB > 100',
      query_type: 'CMPIVOT_KQL',
      target_scope: 'ALL_FLEET',
      initiated_by: 'SecOps Analyst'
    };
    const res = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: payload
    });
    assert.equal(res.status, 201);
    assert.ok(res.data.id.startsWith('qry-'));
    assert.equal(res.data.status, 'STREAMING');
    assert.equal(res.data.query_text, payload.query_text);
  });

  test('QUERY-05: POST /api/v1/fleet/queries/sessions rejects missing query_text with 400', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: {}
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'QUERY_DISPATCH_ERROR');
  });

  test('QUERY-06: GET /api/v1/fleet/queries/sessions/:id retrieves session details', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions/qry-default-process-audit');
    assert.equal(res.status, 200);
    assert.equal(res.data.id, 'qry-default-process-audit');
    assert.equal(res.data.status, 'COMPLETED');
    assert.equal(res.data.completion_percent, 100);
  });

  test('QUERY-07: GET /api/v1/fleet/queries/sessions lists all query sessions', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.sessions));
    assert.ok(res.data.sessions.length >= 2);
  });

  test('QUERY-08: POST /api/v1/nodes/:id/queries/:queryId/results ingests endpoint results', async () => {
    // Create new session first
    const createRes = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: {
        query_text: 'ServiceList | where State == "Running"',
        target_scope: 'DEVICE',
        target_id: 'DESKTOP-R0H12DJ'
      }
    });
    const qid = createRes.data.id;

    const ingestRes = await apiRequest(`/api/v1/nodes/DESKTOP-R0H12DJ/queries/${qid}/results`, {
      method: 'POST',
      body: {
        hostname: 'DESKTOP-R0H12DJ',
        duration_ms: 280,
        data_rows: [
          { Name: 'wuauserv', DisplayName: 'Windows Update', Status: 'Running' },
          { Name: 'WinDefend', DisplayName: 'Microsoft Defender Antivirus Service', Status: 'Running' }
        ]
      }
    });

    assert.equal(ingestRes.status, 200);
    assert.equal(ingestRes.data.rows_ingested, 2);
    assert.equal(ingestRes.data.status, 'COMPLETED');
  });

  test('QUERY-09: GET /api/v1/fleet/queries/sessions/:id/results retrieves parsed tabular rows', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions/qry-default-process-audit/results');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.results));
    assert.equal(res.data.results.length, 1);
    assert.equal(res.data.results[0].data.ProcessName, 'node');
  });

  test('QUERY-10: Ingesting results for unknown session returns 400', async () => {
    const res = await apiRequest('/api/v1/nodes/DESKTOP-UNKNOWN/queries/nonexistent-query-id/results', {
      method: 'POST',
      body: { data_rows: [{ test: 1 }] }
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error, 'QUERY_INGEST_ERROR');
  });

  test('QUERY-11: POST /api/v1/fleet/queries/sessions/:id/cancel cancels query session', async () => {
    const createRes = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: { query_text: 'Registry("HKLM\\SOFTWARE\\...")' }
    });
    const qid = createRes.data.id;

    const cancelRes = await apiRequest(`/api/v1/fleet/queries/sessions/${qid}/cancel`, {
      method: 'POST'
    });
    assert.equal(cancelRes.status, 200);
    assert.equal(cancelRes.data.success, true);

    const getRes = await apiRequest(`/api/v1/fleet/queries/sessions/${qid}`);
    assert.equal(getRes.data.status, 'CANCELLED');
  });

  test('QUERY-12: Ingesting results after session cancellation is rejected gracefully', async () => {
    const createRes = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: { query_text: 'ProcessList' }
    });
    const qid = createRes.data.id;

    await apiRequest(`/api/v1/fleet/queries/sessions/${qid}/cancel`, { method: 'POST' });

    const ingestRes = await apiRequest(`/api/v1/nodes/DESKTOP-R0H12DJ/queries/${qid}/results`, {
      method: 'POST',
      body: { data_rows: [{ ProcessName: 'powershell' }] }
    });
    assert.equal(ingestRes.status, 200);
    assert.equal(ingestRes.data.status, 'CANCELLED');
  });

  test('QUERY-13: GET /api/v1/fleet/queries/sessions/:id/export generates valid CSV', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions/qry-default-process-audit/export');
    assert.equal(res.status, 200);
    assert.ok(typeof res.data === 'string');
    assert.ok(res.data.includes('DeviceID,Hostname,DurationMS,ReceivedAt'));
    assert.ok(res.data.includes('"DESKTOP-R0H12DJ"'));
    assert.ok(res.data.includes('"node"'));
  });

  test('QUERY-14: Empty results session export returns valid header-only CSV', async () => {
    const createRes = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: { query_text: 'EmptyQuery' }
    });
    const qid = createRes.data.id;

    const res = await apiRequest(`/api/v1/fleet/queries/sessions/${qid}/export`);
    assert.equal(res.status, 200);
    assert.ok(res.data.startsWith('DeviceID,Hostname,Timestamp,Result'));
  });

  test('QUERY-15: Security rejection — request without fleet key returns 401', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/queries/stats`);
    assert.equal(res.status, 401);
  });

  test('QUERY-16: Targeting specific device sets total_targets to 1', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: {
        query_text: 'CimInstance("Win32_Bios")',
        target_scope: 'DEVICE',
        target_id: 'DESKTOP-R0H12DJ'
      }
    });
    assert.equal(res.status, 201);
    assert.equal(res.data.target_scope, 'DEVICE');
    assert.equal(res.data.target_id, 'DESKTOP-R0H12DJ');
    assert.equal(res.data.total_targets, 1);
  });

  test('QUERY-17: Batch rows ingestion handles multiple records seamlessly', async () => {
    const createRes = await apiRequest('/api/v1/fleet/queries/sessions', {
      method: 'POST',
      body: { query_text: 'ActiveNetworkConnections' }
    });
    const qid = createRes.data.id;

    const rows = [
      { LocalPort: 8443, State: 'Listen', OwningProcess: 1904 },
      { LocalPort: 443, State: 'Established', OwningProcess: 2400 },
      { LocalPort: 53, State: 'Listen', OwningProcess: 800 }
    ];

    const ingestRes = await apiRequest(`/api/v1/nodes/DESKTOP-R0H12DJ/queries/${qid}/results`, {
      method: 'POST',
      body: { data_rows: rows, duration_ms: 120 }
    });
    assert.equal(ingestRes.data.rows_ingested, 3);

    const getRes = await apiRequest(`/api/v1/fleet/queries/sessions/${qid}/results`);
    assert.equal(getRes.data.results.length, 3);
  });

  test('QUERY-18: Query completion percentage is correctly computed', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions/qry-default-process-audit');
    assert.equal(res.data.completion_percent, 100);
  });

  test('QUERY-19: Average query execution latency is tracked in stats', async () => {
    const stats = await apiRequest('/api/v1/fleet/queries/stats');
    assert.ok(stats.data.averageExecutionLatencyMs > 0);
  });

  test('QUERY-20: GET /api/v1/fleet/queries/sessions/:id returns 404 for unknown session', async () => {
    const res = await apiRequest('/api/v1/fleet/queries/sessions/unknown-id-xyz');
    assert.equal(res.status, 404);
    assert.equal(res.data.error, 'SESSION_NOT_FOUND');
  });
});
