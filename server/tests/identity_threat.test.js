/**
 * Iteration 56: Identity Threat Detection & Response (ITDR) Test Suite
 * Module: server/tests/identity_threat.test.js
 *
 * Validates:
 * 1. Aggregated ITDR metrics and statistics (/itdr/stats)
 * 2. Fleet key authentication requirement
 * 3. Identity threat detections listing (/itdr/detections)
 * 4. Attack vector filtering (KERBEROASTING, DCSYNC, LSASS_MEMORY_DUMP, etc.)
 * 5. Status filtering (NEW, INVESTIGATING, CONTAINED)
 * 6. Single detection retrieval with parsed evidence
 * 7. 404 response on missing detection ID
 * 8. Recording new credential theft detection
 * 9. Validation of attack vector on creation
 * 10. Updating detection status to INVESTIGATING
 * 11. Updating detection status to CONTAINED with remediation action
 * 12. Automated account containment action (/itdr/contain-account)
 * 13. Honeytokens catalog listing (/itdr/honeytokens)
 * 14. Creating new deception honeytoken asset
 * 15. Validation of required fields on honeytoken creation
 * 16. Honeytoken tripwire activation and auto-detection logging
 * 17. Deleting honeytoken from catalog
 * 18. Account risk profiles listing (/itdr/accounts)
 * 19. Account risk assessment recalculation (/itdr/accounts/:name/assess)
 * 20. Node agent ITDR endpoints (pull honeytokens, report tripwire, report theft)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { IdentityThreatEngine } from '../src/services/identityThreatEngine.js';

describe('Iteration 56: Identity Threat Detection & Response (identity_threat.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-itdr-56';
  const TEST_DEVICE_ID = 'dev-itdr-test-01';

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
      VALUES (?, 'DC-PRIMARY-01', 'SN-ITDR-56001', 'Windows Server 2025 Datacenter', '10.0.26100.1742', 34359738368, 'tokenhash-itdr-999', '2.5.0')
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

  test('1. GET /api/v1/fleet/itdr/stats returns valid ITDR metrics', async () => {
    const res = await api('/api/v1/fleet/itdr/stats');
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.ok(res.data.stats);
    assert.ok(res.data.stats.totalDetections >= 3);
    assert.ok(res.data.stats.totalHoneytokens >= 2);
    assert.equal(res.data.stats.itdrOperational, true);
  });

  test('2. GET /api/v1/fleet/itdr/stats rejects unauthenticated requests', async () => {
    const res = await api('/api/v1/fleet/itdr/stats', { noAuth: true });
    assert.equal(res.status, 401);
  });

  test('3. GET /api/v1/fleet/itdr/detections retrieves seeded attack events', async () => {
    const res = await api('/api/v1/fleet/itdr/detections');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.detections));
    assert.ok(res.data.count >= 3);
  });

  test('4. GET /api/v1/fleet/itdr/detections?attack_vector=KERBEROASTING filters accurately', async () => {
    const res = await api('/api/v1/fleet/itdr/detections?attack_vector=KERBEROASTING');
    assert.equal(res.status, 200);
    assert.ok(res.data.detections.length > 0);
    for (const d of res.data.detections) {
      assert.equal(d.attack_vector, 'KERBEROASTING');
    }
  });

  test('5. GET /api/v1/fleet/itdr/detections?status=NEW filters by status', async () => {
    const res = await api('/api/v1/fleet/itdr/detections?status=NEW');
    assert.equal(res.status, 200);
    assert.ok(res.data.detections.length > 0);
    for (const d of res.data.detections) {
      assert.equal(d.status, 'NEW');
    }
  });

  test('6. GET /api/v1/fleet/itdr/detections/:id retrieves single detection with parsed evidence', async () => {
    const res = await api('/api/v1/fleet/itdr/detections/itd-01');
    assert.equal(res.status, 200);
    assert.equal(res.data.detection.id, 'itd-01');
    assert.equal(res.data.detection.target_account, 'svc_sql_reporting');
    assert.ok(res.data.detection.evidence);
  });

  test('7. GET /api/v1/fleet/itdr/detections/:id returns 404 for non-existent detection', async () => {
    const res = await api('/api/v1/fleet/itdr/detections/itd-NON-EXISTENT');
    assert.equal(res.status, 404);
  });

  test('8. POST /api/v1/fleet/itdr/detections records new DCSync detection', async () => {
    const payload = {
      target_account: 'krbtgt',
      source_host: 'WORKSTATION-EVIL-01',
      source_ip: '10.0.0.99',
      attack_vector: 'DCSYNC',
      evidence: {
        replication_guid: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        process_name: 'mimikatz.exe',
        requested_domain: 'LOCALPILOT.CORP'
      }
    };

    const res = await api('/api/v1/fleet/itdr/detections', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.detection.target_account, 'krbtgt');
    assert.equal(res.data.detection.attack_vector, 'DCSYNC');
    assert.ok(res.data.detection.risk_score >= 90);
  });

  test('9. POST /api/v1/fleet/itdr/detections rejects invalid attack vector', async () => {
    const res = await api('/api/v1/fleet/itdr/detections', {
      method: 'POST',
      body: {
        target_account: 'alice',
        source_host: 'WS-01',
        attack_vector: 'INVALID_ATTACK_TYPE'
      }
    });
    assert.equal(res.status, 400);
  });

  test('10. PATCH /api/v1/fleet/itdr/detections/:id updates status to INVESTIGATING', async () => {
    const res = await api('/api/v1/fleet/itdr/detections/itd-01', {
      method: 'PATCH',
      body: { status: 'INVESTIGATING' }
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.detection.status, 'INVESTIGATING');
  });

  test('11. PATCH /api/v1/fleet/itdr/detections/:id updates status to CONTAINED with notes', async () => {
    const res = await api('/api/v1/fleet/itdr/detections/itd-01', {
      method: 'PATCH',
      body: {
        status: 'CONTAINED',
        remediation_notes: 'Service account SPN removed and AES256 forced'
      }
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.detection.status, 'CONTAINED');
    assert.ok(res.data.detection.resolved_at);
  });

  test('12. POST /api/v1/fleet/itdr/contain-account executes automated containment', async () => {
    const res = await api('/api/v1/fleet/itdr/contain-account', {
      method: 'POST',
      body: {
        account_name: 'svc_sql_reporting',
        action: 'ACCOUNT_LOCKED',
        notes: 'Locked by SecOps after Kerberoasting interception'
      }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.equal(res.data.account.containment_status, 'ACCOUNT_LOCKED');
  });

  test('13. GET /api/v1/fleet/itdr/honeytokens retrieves seeded deception assets', async () => {
    const res = await api('/api/v1/fleet/itdr/honeytokens');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.honeytokens));
    assert.ok(res.data.count >= 2);
  });

  test('14. POST /api/v1/fleet/itdr/honeytokens creates a new honeytoken trap', async () => {
    const payload = {
      honeytoken_type: 'FAKE_SPN_SERVICE',
      account_name: 'svc_printer_decoy',
      domain_name: 'LOCALPILOT.CORP',
      spn: 'print/corp-prn01.localpilot.corp',
      description: 'Decoy printer SPN with weak RC4 encryption ticket'
    };

    const res = await api('/api/v1/fleet/itdr/honeytokens', {
      method: 'POST',
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.success, true);
    assert.equal(res.data.honeytoken.account_name, 'svc_printer_decoy');
    assert.equal(res.data.honeytoken.is_active, 1);
  });

  test('15. POST /api/v1/fleet/itdr/honeytokens rejects missing required parameters', async () => {
    const res = await api('/api/v1/fleet/itdr/honeytokens', {
      method: 'POST',
      body: { account_name: 'only_name' }
    });
    assert.equal(res.status, 400);
  });

  test('16. POST /api/v1/fleet/itdr/honeytokens/:id/trigger trips wire and logs critical detection', async () => {
    const res = await api('/api/v1/fleet/itdr/honeytokens/ihc-01/trigger', {
      method: 'POST',
      body: {
        trigger_host: 'WORKSTATION-ATTACKER',
        attacker_ip: '192.168.1.188',
        details: { logon_type: 3, client_name: 'ATTACKER-BOX' }
      }
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.equal(res.data.triggered, true);
    assert.ok(res.data.honeytoken.trigger_count >= 1);
    assert.equal(res.data.detection.attack_vector, 'HONEYTOKEN_TRIGGERED');
    assert.equal(res.data.detection.risk_score, 99.0);
  });

  test('17. DELETE /api/v1/fleet/itdr/honeytokens/:id removes honeytoken from catalog', async () => {
    const listRes = await api('/api/v1/fleet/itdr/honeytokens');
    const createdToken = listRes.data.honeytokens.find(h => h.account_name === 'svc_printer_decoy');
    assert.ok(createdToken);

    const delRes = await api(`/api/v1/fleet/itdr/honeytokens/${createdToken.id}`, { method: 'DELETE' });
    assert.equal(delRes.status, 200);
    assert.equal(delRes.data.success, true);
  });

  test('18. GET /api/v1/fleet/itdr/accounts retrieves risk profiles', async () => {
    const res = await api('/api/v1/fleet/itdr/accounts');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.accounts));
    assert.ok(res.data.count >= 3);
  });

  test('19. POST /api/v1/fleet/itdr/accounts/:name/assess recalculates account risk', async () => {
    const res = await api('/api/v1/fleet/itdr/accounts/Administrator/assess', {
      method: 'POST'
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.success, true);
    assert.equal(res.data.account.account_name, 'Administrator');
    assert.ok(res.data.account.risk_score !== undefined);
  });

  test('20. Node agent ITDR endpoints operate as expected', async () => {
    // 1. Node queries honeytokens to plant
    const tokensRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/itdr/honeytokens`);
    assert.equal(tokensRes.status, 200);
    assert.ok(Array.isArray(tokensRes.data.honeytokens));

    // 2. Node reports local tripwire
    const tripwireRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/itdr/report-tripwire`, {
      method: 'POST',
      body: {
        account_name: 'DA_Honeytoken_Alpha',
        attacker_ip: '10.0.0.50',
        details: { event_id: 4625, failure_reason: 'Bad password' }
      }
    });
    assert.equal(tripwireRes.status, 201);
    assert.equal(tripwireRes.data.success, true);

    // 3. Node reports local credential theft attempt (LSASS access)
    const theftRes = await api(`/api/v1/nodes/${TEST_DEVICE_ID}/itdr/report-credential-theft`, {
      method: 'POST',
      body: {
        target_account: 'LOCAL_SYSTEM',
        attack_vector: 'LSASS_MEMORY_DUMP',
        risk_score: 95.0,
        evidence: { caller_image: 'c:\temp\mimikatz.exe', target_pid: 684 }
      }
    });
    assert.equal(theftRes.status, 201);
    assert.equal(theftRes.data.success, true);
    assert.equal(theftRes.data.detection.attack_vector, 'LSASS_MEMORY_DUMP');
  });
});
