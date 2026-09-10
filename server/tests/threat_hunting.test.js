/**
 * Iteration 46: Distributed Threat Hunting & IoC Sweeper Test Suite
 * Validates YARA pattern matching, Sigma rules, file hash sweeps, and automated containment.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { ThreatHuntingEngine } from '../src/services/threatHuntingEngine.js';

describe('Iteration 46: Distributed Threat Hunting & IoC Sweeper (threat_hunting.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-hunt-46';
  const TEST_DEVICE_ID = 'dev-hunt-test-01';
  let createdHuntId;
  let createdIocId;

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

    // Ensure sample device exists
    db.prepare(`
      INSERT OR REPLACE INTO devices (id, hostname, serial_number, os_name, os_version, total_ram_bytes, node_token_hash, agent_version)
      VALUES (?, 'DESKTOP-HUNT-01', 'SN-HUNT-46001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-hunt-999', '2.5.0')
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

  test('HUNT-01: GET /api/v1/fleet/hunting/stats returns baseline hunting metrics and active IoCs', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalCampaigns, 'number');
    assert.equal(typeof data.activeCampaigns, 'number');
    assert.equal(typeof data.activeWatchlistIndicators, 'number');
    assert.equal(data.subSecondSweepSla, true);
  });

  test('HUNT-02: GET /api/v1/fleet/hunting/campaigns returns seeded campaigns', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/campaigns');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.campaigns));
    assert.ok(data.campaigns.length >= 1);
    const cs = data.campaigns.find(c => c.id === 'hunt-cobalt-strike-beacon');
    assert.ok(cs, 'Should find seeded Cobalt Strike hunt');
    assert.equal(cs.hunt_type, 'YARA_SCAN');
    assert.equal(cs.action_on_match, 'CONTAIN_HOST');
  });

  test('HUNT-03: POST /api/v1/fleet/hunting/campaigns launches a new YARA hunt campaign', async () => {
    const newHunt = {
      name: 'BlackCat / ALPHV Ransomware Binary Sweeper',
      description: 'Scans for BlackCat Rust-compiled encryption routines and privilege escalation drops',
      hunt_type: 'YARA_SCAN',
      pattern_definition: 'rule BlackCat_Rust_Encryptor { strings: $s1 = "src\\alphv.rs" $s2 = "pkill.exe" condition: any of them }',
      severity: 'CRITICAL',
      mitre_technique: 'T1486',
      action_on_match: 'CONTAIN_HOST'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/hunting/campaigns', newHunt);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.campaign.name, newHunt.name);
    assert.equal(data.campaign.status, 'ACTIVE');
    createdHuntId = data.campaign.id;
  });

  test('HUNT-04: POST /api/v1/fleet/hunting/campaigns rejects campaign with missing name with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/hunting/campaigns', { description: 'Missing name' });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('HUNT-05: GET /api/v1/fleet/hunting/campaigns/:id returns single hunt campaign by ID', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/hunting/campaigns/${createdHuntId}`);
    assert.equal(status, 200);
    assert.equal(data.id, createdHuntId);
    assert.equal(data.status, 'ACTIVE');
  });

  test('HUNT-06: GET /api/v1/fleet/hunting/campaigns/:id returns 404 for unknown ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/campaigns/non-existent-hunt');
    assert.equal(status, 404);
    assert.equal(data.error, 'HUNT_NOT_FOUND');
  });

  test('HUNT-07: POST /api/v1/fleet/hunting/campaigns/:id/cancel marks active campaign as CANCELLED', async () => {
    const { status, data } = await apiRequest('POST', `/api/v1/fleet/hunting/campaigns/${createdHuntId}/cancel`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', `/api/v1/fleet/hunting/campaigns/${createdHuntId}`);
    assert.equal(check.data.status, 'CANCELLED');
  });

  test('HUNT-08: DELETE /api/v1/fleet/hunting/campaigns/:id removes campaign and returns 200', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/hunting/campaigns/${createdHuntId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', `/api/v1/fleet/hunting/campaigns/${createdHuntId}`);
    assert.equal(check.status, 404);
  });

  test('HUNT-09: GET /api/v1/fleet/hunting/matches lists all detected matches', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/matches');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.matches));
  });

  test('HUNT-10: GET /api/v1/fleet/hunting/campaigns/:id/matches filters matches by campaign ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/campaigns/hunt-cobalt-strike-beacon/matches');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.matches));
  });

  test('HUNT-11: POST /api/v1/nodes/:id/hunting/matches ingests endpoint IoC match', async () => {
    const matchPayload = {
      hunt_id: 'hunt-cobalt-strike-beacon',
      hostname: 'DESKTOP-HUNT-01',
      match_type: 'YARA_PATTERN_HIT',
      matched_item: 'ReflectiveLoader in rundll32.exe memory space',
      file_path: 'C:\\Windows\\System32\\rundll32.exe',
      sha256_hash: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
      evidence_snippet: { section: '.text', offset: '0x1000', rule: 'CobaltStrike_Beacon' },
      mitre_technique: 'T1055'
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/hunting/matches`, matchPayload);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.match.device_id, TEST_DEVICE_ID);
    assert.equal(data.match.matched_item, matchPayload.matched_item);
  });

  test('HUNT-12: POST /api/v1/nodes/:id/hunting/matches increments matches_detected on parent campaign', async () => {
    const hunt = db.prepare('SELECT matches_detected FROM threat_hunt_campaigns WHERE id = ?').get('hunt-cobalt-strike-beacon');
    assert.ok(hunt.matches_detected >= 1);
  });

  test('HUNT-13: POST /api/v1/nodes/:id/hunting/matches automatically triggers host containment on CONTAIN_HOST action', async () => {
    const cont = db.prepare('SELECT * FROM host_containment_states WHERE device_id = ?').get(TEST_DEVICE_ID);
    assert.ok(cont, 'Host containment state should be registered');
    assert.equal(cont.containment_status, 'CONTAINED');
    assert.ok(cont.reason.includes('Automated containment triggered by Threat Hunt match'));
  });

  test('HUNT-14: POST /api/v1/nodes/:id/hunting/matches records critical security event in audit ledger', async () => {
    const evt = db.prepare(`
      SELECT * FROM security_events 
      WHERE device_id = ? AND severity = 'CRITICAL' AND event_source = 'LocalPilotThreatHunting'
      ORDER BY id DESC LIMIT 1
    `).get(TEST_DEVICE_ID);
    assert.ok(evt, 'Critical security event should be recorded');
    assert.ok(evt.summary.includes('Threat Hunt Detection'));
  });

  test('HUNT-15: GET /api/v1/fleet/hunting/iocs lists threat intelligence watchlist indicators', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/iocs');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.iocs));
    assert.ok(data.iocs.length >= 3);
  });

  test('HUNT-16: POST /api/v1/fleet/hunting/iocs creates new threat watchlist indicator', async () => {
    const newIoc = {
      indicator_type: 'SHA256',
      indicator_value: '5d41402abc4b2a76b9719d911017c592a12d1fb947a5a879796e6d1c801d9326',
      threat_name: 'QakBot Modular Banking Trojan Dropper',
      confidence: 'HIGH',
      action_on_match: 'CONTAIN_HOST'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/hunting/iocs', newIoc);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.ioc.threat_name, newIoc.threat_name);
    assert.equal(data.ioc.action_on_match, 'CONTAIN_HOST');
    createdIocId = data.ioc.id;
  });

  test('HUNT-17: POST /api/v1/fleet/hunting/iocs rejects indicator missing value with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/hunting/iocs', { threat_name: 'Missing value' });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('HUNT-18: DELETE /api/v1/fleet/hunting/iocs/:id deletes watchlist indicator', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/hunting/iocs/${createdIocId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', '/api/v1/fleet/hunting/iocs');
    assert.ok(!check.data.iocs.some(i => i.id === createdIocId));
  });

  test('HUNT-19: GET /api/v1/fleet/hunting/campaigns/:id/script synthesizes PowerShell hunting execution script', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/hunting/campaigns/hunt-cobalt-strike-beacon/script');
    assert.equal(status, 200);
    assert.equal(data.hunt_id, 'hunt-cobalt-strike-beacon');
    assert.ok(data.script.includes('CobaltStrike_Beacon'));
    assert.ok(data.script.includes('Get-Process'));
  });

  test('HUNT-20: ThreatHuntingEngine.ingestMatch links MITRE ATT&CK technique code properly', async () => {
    const matches = ThreatHuntingEngine.getMatches(db, { deviceId: TEST_DEVICE_ID });
    assert.ok(matches.length >= 1);
    assert.equal(matches[0].mitre_technique, 'T1055');
  });
});
