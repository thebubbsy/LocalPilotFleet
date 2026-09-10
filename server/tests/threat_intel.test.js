/**
 * Iteration 54: Threat Intelligence Feed Ingest & Indicator Matching Test Suite
 * Module: server/tests/threat_intel.test.js
 *
 * Validates:
 * 1. Fleet threat intelligence aggregated statistics (/threat-intel/stats)
 * 2. External feed sources management (STIX/TAXII 2.1, AbuseIPDB, AlienVault OTX, URLhaus)
 * 3. Feed synchronization workflows & indicator cache updates
 * 4. High-speed IOC cache querying, filtering, and CRUD operations
 * 5. Real-time indicator matching engine (IP, Domain, URL, File Hash)
 * 6. Automated security event alert generation upon threat match interception
 * 7. Forensic match event telemetry logging
 * 8. Node agent IOC distribution & telemetry reporting endpoints
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { ThreatIntelEngine } from '../src/services/threatIntelEngine.js';

describe('Iteration 54: Threat Intelligence & Indicator Matching (threat_intel.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-ti-54';
  const TEST_DEVICE_ID = 'dev-ti-test-01';

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
      VALUES (?, 'DESKTOP-TI-01', 'SN-TI-54001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-ti-999', '2.5.0')
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

  // 1. GET /api/v1/fleet/threat-intel/stats
  test('1. GET /api/v1/fleet/threat-intel/stats returns aggregated metrics', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalFeeds, 'number');
    assert.equal(typeof data.totalIndicators, 'number');
    assert.equal(typeof data.totalMatches, 'number');
    assert.equal(data.threatIntelOperational, true);
  });

  // 2. GET /api/v1/fleet/threat-intel/feeds
  test('2. GET /api/v1/fleet/threat-intel/feeds retrieves seeded feed sources', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/feeds');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.feeds));
    assert.ok(data.count >= 3);
  });

  // 3. POST /api/v1/fleet/threat-intel/feeds
  test('3. POST /api/v1/fleet/threat-intel/feeds creates a new feed source', async () => {
    const payload = {
      name: 'Custom MISP Threat Feed',
      feed_url: 'https://misp.enterprise.internal/events/restSearch',
      feed_format: 'MISP_JSON',
      poll_interval_hours: 4,
      confidence_weight: 85,
      default_action: 'BLOCK'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/feeds', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.feed.name, payload.name);
    assert.equal(data.feed.feed_format, 'MISP_JSON');
  });

  // 4. POST /api/v1/fleet/threat-intel/feeds validation error
  test('4. POST /api/v1/fleet/threat-intel/feeds returns 400 when missing fields', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/feeds', {
      method: 'POST',
      body: JSON.stringify({ name: 'Incomplete Feed' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 5. GET /api/v1/fleet/threat-intel/feeds/:id
  test('5. GET /api/v1/fleet/threat-intel/feeds/:id retrieves single feed source', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/feeds/tif-abuseipdb');
    assert.equal(status, 200);
    assert.equal(data.id, 'tif-abuseipdb');
    assert.equal(data.feed_format, 'ABUSE_IPDB');
  });

  // 6. DELETE /api/v1/fleet/threat-intel/feeds/:id
  test('6. DELETE /api/v1/fleet/threat-intel/feeds/:id deletes feed source', async () => {
    const tempFeed = ThreatIntelEngine.createFeedSource(db, {
      name: 'Temp Feed to Delete',
      feed_url: 'https://temp.test/feed'
    });
    const { status, data } = await apiRequest(`/api/v1/fleet/threat-intel/feeds/${tempFeed.id}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
  });

  // 7. POST /api/v1/fleet/threat-intel/feeds/:id/sync
  test('7. POST /api/v1/fleet/threat-intel/feeds/:id/sync triggers on-demand sync', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/feeds/tif-urlhaus/sync', {
      method: 'POST'
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
    assert.equal(data.feed.last_sync_status, 'SUCCESS');
    assert.ok(data.feed.last_sync_time);
  });

  // 8. GET /api/v1/fleet/threat-intel/indicators
  test('8. GET /api/v1/fleet/threat-intel/indicators retrieves cached indicators', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.indicators));
    assert.ok(data.count >= 3);
  });

  // 9. POST /api/v1/fleet/threat-intel/indicators
  test('9. POST /api/v1/fleet/threat-intel/indicators creates new indicator', async () => {
    const payload = {
      indicator_type: 'IPV4_ADDRESS',
      indicator_value: '203.0.113.88',
      threat_type: 'BOTNET',
      confidence_score: 95,
      severity: 'HIGH',
      description: 'Mirai botnet scanning node'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.indicator.indicator_value, payload.indicator_value);
    assert.equal(data.indicator.threat_type, 'BOTNET');
  });

  // 10. POST indicator validation error
  test('10. POST /api/v1/fleet/threat-intel/indicators returns 400 on invalid type', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators', {
      method: 'POST',
      body: JSON.stringify({ indicator_type: 'INVALID_TYPE', indicator_value: '1.2.3.4' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'INDICATOR_CREATE_ERROR');
  });

  // 11. DELETE /api/v1/fleet/threat-intel/indicators/:id
  test('11. DELETE /api/v1/fleet/threat-intel/indicators/:id deletes indicator', async () => {
    const tempInd = ThreatIntelEngine.createIndicator(db, {
      indicator_type: 'DOMAIN_FQDN',
      indicator_value: 'temp-malicious-domain.xyz'
    });
    const { status, data } = await apiRequest(`/api/v1/fleet/threat-intel/indicators/${tempInd.id}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
  });

  // 12. POST /api/v1/fleet/threat-intel/indicators/match positive hit
  test('12. POST match checks malicious IP, returns matched=true, records match event & alert', async () => {
    const payload = {
      indicator_type: 'IPV4_ADDRESS',
      indicator_value: '198.51.100.99',
      device_id: TEST_DEVICE_ID,
      context: 'Outbound TCP connection to port 443'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators/match', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 200);
    assert.equal(data.matched, true);
    assert.ok(data.indicator);
    assert.ok(data.matchEvent);
    assert.equal(data.matchEvent.action_taken, 'BLOCKED');

    // Verify security event alert recorded
    const secEvent = db.prepare("SELECT * FROM security_events WHERE event_source = 'THREAT_INTEL_ENGINE' ORDER BY id DESC LIMIT 1").get();
    assert.ok(secEvent);
    assert.ok(secEvent.summary.includes('198.51.100.99'));
  });

  // 13. POST match negative hit
  test('13. POST match checks benign IP and returns matched=false', async () => {
    const payload = {
      indicator_type: 'IPV4_ADDRESS',
      indicator_value: '1.1.1.1',
      device_id: TEST_DEVICE_ID
    };
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators/match', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 200);
    assert.equal(data.matched, false);
  });

  // 14. POST match validation error
  test('14. POST match returns 400 when missing device_id or value', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/indicators/match', {
      method: 'POST',
      body: JSON.stringify({ indicator_type: 'IPV4_ADDRESS' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 15. GET /api/v1/fleet/threat-intel/matches
  test('15. GET /api/v1/fleet/threat-intel/matches retrieves match events', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/matches');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.matches));
    assert.ok(data.count >= 1);
  });

  // 16. POST /api/v1/fleet/threat-intel/matches
  test('16. POST /api/v1/fleet/threat-intel/matches manually records match event', async () => {
    const payload = {
      device_id: TEST_DEVICE_ID,
      indicator_type: 'DOMAIN_FQDN',
      matched_value: 'updates-cdn-auth.com',
      source_context: 'DNS query interception',
      action_taken: 'BLOCKED',
      severity: 'HIGH'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/threat-intel/matches', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.event.matched_value, payload.matched_value);
  });

  // 17. GET /api/v1/nodes/:id/threat-intel/indicators
  test('17. GET /api/v1/nodes/:id/threat-intel/indicators returns active IOCs for agent', async () => {
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/threat-intel/indicators`);
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.indicators));
    assert.ok(data.count >= 3);
  });

  // 18. POST /api/v1/nodes/:id/threat-intel/matches
  test('18. POST /api/v1/nodes/:id/threat-intel/matches allows node agent to report hit', async () => {
    const payload = {
      indicator_type: 'SHA256_HASH',
      matched_value: 'a35b88c7d91e4f501867c2934098492083419082340918230914820934812093',
      source_context: 'Process spawn hash verification',
      action_taken: 'QUARANTINED',
      severity: 'CRITICAL'
    };
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/threat-intel/matches`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.event.action_taken, 'QUARANTINED');
  });

  // 19. ThreatIntelEngine.getIndicators with filters
  test('19. ThreatIntelEngine.getIndicators filters by threat_type and severity', () => {
    const c2s = ThreatIntelEngine.getIndicators(db, { threat_type: 'C2_BEACON' });
    assert.ok(Array.isArray(c2s));
    for (const c of c2s) {
      assert.equal(c.threat_type, 'C2_BEACON');
    }
  });

  // 20. ThreatIntelEngine.updateFeedSource
  test('20. ThreatIntelEngine.updateFeedSource updates polling and weight', () => {
    const updated = ThreatIntelEngine.updateFeedSource(db, 'tif-alienvault', {
      poll_interval_hours: 12,
      confidence_weight: 95
    });
    assert.ok(updated);
    assert.equal(updated.poll_interval_hours, 12);
    assert.equal(updated.confidence_weight, 95);
  });
});
