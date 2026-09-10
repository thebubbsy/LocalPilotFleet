import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { IncidentResponseEngine } from '../src/services/incidentResponseEngine.js';

describe('Iteration 44: Automated Incident Response & Forensic Triage Engine (incident_response.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-ir-key-12345';

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
      VALUES ('DESKTOP-IR-TEST', 'DESKTOP-IR-TEST', 'SN-IR-999', 'Windows 11', '23H2', 17179869184, 'tokenhash-ir-999', '1.44.0')
    `).run();

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
    const res = await fetch(`${baseUrl}${path}`, { ...options, headers });
    let data;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    return { status: res.status, headers: res.headers, body: data };
  }

  test('IR-01: GET /api/v1/fleet/ir/stats returns baseline metrics and containment SLA', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/stats');
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.totalPlaybooks >= 3);
    assert.ok(res.body.enabledPlaybooks >= 3);
    assert.strictEqual(res.body.sub3SecondContainmentSla, true);
    assert.ok(res.body.containmentEngine.includes('Windows Filtering Platform'));
  });

  test('IR-02: GET /api/v1/fleet/ir/playbooks returns seeded playbooks', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/playbooks');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.playbooks));
    assert.ok(res.body.playbooks.length >= 3);
    const ransomwarePb = res.body.playbooks.find(p => p.trigger_event_type === 'RANSOMWARE_SUSPECT');
    assert.ok(ransomwarePb);
    assert.ok(ransomwarePb.actions.includes('ISOLATE_NETWORK'));
  });

  test('IR-03: POST /api/v1/fleet/ir/playbooks creates a new automated IR playbook', async () => {
    const payload = {
      name: 'Custom Lateral Movement Blocker',
      description: 'Isolates device and kills suspicious SMB sessions',
      trigger_event_type: 'TAMPER_DETECTED',
      actions: ['ISOLATE_NETWORK', 'KILL_PROCESS_TREE'],
      target_scope: 'ALL_FLEET',
      is_enabled: true
    };
    const res = await apiRequest('/api/v1/fleet/ir/playbooks', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.name, payload.name);
    assert.deepStrictEqual(res.body.actions, payload.actions);
    assert.strictEqual(res.body.is_enabled, true);
  });

  test('IR-04: GET /api/v1/fleet/ir/playbooks/:id retrieves single playbook by ID', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/playbooks/pb-ransomware-contain');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.id, 'pb-ransomware-contain');
    assert.strictEqual(res.body.trigger_event_type, 'RANSOMWARE_SUSPECT');
  });

  test('IR-05: GET /api/v1/fleet/ir/playbooks/:id returns 404 for unknown ID', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/playbooks/pb-nonexistent');
    assert.strictEqual(res.status, 404);
  });

  test('IR-06: PATCH /api/v1/fleet/ir/playbooks/:id updates actions and description', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/playbooks/pb-ransomware-contain', {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated ransomware response profile',
        require_dual_custody: true
      })
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.description, 'Updated ransomware response profile');
    assert.strictEqual(res.body.require_dual_custody, true);
  });

  test('IR-07: DELETE /api/v1/fleet/ir/playbooks/:id deletes playbook and returns 200', async () => {
    const created = await apiRequest('/api/v1/fleet/ir/playbooks', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Temporary Disposable Playbook',
        trigger_event_type: 'BRUTE_FORCE_LOGIN'
      })
    });
    const id = created.body.id;
    const delRes = await apiRequest(`/api/v1/fleet/ir/playbooks/${id}`, { method: 'DELETE' });
    assert.strictEqual(delRes.status, 200);
    assert.strictEqual(delRes.body.success, true);

    const getRes = await apiRequest(`/api/v1/fleet/ir/playbooks/${id}`);
    assert.strictEqual(getRes.status, 404);
  });

  test('IR-08: GET /api/v1/fleet/ir/containment returns host containment ledger', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/containment');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.containment_states));
    assert.ok(res.body.count >= 1);
  });

  test('IR-09: POST /api/v1/fleet/devices/:id/contain isolates host and sets status to CONTAINED', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/DESKTOP-IR-TEST/contain', {
      method: 'POST',
      body: JSON.stringify({
        reason: 'Active Cobalt Strike beacon detected',
        isolated_by: 'SOC Lead Sentinel'
      })
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.containment.containment_status, 'CONTAINED');
    assert.strictEqual(res.body.containment.isolated_by, 'SOC Lead Sentinel');
  });

  test('IR-10: POST /api/v1/fleet/devices/:id/contain records critical security event', () => {
    const event = db.prepare("SELECT * FROM security_events WHERE device_id = 'DESKTOP-IR-TEST' AND severity = 'CRITICAL' ORDER BY id DESC LIMIT 1").get();
    assert.ok(event);
    assert.strictEqual(event.severity, 'CRITICAL');
    assert.ok(event.summary.includes('Active Cobalt Strike beacon detected'));
  });

  test('IR-11: POST /api/v1/fleet/devices/:id/release returns host to UNCONTAINED status', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/DESKTOP-IR-TEST/release', {
      method: 'POST',
      body: JSON.stringify({
        reason: 'Remediation completed and verified green',
        released_by: 'SOC Director'
      })
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.containment.containment_status, 'UNCONTAINED');
  });

  test('IR-12: POST /api/v1/fleet/devices/:id/release records containment release security event', () => {
    const event = db.prepare("SELECT * FROM security_events WHERE device_id = 'DESKTOP-IR-TEST' AND severity = 'INFO' ORDER BY id DESC LIMIT 1").get();
    assert.ok(event);
    assert.ok(event.summary.includes('released from network containment'));
  });

  test('IR-13: GET /api/v1/fleet/ir/triage lists all triage packages', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/triage');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.packages));
    assert.ok(res.body.packages.length >= 1);
  });

  test('IR-14: GET /api/v1/fleet/ir/triage?device_id= filters packages by target device', async () => {
    const res = await apiRequest('/api/v1/fleet/ir/triage?device_id=DESKTOP-R0H12DJ');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.packages));
    assert.ok(res.body.packages.every(p => p.device_id === 'DESKTOP-R0H12DJ'));
  });

  test('IR-15: POST /api/v1/fleet/devices/:id/triage queues on-demand forensic package', async () => {
    const res = await apiRequest('/api/v1/fleet/devices/DESKTOP-IR-TEST/triage', {
      method: 'POST',
      body: JSON.stringify({
        artifacts: ['ProcessTree', 'Prefetch', 'MemoryMetadata']
      })
    });
    assert.strictEqual(res.status, 202);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.package.status, 'QUEUED');
    assert.strictEqual(res.body.package.device_id, 'DESKTOP-IR-TEST');
  });

  test('IR-16: POST /api/v1/nodes/:id/ir/triage-upload ingests completed package with SHA-256 hash', async () => {
    const nodeToken = 'valid-token-ir';
    // Queue package first
    const engine = new IncidentResponseEngine(db);
    const queued = engine.createTriagePackage({ device_id: 'DESKTOP-IR-TEST' });

    const uploadRes = await apiRequest('/api/v1/nodes/DESKTOP-IR-TEST/ir/triage-upload', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${nodeToken}`
      },
      body: JSON.stringify({
        package_id: queued.id,
        file_path: 'server/data/triage/test_dump.zip',
        file_size_bytes: 4096000,
        sha256_hash: '3f5a1e2d4c5b6a7e8f90123456789abcdef0123456789abcdef0123456789abc',
        execution_time_ms: 620
      })
    });

    assert.strictEqual(uploadRes.status, 200);
    assert.strictEqual(uploadRes.body.success, true);
    assert.strictEqual(uploadRes.body.package.status, 'COMPLETED');
    assert.strictEqual(uploadRes.body.package.file_size_bytes, 4096000);
  });

  test('IR-17: GET /api/v1/fleet/ir/triage/:id/download streams triage zip archive', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/ir/triage/pkg-baseline-r0h12dj/download`, {
      headers: { 'x-fleet-key': TEST_FLEET_KEY }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/zip');
    assert.ok(res.headers.get('content-disposition').includes('attachment'));
  });

  test('IR-18: IncidentResponseEngine.evaluateSecurityEvent triggers automated playbook actions on matching event', () => {
    const engine = new IncidentResponseEngine(db);
    const result = engine.evaluateSecurityEvent({
      event_type: 'RANSOMWARE_SUSPECT',
      device_id: 'DESKTOP-IR-TEST',
      hostname: 'DESKTOP-IR-TEST'
    });
    assert.strictEqual(result.triggered, true);
    assert.ok(result.executedPlaybooks.length >= 1);
  });

  test('IR-19: IncidentResponseEngine.evaluateSecurityEvent isolates host automatically on RANSOMWARE_SUSPECT', () => {
    const status = db.prepare("SELECT * FROM host_containment_states WHERE device_id = 'DESKTOP-IR-TEST'").get();
    assert.strictEqual(status.containment_status, 'CONTAINED');
    assert.ok(status.isolated_by.includes('Automated Ransomware Kill'));
  });

  test('IR-20: Security event evaluation creates triage package automatically on trigger', () => {
    const pkgs = db.prepare("SELECT * FROM forensic_triage_packages WHERE device_id = 'DESKTOP-IR-TEST' AND trigger_source = 'PLAYBOOK_AUTOMATION'").all();
    assert.ok(pkgs.length >= 1);
  });
});
