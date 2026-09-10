/**
 * Iteration 47: Endpoint Behavioral Sandbox Detonation & Process Lineage Test Suite
 * Module: server/tests/sandbox_detonation.test.js
 *
 * Validates:
 * 1. Automated malware detonation jobs lifecycle (queued, completed, canceled, deleted)
 * 2. Risk scoring (0-100) and automated verdict classification (MALICIOUS, SUSPICIOUS, BENIGN)
 * 3. Autonomous host isolation triggers on high-risk detections
 * 4. Hierarchical Parent-Child Process Lineage Graph synthesis
 * 5. Behavioral micro-telemetry (injection, file drop, C2 beacon, registry persistence)
 * 6. Node agent endpoints for sample submission and lineage logging
 * 7. Windows Sandbox (.wsb) configuration and execution harness generation
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { SandboxDetonationEngine } from '../src/services/sandboxDetonationEngine.js';

describe('Iteration 47: Endpoint Behavioral Sandbox Detonation & Process Lineage (sandbox_detonation.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-sandbox-47';
  const TEST_DEVICE_ID = 'dev-sandbox-test-01';
  let createdJobId;

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
      VALUES (?, 'DESKTOP-DETONATE-01', 'SN-DET-47001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-det-999', '2.5.0')
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

  test('SD-01: GET /api/v1/fleet/sandbox/stats returns baseline detonation metrics and SLA', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalJobs, 'number');
    assert.equal(typeof data.completedJobs, 'number');
    assert.equal(typeof data.maliciousCount, 'number');
    assert.equal(typeof data.totalProcessNodes, 'number');
    assert.equal(data.subSecondSweepSla, true);
  });

  test('SD-02: GET /api/v1/fleet/sandbox/jobs returns seeded detonation tasks', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/jobs');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.jobs));
    assert.ok(data.jobs.length >= 1);
    const qakbot = data.jobs.find(j => j.id === 'det-sample-qakbot');
    assert.ok(qakbot, 'Should find seeded Qakbot detonation job');
    assert.equal(qakbot.verdict, 'MALICIOUS');
    assert.equal(qakbot.automated_remediation, 'ISOLATE_ENDPOINT');
  });

  test('SD-03: POST /api/v1/fleet/sandbox/jobs queues a new suspicious sample for detonation', async () => {
    const newJob = {
      device_id: TEST_DEVICE_ID,
      sample_name: 'payload_dropper.ps1',
      sample_type: 'POWERSHELL_SCRIPT',
      sample_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      file_path: 'C:\\Users\\Family\\AppData\\Local\\Temp\\payload_dropper.ps1',
      file_size_bytes: 4096,
      sandbox_env: 'WIN11_SANDBOX_SECURE',
      automated_remediation: 'ISOLATE_ENDPOINT'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/sandbox/jobs', newJob);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.job.sample_name, 'payload_dropper.ps1');
    assert.equal(data.job.status, 'QUEUED');
    assert.equal(data.job.verdict, 'PENDING');
    createdJobId = data.job.id;
  });

  test('SD-04: POST /api/v1/fleet/sandbox/jobs rejects submission missing required fields with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/sandbox/jobs', { description: 'Missing sample_name' });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  test('SD-05: GET /api/v1/fleet/sandbox/jobs/:id returns single job with attached details', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/sandbox/jobs/${createdJobId}`);
    assert.equal(status, 200);
    assert.equal(data.id, createdJobId);
    assert.equal(data.sample_name, 'payload_dropper.ps1');
  });

  test('SD-06: GET /api/v1/fleet/sandbox/jobs/:id returns 404 for nonexistent job ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/jobs/non-existent-job');
    assert.equal(status, 404);
    assert.equal(data.error, 'JOB_NOT_FOUND');
  });

  test('SD-07: POST /api/v1/fleet/sandbox/jobs/:id/results ingests execution report and calculates verdict', async () => {
    const results = {
      risk_score: 88,
      execution_duration_sec: 42,
      mitre_tactics: ['Execution', 'Persistence', 'Command and Control'],
      process_nodes: [
        {
          process_id: 3312,
          parent_process_id: 1840,
          process_name: 'powershell.exe',
          parent_process_name: 'explorer.exe',
          command_line: 'powershell.exe -ExecutionPolicy Bypass -File payload_dropper.ps1',
          executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          is_anomalous: 1,
          anomaly_reasons: ['Script block logging bypass attempt']
        }
      ],
      behavioral_events: [
        {
          process_id: 3312,
          process_name: 'powershell.exe',
          event_category: 'C2_NETWORK_BEACON',
          event_action: 'HttpDownload',
          target_object: 'http://203.0.113.88/stage2.bin',
          severity: 'CRITICAL',
          mitre_technique: 'T1105'
        }
      ]
    };

    const { status, data } = await apiRequest('POST', `/api/v1/fleet/sandbox/jobs/${createdJobId}/results`, results);
    assert.equal(status, 200);
    assert.ok(data.success);
    assert.equal(data.job.status, 'COMPLETED');
    assert.equal(data.job.verdict, 'MALICIOUS');
    assert.equal(data.job.risk_score, 88);
    assert.equal(data.job.process_lineage.length, 1);
  });

  test('SD-08: POST /api/v1/fleet/sandbox/jobs/:id/results triggers automated host isolation on MALICIOUS verdict', async () => {
    const containment = db.prepare('SELECT * FROM host_containment_states WHERE device_id = ?').get(TEST_DEVICE_ID);
    assert.ok(containment, 'Host containment state should be recorded for the compromised device');
    assert.equal(containment.containment_status, 'CONTAINED');

    const secEvent = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND severity = 'CRITICAL' AND event_source = 'SANDBOX_AUTONOMOUS_CONTAINMENT'
      ORDER BY id DESC LIMIT 1
    `).get(TEST_DEVICE_ID);
    assert.ok(secEvent, 'CRITICAL security event should be generated');
    assert.ok(secEvent.summary.includes('Host isolated following Malicious Sandbox Detonation'));
  });

  test('SD-09: POST /api/v1/fleet/sandbox/jobs/:id/cancel cancels queued job', async () => {
    const toCancel = await apiRequest('POST', '/api/v1/fleet/sandbox/jobs', {
      device_id: TEST_DEVICE_ID,
      sample_name: 'test_cancel.exe',
      sample_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    });
    const cId = toCancel.data.job.id;

    const { status, data } = await apiRequest('POST', `/api/v1/fleet/sandbox/jobs/${cId}/cancel`);
    assert.equal(status, 200);
    assert.ok(data.success);

    const check = await apiRequest('GET', `/api/v1/fleet/sandbox/jobs/${cId}`);
    assert.equal(check.data.status, 'CANCELLED');
  });

  test('SD-10: DELETE /api/v1/fleet/sandbox/jobs/:id deletes detonation job and returns 200', async () => {
    const toDel = await apiRequest('POST', '/api/v1/fleet/sandbox/jobs', {
      device_id: TEST_DEVICE_ID,
      sample_name: 'to_delete.exe',
      sample_sha256: '0000000000000000000000000000000000000000000000000000000000000000'
    });
    const delId = toDel.data.job.id;

    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/sandbox/jobs/${delId}`);
    assert.equal(status, 200);
    assert.ok(data.success);

    const check = await apiRequest('GET', `/api/v1/fleet/sandbox/jobs/${delId}`);
    assert.equal(check.status, 404);
  });

  test('SD-11: GET /api/v1/fleet/sandbox/jobs/:id/graph returns hierarchical process lineage tree', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/jobs/det-sample-qakbot/graph');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.nodes));
    assert.ok(data.total_nodes >= 3);
    assert.ok(Array.isArray(data.tree));
    assert.ok(data.tree.length >= 1);
    assert.ok(data.anomalous_nodes_count >= 2);
  });

  test('SD-12: GET /api/v1/fleet/sandbox/events returns behavioral events list', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/events');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    assert.ok(data.events.length >= 1);
  });

  test('SD-13: POST /api/v1/fleet/sandbox/events logs a behavioral event directly', async () => {
    const ev = {
      detonation_id: createdJobId,
      process_id: 3312,
      process_name: 'powershell.exe',
      event_category: 'REGISTRY_PERSISTENCE',
      event_action: 'RegSetValueEx',
      target_object: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
      details: { key: 'Updater', path: 'C:\\Users\\Public\\updater.exe' },
      severity: 'HIGH',
      mitre_technique: 'T1547.001'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/sandbox/events', ev);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.event.event_category, 'REGISTRY_PERSISTENCE');
  });

  test('SD-14: GET /api/v1/fleet/sandbox/events filters by category and severity', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/sandbox/events?event_category=C2_NETWORK_BEACON&severity=CRITICAL');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.events));
    data.events.forEach(e => {
      assert.equal(e.event_category, 'C2_NETWORK_BEACON');
      assert.equal(e.severity, 'CRITICAL');
    });
  });

  test('SD-15: POST /api/v1/nodes/:id/sandbox/submit allows node agent to submit sample', async () => {
    const nodeSample = {
      sample_name: 'suspicious_macro.docm',
      sample_type: 'OFFICE_MACRO',
      sample_sha256: '5d41402abc4b2a76b9719d911017c592',
      file_path: 'C:\\Users\\Tony\\Documents\\suspicious_macro.docm',
      automated_remediation: 'QUARANTINE_FILE'
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/sandbox/submit`, nodeSample);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.job.device_id, TEST_DEVICE_ID);
    assert.equal(data.job.sample_type, 'OFFICE_MACRO');
  });

  test('SD-16: POST /api/v1/nodes/:id/sandbox/lineage records process execution tree node from node agent', async () => {
    const nodeLineage = {
      process_id: 8124,
      parent_process_id: 1840,
      process_name: 'rundll32.exe',
      parent_process_name: 'explorer.exe',
      command_line: 'rundll32.exe C:\\Users\\Public\\test.dll,DllRegisterServer',
      executable_path: 'C:\\Windows\\System32\\rundll32.exe',
      is_anomalous: 1,
      anomaly_reasons: ['DLL loaded from untrusted user directory']
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/sandbox/lineage`, nodeLineage);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.node.process_name, 'rundll32.exe');
    assert.equal(data.node.is_anomalous, 1);
  });

  test('SD-17: GET /api/v1/fleet/sandbox/jobs/:id/script generates Windows Sandbox (.wsb) configuration', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/sandbox/jobs/${createdJobId}/script`);
    assert.equal(status, 200);
    assert.ok(data.sandbox_wsb_xml.includes('<Configuration>'));
    assert.ok(data.sandbox_wsb_xml.includes('<SandboxFolder>C:\\DetonationSandbox</SandboxFolder>'));
    assert.ok(data.detonation_harness_ps1.includes('[LocalPilot Sandbox]'));
  });

  test('SD-18: Process Lineage Tree detects anomalous parent-child execution relationship', async () => {
    const graph = SandboxDetonationEngine.getProcessLineageGraph(db, { detonation_id: 'det-sample-qakbot' });
    assert.ok(graph.nodes.some(n => n.process_name === 'powershell.exe' && n.parent_process_name === 'invoice_oct_report.exe'));
    const psNode = graph.nodes.find(n => n.process_name === 'powershell.exe');
    assert.equal(psNode.is_anomalous, 1);
  });

  test('SD-19: Automatic verdict classification evaluates risk scores correctly', async () => {
    // Test Benign (score 20)
    const benignJob = SandboxDetonationEngine.submitDetonationJob(db, {
      device_id: TEST_DEVICE_ID,
      sample_name: 'safe_util.exe',
      sample_sha256: '1111111111111111111111111111111111111111111111111111111111111111'
    });
    const benignRes = SandboxDetonationEngine.ingestDetonationResult(db, benignJob.id, { risk_score: 20 });
    assert.equal(benignRes.verdict, 'BENIGN');

    // Test Suspicious (score 50)
    const suspJob = SandboxDetonationEngine.submitDetonationJob(db, {
      device_id: TEST_DEVICE_ID,
      sample_name: 'suspicious_util.exe',
      sample_sha256: '2222222222222222222222222222222222222222222222222222222222222222'
    });
    const suspRes = SandboxDetonationEngine.ingestDetonationResult(db, suspJob.id, { risk_score: 50 });
    assert.equal(suspRes.verdict, 'SUSPICIOUS');

    // Test Malicious (score 85)
    const malJob = SandboxDetonationEngine.submitDetonationJob(db, {
      device_id: TEST_DEVICE_ID,
      sample_name: 'ransomware_util.exe',
      sample_sha256: '3333333333333333333333333333333333333333333333333333333333333333'
    });
    const malRes = SandboxDetonationEngine.ingestDetonationResult(db, malJob.id, { risk_score: 85 });
    assert.equal(malRes.verdict, 'MALICIOUS');
  });

  test('SD-20: Sub-second telemetry aggregation SLA under concurrent queries', async () => {
    const start = Date.now();
    const [stats, jobs, events] = await Promise.all([
      apiRequest('GET', '/api/v1/fleet/sandbox/stats'),
      apiRequest('GET', '/api/v1/fleet/sandbox/jobs'),
      apiRequest('GET', '/api/v1/fleet/sandbox/events')
    ]);
    const elapsed = Date.now() - start;
    assert.equal(stats.status, 200);
    assert.equal(jobs.status, 200);
    assert.equal(events.status, 200);
    assert.ok(elapsed < 1000, `Telemetry requests took ${elapsed}ms, expected < 1000ms`);
  });
});
