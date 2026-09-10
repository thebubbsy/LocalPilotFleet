/**
 * Iteration 52: Custom Remediation Automation & Live Response Test Suite
 * Module: server/tests/live_response.test.js
 *
 * Validates:
 * 1. Live Response aggregated fleet statistics (/live-response/stats)
 * 2. Custom remediation package management (CRUD, categories, execution frequency)
 * 3. PowerShell wrapper script generator with detection and remediation stages
 * 4. Interactive remote investigation sessions & command queues
 * 5. Node agent polling for pending queued commands & status transition
 * 6. Node agent reporting command results with exit codes and outputs
 * 7. Malicious artifact quarantine vault & security event alerting
 * 8. Quarantined file restoration and forensic audit logging
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { LiveResponseEngine } from '../src/services/liveResponseEngine.js';

describe('Iteration 52: Custom Remediation & Live Response (live_response.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-lr-52';
  const TEST_DEVICE_ID = 'dev-lr-test-01';

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
      VALUES (?, 'DESKTOP-LR-01', 'SN-LR-52001', 'Windows 11 Pro', '10.0.26100.1742', 17179869184, 'tokenhash-lr-999', '2.5.0')
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

  // 1. GET /api/v1/fleet/live-response/stats
  test('1. GET /api/v1/fleet/live-response/stats returns aggregated fleet metrics', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalPackages, 'number');
    assert.equal(typeof data.totalSessions, 'number');
    assert.equal(typeof data.quarantinedFiles, 'number');
    assert.equal(data.liveResponseAvailable, true);
  });

  // 2. GET /api/v1/fleet/remediation-packages
  test('2. GET /api/v1/fleet/remediation-packages retrieves seeded playbooks', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/remediation-packages');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.packages));
    assert.ok(data.count >= 3);
  });

  // 3. POST /api/v1/fleet/remediation-packages
  test('3. POST /api/v1/fleet/remediation-packages creates a new custom playbook', async () => {
    const payload = {
      name: 'Disable SMBv1 Vulnerable Protocol',
      description: 'Disables legacy SMBv1 protocol to prevent EternalBlue exploitation',
      category: 'SECURITY_HARDENING',
      detection_script: 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol',
      remediation_script: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart',
      run_frequency: 'HOURLY',
      run_as_account: 'SYSTEM'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/remediation-packages', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.package.name, payload.name);
    assert.equal(data.package.category, 'SECURITY_HARDENING');
  });

  // 4. GET /api/v1/fleet/remediation-packages/:id
  test('4. GET /api/v1/fleet/remediation-packages/:id retrieves single package', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/remediation-packages/crp-printspooler');
    assert.equal(status, 200);
    assert.equal(data.id, 'crp-printspooler');
    assert.ok(data.detection_script.includes('Spooler'));
  });

  // 5. DELETE /api/v1/fleet/remediation-packages/:id
  test('5. DELETE /api/v1/fleet/remediation-packages/:id deletes playbook', async () => {
    // Create temporary package to delete
    const created = LiveResponseEngine.createRemediationPackage(db, {
      name: 'Temp Playbook',
      detection_script: 'exit 0',
      remediation_script: 'Write-Host "Done"'
    });
    const { status, data } = await apiRequest(`/api/v1/fleet/remediation-packages/${created.id}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
  });

  // 6. GET /api/v1/fleet/remediation-packages/:id/script
  test('6. GET /api/v1/fleet/remediation-packages/:id/script generates execution wrapper', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/remediation-packages/crp-printspooler/script');
    assert.equal(status, 200);
    assert.ok(typeof data === 'string');
    assert.ok(data.includes('[LocalPilot-Remediation] Starting Playbook'));
    assert.ok(data.includes('DetectionExitCode'));
    assert.ok(data.includes('ConvertTo-Json'));
  });

  // 7. POST /api/v1/fleet/live-response/sessions
  test('7. POST /api/v1/fleet/live-response/sessions starts a remote investigation session', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/sessions', {
      method: 'POST',
      body: JSON.stringify({ device_id: TEST_DEVICE_ID, operator: 'IR Analyst Alice' })
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.ok(data.session.session_id.startsWith('lrs-'));
    assert.equal(data.session.device_id, TEST_DEVICE_ID);
  });

  // 8. POST /api/v1/fleet/live-response/sessions validation error
  test('8. POST /api/v1/fleet/live-response/sessions returns 400 if device_id missing', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/sessions', {
      method: 'POST',
      body: JSON.stringify({ operator: 'IR Analyst Alice' })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 9. POST /api/v1/fleet/live-response/sessions/:sessionId/commands
  test('9. POST /api/v1/fleet/live-response/sessions/:sessionId/commands queues an interactive command', async () => {
    const sessionId = 'lrs-test-session-01';
    const payload = {
      device_id: TEST_DEVICE_ID,
      command_type: 'LIST_DIRECTORY',
      command_payload: 'C:\\Windows\\System32',
      operator: 'SecOps Hunter'
    };
    const { status, data } = await apiRequest(`/api/v1/fleet/live-response/sessions/${sessionId}/commands`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.command.status, 'QUEUED');
    assert.equal(data.command.command_type, 'LIST_DIRECTORY');
  });

  // 10. Critical action TERMINATE_PROCESS queues and logs security event
  test('10. POST TERMINATE_PROCESS command queues and logs security event', async () => {
    const sessionId = 'lrs-test-session-crit';
    const payload = {
      device_id: TEST_DEVICE_ID,
      command_type: 'TERMINATE_PROCESS',
      command_payload: 'pid:4412 /name:evil_ransomware.exe',
      operator: 'SecOps Hunter'
    };
    const { status, data } = await apiRequest(`/api/v1/fleet/live-response/sessions/${sessionId}/commands`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.command.command_type, 'TERMINATE_PROCESS');

    const secEvent = db.prepare("SELECT * FROM security_events WHERE event_source = 'LIVE_RESPONSE_ENGINE' ORDER BY id DESC LIMIT 1").get();
    assert.ok(secEvent);
    assert.ok(secEvent.summary.includes('TERMINATE_PROCESS'));
  });

  // 11. Command validation rejection
  test('11. Command queuing rejects invalid command type', async () => {
    const sessionId = 'lrs-test-session-invalid';
    const payload = {
      device_id: TEST_DEVICE_ID,
      command_type: 'INVALID_UNKNOWN_COMMAND',
      command_payload: 'test'
    };
    const { status, data } = await apiRequest(`/api/v1/fleet/live-response/sessions/${sessionId}/commands`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'COMMAND_QUEUE_ERROR');
  });

  // 12. GET /api/v1/fleet/live-response/sessions/:sessionId/commands
  test('12. GET /api/v1/fleet/live-response/sessions/:sessionId/commands retrieves all commands in session', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/sessions/lrs-session-77/commands');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.commands));
    assert.ok(data.count >= 3);
  });

  // 13. GET /api/v1/nodes/:id/live-response/poll transitions status to IN_PROGRESS
  test('13. GET /api/v1/nodes/:id/live-response/poll polls pending commands and transitions to IN_PROGRESS', async () => {
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/live-response/poll`);
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.commands));
    assert.ok(data.count >= 1);

    const checked = db.prepare('SELECT status FROM live_response_command_sessions WHERE id = ?').get(data.commands[0].id);
    assert.equal(checked.status, 'IN_PROGRESS');
  });

  // 14. POST /api/v1/nodes/:id/live-response/results reports completion
  test('14. POST /api/v1/nodes/:id/live-response/results records successful command execution', async () => {
    const pendingCmd = db.prepare("SELECT id FROM live_response_command_sessions WHERE device_id = ? AND status = 'IN_PROGRESS' LIMIT 1").get(TEST_DEVICE_ID);
    assert.ok(pendingCmd);

    const payload = {
      command_id: pendingCmd.id,
      output: 'Directory listing completed with 42 entries.',
      exit_code: 0,
      status: 'COMPLETED',
      duration_ms: 185
    };
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/live-response/results`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 200);
    assert.equal(data.command.status, 'COMPLETED');
    assert.equal(data.command.exit_code, 0);
    assert.equal(data.command.output, payload.output);
  });

  // 15. POST /api/v1/nodes/:id/live-response/results records failure
  test('15. POST /api/v1/nodes/:id/live-response/results records failed command execution', async () => {
    const newCmd = LiveResponseEngine.queueCommand(db, {
      sessionId: 'lrs-fail-test',
      deviceId: TEST_DEVICE_ID,
      commandType: 'EXEC_CMD',
      commandPayload: 'invalid_bad_command.exe'
    });

    const payload = {
      command_id: newCmd.id,
      output: 'Command not found: invalid_bad_command.exe',
      exit_code: 1,
      status: 'FAILED',
      duration_ms: 45
    };
    const { status, data } = await apiRequest(`/api/v1/nodes/${TEST_DEVICE_ID}/live-response/results`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 200);
    assert.equal(data.command.status, 'FAILED');
    assert.equal(data.command.exit_code, 1);
  });

  // 16. POST /api/v1/fleet/live-response/quarantine vaults artifact and alerts
  test('16. POST /api/v1/fleet/live-response/quarantine stores artifact in vault and creates alert', async () => {
    const payload = {
      device_id: TEST_DEVICE_ID,
      original_path: 'C:\\Users\\Tony\\AppData\\Local\\Temp\\dropper.bat',
      file_name: 'dropper.bat',
      sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      file_size_bytes: 2048,
      threat_name: 'Trojan:BAT/CoinMiner.A',
      quarantined_by: 'Automated Playbook #4'
    };
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/quarantine', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(status, 201);
    assert.equal(data.success, true);
    assert.equal(data.item.status, 'QUARANTINED');
    assert.ok(data.item.quarantine_vault_path.includes('9f86d081884c7d65'));

    const alert = db.prepare("SELECT * FROM security_events WHERE summary LIKE '%dropper.bat%'").get();
    assert.ok(alert);
  });

  // 17. POST quarantine validation rejection
  test('17. POST /api/v1/fleet/live-response/quarantine returns 400 on missing required fields', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/quarantine', {
      method: 'POST',
      body: JSON.stringify({ device_id: TEST_DEVICE_ID })
    });
    assert.equal(status, 400);
    assert.equal(data.error, 'MISSING_FIELDS');
  });

  // 18. GET /api/v1/fleet/live-response/quarantine lists inventory
  test('18. GET /api/v1/fleet/live-response/quarantine lists quarantined inventory', async () => {
    const { status, data } = await apiRequest('/api/v1/fleet/live-response/quarantine');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.files));
    assert.ok(data.count >= 2);
  });

  // 19. POST /api/v1/fleet/live-response/quarantine/:id/restore restores file
  test('19. POST /api/v1/fleet/live-response/quarantine/:id/restore restores artifact', async () => {
    const quarantined = db.prepare("SELECT id FROM quarantined_files_inventory WHERE status = 'QUARANTINED' LIMIT 1").get();
    assert.ok(quarantined);

    const { status, data } = await apiRequest(`/api/v1/fleet/live-response/quarantine/${quarantined.id}/restore`, {
      method: 'POST',
      body: JSON.stringify({ restored_by: 'Senior SecOps Lead', notes: 'Confirmed false positive internal script' })
    });
    assert.equal(status, 200);
    assert.equal(data.success, true);
    assert.equal(data.item.status, 'RESTORED');
    assert.ok(data.item.notes.includes('Confirmed false positive'));
  });

  // 20. LiveResponseEngine.updateRemediationPackage directly updates package
  test('20. LiveResponseEngine.updateRemediationPackage updates playbook parameters', () => {
    const updated = LiveResponseEngine.updateRemediationPackage(db, 'crp-guest-account', {
      run_frequency: 'HOURLY',
      execution_timeout: 60,
      description: 'Updated CIS benchmark guest audit playbook'
    });
    assert.ok(updated);
    assert.equal(updated.run_frequency, 'HOURLY');
    assert.equal(updated.execution_timeout, 60);
    assert.equal(updated.description, 'Updated CIS benchmark guest audit playbook');
  });
});
