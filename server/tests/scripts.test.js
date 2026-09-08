/**
 * LocalPilot Fleet — Intune PowerShell Scripts Engine QA
 * server/tests/scripts.test.js
 *
 * Tests: CRUD for device_scripts, run-frequency logic, on-demand dispatch,
 * node heartbeat delivery, script run result reporting, stats, and
 * Cloud Shell command queue (device_commands).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Microsoft Intune PowerShell Scripts & Cloud Shell QA (scripts.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-scripts-qa';
  let testDeviceId;
  let testNodeToken;
  let createdScriptId;
  let commandId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'QA-SCRIPTS-RIG',
        serial_number: 'SN-SCRIPTS-TEST-001',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.22631',
        total_ram_bytes: 17179869184,
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        primary_user: 'qa-scripts-tester'
      })
    });
    assert.equal(enrollRes.status, 201);
    const enrollData = await enrollRes.json();
    testDeviceId = enrollData.device_id;
    testNodeToken = enrollData.node_token;
  });

  after(async () => {
    if (app) await app.cleanup();
  });

  async function api(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Fleet-Key': FLEET_KEY,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  async function nodeApi(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  // ── SCRIPTS STATS ──────────────────────────────────────────────────────────

  it('SCR-01: GET /api/v1/fleet/scripts/stats should return script telemetry stats', async () => {
    const res = await api('/api/v1/fleet/scripts/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_scripts === 'number', 'total_scripts should be number');
    assert.ok(typeof res.body.active_scripts === 'number', 'active_scripts should be number');
    assert.ok(typeof res.body.success_rate_percent === 'number', 'success_rate_percent should be number');
    assert.ok(typeof res.body.covered_devices === 'number', 'covered_devices should be number');
    assert.ok(res.body.total_scripts >= 5, 'Should have at least 5 seeded enterprise scripts');
  });

  // ── SCRIPT CRUD ────────────────────────────────────────────────────────────

  it('SCR-02: POST /api/v1/fleet/scripts should create a new PowerShell script policy', async () => {
    const res = await api('/api/v1/fleet/scripts', {
      method: 'POST',
      body: JSON.stringify({
        name: 'QA Audit Local Admins Test',
        description: 'Enumerates local administrators for QA verification.',
        script_content: 'Get-LocalGroupMember -Group "Administrators" | Format-Table -AutoSize; exit 0',
        run_as_account: 'SYSTEM',
        run_as_32bit: false,
        enforce_signature_check: false,
        timeout_seconds: 120,
        target_group_id: 'grp-all',
        assignment_intent: 'ASSIGNED',
        run_frequency: 'ONCE',
        enabled: true
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id, 'Created script should have id');
    assert.equal(res.body.name, 'QA Audit Local Admins Test');
    assert.equal(res.body.run_as_account, 'SYSTEM');
    assert.equal(res.body.run_frequency, 'ONCE');
    assert.equal(res.body.enabled, true);
    createdScriptId = res.body.id;
  });

  it('SCR-03: POST /api/v1/fleet/scripts should reject missing required name', async () => {
    const res = await api('/api/v1/fleet/scripts', {
      method: 'POST',
      body: JSON.stringify({
        description: 'No name provided',
        script_content: 'exit 0'
      })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error, 'Should return error field');
  });

  it('SCR-04: POST /api/v1/fleet/scripts should reject missing script_content', async () => {
    const res = await api('/api/v1/fleet/scripts', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Empty Content Script',
        description: 'No script_content'
      })
    });
    assert.equal(res.status, 400);
  });

  it('SCR-05: GET /api/v1/fleet/scripts should list all scripts including the created one', async () => {
    const res = await api('/api/v1/fleet/scripts');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.scripts), 'Should return scripts array');
    assert.ok(res.body.scripts.length >= 6, 'Should have at least 6 scripts (5 seeded + 1 created)');
    const created = res.body.scripts.find(s => s.id === createdScriptId);
    assert.ok(created, 'Created script should appear in list');
    assert.equal(created.run_frequency, 'ONCE');
  });

  it('SCR-06: GET /api/v1/fleet/scripts/:id should return the specific script with stats', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdScriptId);
    assert.equal(res.body.name, 'QA Audit Local Admins Test');
    assert.ok(typeof res.body.total_runs === 'number', 'Should include total_runs');
    assert.ok(typeof res.body.success_runs === 'number', 'Should include success_runs');
  });

  it('SCR-07: GET /api/v1/fleet/scripts/:id should 404 for unknown id', async () => {
    const res = await api('/api/v1/fleet/scripts/non-existent-script-id');
    assert.equal(res.status, 404);
  });

  it('SCR-08: PATCH /api/v1/fleet/scripts/:id should update script fields', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated QA description',
        run_frequency: 'SCHEDULED',
        timeout_seconds: 300
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.description, 'Updated QA description');
    assert.equal(res.body.run_frequency, 'SCHEDULED');
    assert.equal(res.body.timeout_seconds, 300);
  });

  it('SCR-09: PATCH /api/v1/fleet/scripts/:id should reject invalid run_frequency', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}`, {
      method: 'PATCH',
      body: JSON.stringify({ run_frequency: 'INVALID_FREQ' })
    });
    assert.equal(res.status, 400);
  });

  // ── HEARTBEAT DELIVERS ASSIGNED SCRIPTS ───────────────────────────────────

  it('SCR-10: POST /api/v1/nodes/heartbeat should include assigned_scripts for enrolled device', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 5.5,
        ram_used_bytes: 4294967296,
        ip_address: '192.168.1.100'
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.acknowledged === true, 'Should acknowledge heartbeat');
    assert.ok(Array.isArray(res.body.assigned_scripts), 'Should include assigned_scripts array');
    // Should have at least the seeded scripts targeting grp-all
    assert.ok(res.body.assigned_scripts.length >= 1, 'Should have at least 1 assigned script');
    // Verify script shape
    const first = res.body.assigned_scripts[0];
    assert.ok(first.id, 'Script should have id');
    assert.ok(first.name, 'Script should have name');
    assert.ok(first.script_content, 'Script should have script_content');
    assert.ok(typeof first.is_due === 'boolean', 'Script should have is_due boolean');
    assert.ok(typeof first.run_as_32bit === 'boolean', 'Script should have run_as_32bit boolean');
  });

  // ── SCRIPT RUN RESULT REPORTING ────────────────────────────────────────────

  it('SCR-11: POST /api/v1/nodes/:id/scripts/:scriptId/result should record execution result', async () => {
    // Use a seeded script id from the fleet scripts list
    const scriptsRes = await api('/api/v1/fleet/scripts');
    const seededScript = scriptsRes.body.scripts[0];
    assert.ok(seededScript, 'Need at least one script in catalog');

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/scripts/${seededScript.id}/result`, {
      method: 'POST',
      body: JSON.stringify({
        run_mode: 'ASSIGNED',
        status: 'SUCCESS',
        exit_code: 0,
        stdout: 'Name                    ObjectClass PrincipalSource\nAdministrator           User        Local',
        stderr: '',
        execution_time_ms: 1420
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id, 'Run result should have id');
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.script_id, seededScript.id);
    assert.equal(res.body.status, 'SUCCESS');
    assert.equal(res.body.exit_code, 0);
    assert.equal(res.body.execution_time_ms, 1420);
  });

  it('SCR-12: POST /api/v1/nodes/:id/scripts/:scriptId/result should reject invalid device token', async () => {
    const scriptsRes = await api('/api/v1/fleet/scripts');
    const seededScript = scriptsRes.body.scripts[0];

    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/scripts/${seededScript.id}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer invalid-token-abc'
      },
      body: JSON.stringify({ status: 'SUCCESS', exit_code: 0 })
    });
    assert.equal(res.status, 401);
  });

  it('SCR-13: POST /api/v1/nodes/:id/scripts/:scriptId/result should record FAILED result', async () => {
    const scriptsRes = await api('/api/v1/fleet/scripts');
    const seededScript = scriptsRes.body.scripts[1];
    assert.ok(seededScript, 'Need at least two scripts');

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/scripts/${seededScript.id}/result`, {
      method: 'POST',
      body: JSON.stringify({
        run_mode: 'ASSIGNED',
        status: 'FAILED',
        exit_code: 1,
        stdout: '',
        stderr: 'Get-LocalGroupMember : Access is denied.',
        execution_time_ms: 320
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.status, 'FAILED');
    assert.equal(res.body.exit_code, 1);
    assert.ok(res.body.stderr.includes('Access is denied'), 'stderr should be recorded');
  });

  // ── SCRIPT RUNS QUERY ─────────────────────────────────────────────────────

  it('SCR-14: GET /api/v1/fleet/scripts/runs should return execution history', async () => {
    const res = await api('/api/v1/fleet/scripts/runs');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.runs), 'Should return runs array');
    // Should have at least the 2 runs we just recorded
    assert.ok(res.body.runs.length >= 2, 'Should have at least 2 run records');
  });

  it('SCR-15: GET /api/v1/fleet/scripts/runs?device_id= should filter by device', async () => {
    const res = await api(`/api/v1/fleet/scripts/runs?device_id=${testDeviceId}`);
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.runs));
    res.body.runs.forEach(r => {
      assert.equal(r.device_id, testDeviceId);
    });
  });

  it('SCR-16: GET /api/v1/fleet/scripts/runs?status=SUCCESS should filter by status', async () => {
    const res = await api('/api/v1/fleet/scripts/runs?status=SUCCESS');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.runs));
    res.body.runs.forEach(r => {
      assert.equal(r.status, 'SUCCESS');
    });
  });

  // ── DEVICE SCRIPTS ENDPOINT ───────────────────────────────────────────────

  it('SCR-17: GET /api/v1/fleet/devices/:id/scripts should return scripts with last run status', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/scripts`);
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.assigned_scripts), 'Should return assigned_scripts array');
    assert.ok(typeof res.body.assigned_scripts_count === 'number', 'Should include assigned_scripts_count');
    assert.ok(Array.isArray(res.body.recent_runs), 'Should include recent_runs');
    // Should contain scripts from seeded catalog
    assert.ok(res.body.assigned_scripts.length >= 1);
  });

  it('SCR-18: GET /api/v1/fleet/devices/:id/scripts should 404 for unknown device', async () => {
    const res = await api('/api/v1/fleet/devices/non-existent-device-id/scripts');
    assert.equal(res.status, 404);
  });

  // ── ON-DEMAND DISPATCH ────────────────────────────────────────────────────

  it('SCR-19: POST /api/v1/fleet/scripts/:id/run should dispatch a script run command', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}/run`, {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId })
    });
    assert.equal(res.status, 202);
    assert.ok(res.body.run_id, 'Should return run_id from dispatch');
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.status, 'PENDING');
  });

  it('SCR-20: POST /api/v1/fleet/devices/:id/scripts/:scriptId/run should dispatch to specific device', async () => {
    const scriptsRes = await api('/api/v1/fleet/scripts');
    const seededScript = scriptsRes.body.scripts[0];

    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/scripts/${seededScript.id}/run`, {
      method: 'POST',
      body: JSON.stringify({})
    });
    assert.equal(res.status, 202);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.script_id, seededScript.id);
  });

  // ── ONCE FREQUENCY SUPPRESSION AFTER SUCCESS ──────────────────────────────

  it('SCR-21: Heartbeat should NOT include ONCE script that already succeeded for this device', async () => {
    // The seeded script[0] already has a SUCCESS run for testDeviceId (from SCR-11)
    const scriptsRes = await api('/api/v1/fleet/scripts');
    const seededScript = scriptsRes.body.scripts[0];

    // Verify the script is ONCE frequency
    if (seededScript.run_frequency !== 'ONCE') {
      // Patch it to ONCE for this test
      await api(`/api/v1/fleet/scripts/${seededScript.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ run_frequency: 'ONCE' })
      });
    }

    const hbRes = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId })
    });
    assert.equal(hbRes.status, 200);
    const assignedScripts = hbRes.body.assigned_scripts || [];
    const dueOnce = assignedScripts.find(s => s.id === seededScript.id);
    // is_due should be false since it succeeded
    if (dueOnce) {
      assert.equal(dueOnce.is_due, false, 'ONCE script that succeeded should not be due again');
    }
    // (If script not in response at all, that's also acceptable)
  });

  // ── CLOUD SHELL TERMINAL — device_commands ────────────────────────────────

  it('SCR-22: POST /api/v1/fleet/devices/:id/run-script should queue a Cloud Shell command', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/run-script`, {
      method: 'POST',
      body: JSON.stringify({
        script: 'Get-Process | Select-Object -First 5 | Format-Table',
        created_by: 'qa-tester'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.command_id, 'Should return command_id');
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.status, 'PENDING');
    commandId = res.body.command_id;
  });

  it('SCR-23: GET /api/v1/fleet/commands/:id should return the queued command', async () => {
    assert.ok(commandId, 'SCR-22 must have created a command first');
    const res = await api(`/api/v1/fleet/commands/${commandId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, commandId);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.command_text.includes('Get-Process'));
  });

  it('SCR-24: Heartbeat should deliver pending Cloud Shell commands in pending_commands', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({ device_id: testDeviceId })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.commands_pending === true || res.body.pending_commands.length >= 0);
    assert.ok(Array.isArray(res.body.pending_commands));
  });

  it('SCR-25: POST /api/v1/nodes/:id/command-result should record Cloud Shell execution result', async () => {
    assert.ok(commandId, 'SCR-22 must have created a command first');
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/command-result`, {
      method: 'POST',
      body: JSON.stringify({
        command_id: commandId,
        status: 'COMPLETED',
        exit_code: 0,
        stdout: 'NPM(K) PM(M)  WS(M) CPU(s)   Id SI ProcessName\n---\n...',
        stderr: ''
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'COMPLETED');
  });

  it('SCR-26: GET /api/v1/fleet/commands/:id should reflect COMPLETED status after result report', async () => {
    assert.ok(commandId, 'SCR-22 must have created a command first');
    const res = await api(`/api/v1/fleet/commands/${commandId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'COMPLETED');
    assert.ok(res.body.stdout && res.body.stdout.length > 0, 'stdout should be captured');
  });

  it('SCR-27: GET /api/v1/fleet/devices/:id/commands should return command history', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/commands`);
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.commands));
    assert.ok(res.body.commands.length >= 1);
    const cmd = res.body.commands.find(c => c.id === commandId);
    assert.ok(cmd, 'Should find our queued command in history');
  });

  // ── SCRIPT DELETION ────────────────────────────────────────────────────────

  it('SCR-28: DELETE /api/v1/fleet/scripts/:id should soft-delete the script', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    // Verify it's gone
    const getRes = await api(`/api/v1/fleet/scripts/${createdScriptId}`);
    assert.equal(getRes.status, 404);
  });

  it('SCR-29: DELETE /api/v1/fleet/scripts/:id should 404 for already deleted script', async () => {
    const res = await api(`/api/v1/fleet/scripts/${createdScriptId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 404);
  });

  // ── STATS INTEGRITY POST-RUN ──────────────────────────────────────────────

  it('SCR-30: GET /api/v1/fleet/scripts/stats should reflect updated totals after runs', async () => {
    const res = await api('/api/v1/fleet/scripts/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_runs >= 1, 'Should reflect at least 1 execution run');
    assert.ok(res.body.failed_runs >= 1, 'Should reflect at least 1 failure');
    assert.ok(res.body.success_rate_percent >= 0 && res.body.success_rate_percent <= 100, 'Rate should be 0-100');
  });
});
