/**
 * LocalPilot Fleet — Proactive Remediations QA Tests
 * server/tests/remediations.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Proactive Remediations QA (remediations.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-secret-qa';
  const authHeader = { 'X-Fleet-Key': FLEET_KEY };
  const jsonHeader = { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY };

  before(async () => {
    app = await createTestApp({
      fleetKey: FLEET_KEY,
      seed: true
    });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. Fleet Proactive Remediation Endpoints', () => {
    it('GET /api/v1/fleet/remediations returns seed packages with statistics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.remediations));
      assert.ok(data.remediations.length >= 3);

      const tempPkg = data.remediations.find(r => r.id === 'rem-temp-cleanup');
      assert.ok(tempPkg);
      assert.equal(tempPkg.name, 'Auto-Clean Stale Temporary Files & Crash Dumps');
      assert.ok(tempPkg.stats);
      assert.ok(tempPkg.stats.total_runs >= 2);
    });

    it('GET /api/v1/fleet/remediations/stats returns fleet health and healing rate', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_packages >= 3);
      assert.ok(stats.evaluated_devices >= 2);
      assert.ok(stats.issues_detected >= 1);
      assert.ok(stats.issues_remediated >= 1);
      assert.ok(stats.self_healing_rate_pct > 0);
    });

    it('POST /api/v1/fleet/remediations creates a new script package', async () => {
      const newPkg = {
        name: 'Custom Test Package',
        description: 'Verifies test environment integrity',
        target_group_id: 'grp-workstations',
        schedule_type: 'DAILY',
        detection_script: 'Write-Host "Checking"; exit 0',
        remediation_script: 'Write-Host "Fixing"; exit 0'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPkg)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.equal(created.name, newPkg.name);
      assert.equal(created.target_group_id, newPkg.target_group_id);
      assert.equal(created.schedule_type, newPkg.schedule_type);
      assert.ok(created.id.startsWith('rem-'));
    });

    it('PATCH /api/v1/fleet/remediations/:id updates existing package metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/rem-spooler-heal`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          description: 'Updated description for spooler',
          schedule_type: 'HOURLY'
        })
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.description, 'Updated description for spooler');
      assert.equal(updated.schedule_type, 'HOURLY');
    });

    it('GET /api/v1/fleet/remediations/:id returns detailed package with run history', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/rem-temp-cleanup`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.id, 'rem-temp-cleanup');
      assert.ok(Array.isArray(data.runs));
      assert.ok(data.runs.length >= 2);
    });

    it('POST /api/v1/fleet/remediations/:id/run-now dispatches commands to target devices', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/rem-temp-cleanup/run-now`, {
        method: 'POST',
        headers: authHeader
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.target_count >= 1);
      assert.ok(Array.isArray(data.dispatched_targets));
    });
  });

  describe('2. Node Agent Remediation Ingest & Execution', () => {
    it('GET /api/v1/nodes/:id/remediations returns assigned packages for node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/remediations`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.remediations));
      assert.ok(data.remediations.length >= 3);
    });

    it('POST /api/v1/nodes/:id/remediation-result records clean detection (NO_ISSUE)', async () => {
      const resultPayload = {
        remediation_id: 'rem-dns-flush',
        detection_exit_code: 0,
        detection_stdout: 'DNS client resolution operational',
        detection_stderr: ''
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/remediation-result`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(resultPayload)
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.detection_status, 'NO_ISSUE');
      assert.equal(data.remediation_status, 'NOT_NEEDED');
      assert.ok(data.run_id);
    });

    it('POST /api/v1/nodes/:id/remediation-result records auto-healed issue (REMEDIATED)', async () => {
      const resultPayload = {
        remediation_id: 'rem-spooler-heal',
        detection_exit_code: 1,
        detection_stdout: 'Print Spooler is stopped',
        detection_stderr: '',
        remediation_exit_code: 0,
        remediation_stdout: 'Print Spooler service restarted.',
        remediation_stderr: ''
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/remediation-result`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(resultPayload)
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.detection_status, 'ISSUE_DETECTED');
      assert.equal(data.remediation_status, 'REMEDIATED');
    });

    it('POST /api/v1/nodes/:id/remediation-result records remediation failure (FAILED)', async () => {
      const resultPayload = {
        remediation_id: 'rem-spooler-heal',
        detection_exit_code: 1,
        detection_stdout: 'Print Spooler is stopped',
        detection_stderr: '',
        remediation_exit_code: 2,
        remediation_stdout: '',
        remediation_stderr: 'Access denied restarting spooler'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/remediation-result`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(resultPayload)
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.detection_status, 'ISSUE_DETECTED');
      assert.equal(data.remediation_status, 'FAILED');
    });
  });

  describe('3. Package Lifecycle & Cascade Deletion', () => {
    it('DELETE /api/v1/fleet/remediations/:id deletes package and cascades runs', async () => {
      // 1. Create temporary package
      const postRes = await fetch(`${app.baseUrl}/api/v1/fleet/remediations`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Temporary Deletion Target',
          detection_script: 'exit 0',
          remediation_script: 'exit 0'
        })
      });
      const created = await postRes.json();
      const tempId = created.id;

      // 2. Add run for it
      await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/remediation-result`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          remediation_id: tempId,
          detection_exit_code: 0
        })
      });

      // 3. Delete package
      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/${tempId}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      // 4. Verify package is gone
      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/remediations/${tempId}`, {
        headers: authHeader
      });
      assert.equal(getRes.status, 404);
    });
  });
});
