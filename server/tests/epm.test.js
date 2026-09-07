/**
 * LocalPilot Fleet — Endpoint Privilege Management (EPM) QA Tests
 * server/tests/epm.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as epmEngine from '../src/services/epmEngine.js';

describe('Endpoint Privilege Management (EPM) QA (epm.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-epm-qa';
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

  describe('1. EPM Policy Management Endpoints', () => {
    it('GET /api/v1/fleet/epm/policies returns seed policies with attached rule counts', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.policies));
      assert.ok(data.policies.length >= 2);

      const baseline = data.policies.find(p => p.id === 'epm-enterprise-baseline');
      assert.ok(baseline);
      assert.equal(baseline.default_elevation_action, 'REQUIRE_JUSTIFICATION');
      assert.equal(baseline.is_enabled, 1);
      assert.ok(baseline.rule_count >= 2);
    });

    it('GET /api/v1/fleet/epm/policies/:id returns specific policy with attached rules', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/policies/epm-workstations-dev`, { headers: authHeader });
      assert.equal(res.status, 200);
      const policy = await res.json();
      assert.equal(policy.id, 'epm-workstations-dev');
      assert.ok(Array.isArray(policy.rules));
      assert.ok(policy.rules.length >= 2);
    });

    it('POST /api/v1/fleet/epm/policies creates a new custom EPM policy', async () => {
      const newPolicy = {
        name: 'Gaming & Streamer Zero-Lag Elevation',
        description: 'Auto-elevates approved GPU utilities and game capture tools',
        target_group_id: 'grp-workstations',
        default_elevation_action: 'REQUIRE_JUSTIFICATION',
        send_elevation_telemetry: true,
        is_enabled: true
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPolicy)
      });
      assert.equal(res.status, 201);
      const created = await res.json();
      assert.ok(created.id);
      assert.equal(created.name, newPolicy.name);
      assert.equal(created.target_group_id, 'grp-workstations');
    });

    it('PATCH /api/v1/fleet/epm/policies/:id updates policy metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/policies/epm-enterprise-baseline`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({ default_elevation_action: 'AUTO_ELEVATE', description: 'Updated baseline description' })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.default_elevation_action, 'AUTO_ELEVATE');
      assert.equal(updated.description, 'Updated baseline description');
    });

    it('DELETE /api/v1/fleet/epm/policies/:id removes an EPM policy', async () => {
      // Create temporary policy to delete
      const tempPolicy = epmEngine.createEpmPolicy(app.db, {
        name: 'Temporary Policy for Deletion',
        target_group_id: 'grp-all'
      });

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/policies/${tempPolicy.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);

      const check = epmEngine.getEpmPolicy(app.db, tempPolicy.id);
      assert.equal(check, null);
    });
  });

  describe('2. EPM Elevation Rules Endpoints', () => {
    it('GET /api/v1/fleet/epm/rules returns all active elevation rules', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/rules`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.rules));
      assert.ok(data.rules.length >= 4);

      const wingetRule = data.rules.find(r => r.id === 'rule-winget');
      assert.ok(wingetRule);
      assert.equal(wingetRule.elevation_type, 'AUTOMATIC');
      assert.equal(wingetRule.file_name, 'winget.exe');
    });

    it('POST /api/v1/fleet/epm/rules creates a new granular elevation rule', async () => {
      const newRule = {
        policy_id: 'epm-enterprise-baseline',
        rule_name: 'Developer Git Bash',
        description: 'Allows git-bash to execute elevated administrative hooks',
        elevation_type: 'USER_CONFIRMED',
        file_name: 'git-bash.exe',
        file_path: 'C:\\Program Files\\Git\\git-bash.exe',
        child_process_rule: 'ELEVATE_ALL_CHILDREN'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/rules`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newRule)
      });
      assert.equal(res.status, 201);
      const created = await res.json();
      assert.ok(created.id);
      assert.equal(created.file_name, 'git-bash.exe');
      assert.equal(created.elevation_type, 'USER_CONFIRMED');
      assert.equal(created.child_process_rule, 'ELEVATE_ALL_CHILDREN');
    });

    it('POST /api/v1/fleet/epm/rules rejects invalid elevation type', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/rules`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          policy_id: 'epm-enterprise-baseline',
          rule_name: 'Bad Rule',
          elevation_type: 'INVALID_TYPE',
          file_name: 'test.exe'
        })
      });
      assert.equal(res.status, 400);
    });

    it('PATCH /api/v1/fleet/epm/rules/:id updates rule attributes', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/rules/rule-wireshark`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({ elevation_type: 'USER_CONFIRMED', min_file_version: '4.0.0' })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.elevation_type, 'USER_CONFIRMED');
      assert.equal(updated.min_file_version, '4.0.0');
    });

    it('DELETE /api/v1/fleet/epm/rules/:id removes an elevation rule', async () => {
      const tempRule = epmEngine.createEpmRule(app.db, {
        policy_id: 'epm-enterprise-baseline',
        rule_name: 'Temporary Deletion Rule',
        elevation_type: 'AUTOMATIC',
        file_name: 'temp_to_delete.exe'
      });

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/rules/${tempRule.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const check = epmEngine.getEpmRule(app.db, tempRule.id);
      assert.equal(check, undefined);
    });
  });

  describe('3. Dynamic Group Resolution & Node Rules Ingest', () => {
    it('GET /api/v1/nodes/:id/epm-rules delivers assigned rules to enrolled node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-rules`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.rules));
      assert.ok(data.rules.length >= 2);
      assert.ok(data.rules.some(r => r.file_name === 'procexp.exe'));
    });

    it('Heartbeat response includes effective EPM rules', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: 'dev-daddy-pc',
          hostname: 'DADDY-DESKTOP',
          status: 'online',
          cpu_usage_percent: 12.5,
          ram_usage_percent: 45.0
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.epm_rules));
      assert.ok(data.epm_rules.length >= 2);
    });
  });

  describe('4. Elevation Requests & Approval Workflow', () => {
    it('POST /api/v1/nodes/:id/epm-request auto-approves matching AUTOMATIC rule', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-request`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          requested_by_user: 'Tony',
          file_name: 'winget.exe',
          file_path: 'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_\\winget.exe',
          justification: 'Automated background deployment of developer tooling'
        })
      });
      assert.equal(res.status, 201);
      const result = await res.json();
      assert.equal(result.status, 'APPROVED');
      assert.equal(result.elevation_type, 'AUTOMATIC');
      assert.ok(result.expires_at);
    });

    it('POST /api/v1/nodes/:id/epm-request auto-approves matching USER_CONFIRMED rule with justification', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-request`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          requested_by_user: 'Tony',
          file_name: 'procexp.exe',
          file_path: 'C:\\Program Files\\Sysinternals\\procexp.exe',
          justification: 'Troubleshooting high DPC latency on audio interface'
        })
      });
      assert.equal(res.status, 201);
      const result = await res.json();
      assert.equal(result.status, 'APPROVED');
      assert.equal(result.elevation_type, 'USER_CONFIRMED');
    });

    it('POST /api/v1/nodes/:id/epm-request queues PENDING status for SUPPORT_APPROVED rule', async () => {
      // First update rule-wireshark back to SUPPORT_APPROVED
      epmEngine.updateEpmRule(app.db, 'rule-wireshark', { elevation_type: 'SUPPORT_APPROVED' });

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-request`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          requested_by_user: 'Tony',
          file_name: 'Wireshark.exe',
          file_path: 'C:\\Program Files\\Wireshark\\Wireshark.exe',
          justification: 'Capturing packet drops on home subnet'
        })
      });
      assert.equal(res.status, 201);
      const result = await res.json();
      assert.equal(result.status, 'PENDING');
      assert.equal(result.elevation_type, 'SUPPORT_APPROVED');

      // Operator review endpoint approves request
      const reviewRes = await fetch(`${app.baseUrl}/api/v1/fleet/epm/requests/${result.request_id}/review`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          decision: 'APPROVED',
          reviewed_by: 'Matthew Bubb (Admin)',
          notes: 'Granted for 4 hours diagnostic capture window',
          valid_hours: 4
        })
      });
      assert.equal(reviewRes.status, 200);
      const reviewed = await reviewRes.json();
      assert.equal(reviewed.status, 'APPROVED');
      assert.equal(reviewed.reviewed_by, 'Matthew Bubb (Admin)');
      assert.ok(reviewed.expires_at);
    });

    it('POST /api/v1/nodes/:id/epm-request rejects empty or short justification (< 3 chars)', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-request`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          requested_by_user: 'Tony',
          file_name: 'procexp.exe',
          justification: 'no'
        })
      });
      assert.equal(res.status, 400);
    });
  });

  describe('5. Process Elevation Telemetry Ingestion & Audit Trail', () => {
    it('POST /api/v1/nodes/:id/epm-elevation ingests elevated execution event', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/epm-elevation`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          user_name: 'Tony',
          file_name: 'procexp.exe',
          file_path: 'C:\\Program Files\\Sysinternals\\procexp.exe',
          file_hash_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          elevation_type: 'USER_CONFIRMED',
          justification: 'Examining process tree',
          process_id: 19842,
          parent_process_name: 'explorer.exe'
        })
      });
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.status, 'LOGGED');
      assert.ok(body.id);
    });

    it('GET /api/v1/fleet/epm/logs returns forensic elevation audit records', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/logs?device_id=dev-daddy-pc`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.elevation_logs));
      assert.ok(data.elevation_logs.length >= 1);
      assert.ok(data.elevation_logs.some(l => l.file_name === 'procexp.exe'));
    });

    it('GET /api/v1/fleet/devices/:id/epm returns complete device posture', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/epm`, { headers: authHeader });
      assert.equal(res.status, 200);
      const posture = await res.json();
      assert.equal(posture.device_id, 'dev-daddy-pc');
      assert.ok(Array.isArray(posture.effective_rules));
      assert.ok(Array.isArray(posture.recent_elevations));
      assert.ok(posture.rules_count >= 2);
    });
  });

  describe('6. Fleet KPI Analytics', () => {
    it('GET /api/v1/fleet/epm/stats returns aggregated fleet KPI summary', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/epm/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_policies >= 2);
      assert.ok(stats.total_rules >= 4);
      assert.ok(stats.total_elevations >= 1);
    });
  });
});
