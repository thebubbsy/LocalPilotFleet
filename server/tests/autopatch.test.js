/**
 * LocalPilot Fleet — Windows Autopatch & Automated Patch Release Cadence QA Tests
 * server/tests/autopatch.test.js
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as autopatchEngine from '../src/services/autopatchEngine.js';

describe('Windows Autopatch & Automated Patch Release Cadence QA (autopatch.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-autopatch-qa';
  let testDeviceId;
  let testNodeToken;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test workstation
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': FLEET_KEY
      },
      body: JSON.stringify({
        hostname: 'AP-WORKSTATION-01',
        friendly_name: 'Autopatch Workstation 01',
        serial_number: 'AP-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '24H2',
        total_ram_bytes: 34359738368
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

  // AP-01: Engine Stats
  test('AP-01: getAutopatchStats returns overview metrics', () => {
    const stats = autopatchEngine.getAutopatchStats(app.db);
    assert.ok(stats);
    assert.ok(stats.total_releases >= 1);
    assert.ok(typeof stats.fleet_compliance_rate_percent === 'number');
  });

  // AP-02: Rings Definition
  test('AP-02: getRings returns 4 standard progressive rings with phase order', () => {
    const rings = autopatchEngine.getRings(app.db);
    assert.equal(rings.length, 4);
    assert.deepEqual(rings.map(r => r.id), ['ring-test', 'ring-first', 'ring-fast', 'ring-broad']);
    assert.equal(rings[0].phase_order, 1);
    assert.equal(rings[3].phase_order, 4);
  });

  // AP-03: Update Ring
  test('AP-03: updateRing updates deferral days and quality gate thresholds', () => {
    const updated = autopatchEngine.updateRing(app.db, 'ring-fast', {
      deferral_days: 5,
      max_allowable_crash_rate: 1.8,
      min_success_rate: 96.0
    });
    assert.equal(updated.deferral_days, 5);
    assert.equal(updated.max_allowable_crash_rate, 1.8);
    assert.equal(updated.min_success_rate, 96.0);
  });

  // AP-04: Releases List
  test('AP-04: getReleases returns seeded release', () => {
    const releases = autopatchEngine.getReleases(app.db);
    assert.ok(releases.length >= 1);
    const seeded = releases.find(r => r.id === 'rel-2026-09-b');
    assert.ok(seeded);
    assert.equal(seeded.release_type, 'SECURITY_QUALITY');
  });

  // AP-05: Create Monthly Release
  test('AP-05: createRelease creates new Monthly Quality Update release', () => {
    const rel = autopatchEngine.createRelease(app.db, {
      id: 'rel-2026-10-b',
      name: 'Windows 11 October 2026 Quality Update',
      release_month: '2026-10',
      release_type: 'SECURITY_QUALITY',
      target_kb_numbers: 'KB5045000',
      active_phase: 'TEST'
    });
    assert.equal(rel.id, 'rel-2026-10-b');
    assert.equal(rel.active_phase, 'TEST');
    assert.equal(rel.approval_status, 'AUTOMATIC_APPROVED');
  });

  // AP-06: Create Out-of-band expedited release
  test('AP-06: createRelease supports OUT_OF_BAND_EXPEDITED zero-day releases', () => {
    const rel = autopatchEngine.createRelease(app.db, {
      id: 'rel-2026-zero-day',
      name: 'Emergency Out-of-Band Kernel Patch',
      release_month: '2026-09',
      release_type: 'OUT_OF_BAND_EXPEDITED',
      target_kb_numbers: 'KB5049999',
      active_phase: 'BROAD'
    });
    assert.equal(rel.release_type, 'OUT_OF_BAND_EXPEDITED');
    assert.equal(rel.active_phase, 'BROAD');
  });

  // AP-07: Get Release
  test('AP-07: getRelease returns release with deployment details', () => {
    const rel = autopatchEngine.getRelease(app.db, 'rel-2026-09-b');
    assert.ok(rel);
    assert.equal(rel.id, 'rel-2026-09-b');
    assert.ok(Array.isArray(rel.deployments));
  });

  // AP-08: Update Release
  test('AP-08: updateRelease modifies target KBs and approval status', () => {
    const updated = autopatchEngine.updateRelease(app.db, 'rel-2026-10-b', {
      target_kb_numbers: 'KB5045000, KB5045001',
      approval_status: 'PAUSED'
    });
    assert.equal(updated.target_kb_numbers, 'KB5045000, KB5045001');
    assert.equal(updated.approval_status, 'PAUSED');
  });

  // AP-09: Progress Phase
  test('AP-09: progressReleasePhase advances phase from TEST -> FIRST -> FAST -> BROAD', () => {
    const r1 = autopatchEngine.progressReleasePhase(app.db, 'rel-2026-10-b');
    assert.equal(r1.active_phase, 'FIRST');
    const r2 = autopatchEngine.progressReleasePhase(app.db, 'rel-2026-10-b');
    assert.equal(r2.active_phase, 'FAST');
    const r3 = autopatchEngine.progressReleasePhase(app.db, 'rel-2026-10-b');
    assert.equal(r3.active_phase, 'BROAD');
    const r4 = autopatchEngine.progressReleasePhase(app.db, 'rel-2026-10-b');
    assert.equal(r4.active_phase, 'COMPLETED');
  });

  // AP-10: Trigger Rollback
  test('AP-10: triggerPatchRollback sets ROLLED_BACK status and reason', () => {
    const rolledBack = autopatchEngine.triggerPatchRollback(app.db, 'rel-2026-10-b', 'BSOD spike detected in Broad Ring');
    assert.equal(rolledBack.approval_status, 'ROLLED_BACK');
    assert.equal(rolledBack.active_phase, 'ROLLED_BACK');
    assert.equal(rolledBack.rollback_reason, 'BSOD spike detected in Broad Ring');
  });

  // AP-11: Generate Rollback Script
  test('AP-11: generateRollbackScript synthesizes silent wusa.exe removal commands', () => {
    const script = autopatchEngine.generateRollbackScript('KB5044284, KB5044310');
    assert.ok(script.includes('wusa.exe /uninstall /kb:5044284 /quiet /norestart'));
    assert.ok(script.includes('wusa.exe /uninstall /kb:5044310 /quiet /norestart'));
  });

  // AP-12: Record Device Patch Report
  test('AP-12: recordDevicePatchReport stores device installation status and applied KB', () => {
    const dep = autopatchEngine.recordDevicePatchReport(app.db, testDeviceId, {
      release_id: 'rel-2026-09-b',
      ring_id: 'ring-first',
      install_status: 'INSTALLED',
      applied_kb: 'KB5044284',
      exit_code: 0
    });
    assert.ok(dep);
    assert.equal(dep.device_id, testDeviceId);
    assert.equal(dep.install_status, 'INSTALLED');
    assert.equal(dep.applied_kb, 'KB5044284');
  });

  // AP-13: Crash Feedback
  test('AP-13: recordDevicePatchReport tracks post-patch crash metrics', () => {
    const dep = autopatchEngine.recordDevicePatchReport(app.db, testDeviceId, {
      release_id: 'rel-2026-09-b',
      post_patch_crashes: 2
    });
    assert.equal(dep.post_patch_crashes, 2);
  });

  // AP-14: Filter Deployments
  test('AP-14: getDeviceDeployments filters deployments by release_id, ring_id, or install_status', () => {
    const deps = autopatchEngine.getDeviceDeployments(app.db, { release_id: 'rel-2026-09-b', install_status: 'INSTALLED' });
    assert.ok(deps.length >= 1);
    assert.equal(deps[0].install_status, 'INSTALLED');
  });

  // AP-15: Device Autopatch Status
  test('AP-15: getDeviceAutopatchStatus returns device deployment and ring info', () => {
    const status = autopatchEngine.getDeviceAutopatchStatus(app.db, testDeviceId);
    assert.ok(status);
    assert.equal(status.device_id, testDeviceId);
    assert.equal(status.ring_id, 'ring-first');
  });

  // AP-16: Delete Release
  test('AP-16: deleteRelease removes release and associated deployments', () => {
    const ok = autopatchEngine.deleteRelease(app.db, 'rel-2026-zero-day');
    assert.equal(ok, true);
    assert.equal(autopatchEngine.getRelease(app.db, 'rel-2026-zero-day'), null);
  });

  // AP-17: REST GET /api/v1/fleet/autopatch/stats
  test('AP-17: REST GET /api/v1/fleet/autopatch/stats returns aggregate metrics', async () => {
    const { status, body } = await api('/api/v1/fleet/autopatch/stats');
    assert.equal(status, 200);
    assert.ok(body.total_releases >= 1);
    assert.ok(body.total_rings === 4);
    assert.ok(Array.isArray(body.rings));
  });

  // AP-18: REST GET /api/v1/fleet/autopatch/releases and CRUD
  test('AP-18: REST CRUD /api/v1/fleet/autopatch/releases works cleanly', async () => {
    const createRes = await api('/api/v1/fleet/autopatch/releases', {
      method: 'POST',
      body: JSON.stringify({
        id: 'rel-rest-test',
        name: 'REST Autopatch Release Test',
        release_month: '2026-11',
        release_type: 'SECURITY_QUALITY',
        target_kb_numbers: 'KB5046000',
        active_phase: 'TEST'
      })
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.body.release.id, 'rel-rest-test');

    const getRes = await api('/api/v1/fleet/autopatch/releases/rel-rest-test');
    assert.equal(getRes.status, 200);
    assert.equal(getRes.body.name, 'REST Autopatch Release Test');

    const progRes = await api('/api/v1/fleet/autopatch/releases/rel-rest-test/progress', { method: 'POST' });
    assert.equal(progRes.status, 200);
    assert.equal(progRes.body.new_phase, 'FIRST');

    const rollbackRes = await api('/api/v1/fleet/autopatch/releases/rel-rest-test/rollback', {
      method: 'POST',
      body: JSON.stringify({ reason: 'REST test rollback trigger' })
    });
    assert.equal(rollbackRes.status, 200);
    assert.equal(rollbackRes.body.release.active_phase, 'ROLLED_BACK');
    assert.ok(rollbackRes.body.rollback_script.includes('KB5046000'));

    const delRes = await api('/api/v1/fleet/autopatch/releases/rel-rest-test', { method: 'DELETE' });
    assert.equal(delRes.status, 200);
    assert.equal(delRes.body.deleted_id, 'rel-rest-test');
  });

  // AP-19: REST Rings & Deployments
  test('AP-19: REST Rings and Deployments endpoints return valid payload structures', async () => {
    const ringsRes = await api('/api/v1/fleet/autopatch/rings');
    assert.equal(ringsRes.status, 200);
    assert.equal(ringsRes.body.count, 4);

    const updateRingRes = await api('/api/v1/fleet/autopatch/rings/ring-test', {
      method: 'PUT',
      body: JSON.stringify({ deferral_days: 1 })
    });
    assert.equal(updateRingRes.status, 200);
    assert.equal(updateRingRes.body.ring.deferral_days, 1);

    const depsRes = await api('/api/v1/fleet/autopatch/deployments');
    assert.equal(depsRes.status, 200);
    assert.ok(Array.isArray(depsRes.body.deployments));

    const devStatusRes = await api(`/api/v1/fleet/devices/${testDeviceId}/autopatch`);
    assert.equal(devStatusRes.status, 200);
    assert.equal(devStatusRes.body.device_id, testDeviceId);
  });

  // AP-20: Node Telemetry & Patch Reporting (GET & POST)
  test('AP-20: Node API routes handle patch status query and installation reporting', async () => {
    const nodeHeaders = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`
    };

    const getRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/autopatch`, {
      headers: nodeHeaders
    });
    assert.equal(getRes.status, 200);
    const nodeStatus = await getRes.json();
    assert.ok(nodeStatus.device_id);

    const postRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/autopatch/report`, {
      method: 'POST',
      headers: nodeHeaders,
      body: JSON.stringify({
        release_id: 'rel-2026-09-b',
        ring_id: 'ring-first',
        install_status: 'INSTALLED',
        applied_kb: 'KB5044284',
        exit_code: 0,
        post_patch_crashes: 0
      })
    });
    assert.equal(postRes.status, 200);
    const reportData = await postRes.json();
    assert.equal(reportData.success, true);
    assert.equal(reportData.deployment.install_status, 'INSTALLED');
  });
});
