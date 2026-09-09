/**
 * LocalPilot Fleet — Endpoint Analytics & Executive Reporting QA
 * server/tests/analytics.test.js
 *
 * Tests: Health scoring algorithms, device snapshot ingestion,
 * application crash/hang telemetry, top-crashes aggregation,
 * startup performance metrics, and executive reports generation.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { calculateHealthScores } from '../src/services/analyticsEngine.js';

describe('Microsoft Intune Endpoint Analytics & Executive Reports QA (analytics.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-analytics-qa';
  let testDeviceId;
  let testNodeToken;
  let createdReportId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'QA-ANALYTICS-RIG',
        serial_number: 'SN-ANALYTICS-TEST-001',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26200',
        total_ram_bytes: 34359738368,
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        primary_user: 'qa-analytics-lead'
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

  // ── UNIT SCORING ALGORITHM TESTS ──────────────────────────────────────────

  it('ANA-01: calculateHealthScores returns perfect 100 for healthy low-latency metrics', () => {
    const scores = calculateHealthScores({
      bootDurationMs: 15000,
      signinDurationMs: 3000,
      appCrashCount24h: 0,
      appHangCount24h: 0,
      cpuSpikePct: 2.0,
      ramPressurePct: 40.0,
      diskQueueDepth: 0.1
    });
    assert.equal(scores.startupScore, 100);
    assert.equal(scores.reliabilityScore, 100);
    assert.equal(scores.resourceScore, 100);
    assert.equal(scores.overallHealthScore, 100);
  });

  it('ANA-02: calculateHealthScores penalizes slow boot & sign-in durations', () => {
    const scores = calculateHealthScores({
      bootDurationMs: 75000, // 75 seconds
      signinDurationMs: 35000, // 35 seconds
      appCrashCount24h: 0,
      appHangCount24h: 0
    });
    assert.ok(scores.startupScore < 50, 'Startup score should be heavily penalized');
    assert.equal(scores.reliabilityScore, 100);
    assert.ok(scores.overallHealthScore < 100);
  });

  it('ANA-03: calculateHealthScores penalizes app crashes and hangs', () => {
    const scores = calculateHealthScores({
      bootDurationMs: 18000,
      signinDurationMs: 4000,
      appCrashCount24h: 3, // 3 * 15 = 45 deduction
      appHangCount24h: 2  // 2 * 10 = 20 deduction
    });
    assert.equal(scores.startupScore, 100);
    assert.equal(scores.reliabilityScore, 35); // 100 - 65 = 35
    assert.ok(scores.overallHealthScore < 85);
  });

  it('ANA-04: calculateHealthScores penalizes high RAM pressure and CPU spikes', () => {
    const scores = calculateHealthScores({
      cpuSpikePct: 40.0,
      ramPressurePct: 95.0,
      diskQueueDepth: 4.0
    });
    assert.ok(scores.resourceScore < 60, 'Resource score should reflect high pressure');
  });

  // ── FLEET ANALYTICS REST API ──────────────────────────────────────────────

  it('ANA-05: GET /api/v1/fleet/analytics/scores returns default values before snapshots', async () => {
    const res = await api('/api/v1/fleet/analytics/scores');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.avg_health_score === 'number');
    assert.ok(typeof res.body.scored_devices === 'number');
    assert.ok(res.body.distribution, 'Should return distribution object');
  });

  it('ANA-06: POST /api/v1/nodes/:id/analytics-snapshot saves snapshot and returns 201', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/analytics-snapshot`, {
      method: 'POST',
      body: JSON.stringify({
        boot_duration_ms: 22000,
        signin_duration_ms: 6000,
        app_crash_count_24h: 1,
        app_hang_count_24h: 0,
        cpu_spike_pct: 8.5,
        ram_pressure_pct: 62.0,
        disk_queue_depth: 0.8
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(typeof res.body.overall_health_score === 'number');
    assert.ok(res.body.overall_health_score > 0);
  });

  it('ANA-07: POST /api/v1/nodes/:id/analytics-snapshot rejects invalid token with 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/analytics-snapshot`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer bad-token-xyz'
      },
      body: JSON.stringify({ boot_duration_ms: 20000 })
    });
    assert.equal(res.status, 401);
  });

  it('ANA-08: GET /api/v1/fleet/analytics/scores reflects recorded snapshot', async () => {
    const res = await api('/api/v1/fleet/analytics/scores');
    assert.equal(res.status, 200);
    assert.ok(res.body.scored_devices >= 1, 'Should show at least 1 scored device');
    assert.ok(res.body.avg_health_score > 0, 'Average score should be calculated');
  });

  // ── APPLICATION RELIABILITY TELEMETRY ─────────────────────────────────────

  it('ANA-09: POST /api/v1/nodes/:id/app-reliability records crash and hang events', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/app-reliability`, {
      method: 'POST',
      body: JSON.stringify({
        events: [
          {
            app_name: 'explorer.exe',
            app_version: '10.0.26200.5000',
            event_type: 'CRASH',
            faulting_module: 'ntdll.dll',
            exception_code: '0xc0000005',
            occurred_at: new Date().toISOString()
          },
          {
            app_name: 'chrome.exe',
            app_version: '128.0.6613.120',
            event_type: 'HANG',
            faulting_module: 'chrome.dll',
            exception_code: '0x80000003',
            occurred_at: new Date().toISOString()
          },
          {
            app_name: 'explorer.exe',
            app_version: '10.0.26200.5000',
            event_type: 'CRASH',
            faulting_module: 'twinui.pcshell.dll',
            exception_code: '0xc0000409',
            occurred_at: new Date().toISOString()
          }
        ]
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.saved_count, 3);
  });

  it('ANA-10: POST /api/v1/nodes/:id/app-reliability rejects invalid auth with 401', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/app-reliability`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer forged-token'
      },
      body: JSON.stringify({ events: [{ app_name: 'test.exe' }] })
    });
    assert.equal(res.status, 401);
  });

  it('ANA-11: GET /api/v1/fleet/analytics/top-crashes aggregates crashing applications', async () => {
    const res = await api('/api/v1/fleet/analytics/top-crashes');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.top_crashes));
    assert.ok(res.body.top_crashes.length >= 1);
    const explorer = res.body.top_crashes.find(c => c.app_name === 'explorer.exe');
    assert.ok(explorer, 'explorer.exe should be in top crashes');
    assert.equal(explorer.crash_count, 2);
  });

  it('ANA-12: GET /api/v1/fleet/analytics/top-crashes respects limit parameter', async () => {
    const res = await api('/api/v1/fleet/analytics/top-crashes?limit=1');
    assert.equal(res.status, 200);
    assert.equal(res.body.top_crashes.length, 1);
  });

  it('ANA-13: GET /api/v1/fleet/analytics/startup-performance returns boot and sign-in breakdown', async () => {
    const res = await api('/api/v1/fleet/analytics/startup-performance');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.avg_boot_seconds === 'number');
    assert.ok(typeof res.body.avg_signin_seconds === 'number');
    assert.ok(typeof res.body.fast_boot_devices === 'number');
  });

  // ── DEVICE ANALYTICS POSTURE ──────────────────────────────────────────────

  it('ANA-14: GET /api/v1/fleet/devices/:id/analytics returns device history and crash log', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/analytics`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.latest_snapshot, 'Should have latest snapshot');
    assert.ok(Array.isArray(res.body.history), 'Should have history array');
    assert.ok(Array.isArray(res.body.recent_events), 'Should have recent events array');
    assert.ok(res.body.recent_events.length >= 3, 'Should reflect the 3 recorded events');
  });

  it('ANA-15: GET /api/v1/fleet/devices/:id/analytics returns 404 for unknown device', async () => {
    const res = await api('/api/v1/fleet/devices/non-existent-device-id/analytics');
    assert.equal(res.status, 404);
  });

  // ── EXECUTIVE REPORTS ─────────────────────────────────────────────────────

  it('ANA-16: POST /api/v1/fleet/reports/generate creates FLEET_HEALTH report', async () => {
    const res = await api('/api/v1/fleet/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        report_type: 'FLEET_HEALTH',
        created_by: 'QA Automation'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.report_type, 'FLEET_HEALTH');
    assert.equal(res.body.created_by, 'QA Automation');
    createdReportId = res.body.id;
  });

  it('ANA-17: POST /api/v1/fleet/reports/generate creates COMPLIANCE_AUDIT report', async () => {
    const res = await api('/api/v1/fleet/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        report_type: 'COMPLIANCE_AUDIT'
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.report_type, 'COMPLIANCE_AUDIT');
  });

  it('ANA-18: POST /api/v1/fleet/reports/generate creates SECURITY_POSTURE report', async () => {
    const res = await api('/api/v1/fleet/reports/generate', {
      method: 'POST',
      body: JSON.stringify({
        report_type: 'SECURITY_POSTURE'
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.report_type, 'SECURITY_POSTURE');
  });

  it('ANA-19: GET /api/v1/fleet/reports lists generated reports', async () => {
    const res = await api('/api/v1/fleet/reports');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.reports));
    assert.ok(res.body.reports.length >= 3);
  });

  it('ANA-20: GET /api/v1/fleet/reports/:id returns single report with parsed summary', async () => {
    assert.ok(createdReportId, 'Must have createdReportId from ANA-16');
    const res = await api(`/api/v1/fleet/reports/${createdReportId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdReportId);
    assert.equal(res.body.report_type, 'FLEET_HEALTH');
    assert.ok(res.body.summary, 'Should parse summary JSON');
    assert.ok(typeof res.body.summary.total_devices === 'number');
  });
});
