/**
 * LocalPilot Fleet — Endpoint Analytics & Executive Reporting Engine
 * server/src/services/analyticsEngine.js
 *
 * Implements Microsoft Intune Endpoint Analytics:
 * - Startup Performance (boot duration, sign-in duration)
 * - Application Reliability (app crashes, hangs, faulting modules)
 * - Resource Performance (CPU spike frequency, RAM pressure, Disk Queue)
 * - Fleet Health Scoring & Executive Compliance Reports
 */

import { broadcastEvent } from '../routes/events.js';

function genId(prefix = 'das') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
}

/**
 * Calculate component & overall health scores (0-100 scale)
 */
export function calculateHealthScores(metrics = {}) {
  const {
    bootDurationMs = 25000,
    signinDurationMs = 8000,
    appCrashCount24h = 0,
    appHangCount24h = 0,
    cpuSpikePct = 5.0,
    ramPressurePct = 50.0,
    diskQueueDepth = 0.5
  } = metrics;

  // 1. Startup Score (0-100): Boot < 20s = 100, 90s+ = 0; Signin < 5s = 100, 45s+ = 0
  const bootSec = Math.max(0, bootDurationMs / 1000);
  const signinSec = Math.max(0, signinDurationMs / 1000);

  const bootScore = bootSec <= 20 ? 100 : Math.max(0, Math.round(100 - ((bootSec - 20) / 70) * 100));
  const signinScore = signinSec <= 5 ? 100 : Math.max(0, Math.round(100 - ((signinSec - 5) / 40) * 100));
  const startupScore = Math.round(bootScore * 0.6 + signinScore * 0.4);

  // 2. Reliability Score (0-100): 0 issues = 100, -15 per crash, -10 per hang
  const reliabilityDeductions = (Number(appCrashCount24h) * 15) + (Number(appHangCount24h) * 10);
  const reliabilityScore = Math.max(0, Math.min(100, 100 - reliabilityDeductions));

  // 3. Resource Score (0-100): Based on CPU spike, RAM pressure, Disk queue
  let resourceScore = 100;
  if (cpuSpikePct > 20) resourceScore -= Math.min(35, Math.round((cpuSpikePct - 20) * 1.5));
  if (ramPressurePct > 80) resourceScore -= Math.min(35, Math.round((ramPressurePct - 80) * 2));
  if (diskQueueDepth > 2.0) resourceScore -= Math.min(30, Math.round((diskQueueDepth - 2.0) * 10));
  resourceScore = Math.max(0, Math.min(100, resourceScore));

  // 4. Overall Health Score: 30% Startup, 35% Reliability, 35% Resource
  const overallHealthScore = Math.round(
    startupScore * 0.30 +
    reliabilityScore * 0.35 +
    resourceScore * 0.35
  );

  return {
    overallHealthScore,
    startupScore,
    reliabilityScore,
    resourceScore
  };
}

/**
 * Record or update a device analytics snapshot
 */
export function saveAnalyticsSnapshot(db, payload) {
  const {
    deviceId,
    bootDurationMs = 0,
    signinDurationMs = 0,
    appCrashCount24h = 0,
    appHangCount24h = 0,
    cpuSpikePct = 0,
    ramPressurePct = 0,
    diskQueueDepth = 0
  } = payload;

  if (!deviceId) throw new Error('deviceId is required');

  const scores = calculateHealthScores({
    bootDurationMs,
    signinDurationMs,
    appCrashCount24h,
    appHangCount24h,
    cpuSpikePct,
    ramPressurePct,
    diskQueueDepth
  });

  const id = genId('das');

  const stmt = db.prepare(`
    INSERT INTO device_analytics_snapshots (
      id, device_id, boot_duration_ms, signin_duration_ms,
      app_crash_count_24h, app_hang_count_24h, cpu_spike_pct,
      ram_pressure_pct, disk_queue_depth, overall_health_score,
      startup_score, reliability_score, resource_score,
      snapshot_date, created_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    deviceId,
    Number(bootDurationMs) || 0,
    Number(signinDurationMs) || 0,
    Number(appCrashCount24h) || 0,
    Number(appHangCount24h) || 0,
    Number(cpuSpikePct) || 0,
    Number(ramPressurePct) || 0,
    Number(diskQueueDepth) || 0,
    scores.overallHealthScore,
    scores.startupScore,
    scores.reliabilityScore,
    scores.resourceScore
  );

  broadcastEvent('analytics_snapshot_recorded', {
    id,
    device_id: deviceId,
    overall_health_score: scores.overallHealthScore
  });

  return db.prepare('SELECT * FROM device_analytics_snapshots WHERE id = ?').get(id);
}

/**
 * Ingest application crash and hang events
 */
export function saveAppReliabilityEvents(db, deviceId, events = []) {
  if (!deviceId) throw new Error('deviceId is required');
  if (!Array.isArray(events)) throw new Error('events must be an array');

  const insert = db.prepare(`
    INSERT INTO app_reliability_events (
      id, device_id, app_name, app_version, event_type,
      faulting_module, exception_code, occurred_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
  `);

  const saved = [];
  db.exec('BEGIN');
  try {
    for (const evt of events) {
      if (!evt.app_name) continue;
      const id = genId('are');
      const eventType = evt.event_type === 'HANG' ? 'HANG' : 'CRASH';
      insert.run(
        id,
        deviceId,
        String(evt.app_name),
        String(evt.app_version || ''),
        eventType,
        String(evt.faulting_module || ''),
        String(evt.exception_code || ''),
        evt.occurred_at || new Date().toISOString()
      );
      saved.push(id);
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch {}
    throw err;
  }

  return saved;
}

/**
 * Get fleet-wide aggregate scores and distribution
 */
export function getFleetAnalyticsScores(db) {
  const row = db.prepare(`
    WITH latest_snapshots AS (
      SELECT *,
             ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY created_at DESC) as rn
      FROM device_analytics_snapshots
    )
    SELECT
      COUNT(DISTINCT device_id) as scored_devices,
      AVG(overall_health_score) as avg_health_score,
      AVG(startup_score) as avg_startup_score,
      AVG(reliability_score) as avg_reliability_score,
      AVG(resource_score) as avg_resource_score,
      SUM(CASE WHEN overall_health_score >= 85 THEN 1 ELSE 0 END) as excellent_count,
      SUM(CASE WHEN overall_health_score >= 70 AND overall_health_score < 85 THEN 1 ELSE 0 END) as good_count,
      SUM(CASE WHEN overall_health_score < 70 THEN 1 ELSE 0 END) as needs_attention_count
    FROM latest_snapshots
    WHERE rn = 1
  `).get();

  const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const scoredDevices = row.scored_devices || 0;

  return {
    total_devices: totalDevices,
    scored_devices: scoredDevices,
    avg_health_score: scoredDevices > 0 ? Math.round(row.avg_health_score) : 100,
    avg_startup_score: scoredDevices > 0 ? Math.round(row.avg_startup_score) : 100,
    avg_reliability_score: scoredDevices > 0 ? Math.round(row.avg_reliability_score) : 100,
    avg_resource_score: scoredDevices > 0 ? Math.round(row.avg_resource_score) : 100,
    distribution: {
      excellent: row.excellent_count || 0,
      good: row.good_count || 0,
      needs_attention: row.needs_attention_count || 0
    }
  };
}

/**
 * Get top crashing applications across the fleet
 */
export function getTopCrashingApps(db, limit = 10) {
  const rows = db.prepare(`
    SELECT
      app_name,
      COUNT(*) as total_events,
      SUM(CASE WHEN event_type = 'CRASH' THEN 1 ELSE 0 END) as crash_count,
      SUM(CASE WHEN event_type = 'HANG' THEN 1 ELSE 0 END) as hang_count,
      COUNT(DISTINCT device_id) as affected_devices,
      MAX(occurred_at) as last_occurred_at
    FROM app_reliability_events
    GROUP BY app_name
    ORDER BY total_events DESC
    LIMIT ?
  `).all(Number(limit) || 10);

  return rows;
}

/**
 * Get fleet startup performance metrics
 */
export function getStartupPerformanceSummary(db) {
  const row = db.prepare(`
    WITH latest_snapshots AS (
      SELECT *,
             ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY created_at DESC) as rn
      FROM device_analytics_snapshots
    )
    SELECT
      AVG(boot_duration_ms) as avg_boot_ms,
      AVG(signin_duration_ms) as avg_signin_ms,
      SUM(CASE WHEN boot_duration_ms <= 30000 THEN 1 ELSE 0 END) as fast_boot_count,
      SUM(CASE WHEN boot_duration_ms > 30000 AND boot_duration_ms <= 60000 THEN 1 ELSE 0 END) as moderate_boot_count,
      SUM(CASE WHEN boot_duration_ms > 60000 THEN 1 ELSE 0 END) as slow_boot_count
    FROM latest_snapshots
    WHERE rn = 1
  `).get();

  const avgBootSec = row.avg_boot_ms ? (row.avg_boot_ms / 1000).toFixed(1) : '0.0';
  const avgSigninSec = row.avg_signin_ms ? (row.avg_signin_ms / 1000).toFixed(1) : '0.0';

  return {
    avg_boot_seconds: Number(avgBootSec),
    avg_signin_seconds: Number(avgSigninSec),
    fast_boot_devices: row.fast_boot_count || 0,
    moderate_boot_devices: row.moderate_boot_count || 0,
    slow_boot_devices: row.slow_boot_count || 0
  };
}

/**
 * Generate an executive compliance & health report
 */
export function generateExecutiveReport(db, reportType = 'FLEET_HEALTH', createdBy = 'LocalPilot Administrator') {
  const id = genId('rep');
  let summary = {};

  const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const activeDevices = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'active'").get().c;

  if (reportType === 'FLEET_HEALTH') {
    const scores = getFleetAnalyticsScores(db);
    const topCrashes = getTopCrashingApps(db, 5);
    const startup = getStartupPerformanceSummary(db);
    summary = {
      total_devices: totalDevices,
      active_devices: activeDevices,
      scores,
      top_crashes: topCrashes,
      startup
    };
  } else if (reportType === 'COMPLIANCE_AUDIT') {
    const compRows = db.prepare(`
      SELECT compliance_status, COUNT(*) as count
      FROM device_compliance_evaluations
      GROUP BY compliance_status
    `).all();
    const bitlockerProtected = db.prepare("SELECT COUNT(DISTINCT device_id) as c FROM device_bitlocker_volumes WHERE protection_status = 'PROTECTED'").get().c;
    summary = {
      total_devices: totalDevices,
      compliance_breakdown: compRows,
      bitlocker_protected_devices: bitlockerProtected
    };
  } else if (reportType === 'SECURITY_POSTURE') {
    const defenderRtp = db.prepare("SELECT COUNT(*) as c FROM device_antivirus_status WHERE real_time_protection_enabled = 1").get().c;
    const fwCompliant = db.prepare("SELECT COUNT(*) as c FROM device_firewall_status WHERE compliance_status = 'COMPLIANT'").get().c;
    const asrEventsToday = db.prepare("SELECT COUNT(*) as c FROM asr_events WHERE occurred_at >= DATETIME('now', '-1 day')").get().c;
    summary = {
      total_devices: totalDevices,
      defender_rtp_enabled_devices: defenderRtp,
      firewall_compliant_devices: fwCompliant,
      asr_events_last_24h: asrEventsToday
    };
  } else {
    summary = { total_devices: totalDevices, active_devices: activeDevices };
  }

  db.prepare(`
    INSERT INTO executive_reports (id, report_type, parameters_json, summary_json, created_by, generated_at)
    VALUES (?, ?, ?, ?, ?, DATETIME('now'))
  `).run(id, reportType, JSON.stringify({}), JSON.stringify(summary), createdBy);

  return db.prepare('SELECT * FROM executive_reports WHERE id = ?').get(id);
}

/**
 * List executive reports
 */
export function getExecutiveReports(db, limit = 20) {
  const rows = db.prepare('SELECT * FROM executive_reports ORDER BY generated_at DESC LIMIT ?').all(Number(limit) || 20);
  return rows.map(r => ({
    ...r,
    parameters: JSON.parse(r.parameters_json || '{}'),
    summary: JSON.parse(r.summary_json || '{}')
  }));
}

/**
 * Get device-specific analytics posture and crash history
 */
export function getDeviceAnalytics(db, deviceId) {
  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const latest = db.prepare(`
    SELECT * FROM device_analytics_snapshots
    WHERE device_id = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(deviceId);

  const history = db.prepare(`
    SELECT * FROM device_analytics_snapshots
    WHERE device_id = ?
    ORDER BY created_at DESC LIMIT 14
  `).all(deviceId);

  const crashes = db.prepare(`
    SELECT * FROM app_reliability_events
    WHERE device_id = ?
    ORDER BY occurred_at DESC LIMIT 20
  `).all(deviceId);

  return {
    device_id: deviceId,
    hostname: device.hostname,
    latest_snapshot: latest || null,
    history,
    recent_events: crashes
  };
}
