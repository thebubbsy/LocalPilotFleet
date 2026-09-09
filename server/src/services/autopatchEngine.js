/**
 * LocalPilot Fleet — Windows Autopatch & Automated Patch Release Cadence Engine
 * server/src/services/autopatchEngine.js
 *
 * Manages progressive rollout rings (Test -> First -> Fast -> Broad),
 * Patch Tuesday release sequencing, health quality gates, and automated rollback safeguards.
 */

import crypto from 'node:crypto';

export function getAutopatchStats(db) {
  const totalReleases = db.prepare('SELECT COUNT(*) as c FROM autopatch_release_cadence').get().c;
  const activeReleases = db.prepare("SELECT COUNT(*) as c FROM autopatch_release_cadence WHERE active_phase NOT IN ('COMPLETED', 'ROLLED_BACK')").get().c;
  const totalDeployments = db.prepare('SELECT COUNT(*) as c FROM autopatch_device_deployments').get().c;
  const installedDeployments = db.prepare("SELECT COUNT(*) as c FROM autopatch_device_deployments WHERE install_status = 'INSTALLED'").get().c;
  const rolledBackCount = db.prepare("SELECT COUNT(*) as c FROM autopatch_device_deployments WHERE install_status = 'ROLLED_BACK'").get().c;
  const failedCount = db.prepare("SELECT COUNT(*) as c FROM autopatch_device_deployments WHERE install_status = 'FAILED'").get().c;

  const fleetComplianceRate = totalDeployments > 0
    ? Math.round((installedDeployments / totalDeployments) * 1000) / 10
    : 100.0;

  const activeRelease = db.prepare(`
    SELECT * FROM autopatch_release_cadence 
    WHERE active_phase NOT IN ('COMPLETED', 'ROLLED_BACK')
    ORDER BY created_at DESC LIMIT 1
  `).get() || null;

  const rings = db.prepare('SELECT * FROM autopatch_rings ORDER BY phase_order ASC').all();

  return {
    total_releases: totalReleases,
    active_releases: activeReleases,
    total_deployments: totalDeployments,
    installed_deployments: installedDeployments,
    failed_deployments: failedCount,
    rolled_back_count: rolledBackCount,
    fleet_compliance_rate_percent: fleetComplianceRate,
    active_release: activeRelease,
    total_rings: rings.length,
    rings: rings
  };
}

export function getReleases(db, filter = {}) {
  let query = 'SELECT * FROM autopatch_release_cadence';
  const conditions = [];
  const params = [];

  if (filter.active_phase) {
    conditions.push('active_phase = ?');
    params.push(filter.active_phase);
  }
  if (filter.approval_status) {
    conditions.push('approval_status = ?');
    params.push(filter.approval_status);
  }
  if (filter.release_type) {
    conditions.push('release_type = ?');
    params.push(filter.release_type);
  }

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }
  query += ' ORDER BY scheduled_start_date DESC';

  return db.prepare(query).all(...params);
}

export function getRelease(db, id) {
  if (!id) return null;
  const release = db.prepare('SELECT * FROM autopatch_release_cadence WHERE id = ?').get(id);
  if (!release) return null;

  const deployments = db.prepare(`
    SELECT d.id, d.device_id, dev.hostname, d.ring_id, r.name as ring_name,
           d.install_status, d.applied_kb, d.exit_code, d.post_patch_crashes, d.installed_at
    FROM autopatch_device_deployments d
    JOIN devices dev ON d.device_id = dev.id
    JOIN autopatch_rings r ON d.ring_id = r.id
    WHERE d.release_id = ?
    ORDER BY r.phase_order ASC, dev.hostname ASC
  `).all(id);

  return {
    ...release,
    deployments
  };
}

export function createRelease(db, data) {
  const id = data.id || `rel-${Date.now()}`;
  const name = data.name || 'Monthly Windows Quality Update';
  const releaseMonth = data.release_month || new Date().toISOString().slice(0, 7);
  const releaseType = data.release_type || 'SECURITY_QUALITY';
  const targetKb = data.target_kb_numbers || 'KB5044284';
  const approvalStatus = data.approval_status || 'AUTOMATIC_APPROVED';
  const activePhase = data.active_phase || 'TEST';
  const scheduledStart = data.scheduled_start_date || new Date().toISOString();
  const broadTarget = data.broad_target_date || null;

  db.prepare(`
    INSERT INTO autopatch_release_cadence (
      id, name, release_month, release_type, target_kb_numbers,
      approval_status, active_phase, scheduled_start_date, broad_target_date
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, name, releaseMonth, releaseType, targetKb,
    approvalStatus, activePhase, scheduledStart, broadTarget
  );

  return getRelease(db, id);
}

export function updateRelease(db, id, data) {
  if (!id) return null;
  const existing = db.prepare('SELECT * FROM autopatch_release_cadence WHERE id = ?').get(id);
  if (!existing) return null;

  const name = data.name !== undefined ? data.name : existing.name;
  const targetKb = data.target_kb_numbers !== undefined ? data.target_kb_numbers : existing.target_kb_numbers;
  const approvalStatus = data.approval_status !== undefined ? data.approval_status : existing.approval_status;
  const activePhase = data.active_phase !== undefined ? data.active_phase : existing.active_phase;
  const broadTarget = data.broad_target_date !== undefined ? data.broad_target_date : existing.broad_target_date;
  const rollbackReason = data.rollback_reason !== undefined ? data.rollback_reason : existing.rollback_reason;

  db.prepare(`
    UPDATE autopatch_release_cadence SET
      name = ?,
      target_kb_numbers = ?,
      approval_status = ?,
      active_phase = ?,
      broad_target_date = ?,
      rollback_reason = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(name, targetKb, approvalStatus, activePhase, broadTarget, rollbackReason, id);

  return getRelease(db, id);
}

export function deleteRelease(db, id) {
  if (!id) return false;
  const res = db.prepare('DELETE FROM autopatch_release_cadence WHERE id = ?').run(id);
  return res.changes > 0;
}

export function progressReleasePhase(db, id) {
  if (!id) return null;
  const release = db.prepare('SELECT * FROM autopatch_release_cadence WHERE id = ?').get(id);
  if (!release) return null;

  const phases = ['TEST', 'FIRST', 'FAST', 'BROAD', 'COMPLETED'];
  const currentIndex = phases.indexOf(release.active_phase);
  if (currentIndex === -1 || currentIndex >= phases.length - 1) {
    return release;
  }

  const nextPhase = phases[currentIndex + 1];
  db.prepare(`
    UPDATE autopatch_release_cadence SET
      active_phase = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(nextPhase, id);

  return getRelease(db, id);
}

export function triggerPatchRollback(db, id, reason = 'Administrator initiated safety rollback') {
  if (!id) return null;
  const release = db.prepare('SELECT * FROM autopatch_release_cadence WHERE id = ?').get(id);
  if (!release) return null;

  db.prepare(`
    UPDATE autopatch_release_cadence SET
      approval_status = 'ROLLED_BACK',
      active_phase = 'ROLLED_BACK',
      rollback_reason = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(reason, id);

  db.prepare(`
    UPDATE autopatch_device_deployments SET
      install_status = 'ROLLED_BACK',
      error_message = ?,
      updated_at = DATETIME('now')
    WHERE release_id = ? AND install_status IN ('INSTALLING', 'REBOOT_PENDING', 'INSTALLED')
  `).run(reason, id);

  return getRelease(db, id);
}

export function generateRollbackScript(kbNumbers = '') {
  const kbs = kbNumbers.split(',').map(s => s.trim().replace(/^KB/i, '')).filter(Boolean);
  const commands = kbs.map(kb => `wusa.exe /uninstall /kb:${kb} /quiet /norestart`).join('\n');
  return `# LocalPilot Autopatch Automated Rollback Script
Write-Output "Initiating emergency quality update rollback for KB: ${kbNumbers}"
${commands}
Write-Output "Rollback command dispatched. Reboot required to complete uninstallation."
`;
}

export function getRings(db) {
  return db.prepare(`
    SELECT r.*, COUNT(d.id) as assigned_devices_count
    FROM autopatch_rings r
    LEFT JOIN autopatch_device_deployments d ON r.id = d.ring_id
    GROUP BY r.id
    ORDER BY r.phase_order ASC
  `).all();
}

export function getRing(db, id) {
  if (!id) return null;
  return db.prepare('SELECT * FROM autopatch_rings WHERE id = ?').get(id);
}

export function updateRing(db, id, data) {
  if (!id) return null;
  const existing = db.prepare('SELECT * FROM autopatch_rings WHERE id = ?').get(id);
  if (!existing) return null;

  const deferral = data.deferral_days !== undefined ? Number(data.deferral_days) : existing.deferral_days;
  const maxCrash = data.max_allowable_crash_rate !== undefined ? Number(data.max_allowable_crash_rate) : existing.max_allowable_crash_rate;
  const minSuccess = data.min_success_rate !== undefined ? Number(data.min_success_rate) : existing.min_success_rate;

  db.prepare(`
    UPDATE autopatch_rings SET
      deferral_days = ?,
      max_allowable_crash_rate = ?,
      min_success_rate = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(deferral, maxCrash, minSuccess, id);

  return getRing(db, id);
}

export function getDeviceDeployments(db, filter = {}) {
  let query = `
    SELECT d.*, r.name as ring_name, r.phase_order, dev.hostname, dev.primary_user, rel.name as release_name, rel.target_kb_numbers
    FROM autopatch_device_deployments d
    JOIN autopatch_rings r ON d.ring_id = r.id
    JOIN devices dev ON d.device_id = dev.id
    JOIN autopatch_release_cadence rel ON d.release_id = rel.id
  `;
  const conditions = [];
  const params = [];

  if (filter.device_id) {
    conditions.push('d.device_id = ?');
    params.push(filter.device_id);
  }
  if (filter.release_id) {
    conditions.push('d.release_id = ?');
    params.push(filter.release_id);
  }
  if (filter.ring_id) {
    conditions.push('d.ring_id = ?');
    params.push(filter.ring_id);
  }
  if (filter.install_status) {
    conditions.push('d.install_status = ?');
    params.push(filter.install_status);
  }

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }
  query += ' ORDER BY r.phase_order ASC, dev.hostname ASC';

  return db.prepare(query).all(...params);
}

export function getDeviceAutopatchStatus(db, deviceId) {
  if (!deviceId) return null;
  const deployment = db.prepare(`
    SELECT d.*, r.name as ring_name, r.deferral_days, rel.name as release_name, rel.target_kb_numbers, rel.active_phase, rel.approval_status
    FROM autopatch_device_deployments d
    JOIN autopatch_rings r ON d.ring_id = r.id
    JOIN autopatch_release_cadence rel ON d.release_id = rel.id
    WHERE d.device_id = ?
    ORDER BY d.created_at DESC LIMIT 1
  `).get(deviceId);

  return deployment || null;
}

export function recordDevicePatchReport(db, deviceId, report = {}) {
  if (!deviceId) return null;
  const releaseId = report.release_id;
  if (!releaseId) return null;

  const status = report.install_status || 'INSTALLED';
  const appliedKb = report.applied_kb || '';
  const exitCode = report.exit_code !== undefined ? Number(report.exit_code) : 0;
  const crashes = report.post_patch_crashes !== undefined ? Number(report.post_patch_crashes) : 0;
  const error = report.error_message || '';
  const ringId = report.ring_id || 'ring-first';

  const existing = db.prepare('SELECT id FROM autopatch_device_deployments WHERE release_id = ? AND device_id = ?').get(releaseId, deviceId);

  if (existing) {
    db.prepare(`
      UPDATE autopatch_device_deployments SET
        install_status = ?,
        applied_kb = ?,
        exit_code = ?,
        post_patch_crashes = ?,
        error_message = ?,
        installed_at = CASE WHEN ? = 'INSTALLED' THEN DATETIME('now') ELSE installed_at END,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(status, appliedKb, exitCode, crashes, error, status, existing.id);
  } else {
    const id = `dep-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    db.prepare(`
      INSERT INTO autopatch_device_deployments (
        id, release_id, device_id, ring_id, install_status, applied_kb, exit_code, post_patch_crashes, error_message, installed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = 'INSTALLED' THEN DATETIME('now') ELSE NULL END)
    `).run(id, releaseId, deviceId, ringId, status, appliedKb, exitCode, crashes, error, status);
  }

  return getDeviceAutopatchStatus(db, deviceId);
}

export default {
  getAutopatchStats,
  getReleases,
  getRelease,
  createRelease,
  updateRelease,
  deleteRelease,
  progressReleasePhase,
  triggerPatchRollback,
  generateRollbackScript,
  getRings,
  getRing,
  updateRing,
  getDeviceDeployments,
  getDeviceAutopatchStatus,
  recordDevicePatchReport
};
