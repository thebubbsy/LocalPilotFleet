/**
 * LocalPilot Fleet — Microsoft Intune Application Management & Packaging Engine
 * server/src/services/appManagementEngine.js
 *
 * Manages Win32 and Winget enterprise app catalogs, declarative assignment intents
 * (REQUIRED, AVAILABLE, UNINSTALL), multi-vector detection rules, requirement rules,
 * and per-device installation tracking.
 */

import crypto from 'node:crypto';

export class AppManagementEngine {
  /**
   * Get all managed applications with per-app fleet installation statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getAllApps(db) {
    const apps = db.prepare(`
      SELECT a.*, g.name as target_group_name, g.color as target_group_color
      FROM apps a
      LEFT JOIN dynamic_groups g ON a.target_group_id = g.id
      ORDER BY a.name ASC
    `).all();

    const deviceCounts = db.prepare(`
      SELECT 
        app_id,
        COUNT(*) as total_targeted,
        SUM(CASE WHEN install_status = 'INSTALLED' THEN 1 ELSE 0 END) as installed_count,
        SUM(CASE WHEN install_status = 'PENDING' OR install_status = 'INSTALLING' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN install_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
        SUM(CASE WHEN install_status = 'NOT_APPLICABLE' THEN 1 ELSE 0 END) as not_applicable_count
      FROM device_app_status
      GROUP BY app_id
    `).all();

    const countMap = new Map();
    for (const dc of deviceCounts) {
      countMap.set(dc.app_id, dc);
    }

    return apps.map(app => {
      const stats = countMap.get(app.id) || {
        total_targeted: 0,
        installed_count: 0,
        pending_count: 0,
        failed_count: 0,
        not_applicable_count: 0
      };

      const rateBase = stats.installed_count + stats.failed_count;
      const installRate = rateBase > 0
        ? Math.round((stats.installed_count / rateBase) * 100 * 10) / 10
        : (stats.installed_count > 0 ? 100.0 : 0.0);

      let detectionRules = [];
      try {
        detectionRules = JSON.parse(app.detection_rules_json || '[]');
      } catch {}

      let requirementRules = {};
      try {
        requirementRules = JSON.parse(app.requirement_rules_json || '{}');
      } catch {}

      return {
        ...app,
        detection_rules: detectionRules,
        requirement_rules: requirementRules,
        stats: {
          total_targeted: stats.total_targeted,
          installed_count: stats.installed_count,
          pending_count: stats.pending_count,
          failed_count: stats.failed_count,
          not_applicable_count: stats.not_applicable_count,
          install_rate_percent: installRate
        }
      };
    });
  }

  /**
   * Get single application by ID with detailed per-device installation statuses.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getAppById(db, id) {
    const app = db.prepare(`
      SELECT a.*, g.name as target_group_name, g.color as target_group_color
      FROM apps a
      LEFT JOIN dynamic_groups g ON a.target_group_id = g.id
      WHERE a.id = ?
    `).get(id);

    if (!app) return null;

    const deviceStatuses = db.prepare(`
      SELECT 
        das.*,
        d.hostname,
        d.friendly_name,
        d.primary_user,
        d.status as device_node_status,
        d.ip_address,
        d.os_build
      FROM device_app_status das
      JOIN devices d ON das.device_id = d.id
      WHERE das.app_id = ?
      ORDER BY das.updated_at DESC
    `).all(id);

    let detectionRules = [];
    try {
      detectionRules = JSON.parse(app.detection_rules_json || '[]');
    } catch {}

    let requirementRules = {};
    try {
      requirementRules = JSON.parse(app.requirement_rules_json || '{}');
    } catch {}

    const installed = deviceStatuses.filter(s => s.install_status === 'INSTALLED').length;
    const failed = deviceStatuses.filter(s => s.install_status === 'FAILED').length;
    const pending = deviceStatuses.filter(s => s.install_status === 'PENDING' || s.install_status === 'INSTALLING').length;
    const notApplicable = deviceStatuses.filter(s => s.install_status === 'NOT_APPLICABLE').length;

    const rateBase = installed + failed;
    const installRate = rateBase > 0
      ? Math.round((installed / rateBase) * 100 * 10) / 10
      : (installed > 0 ? 100.0 : 0.0);

    return {
      ...app,
      detection_rules: detectionRules,
      requirement_rules: requirementRules,
      stats: {
        total_targeted: deviceStatuses.length,
        installed_count: installed,
        failed_count: failed,
        pending_count: pending,
        not_applicable_count: notApplicable,
        install_rate_percent: installRate
      },
      device_statuses: deviceStatuses
    };
  }

  /**
   * Create a new Intune application package in catalog.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} data
   * @returns {object}
   */
  createApp(db, data) {
    if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
      throw new Error('Application name is required.');
    }

    const id = data.id || `app-${crypto.randomUUID().slice(0, 8)}`;
    const detectionRulesJson = typeof data.detection_rules === 'string'
      ? data.detection_rules
      : JSON.stringify(data.detection_rules || []);

    const requirementRulesJson = typeof data.requirement_rules === 'string'
      ? data.requirement_rules
      : JSON.stringify(data.requirement_rules || {});

    db.prepare(`
      INSERT INTO apps (
        id, name, description, publisher, version, category, app_type,
        package_identifier, assignment_intent, target_group_id,
        install_command, uninstall_command, detection_rules_json, requirement_rules_json,
        icon_url, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.name.trim(),
      data.description || null,
      data.publisher || null,
      data.version || null,
      data.category || 'Developer Tools',
      data.app_type || 'WINGET',
      data.package_identifier || null,
      data.assignment_intent || 'REQUIRED',
      data.target_group_id || 'grp-all',
      data.install_command || null,
      data.uninstall_command || null,
      detectionRulesJson,
      requirementRulesJson,
      data.icon_url || null,
      data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1
    );

    return this.getAppById(db, id);
  }

  /**
   * Update an existing managed application.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} data
   * @returns {object}
   */
  updateApp(db, id, data) {
    const existing = this.getAppById(db, id);
    if (!existing) {
      throw new Error(`Application '${id}' not found.`);
    }

    const name = data.name !== undefined ? data.name : existing.name;
    const description = data.description !== undefined ? data.description : existing.description;
    const publisher = data.publisher !== undefined ? data.publisher : existing.publisher;
    const version = data.version !== undefined ? data.version : existing.version;
    const category = data.category !== undefined ? data.category : existing.category;
    const appType = data.app_type !== undefined ? data.app_type : existing.app_type;
    const packageIdentifier = data.package_identifier !== undefined ? data.package_identifier : existing.package_identifier;
    const assignmentIntent = data.assignment_intent !== undefined ? data.assignment_intent : existing.assignment_intent;
    const targetGroupId = data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id;
    const installCommand = data.install_command !== undefined ? data.install_command : existing.install_command;
    const uninstallCommand = data.uninstall_command !== undefined ? data.uninstall_command : existing.uninstall_command;

    const detectionRulesJson = data.detection_rules !== undefined
      ? (typeof data.detection_rules === 'string' ? data.detection_rules : JSON.stringify(data.detection_rules))
      : existing.detection_rules_json;

    const requirementRulesJson = data.requirement_rules !== undefined
      ? (typeof data.requirement_rules === 'string' ? data.requirement_rules : JSON.stringify(data.requirement_rules))
      : existing.requirement_rules_json;

    const iconUrl = data.icon_url !== undefined ? data.icon_url : existing.icon_url;
    const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE apps SET
        name = ?,
        description = ?,
        publisher = ?,
        version = ?,
        category = ?,
        app_type = ?,
        package_identifier = ?,
        assignment_intent = ?,
        target_group_id = ?,
        install_command = ?,
        uninstall_command = ?,
        detection_rules_json = ?,
        requirement_rules_json = ?,
        icon_url = ?,
        is_enabled = ?,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, publisher, version, category, appType,
      packageIdentifier, assignmentIntent, targetGroupId,
      installCommand, uninstallCommand, detectionRulesJson, requirementRulesJson,
      iconUrl, isEnabled, id
    );

    return this.getAppById(db, id);
  }

  /**
   * Delete an application package and cascade status records.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deleteApp(db, id) {
    const existing = db.prepare('SELECT id FROM apps WHERE id = ?').get(id);
    if (!existing) return false;

    db.prepare('DELETE FROM apps WHERE id = ?').run(id);
    return true;
  }

  /**
   * Resolve all applications assigned to a specific device based on group membership.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {Array<object>}
   */
  getDeviceAssignedApps(db, deviceId) {
    const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId);
    if (!device) return [];

    const memberships = db.prepare(`
      SELECT group_id FROM group_memberships WHERE device_id = ?
    `).all(deviceId).map(m => m.group_id);

    if (!memberships.includes('grp-all')) {
      memberships.push('grp-all');
    }

    const placeholders = memberships.map(() => '?').join(',');
    const apps = db.prepare(`
      SELECT 
        a.*,
        das.id as status_id,
        das.install_status,
        das.detection_state,
        das.installed_version,
        das.error_code,
        das.error_message,
        das.last_attempt_at
      FROM apps a
      LEFT JOIN device_app_status das ON (a.id = das.app_id AND das.device_id = ?)
      WHERE a.is_enabled = 1
        AND (a.target_group_id IS NULL OR a.target_group_id IN (${placeholders}))
      ORDER BY a.name ASC
    `).all(deviceId, ...memberships);

    return apps.map(app => {
      let detectionRules = [];
      try {
        detectionRules = JSON.parse(app.detection_rules_json || '[]');
      } catch {}

      let requirementRules = {};
      try {
        requirementRules = JSON.parse(app.requirement_rules_json || '{}');
      } catch {}

      return {
        ...app,
        detection_rules: detectionRules,
        requirement_rules: requirementRules,
        install_status: app.install_status || 'PENDING',
        detection_state: app.detection_state !== undefined ? app.detection_state : 0
      };
    });
  }

  /**
   * Record or update application installation status from node agent.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} appId
   * @param {object} payload
   * @returns {object}
   */
  recordAppStatus(db, deviceId, appId, payload) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    const app = db.prepare('SELECT id, name, assignment_intent FROM apps WHERE id = ?').get(appId);
    if (!app) throw new Error(`Application '${appId}' not found.`);

    const statusId = `das-${crypto.randomUUID().slice(0, 10)}`;
    const installStatus = payload.install_status || 'PENDING';
    const detectionState = payload.detection_state ? 1 : 0;
    const installedVersion = payload.installed_version || null;
    const errorCode = payload.error_code !== undefined ? payload.error_code : null;
    const errorMessage = payload.error_message || null;
    const lastAttemptAt = payload.last_attempt_at || new Date().toISOString();

    db.prepare(`
      INSERT INTO device_app_status (
        id, device_id, app_id, install_status, detection_state,
        installed_version, error_code, error_message, last_attempt_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
      ON CONFLICT(device_id, app_id) DO UPDATE SET
        install_status = excluded.install_status,
        detection_state = excluded.detection_state,
        installed_version = excluded.installed_version,
        error_code = excluded.error_code,
        error_message = excluded.error_message,
        last_attempt_at = excluded.last_attempt_at,
        updated_at = DATETIME('now')
    `).run(
      statusId, deviceId, appId, installStatus, detectionState,
      installedVersion, errorCode, errorMessage, lastAttemptAt
    );

    if (installStatus === 'FAILED') {
      try {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
          ) VALUES (?, 'POLICY_DRIFT', 1034, 'IntuneAppManager', 'HIGH', ?, ?, 0)
        `).run(
          deviceId,
          `Application installation failed for "${app.name}" on ${device.hostname}`,
          JSON.stringify({
            app_id: appId,
            app_name: app.name,
            error_code: errorCode,
            error_message: errorMessage,
            attempted_at: lastAttemptAt
          })
        );
      } catch {}
    }

    return {
      success: true,
      device_id: deviceId,
      app_id: appId,
      install_status: installStatus,
      detection_state: detectionState
    };
  }

  /**
   * Get aggregate fleet statistics for application management.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getAppFleetStats(db) {
    const totalApps = db.prepare('SELECT COUNT(*) as count FROM apps WHERE is_enabled = 1').get().count;
    
    const statusCounts = db.prepare(`
      SELECT 
        COUNT(*) as total_records,
        SUM(CASE WHEN install_status = 'INSTALLED' THEN 1 ELSE 0 END) as installed_count,
        SUM(CASE WHEN install_status = 'PENDING' OR install_status = 'INSTALLING' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN install_status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
        SUM(CASE WHEN install_status = 'NOT_APPLICABLE' THEN 1 ELSE 0 END) as not_applicable_count
      FROM device_app_status
    `).get();

    const installed = statusCounts.installed_count || 0;
    const failed = statusCounts.failed_count || 0;
    const pending = statusCounts.pending_count || 0;
    const notApplicable = statusCounts.not_applicable_count || 0;

    const rateBase = installed + failed;
    const installRate = rateBase > 0
      ? Math.round((installed / rateBase) * 100 * 10) / 10
      : (installed > 0 ? 100.0 : 100.0);

    const totalMonitoredDevices = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count FROM device_app_status
    `).get().count;

    return {
      total_apps: totalApps,
      total_monitored_devices: totalMonitoredDevices,
      total_installed: installed,
      total_pending: pending,
      total_failed: failed,
      total_not_applicable: notApplicable,
      fleet_install_rate_percent: installRate
    };
  }

  /**
   * Queue an on-demand installation or re-evaluation command for a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} appId
   * @returns {object}
   */
  queueAppInstallCommand(db, deviceId, appId) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error(`Device '${deviceId}' not found.`);

    const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(appId);
    if (!app) throw new Error(`Application '${appId}' not found.`);

    if (!app.install_command) {
      throw new Error(`Application '${app.name}' has no configured install command.`);
    }

    const commandId = `cmd-${crypto.randomUUID().slice(0, 10)}`;
    const scriptContent = `
# Intune Win32/Winget App Deployer
Write-Host "Initiating Intune App deployment: ${app.name} (${app.id})..."
$cmd = "${app.install_command.replace(/"/g, '`"')}"
Write-Host "Executing: $cmd"
Invoke-Expression $cmd
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) { $exitCode = 0 }
Write-Host "Execution completed with exit code: $exitCode"
exit $exitCode
    `.trim();

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'admin', 'PENDING', DATETIME('now'))
    `).run(
      commandId,
      deviceId,
      scriptContent
    );

    this.recordAppStatus(db, deviceId, appId, {
      install_status: 'INSTALLING',
      last_attempt_at: new Date().toISOString()
    });

    return {
      success: true,
      command_id: commandId,
      device_id: deviceId,
      app_id: appId,
      app_name: app.name
    };
  }
}

export const appManagementEngine = new AppManagementEngine();
