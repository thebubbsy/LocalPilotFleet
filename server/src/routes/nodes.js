/**
 * LocalPilot Fleet — Node Agent Endpoints
 * server/src/routes/nodes.js
 */

import crypto from 'node:crypto';
import { getDb } from '../db.js';
import { requireFleetKey, requireNodeToken, requireFleetKeyOrNodeToken, generateNodeToken } from '../utils/auth.js';
import { sendJson } from '../utils/router.js';
import dynamicGroupsService from '../services/dynamicGroups.js';
import policyEngine from '../services/policyEngine.js';
import alertEngine from '../services/alertEngine.js';
import remediationEngine from '../services/remediationEngine.js';
import { configProfileEngine } from '../services/configProfileEngine.js';
import { updateRingEngine } from '../services/updateRingEngine.js';
import { complianceEngine } from '../services/complianceEngine.js';
import { appManagementEngine } from '../services/appManagementEngine.js';
import { broadcastEvent } from './events.js';

export function registerNodeRoutes(router) {
  // 1. POST /api/v1/nodes/enroll
  router.post('/api/v1/nodes/enroll', async (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const body = req.body || {};
    const {
      hostname,
      serial_number,
      uuid,
      mac_address,
      friendly_name,
      tags,
      os_name,
      os_version,
      os_build,
      os_architecture,
      cpu_model,
      cpu_cores,
      cpu_logical,
      total_ram_bytes,
      gpu_name,
      has_battery,
      battery_percent,
      battery_charging,
      tpm_present,
      tpm_version,
      tpm_enabled,
      secure_boot_enabled,
      bitlocker_status,
      primary_user,
      agent_version
    } = body;

    if (!hostname || !os_name || !total_ram_bytes) {
      sendJson(res, 400, {
        error: 'BAD_REQUEST',
        message: 'Missing required enrollment parameters: hostname, os_name, and total_ram_bytes are mandatory'
      });
      return;
    }

    try {
      const db = getDb();
      const tokenData = generateNodeToken();

      // Check if device with same serial_number or uuid exists
      let existingDevice = null;
      if (serial_number) {
        existingDevice = db.prepare('SELECT * FROM devices WHERE serial_number = ?').get(serial_number);
      }
      if (!existingDevice && uuid) {
        existingDevice = db.prepare('SELECT * FROM devices WHERE uuid = ?').get(uuid);
      }

      let deviceId;
      let statusCode = 201;

      const tagsJson = Array.isArray(tags) ? JSON.stringify(tags) : (typeof tags === 'string' ? tags : '[]');

      if (existingDevice) {
        deviceId = existingDevice.id;
        db.prepare(`
          UPDATE devices SET
            hostname = ?,
            friendly_name = COALESCE(?, friendly_name),
            uuid = COALESCE(?, uuid),
            mac_address = COALESCE(?, mac_address),
            tags_json = ?,
            os_name = ?,
            os_version = COALESCE(?, os_version),
            os_build = COALESCE(?, os_build),
            os_architecture = COALESCE(?, os_architecture),
            cpu_model = COALESCE(?, cpu_model),
            cpu_cores = COALESCE(?, cpu_cores),
            cpu_logical = COALESCE(?, cpu_logical),
            total_ram_bytes = ?,
            gpu_name = COALESCE(?, gpu_name),
            has_battery = COALESCE(?, has_battery),
            battery_percent = COALESCE(?, battery_percent),
            battery_charging = COALESCE(?, battery_charging),
            tpm_present = COALESCE(?, tpm_present),
            tpm_version = COALESCE(?, tpm_version),
            tpm_enabled = COALESCE(?, tpm_enabled),
            secure_boot_enabled = COALESCE(?, secure_boot_enabled),
            bitlocker_status = COALESCE(?, bitlocker_status),
            primary_user = COALESCE(?, primary_user),
            node_token_hash = ?,
            agent_version = COALESCE(?, agent_version),
            last_seen_at = DATETIME('now'),
            status = 'online',
            updated_at = DATETIME('now')
          WHERE id = ?
        `).run(
          hostname,
          friendly_name || null,
          uuid || null,
          mac_address || null,
          tagsJson,
          os_name,
          os_version || null,
          os_build || null,
          os_architecture || '64-bit',
          cpu_model || null,
          cpu_cores || null,
          cpu_logical || null,
          Number(total_ram_bytes),
          gpu_name || null,
          has_battery ? 1 : 0,
          battery_percent !== undefined ? Number(battery_percent) : null,
          battery_charging ? 1 : 0,
          tpm_present ? 1 : 0,
          tpm_version || null,
          tpm_enabled ? 1 : 0,
          secure_boot_enabled ? 1 : 0,
          bitlocker_status || 'Disabled',
          primary_user || null,
          tokenData.hash,
          agent_version || '1.0.0',
          deviceId
        );
      } else {
        deviceId = crypto.randomUUID();
        db.prepare(`
          INSERT INTO devices (
            id, hostname, friendly_name, serial_number, uuid, mac_address,
            tags_json, os_name, os_version, os_build, os_architecture,
            cpu_model, cpu_cores, cpu_logical, total_ram_bytes, gpu_name,
            has_battery, battery_percent, battery_charging,
            tpm_present, tpm_version, tpm_enabled, secure_boot_enabled, bitlocker_status,
            primary_user, node_token_hash, agent_version, status, connection_route
          ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, 'online', 'LAN'
          )
        `).run(
          deviceId,
          hostname,
          friendly_name || hostname,
          serial_number || null,
          uuid || null,
          mac_address || null,
          tagsJson,
          os_name,
          os_version || '10.0',
          os_build || null,
          os_architecture || '64-bit',
          cpu_model || null,
          cpu_cores || null,
          cpu_logical || null,
          Number(total_ram_bytes),
          gpu_name || null,
          has_battery ? 1 : 0,
          battery_percent !== undefined ? Number(battery_percent) : null,
          battery_charging ? 1 : 0,
          tpm_present ? 1 : 0,
          tpm_version || null,
          tpm_enabled ? 1 : 0,
          secure_boot_enabled ? 1 : 0,
          bitlocker_status || 'Disabled',
          primary_user || null,
          tokenData.hash,
          agent_version || '1.0.0'
        );
      }

      // Re-evaluate dynamic groups
      const assignedGroups = dynamicGroupsService.reevaluateDeviceMemberships(db, deviceId);

      broadcastEvent('node_enrolled', {
        device_id: deviceId,
        hostname,
        friendly_name: friendly_name || hostname,
        assigned_groups: assignedGroups
      });

      sendJson(res, statusCode, {
        status: 'enrolled',
        device_id: deviceId,
        node_token: tokenData.token,
        heartbeat_interval_sec: 60,
        telemetry_interval_min: 15,
        assigned_groups: assignedGroups
      });
    } catch (err) {
      sendJson(res, 500, { error: 'ENROLLMENT_ERROR', message: err.message });
    }
  });

  // 2. POST /api/v1/nodes/heartbeat
  router.post('/api/v1/nodes/heartbeat', async (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;

    const body = req.body || {};
    const deviceId = req.device?.id || body.device_id;
    if (!deviceId) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing device_id' });
      return;
    }
    const {
      cpu_usage_percent,
      ram_used_bytes,
      ram_free_bytes,
      ram_usage_percent,
      battery_percent,
      battery_charging,
      ip_address,
      connection_route,
      uptime_seconds,
      primary_user,
      active_user
    } = body;
    const currentActiveUser = active_user || primary_user || null;

    try {
      const db = getDb();
      db.prepare(`
        UPDATE devices SET
          last_seen_at = DATETIME('now'),
          status = CASE WHEN status = 'drifted' THEN 'drifted' WHEN status = 'quarantined' THEN 'quarantined' ELSE 'online' END,
          ip_address = COALESCE(?, ip_address),
          connection_route = COALESCE(?, connection_route),
          battery_percent = COALESCE(?, battery_percent),
          battery_charging = COALESCE(?, battery_charging),
          primary_user = COALESCE(?, primary_user),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        ip_address || null,
        connection_route || null,
        battery_percent !== undefined ? Number(battery_percent) : null,
        battery_charging !== undefined ? (battery_charging ? 1 : 0) : null,
        currentActiveUser,
        deviceId
      );

      const deviceRecord = req.device || db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);

      broadcastEvent('heartbeat', {
        device_id: deviceId,
        hostname: deviceRecord?.hostname || 'Unknown',
        primary_user: currentActiveUser || deviceRecord?.primary_user || 'Unknown',
        cpu_usage_percent: cpu_usage_percent || null,
        ram_usage_percent: ram_usage_percent || null,
        connection_route: connection_route || deviceRecord?.connection_route || 'LAN',
        status: deviceRecord?.status || 'online'
      });

      // Check for pending remote execution commands for this node
      const pendingCommands = db.prepare(`
        SELECT id, command_text FROM device_commands
        WHERE device_id = ? AND status = 'PENDING'
        ORDER BY created_at ASC
      `).all(deviceId);

      if (pendingCommands.length > 0) {
        const markStmt = db.prepare("UPDATE device_commands SET status = 'RUNNING', executed_at = DATETIME('now') WHERE id = ?");
        for (const c of pendingCommands) {
          markStmt.run(c.id);
        }
      }

      // Check for assigned proactive remediations
      const assignedRemediations = remediationEngine.getRemediationsForDevice(db, deviceId);

      // Check for assigned configuration profiles
      const assignedProfiles = configProfileEngine.getProfilesForDevice(db, deviceId);

      // Check for assigned update ring
      const assignedRing = updateRingEngine.getRingForDevice(db, deviceId);

      // Check for assigned compliance policies
      const assignedCompliancePolicies = complianceEngine.getPoliciesForDevice(db, deviceId);

      // Check for assigned applications
      const assignedApps = appManagementEngine.getDeviceAssignedApps(db, deviceId);

      sendJson(res, 200, {
        acknowledged: true,
        server_time: new Date().toISOString(),
        commands_pending: pendingCommands.length > 0,
        pending_commands: pendingCommands,
        remediations: assignedRemediations,
        profiles: assignedProfiles,
        update_ring: assignedRing,
        compliance_policies: assignedCompliancePolicies,
        assigned_apps: assignedApps
      });
    } catch (err) {
      sendJson(res, 500, { error: 'HEARTBEAT_ERROR', message: err.message });
    }
  });

  // 3. POST /api/v1/nodes/telemetry
  router.post('/api/v1/nodes/telemetry', async (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;

    const body = req.body || {};
    const deviceId = req.device?.id || body.device_id;
    if (!deviceId) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing device_id' });
      return;
    }
    const hardware = body.hardware || {};
    const security = body.security || {};
    const installedSoftware = body.installed_software || [];

    try {
      const db = getDb();

      // Extract metrics
      const cpuUsage = Number(hardware.cpu_usage_percent || 0);
      const ramUsed = Number(hardware.ram_used_bytes || 0);
      const ramFree = Number(hardware.ram_free_bytes || 0);
      const ramUsage = Number(hardware.ram_usage_percent || (ramUsed + ramFree > 0 ? (ramUsed / (ramUsed + ramFree)) * 100 : 0));
      const disks = hardware.disks || [];
      const networks = hardware.network_adapters || [];
      const primaryDisk = disks.find(d => d.drive_letter === 'C:' || d.drive === 'C:') || disks[0] || {};
      const diskFreeGb = primaryDisk.free_gb !== undefined ? Number(primaryDisk.free_gb) : null;
      const uptimeSeconds = Number(body.uptime_seconds || hardware.uptime_seconds || 0);
      const processCount = Number(hardware.process_count || 0);

      // 1. Insert telemetry snapshot
      db.prepare(`
        INSERT INTO telemetry_snapshots (
          device_id, timestamp, cpu_usage_percent, ram_used_bytes, ram_free_bytes,
          ram_usage_percent, disk_free_gb, disks_json, network_json,
          battery_percent, battery_charging, process_count, uptime_seconds
        ) VALUES (?, DATETIME('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        deviceId,
        cpuUsage,
        ramUsed,
        ramFree,
        ramUsage,
        diskFreeGb,
        JSON.stringify(disks),
        JSON.stringify(networks),
        body.battery_percent !== undefined ? Number(body.battery_percent) : null,
        body.battery_charging ? 1 : 0,
        processCount,
        uptimeSeconds
      );

      // 2. Update device posture
      const tpmPresent = security.tpm_present !== undefined ? (security.tpm_present ? 1 : 0) : null;
      const tpmEnabled = security.tpm_enabled !== undefined ? (security.tpm_enabled ? 1 : 0) : null;
      const secureBoot = security.secure_boot_enabled !== undefined ? (security.secure_boot_enabled ? 1 : 0) : null;
      let bitlockerStatus = null;
      if (Array.isArray(security.bitlocker_volumes) && security.bitlocker_volumes.length > 0) {
        const sysVol = security.bitlocker_volumes.find(v => v.mount_point === 'C:') || security.bitlocker_volumes[0];
        bitlockerStatus = sysVol.protection_status === 'On' ? 'FullyEncrypted' : 'Disabled';
      }

      const reportedUser = body.primary_user || body.active_user || null;

      db.prepare(`
        UPDATE devices SET
          last_seen_at = DATETIME('now'),
          tpm_present = COALESCE(?, tpm_present),
          tpm_enabled = COALESCE(?, tpm_enabled),
          secure_boot_enabled = COALESCE(?, secure_boot_enabled),
          bitlocker_status = COALESCE(?, bitlocker_status),
          primary_user = COALESCE(?, primary_user),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(tpmPresent, tpmEnabled, secureBoot, bitlockerStatus, reportedUser, deviceId);

      // 3. Re-evaluate dynamic groups
      const activeGroups = dynamicGroupsService.reevaluateDeviceMemberships(db, deviceId, { disk_free_gb: diskFreeGb }, installedSoftware);

      // 4. Re-evaluate policy compliance and drift detection
      const compliance = policyEngine.evaluateAndPersistDeviceCompliance(db, deviceId, installedSoftware);

      broadcastEvent('telemetry_updated', {
        device_id: deviceId,
        hostname: req.device.hostname,
        primary_user: reportedUser || req.device.primary_user,
        compliance_status: compliance.compliance_status,
        drift_detected: !compliance.is_compliant,
        active_groups: activeGroups
      });

      sendJson(res, 200, {
        status: 'processed',
        group_reevaluated: true,
        active_groups: activeGroups,
        compliance_status: compliance.compliance_status,
        drift_detected: !compliance.is_compliant,
        drift_reasons: compliance.drift_reasons
      });
    } catch (err) {
      sendJson(res, 500, { error: 'TELEMETRY_ERROR', message: err.message });
    }
  });

  // 4. POST /api/v1/nodes/events
  router.post('/api/v1/nodes/events', async (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;

    const body = req.body || {};
    const deviceId = req.device?.id || body.device_id;
    if (!deviceId) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing device_id' });
      return;
    }
    const {
      event_type,
      event_id,
      event_source = 'LocalPilotWatchdog',
      severity = 'CRITICAL',
      summary,
      timestamp,
      details = {}
    } = body;
    const eventSummary = summary || body.description;

    if (!event_type || !eventSummary) {
      sendJson(res, 400, {
        error: 'BAD_REQUEST',
        message: 'event_type and summary (or description) are required'
      });
      return;
    }

    let normalizedEventType = (event_type || '').toUpperCase();
    if (normalizedEventType === 'PRIVILEGE_ESCALATION') normalizedEventType = 'ADMIN_ADDED';
    if (normalizedEventType === 'SOFTWARE_INSTALLED') normalizedEventType = 'APP_INSTALLED';
    if (normalizedEventType === 'DRIFT_DETECTED') normalizedEventType = 'POLICY_DRIFT';

    const normalizedSeverity = (severity || 'HIGH').toUpperCase();

    try {
      const db = getDb();
      const insertStmt = db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, DATETIME('now')))
      `);

      const result = insertStmt.run(
        deviceId,
        normalizedEventType,
        event_id ? Number(event_id) : null,
        event_source,
        normalizedSeverity,
        eventSummary,
        JSON.stringify(details),
        timestamp || null
      );

      const eventRecordId = Number(result.lastInsertRowid);

      // Fetch fleet settings for notification targets
      const settingsRows = db.prepare('SELECT key, value FROM fleet_settings').all();
      const settings = Object.fromEntries(settingsRows.map(r => [r.key, r.value]));

      const eventRecord = {
        id: eventRecordId,
        device_id: deviceId,
        event_type: normalizedEventType,
        event_id,
        event_source,
        severity: normalizedSeverity,
        summary: eventSummary,
        raw_payload_json: JSON.stringify(details),
        created_at: timestamp || new Date().toISOString()
      };

      const alertResult = await alertEngine.dispatchAlert(eventRecord, settings);

      sendJson(res, 202, {
        status: 'dispatched',
        event_record_id: eventRecordId,
        toast_fired: alertResult.toast_fired,
        webhooks_dispatched: alertResult.webhooks_dispatched
      });
    } catch (err) {
      sendJson(res, 500, { error: 'EVENT_INGEST_ERROR', message: err.message });
    }
  });

  // 5. GET /api/v1/nodes/:id/policy
  router.get('/api/v1/nodes/:id/policy', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const policy = policyEngine.getEffectivePolicyForDevice(db, targetDeviceId);
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_QUERY_ERROR', message: err.message });
    }
  });

  // 6. POST /api/v1/nodes/:id/command-result (Agent reports script execution result)
  router.post('/api/v1/nodes/:id/command-result', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    const { command_id, status = 'COMPLETED', exit_code = 0, stdout = '', stderr = '' } = body;

    if (!command_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'command_id is required' });
      return;
    }

    try {
      const db = getDb();
      const cmd = db.prepare('SELECT * FROM device_commands WHERE id = ? AND device_id = ?').get(command_id, targetDeviceId);
      if (!cmd) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Command not found for this device' });
        return;
      }

      const finalStatus = (status === 'COMPLETED' || status === 'FAILED') ? status : (exit_code === 0 ? 'COMPLETED' : 'FAILED');

      db.prepare(`
        UPDATE device_commands SET
          status = ?,
          exit_code = ?,
          stdout = ?,
          stderr = ?,
          completed_at = DATETIME('now')
        WHERE id = ?
      `).run(
        finalStatus,
        exit_code !== undefined && exit_code !== null ? Number(exit_code) : 0,
        stdout || '',
        stderr || '',
        command_id
      );

      broadcastEvent('command_completed', {
        command_id,
        device_id: targetDeviceId,
        status: finalStatus,
        exit_code: Number(exit_code) || 0,
        stdout: stdout || '',
        stderr: stderr || ''
      });

      sendJson(res, 200, {
        success: true,
        command_id,
        status: finalStatus
      });
    } catch (err) {
      sendJson(res, 500, { error: 'COMMAND_RESULT_ERROR', message: err.message });
    }
  });

  // 7. GET /api/v1/nodes/:id/remediations
  router.get('/api/v1/nodes/:id/remediations', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const remediations = remediationEngine.getRemediationsForDevice(db, targetDeviceId);
      sendJson(res, 200, { remediations });
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATIONS_FETCH_ERROR', message: err.message });
    }
  });

  // 8. POST /api/v1/nodes/:id/remediation-result
  router.post('/api/v1/nodes/:id/remediation-result', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    const { remediation_id } = body;

    if (!remediation_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'remediation_id is required' });
      return;
    }

    try {
      const db = getDb();
      const result = remediationEngine.recordRemediationRun(db, {
        ...body,
        device_id: targetDeviceId
      });

      broadcastEvent('remediation_run_completed', {
        device_id: targetDeviceId,
        remediation_id,
        detection_status: result.detection_status,
        remediation_status: result.remediation_status
      });

      sendJson(res, 200, {
        success: true,
        run_id: result.run_id,
        detection_status: result.detection_status,
        remediation_status: result.remediation_status
      });
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_RESULT_ERROR', message: err.message });
    }
  });

  // 9. GET /api/v1/nodes/:id/profiles
  router.get('/api/v1/nodes/:id/profiles', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const profiles = configProfileEngine.getProfilesForDevice(db, targetDeviceId);
      sendJson(res, 200, { profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 10. POST /api/v1/nodes/:id/profile-compliance
  router.post('/api/v1/nodes/:id/profile-compliance', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    const { profile_id, setting_results = [] } = body;

    if (!profile_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'profile_id is required' });
      return;
    }

    try {
      const db = getDb();
      const result = configProfileEngine.recordDeviceCompliance(db, targetDeviceId, profile_id, setting_results);

      broadcastEvent('profile_compliance_updated', {
        device_id: targetDeviceId,
        profile_id,
        compliance_status: result.compliance_status,
        compliant_count: result.compliant_count,
        non_compliant_count: result.non_compliant_count,
        error_count: result.error_count
      });

      sendJson(res, 200, {
        success: true,
        ...result
      });
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILE_COMPLIANCE_ERROR', message: err.message });
    }
  });

  // 11. GET /api/v1/nodes/:id/update-ring
  router.get('/api/v1/nodes/:id/update-ring', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const ring = updateRingEngine.getRingForDevice(db, targetDeviceId);
      sendJson(res, 200, { update_ring: ring });
    } catch (err) {
      sendJson(res, 500, { error: 'UPDATE_RING_FETCH_ERROR', message: err.message });
    }
  });

  // 12. POST /api/v1/nodes/:id/update-status
  router.post('/api/v1/nodes/:id/update-status', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const result = updateRingEngine.recordDeviceUpdateStatus(db, targetDeviceId, body);

      broadcastEvent('device_update_status_updated', {
        device_id: targetDeviceId,
        reboot_pending: result.reboot_pending,
        compliance_status: result.compliance_status,
        ring_id: result.ring_id
      });

      sendJson(res, 200, {
        success: true,
        ...result
      });
    } catch (err) {
      sendJson(res, 500, { error: 'UPDATE_STATUS_RECORD_ERROR', message: err.message });
    }
  });

  // 13. GET /api/v1/nodes/:id/compliance-policies
  router.get('/api/v1/nodes/:id/compliance-policies', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const policies = complianceEngine.getPoliciesForDevice(db, targetDeviceId);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 14. POST /api/v1/nodes/:id/compliance-report
  router.post('/api/v1/nodes/:id/compliance-report', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const results = complianceEngine.evaluateDeviceCompliance(db, targetDeviceId, body);

      broadcastEvent('compliance_evaluation_reported', {
        device_id: targetDeviceId,
        policies_evaluated: results.length
      });

      sendJson(res, 200, {
        success: true,
        evaluations: results
      });
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_REPORT_ERROR', message: err.message });
    }
  });

  // 15. GET /api/v1/nodes/:id/apps
  router.get('/api/v1/nodes/:id/apps', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const apps = appManagementEngine.getDeviceAssignedApps(db, targetDeviceId);
      sendJson(res, 200, { apps });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_APPS_FETCH_ERROR', message: err.message });
    }
  });

  // 16. POST /api/v1/nodes/:id/app-status
  router.post('/api/v1/nodes/:id/app-status', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    const { app_id, ...statusPayload } = body;
    if (!app_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing app_id' });
      return;
    }

    try {
      const db = getDb();
      const result = appManagementEngine.recordAppStatus(db, targetDeviceId, app_id, statusPayload);

      broadcastEvent('device_app_status_updated', {
        device_id: targetDeviceId,
        app_id,
        install_status: result.install_status,
        detection_state: result.detection_state
      });

      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_APP_STATUS_ERROR', message: err.message });
    }
  });
}

export default registerNodeRoutes;
