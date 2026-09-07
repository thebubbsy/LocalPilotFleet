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
    if (!requireNodeToken(req, res)) return;

    const deviceId = req.device.id;
    const body = req.body || {};
    const {
      cpu_usage_percent,
      ram_used_bytes,
      ram_free_bytes,
      ram_usage_percent,
      battery_percent,
      battery_charging,
      ip_address,
      connection_route,
      uptime_seconds
    } = body;

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
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        ip_address || null,
        connection_route || null,
        battery_percent !== undefined ? Number(battery_percent) : null,
        battery_charging !== undefined ? (battery_charging ? 1 : 0) : null,
        deviceId
      );

      broadcastEvent('heartbeat', {
        device_id: deviceId,
        hostname: req.device.hostname,
        cpu_usage_percent: cpu_usage_percent || null,
        ram_usage_percent: ram_usage_percent || null,
        connection_route: connection_route || req.device.connection_route,
        status: req.device.status
      });

      sendJson(res, 200, {
        acknowledged: true,
        server_time: new Date().toISOString(),
        commands_pending: false
      });
    } catch (err) {
      sendJson(res, 500, { error: 'HEARTBEAT_ERROR', message: err.message });
    }
  });

  // 3. POST /api/v1/nodes/telemetry
  router.post('/api/v1/nodes/telemetry', async (req, res) => {
    if (!requireNodeToken(req, res)) return;

    const deviceId = req.device.id;
    const body = req.body || {};
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

      db.prepare(`
        UPDATE devices SET
          last_seen_at = DATETIME('now'),
          tpm_present = COALESCE(?, tpm_present),
          tpm_enabled = COALESCE(?, tpm_enabled),
          secure_boot_enabled = COALESCE(?, secure_boot_enabled),
          bitlocker_status = COALESCE(?, bitlocker_status),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(tpmPresent, tpmEnabled, secureBoot, bitlockerStatus, deviceId);

      // 3. Re-evaluate dynamic groups
      const activeGroups = dynamicGroupsService.reevaluateDeviceMemberships(db, deviceId, { disk_free_gb: diskFreeGb }, installedSoftware);

      // 4. Re-evaluate policy compliance and drift detection
      const compliance = policyEngine.evaluateAndPersistDeviceCompliance(db, deviceId, installedSoftware);

      broadcastEvent('telemetry_updated', {
        device_id: deviceId,
        hostname: req.device.hostname,
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
    if (!requireNodeToken(req, res)) return;

    const deviceId = req.device.id;
    const body = req.body || {};
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
}

export default registerNodeRoutes;
