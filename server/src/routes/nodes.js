import { MobileThreatDefenseEngine } from '../services/mobileThreatDefenseEngine.js';
import { EnterpriseVpnProfileEngine } from '../services/enterpriseVpnProfileEngine.js';
import { ScepPkiEnrollmentEngine } from '../services/scepPkiEnrollmentEngine.js';
import { MamAppProtectionEngine } from '../services/mamAppProtectionEngine.js';
import { MultiPlatformUemEngine } from '../services/multiPlatformUemEngine.js';
import { HardwareAttestationEngine } from '../services/hardwareAttestationEngine.js';
import { LicenseOptimizationEngine } from '../services/licenseOptimizationEngine.js';
import { RansomwareCanaryEngine } from '../services/ransomwareCanaryEngine.js';
import { CloudAppDiscoveryEngine } from '../services/cloudAppDiscoveryEngine.js';
import { UebaEngine } from '../services/uebaEngine.js';
import { ExploitProtectionEngine } from '../services/exploitProtectionEngine.js';
import { CisBenchmarkEngine } from '../services/cisBenchmarkEngine.js';
import { DlpEngine } from '../services/dlpEngine.js';
import { IdentityThreatEngine } from '../services/identityThreatEngine.js';
import { VulnerabilityManagementEngine } from '../services/vulnerabilityManagementEngine.js';
import { ThreatIntelEngine } from '../services/threatIntelEngine.js';
import { IncidentCorrelationEngine } from '../services/incidentCorrelationEngine.js';
import { LiveResponseEngine } from '../services/liveResponseEngine.js';
import { NetworkIsolationEngine } from '../services/networkIsolationEngine.js';
import { TamperProtectionEngine } from '../services/tamperProtectionEngine.js';
import { PeripheralControlEngine } from '../services/peripheralControlEngine.js';
import { WebProtectionEngine } from '../services/webProtectionEngine.js';
import { SandboxDetonationEngine } from '../services/sandboxDetonationEngine.js';
import { ThreatHuntingEngine } from '../services/threatHuntingEngine.js';
import { DeviceHealthAttestationEngine } from '../services/deviceHealthAttestationEngine.js';
import { incidentResponseEngine, IncidentResponseEngine } from '../services/incidentResponseEngine.js';
import { contentDistributionEngine } from '../services/contentDistributionEngine.js';
import { VaultSecretsEngine } from '../services/vaultSecretsEngine.js';
import { LiveQueryEngine } from '../services/liveQueryEngine.js';
import { mdmCspEngine } from '../services/mdmCspEngine.js';
import * as supervisorEngine from '../services/supervisorEngine.js';
import * as realtimePushEngine from '../services/realtimePushEngine.js';
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
import { endpointSecurityEngine } from '../services/endpointSecurityEngine.js';
import { bitlockerEngine } from '../services/bitlockerEngine.js';
import { lapsEngine } from '../services/lapsEngine.js';
import * as epmEngine from '../services/epmEngine.js';
import * as autopilotEngine from '../services/autopilotEngine.js';
import * as remoteActionEngine from '../services/remoteActionEngine.js';
import * as firewallEngine from '../services/firewallEngine.js';
import * as scriptsEngine from '../services/scriptsEngine.js';
import * as asrEngine from '../services/asrEngine.js';
import * as analyticsEngine from '../services/analyticsEngine.js';
import * as messagesEngine from '../services/messagesEngine.js';
import * as certificateEngine from '../services/certificateEngine.js';
import * as networkEngine from '../services/networkEngine.js';
import * as kioskEngine from '../services/kioskEngine.js';
import * as storageAccessEngine from '../services/storageAccessEngine.js';
import * as deliveryOptimizationEngine from '../services/deliveryOptimizationEngine.js';
import * as dfciEngine from '../services/dfciEngine.js';
import * as wipEngine from '../services/wipEngine.js';
import * as whfbEngine from '../services/whfbEngine.js';
import * as driverUpdateEngine from '../services/driverUpdateEngine.js';
import * as remoteHelpEngine from '../services/remoteHelpEngine.js';
import * as featureUpdateEngine from '../services/featureUpdateEngine.js';
import * as enterpriseAppEngine from '../services/enterpriseAppEngine.js';
import * as vulnerabilityEngine from '../services/vulnerabilityEngine.js';
import * as autopatchEngine from '../services/autopatchEngine.js';
import * as cloudPcEngine from '../services/cloudPcEngine.js';
import * as pkiSigningEngine from '../services/pkiSigningEngine.js';
import { broadcastEvent } from './events.js';

export function registerNodeRoutes(router) {

  function authenticateNode(req, res) {
    if (requireFleetKeyOrNodeToken(req, res)) {
      return req.device || { id: req.params?.id || 'fleet_admin', hostname: 'authorized' };
    }
    return null;
  }

  // POST /api/v1/nodes/:id/queries/:queryId/results — Ingest live query results from node
  router.post('/api/v1/nodes/:id/queries/:queryId/results', (req, res) => {
    const { id, queryId } = req.params;
    const { hostname, data_rows, duration_ms } = req.body || {};
    try {
      const engine = new LiveQueryEngine(getDb());
      const result = engine.ingestQueryResult(queryId, id, hostname || id, data_rows || [], duration_ms || 350);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'QUERY_INGEST_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/vault/escrow — Workstation DPAPI-NG / BitLocker / LAPS credential escrow
  router.post('/api/v1/nodes/:id/vault/escrow', (req, res) => {
    const { id } = req.params;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const stored = engine.storeSecret({
        ...req.body,
        device_id: id
      }, `NodeAgent:${id}`);
      sendJson(res, 201, { success: true, secret_id: stored.secret_id });
    } catch (err) {
      sendJson(res, 400, { error: 'VAULT_ESCROW_ERROR', message: err.message });
    }
  });
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

      // Synchronize with Windows Autopilot hardware hash registry if applicable
      let autopilotInfo = null;
      try {
        autopilotInfo = autopilotEngine.syncDeviceWithAutopilot(db, deviceId, serial_number, body.hardware_hash);
      } catch (apErr) {
        console.warn('[Autopilot Sync Warning]:', apErr.message);
      }

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
        assigned_groups: assignedGroups,
        autopilot: autopilotInfo ? { registered: true, profile_id: autopilotInfo.profile_id, deployment_status: autopilotInfo.deployment_status } : { registered: false }
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

      // Check for assigned endpoint security policy
      const assignedSecurityPolicy = endpointSecurityEngine.getEffectivePolicyForDevice(db, deviceId);

      // Check for assigned BitLocker disk encryption policy
      const assignedBitLockerPolicy = bitlockerEngine.getEffectivePolicyForDevice(db, deviceId);

      // Check for assigned LAPS policy
      const assignedLapsPolicy = lapsEngine.getEffectivePolicyForDevice(db, deviceId);

      // Check for pending remote lifecycle & diagnostic actions
      const pendingRemoteActions = remoteActionEngine.getPendingActionsForNode(deviceId);

      sendJson(res, 200, {
        acknowledged: true,
        server_time: new Date().toISOString(),
        commands_pending: pendingCommands.length > 0,
        pending_commands: pendingCommands,
        pending_remote_actions: pendingRemoteActions,
        remediations: assignedRemediations,
        profiles: assignedProfiles,
        update_ring: assignedRing,
        compliance_policies: assignedCompliancePolicies,
        assigned_apps: assignedApps,
        endpoint_security_policy: assignedSecurityPolicy,
        bitlocker_policy: assignedBitLockerPolicy,
        laps_policy: assignedLapsPolicy,
        epm_rules: epmEngine.getEffectiveEpmRulesForDevice(db, deviceId),
        autopilot: autopilotEngine.getDeviceAutopilotPosture(db, deviceId),
        firewall_policy: {
          effective_rules: firewallEngine.getEffectiveRulesForDevice(db, deviceId)
        },
        assigned_scripts: scriptsEngine.getAssignedScriptsForDevice(db, deviceId),
        assigned_asr_policy: asrEngine.getAssignedASRPolicyForDevice(db, deviceId),
        pending_messages: messagesEngine.getPendingMessagesForDevice(db, deviceId),
        certificate_profiles: certificateEngine.getEffectiveProfilesForDevice(db, deviceId),
        network_profiles: networkEngine.getEffectiveProfilesForDevice(db, deviceId),
        kiosk_profile: kioskEngine.getEffectiveKioskProfileForDevice(db, deviceId),
        storage_access_policy: storageAccessEngine.getEffectivePolicyForDevice(db, deviceId),
        delivery_optimization_policy: deliveryOptimizationEngine.getEffectivePolicyForDevice(db, deviceId),
        dfci_policy: dfciEngine.getEffectivePolicyForDevice(db, deviceId),
        wip_policy: wipEngine.getEffectiveWipPolicyForDevice(db, deviceId),
        whfb_policy: whfbEngine.getEffectiveWhfbPolicyForDevice(db, deviceId),
        driver_policy: driverUpdateEngine.getEffectiveDriverPolicyForDevice(db, deviceId),
        pending_remote_help_sessions: remoteHelpEngine.getPendingSessionsForDevice(deviceId),
        feature_update_policy: featureUpdateEngine.getEffectiveFeaturePolicyForDevice(deviceId),
        active_feature_policy: featureUpdateEngine.getEffectiveFeaturePolicyForDevice(deviceId),
        expedited_quality_update: featureUpdateEngine.getEffectiveExpeditedUpdateForDevice(deviceId),
        active_expedited_update: featureUpdateEngine.getEffectiveExpeditedUpdateForDevice(deviceId),
        pending_portal_installs: enterpriseAppEngine.getPendingDeviceInstalls(db, deviceId)
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
          installed_software_json = COALESCE(?, installed_software_json),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        tpmPresent,
        tpmEnabled,
        secureBoot,
        bitlockerStatus,
        reportedUser,
        installedSoftware.length > 0 ? JSON.stringify(installedSoftware) : null,
        deviceId
      );

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

  // 17. GET /api/v1/nodes/:id/security-policy
  router.get('/api/v1/nodes/:id/security-policy', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const policy = endpointSecurityEngine.getEffectivePolicyForDevice(db, targetDeviceId);
      sendJson(res, 200, { policy });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_SECURITY_POLICY_ERROR', message: err.message });
    }
  });

  // 18. POST /api/v1/nodes/:id/antivirus-status
  router.post('/api/v1/nodes/:id/antivirus-status', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const result = endpointSecurityEngine.recordAntivirusStatus(db, targetDeviceId, body);

      broadcastEvent('antivirus_status_updated', {
        device_id: targetDeviceId,
        real_time_protection_enabled: result.real_time_protection_enabled,
        signature_version: result.signature_version,
        signature_age_days: result.signature_age_days,
        health_status: result.health_status
      });

      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_AV_STATUS_ERROR', message: err.message });
    }
  });

  // 19. POST /api/v1/nodes/:id/threat-detection
  router.post('/api/v1/nodes/:id/threat-detection', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    if (!body.threat_name) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing threat_name' });
      return;
    }

    try {
      const db = getDb();
      const result = endpointSecurityEngine.recordThreatDetection(db, targetDeviceId, body);

      broadcastEvent('threat_detected', {
        device_id: targetDeviceId,
        threat_name: result.threat_name,
        severity: result.severity,
        action_taken: result.action_taken
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_THREAT_DETECTION_ERROR', message: err.message });
    }
  });

  // 20. GET /api/v1/nodes/:id/bitlocker-policy
  router.get('/api/v1/nodes/:id/bitlocker-policy', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const policy = bitlockerEngine.getEffectivePolicyForDevice(db, targetDeviceId);
      sendJson(res, 200, { policy });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_BITLOCKER_POLICY_ERROR', message: err.message });
    }
  });

  // 21. POST /api/v1/nodes/:id/bitlocker-status (Report volume encryption state)
  router.post('/api/v1/nodes/:id/bitlocker-status', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const result = bitlockerEngine.recordVolumeStatus(db, targetDeviceId, body);

      broadcastEvent('bitlocker_status_updated', {
        device_id: targetDeviceId,
        mount_point: result.mount_point,
        protection_status: result.protection_status,
        volume_status: result.volume_status,
        encryption_percentage: result.encryption_percentage
      });

      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_BITLOCKER_STATUS_ERROR', message: err.message });
    }
  });

  // 22. POST /api/v1/nodes/:id/bitlocker-escrow (Escrow 48-digit recovery password into vault)
  router.post('/api/v1/nodes/:id/bitlocker-escrow', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    if (!body.key_protector_id || !body.recovery_password) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing key_protector_id or recovery_password' });
      return;
    }

    try {
      const db = getDb();
      const result = bitlockerEngine.escrowRecoveryKey(db, targetDeviceId, body);

      broadcastEvent('bitlocker_key_escrowed', {
        device_id: targetDeviceId,
        mount_point: result.volume_mount_point,
        key_id: result.id,
        key_id_short: result.key_id_short
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_BITLOCKER_ESCROW_ERROR', message: err.message });
    }
  });

  // 23. GET /api/v1/nodes/:id/laps-policy (Get effective LAPS policy for node)
  router.get('/api/v1/nodes/:id/laps-policy', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const policy = lapsEngine.getEffectivePolicyForDevice(db, targetDeviceId);
      sendJson(res, 200, { policy });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_LAPS_POLICY_ERROR', message: err.message });
    }
  });

  // 24. POST /api/v1/nodes/:id/laps-escrow (Escrow newly rotated local admin password)
  router.post('/api/v1/nodes/:id/laps-escrow', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    if (!body.password) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Missing password in escrow payload' });
      return;
    }

    try {
      const db = getDb();
      const result = lapsEngine.escrowPassword(db, targetDeviceId, body);

      broadcastEvent('laps_password_escrowed', {
        device_id: targetDeviceId,
        account_name: result.account_name,
        expires_at: result.expires_at
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_LAPS_ESCROW_ERROR', message: err.message });
    }
  });

  // 25. GET /api/v1/nodes/:id/epm-rules (Get effective EPM rules for node)
  router.get('/api/v1/nodes/:id/epm-rules', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const rules = epmEngine.getEffectiveEpmRulesForDevice(db, targetDeviceId);
      sendJson(res, 200, { rules, count: rules.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_EPM_RULES_ERROR', message: err.message });
    }
  });

  // 26. POST /api/v1/nodes/:id/epm-request (Submit standard user elevation request)
  router.post('/api/v1/nodes/:id/epm-request', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const result = epmEngine.requestElevation(db, targetDeviceId, body);

      broadcastEvent('epm_request_submitted', {
        device_id: targetDeviceId,
        file_name: result.file_name,
        status: result.status,
        request_id: result.request_id
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_EPM_REQUEST_ERROR', message: err.message });
    }
  });

  // 27. POST /api/v1/nodes/:id/epm-elevation (Ingest elevated execution telemetry)
  router.post('/api/v1/nodes/:id/epm-elevation', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const result = epmEngine.logElevationEvent(db, targetDeviceId, body);

      broadcastEvent('epm_elevation_logged', {
        device_id: targetDeviceId,
        file_name: body.file_name,
        user_name: body.user_name || 'StandardUser'
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_EPM_ELEVATION_LOG_ERROR', message: err.message });
    }
  });

  // 28. GET /api/v1/nodes/:id/autopilot-profile (Fetch assigned Autopilot profile and ESP)
  router.get('/api/v1/nodes/:id/autopilot-profile', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    try {
      const db = getDb();
      const posture = autopilotEngine.getDeviceAutopilotPosture(db, targetDeviceId);
      if (!posture || !posture.is_registered) {
        sendJson(res, 404, { error: 'NOT_REGISTERED', message: 'Device is not registered in Windows Autopilot' });
        return;
      }
      sendJson(res, 200, posture);
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_AUTOPILOT_PROFILE_ERROR', message: err.message });
    }
  });

  // 29. POST /api/v1/nodes/:id/provisioning-event (Ingest OOBE/ESP phase progression)
  router.post('/api/v1/nodes/:id/provisioning-event', async (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;

    const body = req.body || {};
    try {
      const db = getDb();
      const apDev = db.prepare('SELECT id FROM autopilot_devices WHERE device_id = ?').get(targetDeviceId);
      const autopilotDeviceId = apDev ? apDev.id : body.autopilot_device_id;

      if (!autopilotDeviceId) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'No registered Autopilot device record associated with this node' });
        return;
      }

      const result = autopilotEngine.logProvisioningEvent(db, {
        autopilot_device_id: autopilotDeviceId,
        device_id: targetDeviceId,
        phase: body.phase,
        step_name: body.step_name,
        status: body.status,
        error_code: body.error_code,
        details: body.details
      });

      broadcastEvent('autopilot_provisioning_event', {
        device_id: targetDeviceId,
        autopilot_device_id: autopilotDeviceId,
        phase: result.phase,
        status: result.status,
        step_name: body.step_name
      });

      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_PROVISIONING_EVENT_ERROR', message: err.message });
    }
  });

  // 30. GET /api/v1/nodes/:id/remote-actions/pending
  router.get('/api/v1/nodes/:id/remote-actions/pending', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const actions = remoteActionEngine.getPendingActionsForNode(id);
      sendJson(res, 200, { device_id: id, count: actions.length, actions });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_PENDING_ACTIONS_ERROR', message: err.message });
    }
  });

  // 31. POST /api/v1/nodes/:id/remote-actions/:actionId/result
  router.post('/api/v1/nodes/:id/remote-actions/:actionId/result', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id, actionId } = req.params;
    const body = req.body || {};
    try {
      const result = remoteActionEngine.completeRemoteAction({
        actionId,
        deviceId: id,
        status: body.status || 'COMPLETED',
        resultData: body.result_data || body.result || {},
        errorMessage: body.error_message || body.error || null
      });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_ACTION_RESULT_ERROR', message: err.message });
    }
  });

  // 32. POST /api/v1/nodes/:id/diagnostics-upload
  router.post('/api/v1/nodes/:id/diagnostics-upload', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const bundle = remoteActionEngine.saveDiagnosticsBundle({
        deviceId: id,
        remoteActionId: body.remote_action_id || null,
        fileName: body.file_name || `diagnostics-${id}-${Date.now()}.zip`,
        base64Data: body.base64_data || body.data || '',
        categories: body.categories || ['SYSTEM_LOGS', 'SECURITY_LOGS'],
        summary: body.summary || {}
      });
      sendJson(res, 201, bundle);
    } catch (err) {
      sendJson(res, 400, { error: 'DIAGNOSTICS_UPLOAD_ERROR', message: err.message });
    }
  });

  // 33. POST /api/v1/nodes/:id/firewall-status
  router.post('/api/v1/nodes/:id/firewall-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const status = firewallEngine.saveDeviceFirewallStatus(db, id, body);
      broadcastEvent('node_firewall_reported', { device_id: id, compliance_status: status.compliance_status });
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 400, { error: 'FIREWALL_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 34. POST /api/v1/nodes/:id/listening-ports
  router.post('/api/v1/nodes/:id/listening-ports', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    const portsList = Array.isArray(body) ? body : (body.ports || []);
    try {
      const db = getDb();
      const saved = firewallEngine.saveDeviceListeningPorts(db, id, portsList);
      sendJson(res, 200, { device_id: id, count: saved.length, ports: saved });
    } catch (err) {
      sendJson(res, 400, { error: 'LISTENING_PORTS_REPORT_ERROR', message: err.message });
    }
  });

  // 35. POST /api/v1/nodes/:id/scripts/:scriptId/result (Agent reports Intune script execution result)
  router.post('/api/v1/nodes/:id/scripts/:scriptId/result', (req, res) => {
    const targetDeviceId = req.params.id;
    if (!requireFleetKeyOrNodeToken(req, res, targetDeviceId)) return;
    const { scriptId } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const runRecord = scriptsEngine.saveScriptRunResult(db, {
        deviceId: targetDeviceId,
        scriptId: scriptId,
        runMode: body.run_mode || 'ASSIGNED',
        status: body.status || (body.exit_code === 0 ? 'SUCCESS' : 'FAILED'),
        exitCode: body.exit_code !== undefined ? Number(body.exit_code) : 0,
        stdout: body.stdout || '',
        stderr: body.stderr || '',
        executionTimeMs: body.execution_time_ms || 0
      });
      broadcastEvent('script_run_completed', {
        device_id: targetDeviceId,
        script_id: scriptId,
        status: runRecord.status,
        exit_code: runRecord.exit_code
      });
      sendJson(res, 201, runRecord);
    } catch (err) {
      sendJson(res, 400, { error: 'SCRIPT_RUN_RESULT_ERROR', message: err.message });
    }
  });

  // 36. POST /api/v1/nodes/:id/asr-status (Agent reports ASR posture snapshot)
  router.post('/api/v1/nodes/:id/asr-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const status = asrEngine.saveDeviceASRStatus(db, {
        deviceId: id,
        policyId: body.policy_id || null,
        asrRulesStatus: body.asr_rules_status || {},
        networkProtectionMode: body.network_protection_mode || 'UNKNOWN',
        controlledFolderAccess: body.controlled_folder_access || 'UNKNOWN',
        exploitProtectionApplied: body.exploit_protection_applied || false
      });
      broadcastEvent('node_asr_status_reported', { device_id: id });
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 400, { error: 'ASR_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 37. POST /api/v1/nodes/:id/asr-events (Agent reports bulk ASR events)
  router.post('/api/v1/nodes/:id/asr-events', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    const events = Array.isArray(body) ? body : (body.events || []);
    try {
      const db = getDb();
      const saved = asrEngine.saveASREvents(db, id, events);
      broadcastEvent('node_asr_events_reported', { device_id: id, count: saved.length });
      sendJson(res, 200, { device_id: id, saved_count: saved.length });
    } catch (err) {
      sendJson(res, 400, { error: 'ASR_EVENTS_REPORT_ERROR', message: err.message });
    }
  });

  // 38. POST /api/v1/nodes/:id/analytics-snapshot (Agent reports boot/sign-in & performance metrics)
  router.post('/api/v1/nodes/:id/analytics-snapshot', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const snapshot = analyticsEngine.saveAnalyticsSnapshot(db, {
        deviceId: id,
        bootDurationMs: body.boot_duration_ms,
        signinDurationMs: body.signin_duration_ms,
        appCrashCount24h: body.app_crash_count_24h,
        appHangCount24h: body.app_hang_count_24h,
        cpuSpikePct: body.cpu_spike_pct,
        ramPressurePct: body.ram_pressure_pct,
        diskQueueDepth: body.disk_queue_depth
      });
      sendJson(res, 201, snapshot);
    } catch (err) {
      sendJson(res, 400, { error: 'ANALYTICS_SNAPSHOT_ERROR', message: err.message });
    }
  });

  // 39. POST /api/v1/nodes/:id/app-reliability (Agent reports application crashes and hangs)
  router.post('/api/v1/nodes/:id/app-reliability', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    const events = Array.isArray(body) ? body : (body.events || []);
    try {
      const db = getDb();
      const saved = analyticsEngine.saveAppReliabilityEvents(db, id, events);
      broadcastEvent('app_reliability_events_reported', { device_id: id, count: saved.length });
      sendJson(res, 200, { device_id: id, saved_count: saved.length });
    } catch (err) {
      sendJson(res, 400, { error: 'APP_RELIABILITY_REPORT_ERROR', message: err.message });
    }
  });

  // 40. POST /api/v1/nodes/:id/messages/:messageId/ack (Agent acks message delivery or user interaction)
  router.post('/api/v1/nodes/:id/messages/:messageId/ack', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id, messageId } = req.params;
    const { status = 'DELIVERED', interacted } = req.body || {};
    try {
      const db = getDb();
      const result = messagesEngine.recordDeliveryStatus(db, {
        messageId,
        deviceId: id,
        status,
        interactedAt: interacted
      });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'MESSAGE_ACK_ERROR', message: err.message });
    }
  });

  // 41. POST /api/v1/nodes/:id/certificates (Agent reports discovered / installed certificates)
  router.post('/api/v1/nodes/:id/certificates', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    const certList = Array.isArray(body) ? body : (body.certificates || []);
    try {
      const db = getDb();
      const result = certificateEngine.saveDeviceCertificates(db, id, certList);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'CERTIFICATES_REPORT_ERROR', message: err.message });
    }
  });

  // 42. GET /api/v1/nodes/:id/certificate-profiles (Agent fetches assigned certificate profiles)
  router.get('/api/v1/nodes/:id/certificate-profiles', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profiles = certificateEngine.getEffectiveProfilesForDevice(db, id);
      sendJson(res, 200, { device_id: id, profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'CERTIFICATE_PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 43. POST /api/v1/nodes/:id/network-posture (Agent reports active Wi-Fi and VPN posture)
  router.post('/api/v1/nodes/:id/network-posture', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = networkEngine.saveDeviceNetworkPosture(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'NETWORK_POSTURE_REPORT_ERROR', message: err.message });
    }
  });

  // 44. GET /api/v1/nodes/:id/network-profiles (Agent fetches assigned Wi-Fi / VPN profiles)
  router.get('/api/v1/nodes/:id/network-profiles', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profiles = networkEngine.getEffectiveProfilesForDevice(db, id);
      sendJson(res, 200, { device_id: id, profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 45. POST /api/v1/nodes/:id/kiosk-status (Agent reports active kiosk & shell posture)
  router.post('/api/v1/nodes/:id/kiosk-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = kioskEngine.saveDeviceKioskStatus(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'KIOSK_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 46. GET /api/v1/nodes/:id/kiosk-profile (Agent fetches assigned kiosk profile)
  router.get('/api/v1/nodes/:id/kiosk-profile', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profile = kioskEngine.getEffectiveKioskProfileForDevice(db, id);
      sendJson(res, 200, { device_id: id, profile });
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_PROFILE_FETCH_ERROR', message: err.message });
    }
  });

  // 47. POST /api/v1/nodes/:id/storage-status (Agent reports removable drives & BitLocker To Go posture)
  router.post('/api/v1/nodes/:id/storage-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = storageAccessEngine.saveDeviceStorageStatus(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'STORAGE_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 48. POST /api/v1/nodes/:id/storage-event (Agent logs USB drive insertion, removal, or block event)
  router.post('/api/v1/nodes/:id/storage-event', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = storageAccessEngine.recordStorageEvent(db, id, req.body || {});
      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'STORAGE_EVENT_REPORT_ERROR', message: err.message });
    }
  });

  // 49. GET /api/v1/nodes/:id/storage-policy (Agent fetches assigned removable storage policy)
  router.get('/api/v1/nodes/:id/storage-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = storageAccessEngine.getEffectivePolicyForDevice(db, id);
      sendJson(res, 200, { device_id: id, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 50. POST /api/v1/nodes/:id/delivery-optimization-status (Agent reports P2P cache, downloads, and peer stats)
  router.post('/api/v1/nodes/:id/delivery-optimization-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = deliveryOptimizationEngine.saveDeviceDOStatus(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'DO_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 51. POST /api/v1/nodes/:id/delivery-optimization-log (Agent logs package download from peer or CDN)
  router.post('/api/v1/nodes/:id/delivery-optimization-log', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = deliveryOptimizationEngine.recordContentTransfer(db, id, req.body || {});
      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'DO_CONTENT_LOG_ERROR', message: err.message });
    }
  });

  // 52. GET /api/v1/nodes/:id/delivery-optimization-policy (Agent fetches assigned Delivery Optimization policy)
  router.get('/api/v1/nodes/:id/delivery-optimization-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = deliveryOptimizationEngine.getEffectivePolicyForDevice(db, id);
      sendJson(res, 200, { device_id: id, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 53. POST /api/v1/nodes/:id/dfci-status (Agent reports UEFI firmware, TPM, Secure Boot & root-of-trust posture)
  router.post('/api/v1/nodes/:id/dfci-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = dfciEngine.saveDeviceDfciStatus(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'DFCI_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 54. POST /api/v1/nodes/:id/dfci-event (Agent reports firmware change or hardware tamper alert)
  router.post('/api/v1/nodes/:id/dfci-event', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = dfciEngine.recordDfciEvent(db, id, req.body || {});
      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'DFCI_EVENT_LOG_ERROR', message: err.message });
    }
  });

  // 55. GET /api/v1/nodes/:id/dfci-policy (Agent fetches assigned DFCI firmware policy)
  router.get('/api/v1/nodes/:id/dfci-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = dfciEngine.getEffectivePolicyForDevice(db, id);
      sendJson(res, 200, { device_id: id, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 56. POST /api/v1/nodes/:id/wip-status (Agent reports WIP data protection and exfiltration metrics)
  router.post('/api/v1/nodes/:id/wip-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = wipEngine.saveDeviceWipStatus(db, id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'WIP_STATUS_REPORT_ERROR', message: err.message });
    }
  });

  // 57. POST /api/v1/nodes/:id/wip-event (Agent reports corporate data violation or exfiltration attempt)
  router.post('/api/v1/nodes/:id/wip-event', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = wipEngine.recordWipEvent(db, id, req.body || {});
      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'WIP_EVENT_LOG_ERROR', message: err.message });
    }
  });

  // 58. GET /api/v1/nodes/:id/wip-policy (Agent fetches effective assigned WIP policy)
  router.get('/api/v1/nodes/:id/wip-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = wipEngine.getEffectiveWipPolicyForDevice(db, id);
      sendJson(res, 200, { device_id: id, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // ── Windows Hello for Business (WHfB) & FIDO2 Node Routes (59–61) ──
  // 59. POST /api/v1/nodes/:id/whfb-status (Agent reports WHfB enrollment & hardware attestation)
  router.post('/api/v1/nodes/:id/whfb-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = whfbEngine.saveDeviceWhfbStatus(db, id, req.body || {});
      sendJson(res, 200, { ok: true, whfb_status: result });
    } catch (err) {
      sendJson(res, 400, { error: 'WHFB_STATUS_INGEST_ERROR', message: err.message });
    }
  });

  // 60. POST /api/v1/nodes/:id/whfb-event (Agent reports PIN/Biometric/FIDO2 authentication event)
  router.post('/api/v1/nodes/:id/whfb-event', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = whfbEngine.recordWhfbEvent(db, id, req.body || {});
      sendJson(res, 201, result);
    } catch (err) {
      sendJson(res, 400, { error: 'WHFB_EVENT_LOG_ERROR', message: err.message });
    }
  });

  // 61. GET /api/v1/nodes/:id/whfb-policy (Agent fetches effective assigned WHfB policy)
  router.get('/api/v1/nodes/:id/whfb-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = whfbEngine.getEffectiveWhfbPolicyForDevice(db, id);
      sendJson(res, 200, { device_id: id, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // ── Windows Driver & Firmware Update Profiles (WUfB) Node Routes (62–64) ──
  // 62. POST /api/v1/nodes/:id/drivers/inventory (Agent reports scanned PnP signed drivers & firmware)
  router.post('/api/v1/nodes/:id/drivers/inventory', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const drivers = req.body?.drivers || req.body || [];
      const result = driverUpdateEngine.saveDeviceDriverInventory(db, id, drivers);
      sendJson(res, 200, { ok: true, drivers_ingested: result.count, result });
    } catch (err) {
      sendJson(res, 400, { error: 'DRIVER_INVENTORY_INGEST_ERROR', message: err.message });
    }
  });

  // 63. GET /api/v1/nodes/:id/driver-policy (Agent fetches effective assigned Driver update policy & approval registry script)
  router.get('/api/v1/nodes/:id/driver-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = driverUpdateEngine.getEffectiveDriverPolicyForDevice(db, id);
      const registryScript = driverUpdateEngine.generateDriverRegistryScript(policy);
      sendJson(res, 200, { device_id: id, policy, registry_script: registryScript });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 64. GET /api/v1/nodes/:id/drivers (Agent or admin queries drivers inventory for specific device)
  router.get('/api/v1/nodes/:id/drivers', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const data = driverUpdateEngine.getDeviceDrivers(db, id);
      sendJson(res, 200, data);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DRIVERS_FETCH_ERROR', message: err.message });
    }
  });

  // ── Remote Help & Unattended Assistance Node Routes (65–67) ──
  // 65. POST /api/v1/nodes/:id/remote-help/connect (Node connects or activates session via PIN)
  router.post('/api/v1/nodes/:id/remote-help/connect', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { session_code, session_id, sharer_user } = req.body || {};
    try {
      const session = remoteHelpEngine.connectSession(session_code || session_id, { sharer_user });
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_CONNECT_ERROR', message: err.message });
    }
  });

  // 66. POST /api/v1/nodes/:id/remote-help/disconnect (Node reports session end/disconnect)
  router.post('/api/v1/nodes/:id/remote-help/disconnect', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { session_id, actor_user, reason } = req.body || {};
    try {
      const session = remoteHelpEngine.terminateSession(session_id, actor_user || 'Workstation Node', reason || 'Workstation disconnected');
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_DISCONNECT_ERROR', message: err.message });
    }
  });

  // 67. POST /api/v1/nodes/:id/remote-help/event (Node logs remote help activity or elevation)
  router.post('/api/v1/nodes/:id/remote-help/event', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const { session_id, actor_user, action, details } = req.body || {};
    try {
      const log = remoteHelpEngine.recordAuditEvent({
        session_id,
        device_id: id,
        actor_user: actor_user || 'Workstation Node',
        action: action || 'SESSION_STARTED',
        details: details || ''
      });
      sendJson(res, 201, log);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_EVENT_ERROR', message: err.message });
    }
  });

  // ── Windows Feature Update Profiles & Expedited Quality Updates (68–70) ──
  // 68. POST /api/v1/nodes/:id/feature-status (Agent reports OS version, build, offering, and expedited patch posture)
  router.post('/api/v1/nodes/:id/feature-status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const result = featureUpdateEngine.saveDeviceFeatureUpdateStatus(id, req.body || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'FEATURE_STATUS_SAVE_ERROR', message: err.message });
    }
  });

  // 69. GET /api/v1/nodes/:id/feature-policy (Agent queries effective assigned Feature Update policy & version lock script)
  router.get('/api/v1/nodes/:id/feature-policy', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const policy = featureUpdateEngine.getEffectiveFeaturePolicyForDevice(id);
      const registryScript = policy ? featureUpdateEngine.generateFeatureRegistryScript(policy) : '';
      sendJson(res, 200, { device_id: id, policy, effective_feature_policy: policy, registry_script: registryScript });
    } catch (err) {
      sendJson(res, 500, { error: 'FEATURE_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 70. GET /api/v1/nodes/:id/expedited-update (Agent queries active emergency expedited quality hotfix)
  router.get('/api/v1/nodes/:id/expedited-update', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const exp = featureUpdateEngine.getEffectiveExpeditedUpdateForDevice(id);
      const expediteScript = exp ? featureUpdateEngine.generateExpeditedRegistryScript(exp) : '';
      sendJson(res, 200, { device_id: id, expedited_update: exp, expedite_script: expediteScript });
    } catch (err) {
      sendJson(res, 500, { error: 'EXPEDITED_UPDATE_FETCH_ERROR', message: err.message });
    }
  });

  // 71. GET /api/v1/nodes/:id/company-portal/catalog (Device queries self-service catalog with installation status)
  router.get('/api/v1/nodes/:id/company-portal/catalog', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const catalog = enterpriseAppEngine.getCompanyPortalCatalog(getDb(), id);
      sendJson(res, 200, { device_id: id, catalog, total: catalog.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PORTAL_CATALOG_FETCH_ERROR', message: err.message });
    }
  });

  // 72. POST /api/v1/nodes/:id/company-portal/request (Device submits self-service app request)
  router.post('/api/v1/nodes/:id/company-portal/request', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const request = enterpriseAppEngine.createCompanyPortalRequest(getDb(), {
        ...req.body,
        device_id: id
      });
      sendJson(res, 201, { success: true, request });
    } catch (err) {
      sendJson(res, 400, { error: 'PORTAL_REQUEST_ERROR', message: err.message });
    }
  });

  // 73. POST /api/v1/nodes/:id/company-portal/requests/:reqId/status (Device agent updates installation progress)
  router.post('/api/v1/nodes/:id/company-portal/requests/:reqId/status', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { reqId } = req.params;
    try {
      const updated = enterpriseAppEngine.updateCompanyPortalRequestStatus(getDb(), reqId, req.body);
      if (!updated) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Request not found' });
      sendJson(res, 200, { success: true, request: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'PORTAL_STATUS_UPDATE_ERROR', message: err.message });
    }
  });

  // 74. GET /api/v1/nodes/:id/vulnerabilities (Agent queries active CVE vulnerabilities affecting it)
  router.get('/api/v1/nodes/:id/vulnerabilities', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const vulns = vulnerabilityEngine.getDeviceVulnerabilities(getDb(), id, { status: 'ACTIVE' });
      sendJson(res, 200, { device_id: id, active_vulnerabilities: vulns, count: vulns.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_VULNS_FETCH_ERROR', message: err.message });
    }
  });

  // 75. POST /api/v1/nodes/:id/vulnerabilities/scan (Agent submits installed software for CVE assessment)
  router.post('/api/v1/nodes/:id/vulnerabilities/scan', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const software = req.body.software || [];
      if (Array.isArray(software) && software.length > 0) {
        try {
          getDb().prepare("UPDATE devices SET installed_software_json = ?, updated_at = DATETIME('now') WHERE id = ?")
            .run(JSON.stringify(software), id);
        } catch {}
      }
      const activeVulns = vulnerabilityEngine.assessDeviceVulnerabilities(getDb(), id, software);
      sendJson(res, 200, { success: true, device_id: id, active_vulnerabilities: activeVulns, count: activeVulns.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_VULN_SCAN_ERROR', message: err.message });
    }
  });

  // 77. GET /api/v1/nodes/:id/autopatch (Node queries assigned patch cadence and target KBs)
  router.get('/api/v1/nodes/:id/autopatch', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const status = autopatchEngine.getDeviceAutopatchStatus(getDb(), id);
      const activeRelease = getDb().prepare("SELECT * FROM autopatch_release_cadence WHERE active_phase NOT IN ('COMPLETED', 'ROLLED_BACK') ORDER BY created_at DESC LIMIT 1").get();
      sendJson(res, 200, { device_id: id, deployment: status, active_release: activeRelease || null });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_AUTOPATCH_FETCH_ERROR', message: err.message });
    }
  });

  // 78. POST /api/v1/nodes/:id/autopatch/report (Node reports patch install status and health)
  router.post('/api/v1/nodes/:id/autopatch/report', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const updated = autopatchEngine.recordDevicePatchReport(getDb(), id, req.body || {});
      sendJson(res, 200, { success: true, device_id: id, deployment: updated });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_AUTOPATCH_REPORT_ERROR', message: err.message });
    }
  });

  // 76. GET /api/v1/nodes/:id/baselines (Agent queries assigned security baseline audit & remediation scripts)
  router.get('/api/v1/nodes/:id/baselines', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const baselines = vulnerabilityEngine.getSecurityBaselines(getDb(), { enabled: 1 });
      const payloads = baselines.map(b => ({
        id: b.id,
        name: b.name,
        category: b.category,
        audit_script: vulnerabilityEngine.generateBaselineAuditScript(b),
        remediation_script: vulnerabilityEngine.generateBaselineRemediationScript(b)
      }));
      sendJson(res, 200, { device_id: id, baselines: payloads, count: payloads.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_BASELINES_FETCH_ERROR', message: err.message });
    }
  });

  // 79. GET /api/v1/nodes/:id/cloud-pc (Node queries assigned Cloud PC / VM instances)
  router.get('/api/v1/nodes/:id/cloud-pc', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const instances = getDb().prepare('SELECT * FROM cloud_pc_instances WHERE host_device_id = ?').all(id);
      sendJson(res, 200, { device_id: id, cloud_pcs: instances, count: instances.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_CLOUD_PC_FETCH_ERROR', message: err.message });
    }
  });

  // 80. POST /api/v1/nodes/:id/cloud-pc/report (Node reports local Hyper-V / WSL2 VMs)
  router.post('/api/v1/nodes/:id/cloud-pc/report', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const vms = req.body?.vms || [];
      sendJson(res, 200, { success: true, device_id: id, reported_vms_count: vms.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_CLOUD_PC_REPORT_ERROR', message: err.message });
    }
  });

  // 81. GET /api/v1/pki/cert (Public Root CA certificate for Zero-Trust agents)
  router.get('/api/v1/pki/cert', (req, res) => {
    try {
      const cert = pkiSigningEngine.getPublicCertificate(getDb());
      sendJson(res, 200, cert);
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_CERT_ERROR', message: err.message });
    }
  });

  // 82. GET /api/v1/nodes/:id/pki/cert (Node queries code signing CA cert)
  router.get('/api/v1/nodes/:id/pki/cert', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    try {
      const cert = pkiSigningEngine.getPublicCertificate(getDb());
      sendJson(res, 200, { device_id: req.params.id, ...cert });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_PKI_CERT_ERROR', message: err.message });
    }
  });

  // 83. POST /api/v1/nodes/:id/pki/verify-report (Node reports payload verification result)
  router.post('/api/v1/nodes/:id/pki/verify-report', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    try {
      const { target_id, signature_valid, signer_thumbprint, rejection_reason } = req.body || {};
      sendJson(res, 200, {
        success: true,
        device_id: req.params.id,
        status: signature_valid ? 'VERIFIED' : 'REJECTED',
        logged_at: new Date().toISOString()
      });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_PKI_REPORT_ERROR', message: err.message });
    }
  });

  // 84. GET /api/v1/nodes/:id/push/stream (SSE Duplex Real-Time Push Stream)
  router.get('/api/v1/nodes/:id/push/stream', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    const db = getDb();

    // Register active channel in DB
    const clientIp = req.socket.remoteAddress || req.headers['x-forwarded-for'] || '';
    const userAgent = req.headers['user-agent'] || 'LocalPilot-Agent';
    realtimePushEngine.registerChannel(db, {
      nodeId: id,
      transportType: 'SSE_STREAM',
      protocolVersion: 'v1.0',
      clientIp,
      userAgent
    });

    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    res.write(`event: connected\ndata: ${JSON.stringify({ status: 'CONNECTED', node_id: id, timestamp: new Date().toISOString() })}\n\n`);

    // Attach to in-memory push dispatcher
    realtimePushEngine.attachClientStream(id, res);

    // Flush any pending queued messages immediately
    const pending = realtimePushEngine.getPendingMessagesForNode(db, id);
    for (const msg of pending) {
      let payloadObj = {};
      try { payloadObj = JSON.parse(msg.payload_json); } catch {}
      res.write(`event: ${msg.topic}\ndata: ${JSON.stringify({ message_id: msg.id, topic: msg.topic, priority: msg.priority, payload: payloadObj, dispatched_at: msg.dispatched_at })}\n\n`);
    }

    // Keepalive ping interval
    const pingTimer = setInterval(() => {
      try {
        res.write(': ping\n\n');
        realtimePushEngine.heartbeatChannel(db, id);
      } catch {
        clearInterval(pingTimer);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(pingTimer);
      realtimePushEngine.detachClientStream(id, res);
      realtimePushEngine.closeChannel(db, id);
    });
  });

  // 85. POST /api/v1/nodes/:id/push/ack (Node confirms instant message delivery & latency)
  router.post('/api/v1/nodes/:id/push/ack', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const { message_id, client_timestamp, latency_ms, error_message } = req.body || {};
      if (!message_id) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'message_id is required' });
      }

      const result = realtimePushEngine.acknowledgePushMessage(getDb(), {
        messageId: message_id,
        nodeId: id,
        clientTimestamp: client_timestamp,
        latencyMs: latency_ms ? Number(latency_ms) : null,
        errorMessage: error_message
      });

      if (result.error) {
        return sendJson(res, 404, result);
      }

      sendJson(res, 200, { success: true, message: result });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_ACK_ERROR', message: err.message });
    }
  });

  // 86. GET /api/v1/nodes/:id/push/pending (Poll fallback for queued push messages)
  router.get('/api/v1/nodes/:id/push/pending', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const pending = realtimePushEngine.getPendingMessagesForNode(getDb(), id);
      sendJson(res, 200, { node_id: id, pending_messages: pending, count: pending.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_PENDING_ERROR', message: err.message });
    }
  });

  // 87. POST /api/v1/nodes/:id/push/ping (Channel heartbeat)
  router.post('/api/v1/nodes/:id/push/ping', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const channelId = req.body?.channel_id || id;
      realtimePushEngine.heartbeatChannel(getDb(), channelId);
      sendJson(res, 200, { success: true, timestamp: new Date().toISOString() });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_PING_ERROR', message: err.message });
    }
  });

  // 88. POST /api/v1/nodes/:id/supervisor/register
  router.post('/api/v1/nodes/:id/supervisor/register', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const sup = supervisorEngine.registerSupervisor(getDb(), {
        deviceId: id,
        ...req.body
      });
      sendJson(res, 200, { success: true, supervisor: sup });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_REG_ERROR', message: err.message });
    }
  });

  // 89. POST /api/v1/nodes/:id/supervisor/heartbeat
  router.post('/api/v1/nodes/:id/supervisor/heartbeat', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const ok = supervisorEngine.heartbeatSupervisor(getDb(), {
        deviceId: id,
        ...req.body
      });
      sendJson(res, 200, { success: ok, timestamp: new Date().toISOString() });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_HEARTBEAT_ERROR', message: err.message });
    }
  });

  // 90. POST /api/v1/nodes/:id/supervisor/crash (Watchdog reports worker crash & auto-restart)
  router.post('/api/v1/nodes/:id/supervisor/crash', (req, res) => {
    if (!requireFleetKeyOrNodeToken(req, res)) return;
    const { id } = req.params;
    try {
      const dump = supervisorEngine.recordCrashDump(getDb(), {
        deviceId: id,
        ...req.body
      });
      sendJson(res, 200, { success: true, crash_id: dump.id, recovery_action: dump.recovery_action });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_CRASH_REPORT_ERROR', message: err.message });
    }
  });


  // 91. GET /api/v1/nodes/:id/mdm/csps
  router.get('/api/v1/nodes/:id/mdm/csps', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const effectiveCsps = mdmCspEngine.getEffectiveCspPoliciesForDevice(req.params.id);
      sendJson(res, 200, { csps: effectiveCsps, count: effectiveCsps.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_CSP_ERROR', message: err.message });
    }
  });

  // 92. POST /api/v1/nodes/:id/mdm/autopilot-hash
  router.post('/api/v1/nodes/:id/mdm/autopilot-hash', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const harvested = mdmCspEngine.harvestAutopilotHardwareHash({
        device_id: req.params.id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, hardware_hash: harvested });
    } catch (err) {
      sendJson(res, 400, { error: 'AP_HARVEST_ERROR', message: err.message });
    }
  });

  // 93. POST /api/v1/nodes/:id/mdm/wipe-status
  router.post('/api/v1/nodes/:id/mdm/wipe-status', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const updated = mdmCspEngine.updateRemoteWipeStatus(req.body?.wipe_id, req.body || {});
      sendJson(res, 200, { success: true, wipe: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'WIPE_STATUS_ERROR', message: err.message });
    }
  });


  // ── Dimension 4: Node Content Distribution & P2P Mesh Routes (94–97) ──
  // 94. GET /api/v1/nodes/:id/bits/jobs
  router.get('/api/v1/nodes/:id/bits/jobs', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const db = getDb();
      const jobs = contentDistributionEngine.getBitsJobs(db, { deviceId: req.params.id });
      sendJson(res, 200, { jobs, count: jobs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'NODE_BITS_JOBS_ERROR', message: err.message });
    }
  });

  // 95. POST /api/v1/nodes/:id/bits/progress
  router.post('/api/v1/nodes/:id/bits/progress', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const db = getDb();
      const jobId = req.body?.job_id;
      if (!jobId) {
        return sendJson(res, 400, { error: 'JOB_ID_REQUIRED', message: 'job_id is required' });
      }
      const updated = contentDistributionEngine.updateBitsJobProgress(db, jobId, req.body || {});
      sendJson(res, 200, { success: true, job: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_BITS_PROGRESS_ERROR', message: err.message });
    }
  });

  // 96. POST /api/v1/nodes/:id/p2p/announce
  router.post('/api/v1/nodes/:id/p2p/announce', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const db = getDb();
      const seed = contentDistributionEngine.registerP2pSeed(db, {
        device_id: req.params.id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, seed });
    } catch (err) {
      sendJson(res, 400, { error: 'P2P_ANNOUNCE_ERROR', message: err.message });
    }
  });

  // 97. GET /api/v1/nodes/:id/p2p/peers
  router.get('/api/v1/nodes/:id/p2p/peers', (req, res) => {
    const authNode = authenticateNode(req, res);
    if (!authNode) return;
    try {
      const db = getDb();
      const sha = req.query?.content_sha256;
      const subnet = req.query?.subnet_cidr;
      if (!sha) {
        return sendJson(res, 400, { error: 'SHA_REQUIRED', message: 'content_sha256 query param is required' });
      }
      const peers = contentDistributionEngine.findPeerSeedsForContent(db, sha, subnet);
      sendJson(res, 200, { peers, count: peers.length });
    } catch (err) {
      sendJson(res, 500, { error: 'P2P_PEERS_ERROR', message: err.message });
    }
  });
  // POST /api/v1/nodes/:id/ir/triage-upload — Agent uploads completed triage package
  router.post('/api/v1/nodes/:id/ir/triage-upload', (req, res) => {
    const { id } = req.params;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const { package_id, file_path, file_size_bytes, sha256_hash, execution_time_ms } = req.body || {};
      if (!package_id) {
        sendJson(res, 400, { error: 'PACKAGE_ID_REQUIRED', message: 'package_id is required' });
        return;
      }
      const updated = engine.ingestTriagePackage(package_id, {
        file_path,
        file_size_bytes,
        sha256_hash,
        execution_time_ms
      });
      sendJson(res, 200, { success: true, package: updated });
    } catch (err) {
      sendJson(res, 500, { error: 'TRIAGE_INGEST_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/dha/attest — Agent submits TPM 2.0 quote and measured boot telemetry
  router.post('/api/v1/nodes/:id/dha/attest', (req, res) => {
    const { id } = req.params;
    try {
      const report = DeviceHealthAttestationEngine.verifyAttestationQuote(getDb(), id, req.body || {});
      sendJson(res, 200, { success: true, report });
    } catch (err) {
      sendJson(res, 400, { error: 'DHA_ATTESTATION_ERROR', message: err.message });
    }
  });


  // POST /api/v1/nodes/:id/hunting/matches — Agent reports threat hunt match findings
  router.post('/api/v1/nodes/:id/hunting/matches', (req, res) => {
    const { id } = req.params;
    try {
      const match = ThreatHuntingEngine.ingestMatch(getDb(), {
        device_id: id,
        ...req.body
      });
      sendJson(res, 201, { success: true, match });
    } catch (err) {
      sendJson(res, 400, { error: 'MATCH_INGEST_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/sandbox/submit — Agent submits sample for detonation
  router.post('/api/v1/nodes/:id/sandbox/submit', (req, res) => {
    const { id } = req.params;
    try {
      const job = SandboxDetonationEngine.submitDetonationJob(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, job });
    } catch (err) {
      sendJson(res, 400, { error: 'SANDBOX_NODE_SUBMIT_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/sandbox/lineage — Agent reports process lineage node
  router.post('/api/v1/nodes/:id/sandbox/lineage', (req, res) => {
    const { id } = req.params;
    try {
      const node = SandboxDetonationEngine.logProcessLineageNode(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, node });
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_LINEAGE_LOG_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/web-protection/events — Agent reports web intercept or SmartScreen event
  router.post('/api/v1/nodes/:id/web-protection/events', (req, res) => {
    const { id } = req.params;
    try {
      const event = WebProtectionEngine.logWebProtectionEvent(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_WEB_EVENT_ERROR', message: err.message });
    }
  });


  // POST /api/v1/nodes/:id/peripheral-control/events — Node agent logs USB/peripheral event
  router.post('/api/v1/nodes/:id/peripheral-control/events', (req, res) => {
    const { id } = req.params;
    try {
      const event = PeripheralControlEngine.logPeripheralEvent(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: 'NODE_PERIPHERAL_EVENT_ERROR', message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/tamper-protection/events — Node agent reports tamper attempt
  router.post('/api/v1/nodes/:id/tamper-protection/events', (req, res) => {
    const { id } = req.params;
    try {
      const event = TamperProtectionEngine.logTamperEvent(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_TAMPER_EVENT_ERROR", message: err.message });
    }
  });

  // POST /api/v1/nodes/:id/network-isolation/logs — Node agent reports isolation packet drops
  router.post('/api/v1/nodes/:id/network-isolation/logs', (req, res) => {
    const { id } = req.params;
    try {
      const log = NetworkIsolationEngine.logIsolationEvent(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, log });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_ISOLATION_LOG_ERROR", message: err.message });
    }
  });

  // 551. GET /api/v1/nodes/:id/live-response/poll — Node agent polls for pending live response commands
  router.get('/api/v1/nodes/:id/live-response/poll', (req, res) => {
    const { id } = req.params;
    try {
      const commands = LiveResponseEngine.getPendingCommandsForDevice(getDb(), id);
      sendJson(res, 200, { device_id: id, commands, count: commands.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_COMMAND_POLL_ERROR", message: err.message });
    }
  });

  // 552. POST /api/v1/nodes/:id/live-response/results — Node agent reports command execution results
  router.post('/api/v1/nodes/:id/live-response/results', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.command_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "command_id is required" });
        return;
      }
      const command = LiveResponseEngine.completeCommand(getDb(), req.body.command_id, {
        output: req.body.output,
        exitCode: req.body.exit_code,
        status: req.body.status,
        durationMs: req.body.duration_ms
      });
      sendJson(res, 200, { success: true, command });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_COMMAND_RESULT_ERROR", message: err.message });
    }
  });

  // 565. GET /api/v1/nodes/:id/incidents — Retrieve incidents linked to this node
  router.get('/api/v1/nodes/:id/incidents', (req, res) => {
    const { id } = req.params;
    try {
      const incidents = IncidentCorrelationEngine.getIncidents(getDb(), { primary_device_id: id });
      sendJson(res, 200, { device_id: id, incidents, count: incidents.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_INCIDENTS_FETCH_ERROR", message: err.message });
    }
  });

  // 566. POST /api/v1/nodes/:id/incidents/trigger-correlation — Node agent triggers incident correlation sweep
  router.post('/api/v1/nodes/:id/incidents/trigger-correlation', (req, res) => {
    const { id } = req.params;
    try {
      const result = IncidentCorrelationEngine.correlateAlerts(getDb(), id);
      sendJson(res, 200, { success: true, result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_CORRELATION_TRIGGER_ERROR", message: err.message });
    }
  });

  // 579. GET /api/v1/nodes/:id/threat-intel/indicators — Node agent pulls active IOC blocklist
  router.get('/api/v1/nodes/:id/threat-intel/indicators', (req, res) => {
    try {
      const indicators = ThreatIntelEngine.getIndicators(getDb(), { is_active: 1, limit: 200 });
      sendJson(res, 200, { indicators, count: indicators.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_INDICATORS_FETCH_ERROR", message: err.message });
    }
  });

  // 580. POST /api/v1/nodes/:id/threat-intel/matches — Node agent reports live indicator hit
  router.post('/api/v1/nodes/:id/threat-intel/matches', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.indicator_type || !req.body?.matched_value) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "indicator_type and matched_value are required" });
        return;
      }
      const event = ThreatIntelEngine.logMatchEvent(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_MATCH_LOG_ERROR", message: err.message });
    }
  });

  // 594. GET /api/v1/nodes/:id/tvm/findings — Node agent queries active vulnerability findings
  router.get('/api/v1/nodes/:id/tvm/findings', (req, res) => {
    const { id } = req.params;
    try {
      const findings = VulnerabilityManagementEngine.getFindings(getDb(), { device_id: id, remediation_status: 'ACTIVE' });
      sendJson(res, 200, { findings, count: findings.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_FINDINGS_FETCH_ERROR", message: err.message });
    }
  });

  // 595. POST /api/v1/nodes/:id/tvm/scan — Node agent triggers vulnerability scan against local inventory
  router.post('/api/v1/nodes/:id/tvm/scan', (req, res) => {
    const { id } = req.params;
    try {
      const result = VulnerabilityManagementEngine.scanDeviceSoftware(getDb(), id);
      sendJson(res, 200, { success: true, result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_TVM_SCAN_ERROR", message: err.message });
    }
  });

  // 608. GET /api/v1/nodes/:id/itdr/honeytokens — Node agent queries active deception assets to monitor
  router.get('/api/v1/nodes/:id/itdr/honeytokens', (req, res) => {
    try {
      const honeytokens = IdentityThreatEngine.getHoneytokens(getDb(), { is_active: 1 });
      sendJson(res, 200, { honeytokens, count: honeytokens.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_HONEYTOKENS_FETCH_ERROR", message: err.message });
    }
  });

  // 609. POST /api/v1/nodes/:id/itdr/report-tripwire — Node agent reports honeytoken tripwire activation
  router.post('/api/v1/nodes/:id/itdr/report-tripwire', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.account_name && !req.body?.honeytoken_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "account_name or honeytoken_id is required" });
        return;
      }
      const device = getDb().prepare('SELECT hostname FROM devices WHERE id = ?').get(id);
      const hostname = device ? device.hostname : id;

      const result = IdentityThreatEngine.triggerHoneytoken(
        getDb(),
        req.body.honeytoken_id || req.body.account_name,
        hostname,
        req.body.attacker_ip || '127.0.0.1',
        req.body.details || {}
      );
      sendJson(res, 201, { success: true, ...result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_TRIPWIRE_REPORT_ERROR", message: err.message });
    }
  });

  // 610. POST /api/v1/nodes/:id/itdr/report-credential-theft — Node agent reports LSASS dump / Kerberoast
  router.post('/api/v1/nodes/:id/itdr/report-credential-theft', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.target_account || !req.body?.attack_vector) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "target_account and attack_vector are required" });
        return;
      }
      const device = getDb().prepare('SELECT hostname FROM devices WHERE id = ?').get(id);
      const hostname = device ? device.hostname : id;

      const detection = IdentityThreatEngine.recordDetection(getDb(), {
        target_account: req.body.target_account,
        source_host: hostname,
        source_ip: req.body.source_ip || '127.0.0.1',
        attack_vector: req.body.attack_vector,
        risk_score: req.body.risk_score,
        evidence: req.body.evidence || req.body.details || {}
      });
      sendJson(res, 201, { success: true, detection });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_CREDENTIAL_THEFT_REPORT_ERROR", message: err.message });
    }
  });

  // 623. GET /api/v1/nodes/:id/dlp/rules — Node agent pulls active rules for local interceptors
  router.get('/api/v1/nodes/:id/dlp/rules', (req, res) => {
    try {
      const rules = DlpEngine.getRules(getDb(), { is_enabled: 1 });
      sendJson(res, 200, { rules, count: rules.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_DLP_RULES_FETCH_ERROR", message: err.message });
    }
  });

  // 624. POST /api/v1/nodes/:id/dlp/report-finding — Node agent reports discovered sensitive file
  router.post('/api/v1/nodes/:id/dlp/report-finding', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.file_path) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "file_path is required" });
        return;
      }
      const finding = DlpEngine.recordScanFinding(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, finding });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_DLP_FINDING_REPORT_ERROR", message: err.message });
    }
  });

  // 625. POST /api/v1/nodes/:id/dlp/report-exfiltration — Node agent reports blocked exfiltration attempt
  router.post('/api/v1/nodes/:id/dlp/report-exfiltration', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.channel || !req.body?.file_or_data_name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "channel and file_or_data_name are required" });
        return;
      }
      const incident = DlpEngine.logExfiltrationIncident(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, incident });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_DLP_EXFILTRATION_REPORT_ERROR", message: err.message });
    }
  });

  // 638. GET /api/v1/nodes/:id/cis/benchmarks — Node agent pulls benchmark rules to audit local registry/GPO
  router.get('/api/v1/nodes/:id/cis/benchmarks', (req, res) => {
    try {
      const rules = CisBenchmarkEngine.getRules(getDb(), req.query || {});
      sendJson(res, 200, { rules, count: rules.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_CIS_RULES_FETCH_ERROR", message: err.message });
    }
  });

  // 639. POST /api/v1/nodes/:id/cis/report-audit — Node agent posts compliance audit scorecard
  router.post('/api/v1/nodes/:id/cis/report-audit', (req, res) => {
    const { id } = req.params;
    try {
      const audit = CisBenchmarkEngine.recordAudit(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, audit });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_CIS_REPORT_AUDIT_ERROR", message: err.message });
    }
  });

  // 640. POST /api/v1/nodes/:id/cis/request-remediation — Node agent requests surgical remediation snippet
  router.post('/api/v1/nodes/:id/cis/request-remediation', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.rule_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "rule_id is required" });
        return;
      }
      const result = CisBenchmarkEngine.applyRemediation(getDb(), id, req.body.rule_id);
      sendJson(res, 200, { success: true, result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_CIS_REQUEST_REMEDIATION_ERROR", message: err.message });
    }
  });

  // =========================================================================
  // ITERATION 59: Windows Exploit Protection & Process Mitigation Node Routes
  // =========================================================================

  // 653. GET /api/v1/nodes/:id/exploit-protection/policy — Node agent pulls assigned exploit protection policy
  router.get('/api/v1/nodes/:id/exploit-protection/policy', (req, res) => {
    try {
      const policies = ExploitProtectionEngine.getPolicies(getDb(), { status: 'ACTIVE' });
      const policy = policies[0] || null;
      if (!policy) {
        sendJson(res, 404, { error: "NO_ACTIVE_POLICY", message: "No active exploit protection policy found" });
        return;
      }
      const fullPolicy = ExploitProtectionEngine.getPolicyById(getDb(), policy.id);
      sendJson(res, 200, { success: true, policy: fullPolicy });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_EXPLOIT_POLICY_ERROR", message: err.message });
    }
  });

  // 654. POST /api/v1/nodes/:id/exploit-protection/report-audit — Node agent reports local mitigation compliance audit
  router.post('/api/v1/nodes/:id/exploit-protection/report-audit', (req, res) => {
    const { id } = req.params;
    try {
      const audit = ExploitProtectionEngine.recordEndpointAudit(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, audit });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_EXPLOIT_AUDIT_REPORT_ERROR", message: err.message });
    }
  });

  // 655. GET /api/v1/nodes/:id/exploit-protection/remediate-script — Node agent pulls PowerShell remediation script
  router.get('/api/v1/nodes/:id/exploit-protection/remediate-script', (req, res) => {
    try {
      const policies = ExploitProtectionEngine.getPolicies(getDb(), { status: 'ACTIVE' });
      const policyId = req.query?.policy_id || policies[0]?.id;
      if (!policyId) {
        sendJson(res, 404, { error: "NO_POLICY_AVAILABLE", message: "No exploit policy available" });
        return;
      }
      const script = ExploitProtectionEngine.generatePowerShellDeployment(getDb(), policyId);
      sendJson(res, 200, { success: true, script });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_EXPLOIT_SCRIPT_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 60: User & Entity Behavior Analytics (UEBA) Node Routes
  // =========================================================================

  // 668. GET /api/v1/nodes/:id/ueba/indicators — Node agent pulls active UEBA indicator baseline
  router.get('/api/v1/nodes/:id/ueba/indicators', (req, res) => {
    try {
      const indicators = UebaEngine.getRiskIndicators(getDb(), { is_active: 1 });
      sendJson(res, 200, { success: true, indicators, count: indicators.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_UEBA_INDICATORS_ERROR", message: err.message });
    }
  });

  // 669. POST /api/v1/nodes/:id/ueba/report-anomaly — Node agent reports local behavioral anomaly
  router.post('/api/v1/nodes/:id/ueba/report-anomaly', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.user_principal || !req.body?.indicator_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "user_principal and indicator_id are required" });
        return;
      }
      const anomaly = UebaEngine.recordBehaviorAnomaly(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, anomaly });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_UEBA_ANOMALY_REPORT_ERROR", message: err.message });
    }
  });

  // 670. GET /api/v1/nodes/:id/ueba/containment-status — Node agent queries user containment state
  router.get('/api/v1/nodes/:id/ueba/containment-status', (req, res) => {
    try {
      const userPrincipal = req.query?.user_principal || '';
      if (!userPrincipal) {
        sendJson(res, 400, { error: "MISSING_USER", message: "user_principal query parameter required" });
        return;
      }
      const profile = UebaEngine.getUserRiskProfile(getDb(), userPrincipal.toLowerCase());
      sendJson(res, 200, {
        success: true,
        user_principal: userPrincipal,
        containment_status: profile?.containment_status || 'MONITORED',
        composite_risk_score: profile?.composite_risk_score || 0
      });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_UEBA_CONTAINMENT_QUERY_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 61: Cloud App Discovery & Shadow SaaS Governance Node Routes
  // =========================================================================

  // 683. GET /api/v1/nodes/:id/cloud-apps/blocklist — Node agent pulls unsanctioned domain blocklist
  router.get('/api/v1/nodes/:id/cloud-apps/blocklist', (req, res) => {
    try {
      const blocklist = CloudAppDiscoveryEngine.generateBlocklist(getDb());
      sendJson(res, 200, { success: true, blocklist });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_BLOCKLIST_FETCH_ERROR", message: err.message });
    }
  });

  // 684. POST /api/v1/nodes/:id/cloud-apps/report-usage — Node agent reports endpoint cloud traffic usage
  router.post('/api/v1/nodes/:id/cloud-apps/report-usage', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.app_id) {
        sendJson(res, 400, { error: "MISSING_APP_ID", message: "app_id is required" });
        return;
      }
      const entry = CloudAppDiscoveryEngine.recordUsageTelemetry(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, entry });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_REPORT_USAGE_ERROR", message: err.message });
    }
  });

  // 685. GET /api/v1/nodes/:id/cloud-apps/policies — Node agent pulls cloud app access policies
  router.get('/api/v1/nodes/:id/cloud-apps/policies', (req, res) => {
    try {
      const policies = CloudAppDiscoveryEngine.getAccessPolicies(getDb(), { is_active: 1 });
      sendJson(res, 200, { success: true, policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_CLOUD_POLICIES_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 62: Automated Ransomware Canary Node Routes
  // =========================================================================

  // 698. GET /api/v1/nodes/:id/ransomware/traps — Node agent pulls active canary files to watch
  router.get('/api/v1/nodes/:id/ransomware/traps', (req, res) => {
    try {
      const traps = RansomwareCanaryEngine.getTraps(getDb(), { status: 'HEALTHY' });
      sendJson(res, 200, { success: true, traps, count: traps.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_CANARY_TRAPS_ERROR", message: err.message });
    }
  });

  // 699. POST /api/v1/nodes/:id/ransomware/report-tamper — Node agent reports canary trip / encryption attempt
  router.post('/api/v1/nodes/:id/ransomware/report-tamper', (req, res) => {
    const { id } = req.params;
    try {
      if (!req.body?.trap_id) {
        sendJson(res, 400, { error: "MISSING_TRAP_ID", message: "trap_id is required" });
        return;
      }
      const detection = RansomwareCanaryEngine.recordTamperDetection(getDb(), {
        device_id: id,
        ...(req.body || {})
      });
      sendJson(res, 201, { success: true, detection });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_REPORT_TAMPER_ERROR", message: err.message });
    }
  });

  // 700. GET /api/v1/nodes/:id/ransomware/policy — Node agent pulls active containment policy
  router.get('/api/v1/nodes/:id/ransomware/policy', (req, res) => {
    try {
      const policies = RansomwareCanaryEngine.getPolicies(getDb(), { is_active: 1 });
      sendJson(res, 200, { success: true, policy: policies[0] || null });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_CANARY_POLICY_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 63: Software License Optimization & Enterprise Metering Endpoints
  // =========================================================================

  // 713. GET /api/v1/nodes/:id/sam/licenses — Endpoint agent checks assigned licenses & product keys
  router.get('/api/v1/nodes/:id/sam/licenses', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const licenses = db.prepare(`
        SELECT sla.id as allocation_id, sla.status, sla.assigned_at,
               sl.id as license_id, sl.product_name, sl.vendor, sl.license_type, sl.license_key, sl.expiration_date
        FROM software_license_allocations sla
        JOIN software_licenses sl ON sla.license_id = sl.id
        WHERE sla.device_id = ? AND sla.status = 'ACTIVE'
      `).all(req.params.id);

      sendJson(res, 200, { success: true, licenses, count: licenses.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_SAM_LICENSES_ERROR", message: err.message });
    }
  });

  // 714. POST /api/v1/nodes/:id/sam/metering-report — Endpoint agent reports process foreground runtime
  router.post('/api/v1/nodes/:id/sam/metering-report', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const items = Array.isArray(req.body?.processes) ? req.body.processes : [req.body || {}];
      let ingested = 0;

      for (const p of items) {
        if (p.process_name) {
          LicenseOptimizationEngine.ingestMeteringTelemetry(db, {
            ...p,
            device_id: req.params.id,
            hostname: node.hostname
          });
          ingested++;
        }
      }

      sendJson(res, 200, { success: true, ingested });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_METERING_REPORT_ERROR", message: err.message });
    }
  });

  // 715. GET /api/v1/nodes/:id/sam/reclaim-orders — Endpoint agent checks for software uninstall/deactivation orders
  router.get('/api/v1/nodes/:id/sam/reclaim-orders', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const orders = db.prepare(`
        SELECT sla.id as allocation_id, sla.reclamation_reason, sl.product_name, sl.vendor
        FROM software_license_allocations sla
        JOIN software_licenses sl ON sla.license_id = sl.id
        WHERE sla.device_id = ? AND sla.status = 'RECLAIMED'
      `).all(req.params.id);

      sendJson(res, 200, { success: true, reclaim_orders: orders, count: orders.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_SAM_RECLAIM_ORDERS_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 64: Hardware Supply Chain & TPM 2.0 Attestation Endpoints
  // =========================================================================

  // 728. GET /api/v1/nodes/:id/hardware-attestation/policy — Agent retrieves active attestation policy
  router.get('/api/v1/nodes/:id/hardware-attestation/policy', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const policy = db.prepare('SELECT * FROM hardware_attestation_policies WHERE is_active = 1 LIMIT 1').get();
      sendJson(res, 200, { success: true, policy: policy || null });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_ATTESTATION_POLICY_ERROR", message: err.message });
    }
  });

  // 729. POST /api/v1/nodes/:id/hardware-attestation/report-boot-pcr — Agent reports measured boot PCR hashes
  router.post('/api/v1/nodes/:id/hardware-attestation/report-boot-pcr', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const log = HardwareAttestationEngine.ingestMeasuredBootLog(db, {
        ...req.body,
        device_id: req.params.id,
        hostname: node.hostname
      });
      sendJson(res, 201, { success: true, log });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_BOOT_PCR_REPORT_ERROR", message: err.message });
    }
  });

  // 730. POST /api/v1/nodes/:id/hardware-attestation/report-components — Agent submits component audit telemetry
  router.post('/api/v1/nodes/:id/hardware-attestation/report-components', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const db = getDb();
      const result = HardwareAttestationEngine.verifyHardwareComponents(db, req.params.id, req.body || {});
      sendJson(res, 200, { success: true, result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_COMPONENTS_REPORT_ERROR", message: err.message });
    }
  });


  // =========================================================================
  // ITERATION 65: Cross-Platform Mobile & Mac Node Endpoints
  // =========================================================================

  // 743. POST /api/v1/nodes/enroll/mobile — Dedicated cross-platform enrollment for macOS, iOS, Android
  router.post('/api/v1/nodes/enroll/mobile', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = MultiPlatformUemEngine.enrollMobileDevice(getDb(), req.body || {});
      sendJson(res, 201, { success: true, enrollment: result });
    } catch (err) {
      sendJson(res, 400, { error: "MOBILE_ENROLLMENT_ERROR", message: err.message });
    }
  });

  // 744. GET /api/v1/nodes/:id/uem/pending-commands — Mobile client polls for pending commands
  router.get('/api/v1/nodes/:id/uem/pending-commands', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const commands = MultiPlatformUemEngine.getPendingCommands(getDb(), req.params.id);
      sendJson(res, 200, { success: true, commands, count: commands.length });
    } catch (err) {
      sendJson(res, 500, { error: "PENDING_COMMANDS_ERROR", message: err.message });
    }
  });

  // 745. POST /api/v1/nodes/:id/uem/acknowledge-command — Mobile client reports command execution outcome
  router.post('/api/v1/nodes/:id/uem/acknowledge-command', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const commandId = req.body?.command_id;
      if (!commandId) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "command_id is required" });
        return;
      }
      const updated = MultiPlatformUemEngine.acknowledgeCommand(getDb(), commandId, req.body?.result_details || {});
      sendJson(res, 200, { success: true, command: updated });
    } catch (err) {
      sendJson(res, 400, { error: "COMMAND_ACKNOWLEDGE_ERROR", message: err.message });
    }
  });

  // =========================================================================
  // ITERATION 66: Mobile Application Management (MAM) Node Endpoints
  // =========================================================================

  // 759. GET /api/v1/nodes/:id/mam/wipe-orders — Mobile client checks for pending selective wipe orders
  router.get('/api/v1/nodes/:id/mam/wipe-orders', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const userEmail = req.query?.user_email || node.primary_user;
      const wipes = MamAppProtectionEngine.getPendingWipesForNodeOrUser(getDb(), {
        userEmail,
        deviceId: req.params.id
      });
      sendJson(res, 200, { success: true, pending_wipes: wipes, count: wipes.length });
    } catch (err) {
      sendJson(res, 500, { error: "MAM_WIPE_QUERY_ERROR", message: err.message });
    }
  });

  // 760. POST /api/v1/nodes/:id/mam/evaluate — Mobile app reports posture and evaluates MAM compliance
  router.post('/api/v1/nodes/:id/mam/evaluate', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const evaluation = MamAppProtectionEngine.evaluateAppCompliance(getDb(), {
        ...(req.body || {}),
        device_id: req.params.id,
        user_email: req.body?.user_email || node.primary_user
      });
      sendJson(res, 200, { success: true, evaluation });
    } catch (err) {
      sendJson(res, 400, { error: "MAM_EVALUATE_ERROR", message: err.message });
    }
  });

  // =========================================================================
  // ITERATION 67: SCEP PKI & 802.1X Protocol Node Routes
  // =========================================================================

  // 772. POST /api/v1/scep/pkiclient.exe — RFC 8894 SCEP protocol enrollment gateway
  router.post('/api/v1/scep/pkiclient.exe', (req, res) => {
    try {
      const operation = req.query?.operation || 'PKIOperation';
      const cert = ScepPkiEnrollmentEngine.enrollCertificateWithCsr(getDb(), req.body || {});
      sendJson(res, 200, { success: true, operation, certificate: cert });
    } catch (err) {
      sendJson(res, 400, { error: "SCEP_PROTOCOL_ERROR", message: err.message });
    }
  });

  // 773. POST /api/v1/scep/enroll — Direct REST CSR enrollment with SCEP challenge
  router.post('/api/v1/scep/enroll', (req, res) => {
    try {
      const cert = ScepPkiEnrollmentEngine.enrollCertificateWithCsr(getDb(), req.body || {});
      sendJson(res, 201, { success: true, certificate: cert });
    } catch (err) {
      sendJson(res, 400, { error: "SCEP_ENROLL_ERROR", message: err.message });
    }
  });

  // 774. GET /api/v1/nodes/:id/scep/certificate — Device agent checks active certificate status & expiry
  router.get('/api/v1/nodes/:id/scep/certificate', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const cert = ScepPkiEnrollmentEngine.getDeviceActiveCertificate(getDb(), req.params.id);
      sendJson(res, 200, { success: true, has_certificate: !!cert, certificate: cert });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_CERT_QUERY_ERROR", message: err.message });
    }
  });

  // 775. GET /api/v1/nodes/:id/scep/wifi-profile — Device agent fetches effective 802.1X Wi-Fi configuration
  router.get('/api/v1/nodes/:id/scep/wifi-profile', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const profile = ScepPkiEnrollmentEngine.getEffectiveDeviceWifiProfile(getDb(), req.params.id);
      sendJson(res, 200, { success: true, profile });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_WIFI_QUERY_ERROR", message: err.message });
    }
  });

  // =========================================================================
  // ITERATION 68: Enterprise VPN & Per-App Node Routes
  // =========================================================================

  // 788. GET /api/v1/nodes/:id/vpn/effective — Device fetches effective VPN profile
  router.get('/api/v1/nodes/:id/vpn/effective', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const profile = EnterpriseVpnProfileEngine.getEffectiveDeviceVpn(getDb(), req.params.id);
      sendJson(res, 200, { success: true, profile });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_VPN_QUERY_ERROR", message: err.message });
    }
  });

  // 789. GET /api/v1/nodes/:id/vpn/per-app-rules — Device agent queries per-app routing rules
  router.get('/api/v1/nodes/:id/vpn/per-app-rules', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const rules = EnterpriseVpnProfileEngine.getDevicePerAppRules(getDb(), req.params.id);
      sendJson(res, 200, { success: true, rules, count: rules.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_PER_APP_QUERY_ERROR", message: err.message });
    }
  });

  // 790. POST /api/v1/nodes/:id/vpn/telemetry — Device reports tunnel connection/disconnect telemetry
  router.post('/api/v1/nodes/:id/vpn/telemetry', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const payload = {
        device_id: req.params.id,
        ...req.body
      };
      const log = EnterpriseVpnProfileEngine.logVpnEvent(getDb(), payload);
      sendJson(res, 201, { success: true, log });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_VPN_TELEMETRY_ERROR", message: err.message });
    }
  });

  // =========================================================================
  // ITERATION 69: Mobile Threat Defense (MTD) Node Routes
  // =========================================================================

  // 802. POST /api/v1/nodes/:id/mtd/signals — Agent reports local threat signal
  router.post('/api/v1/nodes/:id/mtd/signals', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const payload = {
        device_id: req.params.id,
        ...req.body
      };
      const result = MobileThreatDefenseEngine.ingestThreatSignal(getDb(), payload);
      sendJson(res, 201, { success: true, ...result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_MTD_SIGNAL_ERROR", message: err.message });
    }
  });

  // 803. GET /api/v1/nodes/:id/mtd/posture — Agent fetches current device risk posture
  router.get('/api/v1/nodes/:id/mtd/posture', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const evaluation = MobileThreatDefenseEngine.calculateDeviceRiskScore(getDb(), req.params.id);
      sendJson(res, 200, { success: true, evaluation });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_MTD_POSTURE_ERROR", message: err.message });
    }
  });

  // 804. POST /api/v1/nodes/:id/mtd/evaluate — Agent sends health beacon for posture evaluation
  router.post('/api/v1/nodes/:id/mtd/evaluate', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const result = MobileThreatDefenseEngine.evaluateDevicePosture(getDb(), req.params.id, req.body || {});
      sendJson(res, 200, { success: true, result });
    } catch (err) {
      sendJson(res, 400, { error: "NODE_MTD_EVALUATE_ERROR", message: err.message });
    }
  });

  // 805. GET /api/v1/nodes/:id/mtd/remediations/pending — Agent polls pending remediations
  router.get('/api/v1/nodes/:id/mtd/remediations/pending', (req, res) => {
    const node = authenticateNode(req, res);
    if (!node) return;

    try {
      const remediations = MobileThreatDefenseEngine.getRemediations(getDb(), {
        device_id: req.params.id,
        status: 'PENDING'
      });
      sendJson(res, 200, { success: true, remediations, count: remediations.length });
    } catch (err) {
      sendJson(res, 500, { error: "NODE_MTD_REMEDIATIONS_ERROR", message: err.message });
    }
  });

}
