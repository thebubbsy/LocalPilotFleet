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
import { multiTenancyEngine } from '../services/multiTenancyEngine.js';
import { VaultSecretsEngine } from '../services/vaultSecretsEngine.js';
import { LiveQueryEngine } from '../services/liveQueryEngine.js';
import { openApiSpecEngine } from '../services/openApiSpecEngine.js';
import { contentDistributionEngine } from '../services/contentDistributionEngine.js';
import { mdmCspEngine } from '../services/mdmCspEngine.js';
import { rbacEngine } from '../services/rbacEngine.js';
import { siemForwarderEngine } from '../services/siemForwarderEngine.js';
import * as supervisorEngine from '../services/supervisorEngine.js';
import * as realtimePushEngine from '../services/realtimePushEngine.js';
/**
 * LocalPilot Fleet — Fleet Command Center REST Endpoints
 * server/src/routes/fleet.js
 */

import crypto from 'node:crypto';
import { getDb } from '../db.js';
import { requireFleetKey, setFleetKey } from '../utils/auth.js';
import { sendJson } from '../utils/router.js';
import dynamicGroupsService from '../services/dynamicGroups.js';
import remediationEngine from '../services/remediationEngine.js';
import { configProfileEngine } from '../services/configProfileEngine.js';
import { updateRingEngine } from '../services/updateRingEngine.js';
import { complianceEngine } from '../services/complianceEngine.js';
import { appManagementEngine } from '../services/appManagementEngine.js';
import { endpointSecurityEngine } from '../services/endpointSecurityEngine.js';
import { bitlockerEngine } from '../services/bitlockerEngine.js';
import { lapsEngine } from '../services/lapsEngine.js';
import * as epmEngine from '../services/epmEngine.js';
import fs from 'node:fs';
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

export function registerFleetRoutes(router) {
  // 1. GET /api/v1/fleet/stats and /overview
  const handleStats = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();

      const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
      const onlineDevices = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'online'").get().c;
      const offlineDevices = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'offline'").get().c;
      const driftedDevices = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'drifted'").get().c;
      const quarantinedDevices = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status = 'quarantined'").get().c;

      const criticalAlerts = db.prepare(`
        SELECT COUNT(*) as c FROM security_events 
        WHERE severity = 'CRITICAL' AND acknowledged = 0
      `).get().c;

      const ramRow = db.prepare('SELECT COALESCE(SUM(total_ram_gb), 0) as total_ram FROM devices').get();
      const totalFleetRamGb = Math.round(Number(ramRow.total_ram) * 10) / 10;

      sendJson(res, 200, {
        total_devices: totalDevices,
        online: onlineDevices,
        offline: offlineDevices,
        drifted: driftedDevices,
        quarantined: quarantinedDevices,
        critical_alerts: criticalAlerts,
        total_fleet_ram_gb: totalFleetRamGb,
        total_fleet_storage_tb: 2.5
      });
    } catch (err) {
      sendJson(res, 500, { error: 'STATS_ERROR', message: err.message });
    }
  };

  router.get('/api/v1/fleet/stats', handleStats);
  router.get('/api/v1/fleet/overview', handleStats);

  // 2. GET /api/v1/fleet/devices
  router.get('/api/v1/fleet/devices', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const { search, status, group, route, sort = 'last_seen_at DESC', limit = 100, offset = 0 } = req.query;

      const conditions = [];
      const params = [];

      if (search) {
        conditions.push('(d.hostname LIKE ? OR d.friendly_name LIKE ? OR d.ip_address LIKE ?)');
        const s = `%${search}%`;
        params.push(s, s, s);
      }

      if (status) {
        conditions.push('d.status = ?');
        params.push(status);
      }

      if (route) {
        conditions.push('d.connection_route = ?');
        params.push(route);
      }

      if (group) {
        conditions.push('EXISTS (SELECT 1 FROM group_memberships gm WHERE gm.device_id = d.id AND gm.group_id = ?)');
        params.push(group);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      // Safe sorting whitelist
      let orderBy = 'd.last_seen_at DESC';
      if (sort) {
        const lowerSort = sort.toLowerCase();
        if (lowerSort.includes('hostname')) orderBy = lowerSort.includes('desc') ? 'd.hostname DESC' : 'd.hostname ASC';
        else if (lowerSort.includes('ram')) orderBy = lowerSort.includes('desc') ? 'd.total_ram_bytes DESC' : 'd.total_ram_bytes ASC';
        else if (lowerSort.includes('status')) orderBy = lowerSort.includes('desc') ? 'd.status DESC' : 'd.status ASC';
        else if (lowerSort.includes('enrolled')) orderBy = lowerSort.includes('desc') ? 'd.enrolled_at DESC' : 'd.enrolled_at ASC';
      }

      const query = `
        SELECT 
          d.id, d.hostname, d.friendly_name, d.serial_number, d.uuid,
          d.mac_address, d.ip_address, d.public_ip, d.connection_route,
          d.status, d.os_name, d.os_version, d.os_build, d.os_architecture,
          d.cpu_model, d.cpu_cores, d.cpu_logical, d.total_ram_bytes, d.total_ram_gb,
          d.gpu_name, d.has_battery, d.battery_percent, d.battery_charging,
          d.tpm_present, d.tpm_version, d.tpm_enabled, d.secure_boot_enabled,
          d.bitlocker_status, d.primary_user, d.tags_json, d.assigned_group,
          d.agent_version, d.enrolled_at, d.last_seen_at
        FROM devices d
        ${whereClause}
        ORDER BY ${orderBy}
        LIMIT ? OFFSET ?
      `;

      params.push(Number(limit) || 100, Number(offset) || 0);

      const rows = db.prepare(query).all(...params);

      // Parse tags_json
      const devices = rows.map(r => {
        let tags = [];
        try {
          tags = JSON.parse(r.tags_json || '[]');
        } catch {}
        return {
          ...r,
          tags
        };
      });

      const countQuery = `SELECT COUNT(*) as total FROM devices d ${whereClause}`;
      const total = db.prepare(countQuery).get(...params.slice(0, conditions.length * (search ? 3 : 1))).total;

      sendJson(res, 200, {
        devices,
        total_count: total
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICES_QUERY_ERROR', message: err.message });
    }
  });

  // 3. GET /api/v1/fleet/devices/:id
  router.get('/api/v1/fleet/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const deviceId = req.params.id;

      const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Device ${deviceId} not found` });
        return;
      }

      let tags = [];
      try { tags = JSON.parse(device.tags_json || '[]'); } catch {}

      // Groups
      const groups = db.prepare(`
        SELECT g.id, g.name, g.color, g.icon, g.priority
        FROM dynamic_groups g
        JOIN group_memberships m ON g.id = m.group_id
        WHERE m.device_id = ?
        ORDER BY g.priority ASC
      `).all(deviceId);

      // Recent snapshots (last 20)
      const snapshots = db.prepare(`
        SELECT * FROM telemetry_snapshots
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT 20
      `).all(deviceId).map(s => {
        let disks = [];
        let network = [];
        try { disks = JSON.parse(s.disks_json || '[]'); } catch {}
        try { network = JSON.parse(s.network_json || '[]'); } catch {}
        return { ...s, disks, network };
      });

      // Recent events (last 20)
      const events = db.prepare(`
        SELECT * FROM security_events
        WHERE device_id = ?
        ORDER BY created_at DESC
        LIMIT 20
      `).all(deviceId);

      let installedSoftware = [];
      try { installedSoftware = JSON.parse(device.installed_software_json || '[]'); } catch {}

      sendJson(res, 200, {
        ...device,
        tags,
        installed_software: installedSoftware,
        assigned_groups: groups,
        telemetry_snapshots: snapshots,
        security_events: events
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_FETCH_ERROR', message: err.message });
    }
  });

  // 3b. GET /api/v1/fleet/devices/:id/software (Device Installed Software Catalog)
  router.get('/api/v1/fleet/devices/:id/software', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const device = db.prepare('SELECT id, hostname, friendly_name, installed_software_json FROM devices WHERE id = ?').get(req.params.id);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Device ${req.params.id} not found` });
        return;
      }
      let software = [];
      try { software = JSON.parse(device.installed_software_json || '[]'); } catch {}
      sendJson(res, 200, {
        device_id: device.id,
        hostname: device.hostname,
        friendly_name: device.friendly_name,
        total_count: software.length,
        software
      });
    } catch (err) {
      sendJson(res, 500, { error: 'SOFTWARE_FETCH_ERROR', message: err.message });
    }
  });

  // 3c. GET /api/v1/fleet/discovered-apps (Fleet-wide Discovered Applications)
  router.get('/api/v1/fleet/discovered-apps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const rows = db.prepare('SELECT id, hostname, installed_software_json FROM devices WHERE installed_software_json IS NOT NULL').all();
      const appMap = new Map();

      for (const r of rows) {
        let swList = [];
        try { swList = JSON.parse(r.installed_software_json || '[]'); } catch {}
        for (const s of swList) {
          const name = s.name || s.display_name;
          if (!name) continue;
          const key = name.toLowerCase().trim();
          if (!appMap.has(key)) {
            appMap.set(key, {
              name,
              publisher: s.publisher || 'Unknown Publisher',
              version: s.version || s.display_version || '',
              winget_id: s.winget_id || '',
              install_type: s.install_type || (s.name && s.name.includes('.') && !s.name.includes(' ') ? 'AppX' : 'Win32'),
              device_count: 0,
              devices: []
            });
          }
          const entry = appMap.get(key);
          if (!entry.devices.some(d => d.id === r.id)) {
            entry.device_count++;
            entry.devices.push({ id: r.id, hostname: r.hostname });
          }
        }
      }

      const discovered = Array.from(appMap.values()).sort((a, b) => b.device_count - a.device_count || a.name.localeCompare(b.name));
      sendJson(res, 200, {
        total_discovered_apps: discovered.length,
        apps: discovered
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DISCOVERED_APPS_ERROR', message: err.message });
    }
  });

  // 4. PATCH /api/v1/fleet/devices/:id
  router.patch('/api/v1/fleet/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const deviceId = req.params.id;
      const { friendly_name, tags, assigned_group, status } = req.body || {};

      const existing = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
      if (!existing) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Device ${deviceId} not found` });
        return;
      }

      const tagsJson = tags !== undefined
        ? (Array.isArray(tags) ? JSON.stringify(tags) : String(tags))
        : existing.tags_json;

      db.prepare(`
        UPDATE devices SET
          friendly_name = COALESCE(?, friendly_name),
          tags_json = ?,
          assigned_group = COALESCE(?, assigned_group),
          status = COALESCE(?, status),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        friendly_name !== undefined ? friendly_name : null,
        tagsJson,
        assigned_group !== undefined ? assigned_group : null,
        status !== undefined ? status : null,
        deviceId
      );

      const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
      let parsedTags = [];
      try { parsedTags = JSON.parse(updated.tags_json || '[]'); } catch {}

      sendJson(res, 200, {
        ...updated,
        tags: parsedTags
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_UPDATE_ERROR', message: err.message });
    }
  });

  // 5. DELETE /api/v1/fleet/devices/:id
  router.delete('/api/v1/fleet/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const deviceId = req.params.id;

      const result = db.prepare('DELETE FROM devices WHERE id = ?').run(deviceId);
      if (result.changes === 0) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Device ${deviceId} not found` });
        return;
      }

      sendJson(res, 200, {
        success: true,
        message: `Device ${deviceId} decommissioned and deleted`
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DELETE_ERROR', message: err.message });
    }
  });

  // 5b. POST /api/v1/fleet/devices/:id/run-script (Intune Remote Script Runner)
  router.post('/api/v1/fleet/devices/:id/run-script', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const deviceId = req.params.id;
      const { script, command_text, created_by = 'admin' } = req.body || {};
      const commandStr = script || command_text;

      if (!commandStr) {
        sendJson(res, 400, { error: 'BAD_REQUEST', message: 'script or command_text is required' });
        return;
      }

      const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
      if (!dev) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Device ${deviceId} not found` });
        return;
      }

      const commandId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO device_commands (id, device_id, command_text, created_by, status)
        VALUES (?, ?, ?, ?, 'PENDING')
      `).run(commandId, deviceId, commandStr, created_by);

      broadcastEvent('command_queued', {
        command_id: commandId,
        device_id: deviceId,
        hostname: dev.hostname,
        command: commandStr
      });

      sendJson(res, 201, {
        command_id: commandId,
        device_id: deviceId,
        status: 'PENDING',
        message: 'Command queued for execution on target node'
      });
    } catch (err) {
      sendJson(res, 500, { error: 'COMMAND_DISPATCH_ERROR', message: err.message });
    }
  });

  // 5c. GET /api/v1/fleet/commands/:id
  router.get('/api/v1/fleet/commands/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const cmd = db.prepare('SELECT * FROM device_commands WHERE id = ?').get(req.params.id);
      if (!cmd) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Command not found' });
        return;
      }
      sendJson(res, 200, cmd);
    } catch (err) {
      sendJson(res, 500, { error: 'COMMAND_QUERY_ERROR', message: err.message });
    }
  });

  // 5d. GET /api/v1/fleet/devices/:id/commands
  router.get('/api/v1/fleet/devices/:id/commands', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const cmds = db.prepare(`
        SELECT * FROM device_commands WHERE device_id = ? ORDER BY created_at DESC LIMIT 50
      `).all(req.params.id);
      sendJson(res, 200, { commands: cmds });
    } catch (err) {
      sendJson(res, 500, { error: 'COMMAND_LIST_ERROR', message: err.message });
    }
  });

  // 6. GET /api/v1/fleet/groups
  router.get('/api/v1/fleet/groups', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const groups = db.prepare(`
        SELECT 
          g.*,
          COUNT(m.device_id) as member_count
        FROM dynamic_groups g
        LEFT JOIN group_memberships m ON g.id = m.group_id
        GROUP BY g.id
        ORDER BY g.priority ASC
      `).all();

      sendJson(res, 200, groups);
    } catch (err) {
      sendJson(res, 500, { error: 'GROUPS_QUERY_ERROR', message: err.message });
    }
  });

  // 7. POST /api/v1/fleet/groups
  router.post('/api/v1/fleet/groups', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const { id, name, description, rule_syntax, color = '#3B82F6', icon = 'laptop', priority = 100 } = req.body || {};

    if (!name || !rule_syntax) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Group name and rule_syntax are required' });
      return;
    }

    try {
      const db = getDb();
      const groupId = id || `grp-${Date.now()}`;

      // Validate rule syntax
      const validation = dynamicGroupsService.validateRule(rule_syntax);
      if (!validation.valid) {
        sendJson(res, 400, { error: 'INVALID_RULE_SYNTAX', message: validation.error });
        return;
      }

      db.prepare(`
        INSERT INTO dynamic_groups (id, name, description, rule_syntax, is_dynamic, color, icon, priority)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
      `).run(groupId, name, description || null, rule_syntax, color, icon, Number(priority) || 100);

      // Re-evaluate across all devices
      const devices = db.prepare('SELECT id FROM devices').all();
      for (const dev of devices) {
        dynamicGroupsService.reevaluateDeviceMemberships(db, dev.id);
      }

      const memberCount = db.prepare('SELECT COUNT(*) as c FROM group_memberships WHERE group_id = ?').get(groupId).c;

      sendJson(res, 201, {
        id: groupId,
        name,
        description,
        rule_syntax,
        color,
        icon,
        priority,
        member_count: memberCount
      });
    } catch (err) {
      sendJson(res, 500, { error: 'GROUP_CREATE_ERROR', message: err.message });
    }
  });

  // 8. PUT /api/v1/fleet/groups/:id
  router.put('/api/v1/fleet/groups/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const groupId = req.params.id;
    const { name, description, rule_syntax, color, icon, priority } = req.body || {};

    try {
      const db = getDb();

      if (rule_syntax) {
        const validation = dynamicGroupsService.validateRule(rule_syntax);
        if (!validation.valid) {
          sendJson(res, 400, { error: 'INVALID_RULE_SYNTAX', message: validation.error });
          return;
        }
      }

      const result = db.prepare(`
        UPDATE dynamic_groups SET
          name = COALESCE(?, name),
          description = COALESCE(?, description),
          rule_syntax = COALESCE(?, rule_syntax),
          color = COALESCE(?, color),
          icon = COALESCE(?, icon),
          priority = COALESCE(?, priority),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        name || null,
        description !== undefined ? description : null,
        rule_syntax || null,
        color || null,
        icon || null,
        priority !== undefined ? Number(priority) : null,
        groupId
      );

      if (result.changes === 0) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Group ${groupId} not found` });
        return;
      }

      // Re-evaluate across all devices
      const devices = db.prepare('SELECT id FROM devices').all();
      for (const dev of devices) {
        dynamicGroupsService.reevaluateDeviceMemberships(db, dev.id);
      }

      const updated = db.prepare(`
        SELECT g.*, COUNT(m.device_id) as member_count
        FROM dynamic_groups g
        LEFT JOIN group_memberships m ON g.id = m.group_id
        WHERE g.id = ?
        GROUP BY g.id
      `).get(groupId);

      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'GROUP_UPDATE_ERROR', message: err.message });
    }
  });

  // 9. DELETE /api/v1/fleet/groups/:id
  router.delete('/api/v1/fleet/groups/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const groupId = req.params.id;
    try {
      const db = getDb();
      const result = db.prepare('DELETE FROM dynamic_groups WHERE id = ?').run(groupId);

      if (result.changes === 0) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Group ${groupId} not found` });
        return;
      }

      sendJson(res, 200, { success: true, message: `Group ${groupId} deleted` });
    } catch (err) {
      sendJson(res, 500, { error: 'GROUP_DELETE_ERROR', message: err.message });
    }
  });

  // 10. POST /api/v1/fleet/groups/evaluate (Dry-run)
  router.post('/api/v1/fleet/groups/evaluate', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const { rule_syntax } = req.body || {};
    if (!rule_syntax) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'rule_syntax is required' });
      return;
    }

    try {
      const db = getDb();
      const result = dynamicGroupsService.evaluateRuleAgainstAllDevices(db, rule_syntax);
      sendJson(res, result.valid ? 200 : 400, result);
    } catch (err) {
      sendJson(res, 500, { error: 'EVALUATION_ERROR', message: err.message });
    }
  });

  // 11. GET /api/v1/fleet/software and /catalog
  const handleSoftwareList = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const software = db.prepare(`
        SELECT 
          s.*,
          (
            SELECT COUNT(DISTINCT pa.group_id) 
            FROM policy_assignments pa 
            WHERE pa.software_id = s.id
          ) as assigned_groups_count
        FROM software_catalog s
        ORDER BY s.name ASC
      `).all();

      sendJson(res, 200, software);
    } catch (err) {
      sendJson(res, 500, { error: 'SOFTWARE_QUERY_ERROR', message: err.message });
    }
  };

  router.get('/api/v1/fleet/software', handleSoftwareList);
  router.get('/api/v1/fleet/catalog', handleSoftwareList);

  // 12. POST /api/v1/fleet/software and /catalog
  const handleSoftwareCreate = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const { id, name, publisher, winget_id, version = 'latest', category = 'Utilities', description, icon_url, silent_install_args, silent_uninstall_args } = req.body || {};

    if (!name || !winget_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Package name and winget_id are required' });
      return;
    }

    try {
      const db = getDb();
      const softwareId = id || `pkg-${Date.now()}`;

      db.prepare(`
        INSERT INTO software_catalog (
          id, name, publisher, winget_id, version, category, description,
          icon_url, silent_install_args, silent_uninstall_args
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        softwareId,
        name,
        publisher || null,
        winget_id,
        version || 'latest',
        category || 'Utilities',
        description || null,
        icon_url || null,
        silent_install_args || '--silent --accept-package-agreements --accept-source-agreements',
        silent_uninstall_args || '--silent'
      );

      const created = db.prepare('SELECT * FROM software_catalog WHERE id = ?').get(softwareId);
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 500, { error: 'SOFTWARE_CREATE_ERROR', message: err.message });
    }
  };

  router.post('/api/v1/fleet/software', handleSoftwareCreate);
  router.post('/api/v1/fleet/catalog', handleSoftwareCreate);

  // 13. DELETE /api/v1/fleet/software/:id
  const handleSoftwareDelete = (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const softwareId = req.params.id;
    try {
      const db = getDb();
      const result = db.prepare('DELETE FROM software_catalog WHERE id = ?').run(softwareId);
      if (result.changes === 0) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: `Software ${softwareId} not found` });
        return;
      }
      sendJson(res, 200, { success: true });
    } catch (err) {
      sendJson(res, 500, { error: 'SOFTWARE_DELETE_ERROR', message: err.message });
    }
  };

  router.delete('/api/v1/fleet/software/:id', handleSoftwareDelete);
  router.delete('/api/v1/fleet/catalog/:id', handleSoftwareDelete);

  // 14. GET /api/v1/fleet/policies
  router.get('/api/v1/fleet/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const assignments = db.prepare(`
        SELECT 
          pa.id,
          pa.group_id,
          g.name as group_name,
          pa.software_id,
          s.name as software_name,
          s.winget_id,
          pa.assignment_type,
          pa.auto_update,
          pa.enforcement_priority,
          pa.created_at,
          pa.updated_at
        FROM policy_assignments pa
        JOIN dynamic_groups g ON pa.group_id = g.id
        JOIN software_catalog s ON pa.software_id = s.id
        ORDER BY g.priority ASC, pa.enforcement_priority ASC
      `).all();

      sendJson(res, 200, assignments);
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_QUERY_ERROR', message: err.message });
    }
  });

  // 15. PUT /api/v1/fleet/policies
  router.put('/api/v1/fleet/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const { group_id, software_id, assignment_type, auto_update = 1, enforcement_priority = 10 } = req.body || {};

    if (!group_id || !software_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'group_id and software_id are required' });
      return;
    }

    try {
      const db = getDb();

      // If assignment_type is None or delete
      if (!assignment_type || assignment_type === 'None') {
        db.prepare('DELETE FROM policy_assignments WHERE group_id = ? AND software_id = ?').run(group_id, software_id);
        sendJson(res, 200, { success: true, removed: true });
        return;
      }

      if (!['Required', 'Prohibited', 'Available'].includes(assignment_type)) {
        sendJson(res, 400, { error: 'BAD_REQUEST', message: 'assignment_type must be Required, Prohibited, or Available' });
        return;
      }

      const policyId = `pol-${crypto.randomBytes(6).toString('hex')}`;
      db.prepare(`
        INSERT INTO policy_assignments (
          id, group_id, software_id, assignment_type, auto_update, enforcement_priority, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'))
        ON CONFLICT(group_id, software_id) DO UPDATE SET
          assignment_type = excluded.assignment_type,
          auto_update = excluded.auto_update,
          enforcement_priority = excluded.enforcement_priority,
          updated_at = DATETIME('now')
      `).run(policyId, group_id, software_id, assignment_type, auto_update ? 1 : 0, Number(enforcement_priority) || 10);

      const saved = db.prepare(`
        SELECT pa.*, s.name as software_name, s.winget_id, g.name as group_name
        FROM policy_assignments pa
        JOIN dynamic_groups g ON pa.group_id = g.id
        JOIN software_catalog s ON pa.software_id = s.id
        WHERE pa.group_id = ? AND pa.software_id = ?
      `).get(group_id, software_id);

      sendJson(res, 200, saved);
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 16. GET /api/v1/fleet/settings
  router.get('/api/v1/fleet/settings', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const rows = db.prepare('SELECT key, value, data_type, description, is_secret FROM fleet_settings').all();

      const settings = {};
      for (const row of rows) {
        if (row.is_secret) {
          settings[row.key] = '****************';
        } else if (row.data_type === 'number') {
          settings[row.key] = Number(row.value);
        } else if (row.data_type === 'boolean') {
          settings[row.key] = row.value === 'true' || row.value === '1';
        } else {
          settings[row.key] = row.value;
        }
      }

      sendJson(res, 200, settings);
    } catch (err) {
      sendJson(res, 500, { error: 'SETTINGS_QUERY_ERROR', message: err.message });
    }
  });

  // 17. PUT /api/v1/fleet/settings
  router.put('/api/v1/fleet/settings', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const updates = req.body || {};
    try {
      const db = getDb();
      const upsert = db.prepare(`
        INSERT INTO fleet_settings (key, value, updated_at)
        VALUES (?, ?, DATETIME('now'))
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value,
          updated_at = DATETIME('now')
      `);

      for (const [k, v] of Object.entries(updates)) {
        // Skip masked secret placeholder
        if (String(v).startsWith('***')) continue;

        upsert.run(k, String(v));
        if (k === 'fleet_enrollment_key') {
          setFleetKey(String(v));
        }
      }

      sendJson(res, 200, { success: true });
    } catch (err) {
      sendJson(res, 500, { error: 'SETTINGS_UPDATE_ERROR', message: err.message });
    }
  });

  // 18. POST /api/v1/fleet/tunnel/generate
  router.post('/api/v1/fleet/tunnel/generate', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    const { hostname = 'fleet.localpilot.homelab' } = req.body || {};
    const configYml = `tunnel: localpilot-fleet-tunnel\ncredentials-file: C:\\Users\\User\\.cloudflared\\credentials.json\n\ningress:\n  - hostname: ${hostname}\n    service: http://127.0.0.1:8443\n  - service: http_status:404\n`;
    const setupScript = `# Setup Cloudflare Tunnel\ncloudflared.exe tunnel create localpilot-fleet-tunnel\ncloudflared.exe tunnel route dns localpilot-fleet-tunnel ${hostname}\ncloudflared.exe tunnel run localpilot-fleet-tunnel\n`;

    sendJson(res, 200, {
      config_yml: configYml,
      powershell_setup: setupScript
    });
  });

  // 19. GET /api/v1/fleet/tunnel/status
  router.get('/api/v1/fleet/tunnel/status', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const row = db.prepare("SELECT value FROM fleet_settings WHERE key = 'cloudflare_tunnel_hostname'").get();
      const hostname = row ? row.value : '';

      const countCloudflare = db.prepare("SELECT COUNT(*) as c FROM devices WHERE connection_route = 'Cloudflare'").get().c;

      sendJson(res, 200, {
        configured: Boolean(hostname),
        hostname,
        active_connections: countCloudflare
      });
    } catch (err) {
      sendJson(res, 500, { error: 'TUNNEL_STATUS_ERROR', message: err.message });
    }
  });

  /* ── Proactive Remediations ────────────────────────────────────────── */

  // 20. GET /api/v1/fleet/remediations
  router.get('/api/v1/fleet/remediations', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const list = remediationEngine.listRemediations(db);
      sendJson(res, 200, { remediations: list, total_count: list.length });
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_LIST_ERROR', message: err.message });
    }
  });

  // 21. GET /api/v1/fleet/remediations/stats
  router.get('/api/v1/fleet/remediations/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = remediationEngine.getFleetRemediationStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_STATS_ERROR', message: err.message });
    }
  });

  // 22. GET /api/v1/fleet/remediations/:id
  router.get('/api/v1/fleet/remediations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const pkg = remediationEngine.getRemediationDetails(db, req.params.id);
      if (!pkg) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Remediation package not found' });
        return;
      }
      sendJson(res, 200, pkg);
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_DETAIL_ERROR', message: err.message });
    }
  });

  // 23. POST /api/v1/fleet/remediations
  router.post('/api/v1/fleet/remediations', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    const {
      name,
      description = '',
      publisher = 'LocalPilot Admin',
      target_group_id = 'grp-all',
      detection_script,
      remediation_script,
      schedule_type = 'HEARTBEAT'
    } = body;

    if (!name || !detection_script || !remediation_script) {
      sendJson(res, 400, {
        error: 'BAD_REQUEST',
        message: 'name, detection_script, and remediation_script are required'
      });
      return;
    }

    try {
      const db = getDb();
      const id = body.id || `rem-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(`
        INSERT INTO remediations (
          id, name, description, publisher, target_group_id,
          detection_script, remediation_script, schedule_type, is_enabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
      `).run(
        id, name, description, publisher, target_group_id,
        detection_script, remediation_script, schedule_type
      );

      const created = remediationEngine.getRemediationDetails(db, id);
      broadcastEvent('remediation_created', { id, name, target_group_id });

      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_CREATE_ERROR', message: err.message });
    }
  });

  // 24. PATCH /api/v1/fleet/remediations/:id
  router.patch('/api/v1/fleet/remediations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    const id = req.params.id;

    try {
      const db = getDb();
      const existing = db.prepare('SELECT * FROM remediations WHERE id = ?').get(id);
      if (!existing) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Remediation package not found' });
        return;
      }

      db.prepare(`
        UPDATE remediations SET
          name = COALESCE(?, name),
          description = COALESCE(?, description),
          target_group_id = COALESCE(?, target_group_id),
          detection_script = COALESCE(?, detection_script),
          remediation_script = COALESCE(?, remediation_script),
          schedule_type = COALESCE(?, schedule_type),
          is_enabled = CASE WHEN ? IS NOT NULL THEN ? ELSE is_enabled END,
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        body.name ?? null,
        body.description ?? null,
        body.target_group_id ?? null,
        body.detection_script ?? null,
        body.remediation_script ?? null,
        body.schedule_type ?? null,
        body.is_enabled !== undefined ? (body.is_enabled ? 1 : 0) : null,
        body.is_enabled !== undefined ? (body.is_enabled ? 1 : 0) : null,
        id
      );

      const updated = remediationEngine.getRemediationDetails(db, id);
      broadcastEvent('remediation_updated', { id });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_UPDATE_ERROR', message: err.message });
    }
  });

  // 25. DELETE /api/v1/fleet/remediations/:id
  router.delete('/api/v1/fleet/remediations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const id = req.params.id;

    try {
      const db = getDb();
      const existing = db.prepare('SELECT * FROM remediations WHERE id = ?').get(id);
      if (!existing) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Remediation package not found' });
        return;
      }

      db.prepare('DELETE FROM remediations WHERE id = ?').run(id);
      broadcastEvent('remediation_deleted', { id });
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_DELETE_ERROR', message: err.message });
    }
  });

  // 26. POST /api/v1/fleet/remediations/:id/run-now
  router.post('/api/v1/fleet/remediations/:id/run-now', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const id = req.params.id;

    try {
      const db = getDb();
      const pkg = db.prepare('SELECT * FROM remediations WHERE id = ?').get(id);
      if (!pkg) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Remediation package not found' });
        return;
      }

      // Determine target devices
      let targetDevices = [];
      if (!pkg.target_group_id || pkg.target_group_id === 'grp-all') {
        targetDevices = db.prepare("SELECT id, hostname FROM devices WHERE status != 'quarantined'").all();
      } else {
        targetDevices = db.prepare(`
          SELECT d.id, d.hostname FROM devices d
          JOIN group_memberships gm ON d.id = gm.device_id
          WHERE gm.group_id = ? AND d.status != 'quarantined'
        `).all(pkg.target_group_id);
      }

      // Queue an action command for each device with detection + remediation logic wrapper
      const queued = [];
      const wrapperScript = `
# LocalPilot Proactive Remediation Runner: ${pkg.name}
$remId = "${pkg.id}"
$detScript = @'
${pkg.detection_script}
'@
$fixScript = @'
${pkg.remediation_script}
'@

$detOut = ''
$detErr = ''
$detCode = 0
try {
  $res1 = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $detScript 2>&1
  $detCode = $LASTEXITCODE; if ($null -eq $detCode) { $detCode = 0 }
  $detOut = ($res1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join [Environment]::NewLine
  $detErr = ($res1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join [Environment]::NewLine
} catch {
  $detCode = 1
  $detErr = $_.Exception.Message
}

$remCode = $null
$remOut = $null
$remErr = $null
if ($detCode -ne 0) {
  try {
    $res2 = powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $fixScript 2>&1
    $remCode = $LASTEXITCODE; if ($null -eq $remCode) { $remCode = 0 }
    $remOut = ($res2 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join [Environment]::NewLine
    $remErr = ($res2 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join [Environment]::NewLine
  } catch {
    $remCode = 1
    $remErr = $_.Exception.Message
  }
}

# Post result back to node remediation result API
$report = @{
  remediation_id        = $remId
  device_id             = $deviceId
  detection_exit_code   = $detCode
  detection_stdout      = $detOut
  detection_stderr      = $detErr
  remediation_exit_code = $remCode
  remediation_stdout    = $remOut
  remediation_stderr    = $remErr
}

try {
  Invoke-RestMethod -Uri "$baseUrl/api/v1/nodes/$deviceId/remediation-result" -Method POST -Body ($report | ConvertTo-Json) -Headers $authHeaders -TimeoutSec 10 | Out-Null
  Write-Host "Proactive Remediation execution completed. Detection: $detCode, Remediation: $remCode"
} catch {
  Write-Warning "Failed to report remediation result: $($_.Exception.Message)"
}
`;

      const insertCmd = db.prepare(`
        INSERT INTO device_commands (
          id, device_id, command_text, created_by, status, created_at
        ) VALUES (?, ?, ?, 'admin', 'PENDING', DATETIME('now'))
      `);

      for (const dev of targetDevices) {
        const cmdId = crypto.randomUUID();
        insertCmd.run(cmdId, dev.id, wrapperScript);
        queued.push({ device_id: dev.id, hostname: dev.hostname, command_id: cmdId });
      }

      broadcastEvent('remediation_triggered', { remediation_id: id, count: queued.length });

      sendJson(res, 200, {
        success: true,
        remediation_id: id,
        remediation_name: pkg.name,
        target_count: queued.length,
        dispatched_targets: queued
      });
    } catch (err) {
      sendJson(res, 500, { error: 'REMEDIATION_RUN_NOW_ERROR', message: err.message });
    }
  });

  /* ── Configuration Profiles (Settings Catalog & Security Baselines) ─ */

  // 26. GET /api/v1/fleet/profiles
  router.get('/api/v1/fleet/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profiles = configProfileEngine.getAllProfiles(db);
      sendJson(res, 200, { profiles, total_count: profiles.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 27. GET /api/v1/fleet/profiles/stats
  router.get('/api/v1/fleet/profiles/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = configProfileEngine.getFleetProfileStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILES_STATS_ERROR', message: err.message });
    }
  });

  // 28. GET /api/v1/fleet/profiles/catalog
  router.get('/api/v1/fleet/profiles/catalog', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const catalog = configProfileEngine.getSettingCatalogLibrary();
      sendJson(res, 200, { catalog, total_count: catalog.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SETTINGS_CATALOG_ERROR', message: err.message });
    }
  });

  // 29. GET /api/v1/fleet/profiles/:id
  router.get('/api/v1/fleet/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profile = configProfileEngine.getProfileById(db, req.params.id);
      if (!profile) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Configuration profile not found' });
        return;
      }
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILE_DETAIL_ERROR', message: err.message });
    }
  });

  // 30. POST /api/v1/fleet/profiles
  router.post('/api/v1/fleet/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    const { name, description = '', profile_type = 'SettingsCatalog', target_group_id = 'grp-all', settings = [] } = body;

    if (!name || !name.trim()) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Profile name is required' });
      return;
    }

    try {
      const db = getDb();
      const created = configProfileEngine.createProfile(db, {
        name,
        description,
        profile_type,
        target_group_id,
        settings
      });

      broadcastEvent('profile_created', { profile_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILE_CREATE_ERROR', message: err.message });
    }
  });

  // 31. PATCH /api/v1/fleet/profiles/:id
  router.patch('/api/v1/fleet/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};

    try {
      const db = getDb();
      const updated = configProfileEngine.updateProfile(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Configuration profile not found' });
        return;
      }

      broadcastEvent('profile_updated', { profile_id: id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILE_UPDATE_ERROR', message: err.message });
    }
  });

  // 32. DELETE /api/v1/fleet/profiles/:id
  router.delete('/api/v1/fleet/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const deleted = configProfileEngine.deleteProfile(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Configuration profile not found' });
        return;
      }

      broadcastEvent('profile_deleted', { profile_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'PROFILE_DELETE_ERROR', message: err.message });
    }
  });

  // 33. GET /api/v1/fleet/devices/:id/profiles
  router.get('/api/v1/fleet/devices/:id/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(id);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }

      const profiles = configProfileEngine.getProfilesForDevice(db, id);
      sendJson(res, 200, { device_id: id, hostname: device.hostname, profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_PROFILES_ERROR', message: err.message });
    }
  });

  /* ── Windows Update for Business (WUfB Update Rings) ──────────────── */

  // 34. GET /api/v1/fleet/updates/rings
  router.get('/api/v1/fleet/updates/rings', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const rings = updateRingEngine.getAllRings(db);
      sendJson(res, 200, { rings, total_count: rings.length });
    } catch (err) {
      sendJson(res, 500, { error: 'RINGS_FETCH_ERROR', message: err.message });
    }
  });

  // 35. GET /api/v1/fleet/updates/stats
  router.get('/api/v1/fleet/updates/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = updateRingEngine.getFleetUpdateStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'UPDATE_STATS_ERROR', message: err.message });
    }
  });

  // 36. GET /api/v1/fleet/updates/rings/:id
  router.get('/api/v1/fleet/updates/rings/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const ring = updateRingEngine.getRingById(db, req.params.id);
      if (!ring) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Update ring not found' });
        return;
      }
      sendJson(res, 200, ring);
    } catch (err) {
      sendJson(res, 500, { error: 'RING_DETAIL_ERROR', message: err.message });
    }
  });

  // 37. POST /api/v1/fleet/updates/rings
  router.post('/api/v1/fleet/updates/rings', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    const { name } = body;

    if (!name || !name.trim()) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Update ring name is required' });
      return;
    }

    try {
      const db = getDb();
      const created = updateRingEngine.createRing(db, body);
      broadcastEvent('update_ring_created', { ring_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 500, { error: 'RING_CREATE_ERROR', message: err.message });
    }
  });

  // 38. PATCH /api/v1/fleet/updates/rings/:id
  router.patch('/api/v1/fleet/updates/rings/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};

    try {
      const db = getDb();
      const updated = updateRingEngine.updateRing(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Update ring not found' });
        return;
      }

      broadcastEvent('update_ring_updated', { ring_id: id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'RING_UPDATE_ERROR', message: err.message });
    }
  });

  // 39. DELETE /api/v1/fleet/updates/rings/:id
  router.delete('/api/v1/fleet/updates/rings/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const deleted = updateRingEngine.deleteRing(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Update ring not found' });
        return;
      }

      broadcastEvent('update_ring_deleted', { ring_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'RING_DELETE_ERROR', message: err.message });
    }
  });

  // 40. POST /api/v1/fleet/devices/:id/scan-updates
  router.post('/api/v1/fleet/devices/:id/scan-updates', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(id);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }

      const scanScript = `
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $res = $searcher.Search("IsInstalled=0 and Type='Software'")
  Write-Host "Windows Update scan completed. Found $($res.Updates.Count) pending updates."
} catch {
  Start-Process -FilePath "C:\\Windows\\System32\\UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden -ErrorAction SilentlyContinue
  Write-Host "Triggered background Windows Update scan via UsoClient."
}
`;
      const cmdId = crypto.randomUUID();
      db.prepare(`
        INSERT INTO device_commands (
          id, device_id, command_text, created_by, status, created_at
        ) VALUES (?, ?, ?, 'admin', 'PENDING', DATETIME('now'))
      `).run(cmdId, id, scanScript);

      broadcastEvent('command_dispatched', {
        command_id: cmdId,
        device_id: id,
        hostname: device.hostname,
        action: 'scan-updates'
      });

      sendJson(res, 202, {
        success: true,
        command_id: cmdId,
        device_id: id,
        message: 'Windows Update scan queued for node'
      });
    } catch (err) {
      sendJson(res, 500, { error: 'UPDATE_SCAN_DISPATCH_ERROR', message: err.message });
    }
  });

  // 41. GET /api/v1/fleet/devices/:id/update-status
  router.get('/api/v1/fleet/devices/:id/update-status', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const status = db.prepare(`
        SELECT s.*, r.name as ring_name, r.servicing_channel, r.active_hours_start, r.active_hours_end
        FROM device_update_status s
        LEFT JOIN update_rings r ON s.ring_id = r.id
        WHERE s.device_id = ?
      `).get(id);

      if (!status) {
        sendJson(res, 200, { device_id: id, status: null });
        return;
      }

      let reasons = [];
      let hotfixes = [];
      try { reasons = JSON.parse(status.reboot_pending_reasons_json || '[]'); } catch {}
      try { hotfixes = JSON.parse(status.installed_hotfixes_json || '[]'); } catch {}

      sendJson(res, 200, {
        ...status,
        reboot_pending_reasons: reasons,
        installed_hotfixes: hotfixes
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_UPDATE_STATUS_ERROR', message: err.message });
    }
  });

  // 42. GET /api/v1/fleet/compliance/policies
  router.get('/api/v1/fleet/compliance/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const policies = complianceEngine.getAllPolicies(db);
      sendJson(res, 200, { policies, total_count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICIES_QUERY_ERROR', message: err.message });
    }
  });

  // 43. GET /api/v1/fleet/compliance/stats
  router.get('/api/v1/fleet/compliance/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;

    try {
      const db = getDb();
      const stats = complianceEngine.getFleetComplianceStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_STATS_ERROR', message: err.message });
    }
  });

  // 44. GET /api/v1/fleet/compliance/policies/:id
  router.get('/api/v1/fleet/compliance/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const policy = complianceEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Compliance policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICY_GET_ERROR', message: err.message });
    }
  });

  // 45. POST /api/v1/fleet/compliance/policies
  router.post('/api/v1/fleet/compliance/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};

    try {
      const db = getDb();
      const created = complianceEngine.createPolicy(db, body);
      broadcastEvent('compliance_policy_created', { policy_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 46. PATCH /api/v1/fleet/compliance/policies/:id
  router.patch('/api/v1/fleet/compliance/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};

    try {
      const db = getDb();
      const updated = complianceEngine.updatePolicy(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Compliance policy not found' });
        return;
      }
      broadcastEvent('compliance_policy_updated', { policy_id: id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 47. DELETE /api/v1/fleet/compliance/policies/:id
  router.delete('/api/v1/fleet/compliance/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const deleted = complianceEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Compliance policy not found' });
        return;
      }
      broadcastEvent('compliance_policy_deleted', { policy_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'COMPLIANCE_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 48. GET /api/v1/fleet/devices/:id/compliance
  router.get('/api/v1/fleet/devices/:id/compliance', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const evals = db.prepare(`
        SELECT e.*, p.name as policy_name, p.non_compliance_action, p.grace_period_days
        FROM device_compliance_evaluations e
        JOIN compliance_policies p ON e.policy_id = p.id
        WHERE e.device_id = ?
        ORDER BY e.evaluated_at DESC
      `).all(id);

      const parsed = evals.map(e => {
        let rules = [];
        try { rules = JSON.parse(e.rule_results_json || '[]'); } catch {}
        return {
          ...e,
          rule_results: rules
        };
      });

      sendJson(res, 200, { device_id: id, evaluations: parsed });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_COMPLIANCE_QUERY_ERROR', message: err.message });
    }
  });

  // 49. POST /api/v1/fleet/devices/:id/evaluate-compliance
  router.post('/api/v1/fleet/devices/:id/evaluate-compliance', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;

    try {
      const db = getDb();
      const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }

      const results = complianceEngine.evaluateDeviceCompliance(db, id, {
        os_build: device.os_build,
        bitlocker_status: device.bitlocker_status,
        secure_boot_enabled: device.secure_boot_enabled,
        tpm_present: device.tpm_present,
        tpm_enabled: device.tpm_enabled
      });

      broadcastEvent('device_compliance_recalculated', { device_id: id, results_count: results.length });
      sendJson(res, 200, { success: true, device_id: id, results });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_COMPLIANCE_EVAL_ERROR', message: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // INTUNE APPLICATION MANAGEMENT & WIN32/WINGET PACKAGING (50–57)
  // ══════════════════════════════════════════════════════════════════

  // 50. GET /api/v1/fleet/apps
  router.get('/api/v1/fleet/apps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const apps = appManagementEngine.getAllApps(db);
      sendJson(res, 200, apps);
    } catch (err) {
      sendJson(res, 500, { error: 'APPS_QUERY_ERROR', message: err.message });
    }
  });

  // 51. GET /api/v1/fleet/apps/stats
  router.get('/api/v1/fleet/apps/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = appManagementEngine.getAppFleetStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'APPS_STATS_ERROR', message: err.message });
    }
  });

  // 52. GET /api/v1/fleet/apps/:id
  router.get('/api/v1/fleet/apps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const app = appManagementEngine.getAppById(db, id);
      if (!app) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Application package not found' });
        return;
      }
      sendJson(res, 200, app);
    } catch (err) {
      sendJson(res, 500, { error: 'APP_QUERY_ERROR', message: err.message });
    }
  });

  // 53. POST /api/v1/fleet/apps
  router.post('/api/v1/fleet/apps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const created = appManagementEngine.createApp(db, body);
      broadcastEvent('app_created', { app_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'APP_CREATE_ERROR', message: err.message });
    }
  });

  // 54. PATCH /api/v1/fleet/apps/:id
  router.patch('/api/v1/fleet/apps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const updated = appManagementEngine.updateApp(db, id, body);
      broadcastEvent('app_updated', { app_id: updated.id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'APP_UPDATE_ERROR', message: err.message });
    }
  });

  // 55. DELETE /api/v1/fleet/apps/:id
  router.delete('/api/v1/fleet/apps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = appManagementEngine.deleteApp(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Application package not found' });
        return;
      }
      broadcastEvent('app_deleted', { app_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'APP_DELETE_ERROR', message: err.message });
    }
  });

  // 56. GET /api/v1/fleet/devices/:id/apps
  router.get('/api/v1/fleet/devices/:id/apps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const assigned = appManagementEngine.getDeviceAssignedApps(db, id);
      sendJson(res, 200, assigned);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_APPS_ERROR', message: err.message });
    }
  });

  // 57. POST /api/v1/fleet/devices/:id/apps/:appId/install-now
  router.post('/api/v1/fleet/devices/:id/apps/:appId/install-now', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id, appId } = req.params;
    try {
      const db = getDb();
      const result = appManagementEngine.queueAppInstallCommand(db, id, appId);
      broadcastEvent('app_install_dispatched', { device_id: id, app_id: appId, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'APP_INSTALL_QUEUE_ERROR', message: err.message });
    }
  });

  // 58. GET /api/v1/fleet/security/policies
  router.get('/api/v1/fleet/security/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = endpointSecurityEngine.getAllPolicies(db);
      sendJson(res, 200, policies);
    } catch (err) {
      sendJson(res, 500, { error: 'SECURITY_POLICIES_ERROR', message: err.message });
    }
  });

  // 59. GET /api/v1/fleet/security/policies/:id
  router.get('/api/v1/fleet/security/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = endpointSecurityEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Endpoint security policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'SECURITY_POLICY_ERROR', message: err.message });
    }
  });

  // 60. POST /api/v1/fleet/security/policies
  router.post('/api/v1/fleet/security/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const created = endpointSecurityEngine.createPolicy(db, body);
      broadcastEvent('security_policy_created', { policy_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'SECURITY_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 61. PATCH /api/v1/fleet/security/policies/:id
  router.patch('/api/v1/fleet/security/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const updated = endpointSecurityEngine.updatePolicy(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Endpoint security policy not found' });
        return;
      }
      broadcastEvent('security_policy_updated', { policy_id: updated.id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'SECURITY_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 62. DELETE /api/v1/fleet/security/policies/:id
  router.delete('/api/v1/fleet/security/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = endpointSecurityEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Endpoint security policy not found' });
        return;
      }
      broadcastEvent('security_policy_deleted', { policy_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'SECURITY_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 63. GET /api/v1/fleet/security/stats
  router.get('/api/v1/fleet/security/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = endpointSecurityEngine.getSecurityStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'SECURITY_STATS_ERROR', message: err.message });
    }
  });

  // 64. GET /api/v1/fleet/security/antivirus-status
  router.get('/api/v1/fleet/security/antivirus-status', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const statuses = endpointSecurityEngine.getAllDeviceAntivirusStatuses(db, req.query);
      sendJson(res, 200, statuses);
    } catch (err) {
      sendJson(res, 500, { error: 'ANTIVIRUS_STATUS_ERROR', message: err.message });
    }
  });

  // 65. GET /api/v1/fleet/security/threats
  router.get('/api/v1/fleet/security/threats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const threats = endpointSecurityEngine.getThreats(db, req.query);
      sendJson(res, 200, threats);
    } catch (err) {
      sendJson(res, 500, { error: 'THREATS_QUERY_ERROR', message: err.message });
    }
  });

  // 66. PATCH /api/v1/fleet/security/threats/:id/remediate
  router.patch('/api/v1/fleet/security/threats/:id/remediate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const updated = endpointSecurityEngine.remediateThreat(db, id, body.remediation_status || 'RESOLVED');
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Threat record not found' });
        return;
      }
      broadcastEvent('threat_remediated', { threat_id: id, remediation_status: updated.remediation_status });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 500, { error: 'THREAT_REMEDIATE_ERROR', message: err.message });
    }
  });

  // 67. GET /api/v1/fleet/devices/:id/security
  router.get('/api/v1/fleet/devices/:id/security', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const secStatus = endpointSecurityEngine.getDeviceAntivirusStatus(db, id);
      if (!secStatus) {
        // Check if device itself exists
        const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(id);
        if (!dev) {
          sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
          return;
        }
        // Device exists but has not reported Defender status yet
        sendJson(res, 200, {
          device_id: id,
          hostname: dev.hostname,
          antivirus_enabled: 1,
          real_time_protection_enabled: 1,
          signature_age_days: 0,
          health_status: 'HEALTHY',
          recent_threats: [],
          effective_policy: endpointSecurityEngine.getEffectivePolicyForDevice(db, id)
        });
        return;
      }
      sendJson(res, 200, secStatus);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_SECURITY_ERROR', message: err.message });
    }
  });

  // 68. POST /api/v1/fleet/devices/:id/security/scan
  router.post('/api/v1/fleet/devices/:id/security/scan', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = endpointSecurityEngine.queueScanCommand(db, id, body.scan_type || 'QuickScan');
      broadcastEvent('defender_scan_dispatched', { device_id: id, scan_type: result.scan_type, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SCAN_DISPATCH_ERROR', message: err.message });
    }
  });

  // 69. POST /api/v1/fleet/devices/:id/security/update-signatures
  router.post('/api/v1/fleet/devices/:id/security/update-signatures', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = endpointSecurityEngine.queueSignatureUpdateCommand(db, id);
      broadcastEvent('defender_sig_update_dispatched', { device_id: id, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SIG_UPDATE_DISPATCH_ERROR', message: err.message });
    }
  });

  // 70. GET /api/v1/fleet/bitlocker/stats
  router.get('/api/v1/fleet/bitlocker/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = bitlockerEngine.getBitLockerStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_STATS_ERROR', message: err.message });
    }
  });

  // 71. GET /api/v1/fleet/bitlocker/policies
  router.get('/api/v1/fleet/bitlocker/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = bitlockerEngine.getPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_POLICIES_ERROR', message: err.message });
    }
  });

  // 72. GET /api/v1/fleet/bitlocker/policies/:id
  router.get('/api/v1/fleet/bitlocker/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = bitlockerEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'BitLocker policy not found' });
        return;
      }
      sendJson(res, 200, { policy });
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_POLICY_ERROR', message: err.message });
    }
  });

  // 73. POST /api/v1/fleet/bitlocker/policies
  router.post('/api/v1/fleet/bitlocker/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = bitlockerEngine.createPolicy(db, body);
      broadcastEvent('bitlocker_policy_created', { policy_id: policy.id, name: policy.name });
      sendJson(res, 201, { policy });
    } catch (err) {
      sendJson(res, 400, { error: 'BITLOCKER_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 74. PATCH /api/v1/fleet/bitlocker/policies/:id
  router.patch('/api/v1/fleet/bitlocker/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = bitlockerEngine.updatePolicy(db, id, body);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'BitLocker policy not found' });
        return;
      }
      broadcastEvent('bitlocker_policy_updated', { policy_id: id, name: policy.name });
      sendJson(res, 200, { policy });
    } catch (err) {
      sendJson(res, 400, { error: 'BITLOCKER_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 75. DELETE /api/v1/fleet/bitlocker/policies/:id
  router.delete('/api/v1/fleet/bitlocker/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = bitlockerEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'BitLocker policy not found' });
        return;
      }
      broadcastEvent('bitlocker_policy_deleted', { policy_id: id });
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 76. GET /api/v1/fleet/bitlocker/keys (List escrowed recovery keys with masked passwords)
  router.get('/api/v1/fleet/bitlocker/keys', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const device_id = url.searchParams.get('device_id') || undefined;
    const query = url.searchParams.get('query') || undefined;
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    try {
      const db = getDb();
      const keys = bitlockerEngine.getRecoveryKeys(db, { device_id, query, limit, offset });
      sendJson(res, 200, { keys, total: keys.length });
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_KEYS_ERROR', message: err.message });
    }
  });

  // 77. POST /api/v1/fleet/bitlocker/keys/:id/reveal (Unmask password with audit trail)
  router.post('/api/v1/fleet/bitlocker/keys/:id/reveal', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const clientIp = req.socket?.remoteAddress || '127.0.0.1';
      const result = bitlockerEngine.revealRecoveryKey(db, id, {
        accessed_by: body.accessed_by || 'Fleet Administrator',
        access_reason: body.access_reason || 'Endpoint BitLocker recovery unlock',
        ip_address: clientIp
      });

      broadcastEvent('bitlocker_key_revealed', {
        key_id: id,
        device_id: result.device_id,
        hostname: result.hostname,
        mount_point: result.volume_mount_point,
        accessed_by: body.accessed_by || 'Fleet Administrator'
      });

      sendJson(res, 200, result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'BITLOCKER_KEY_REVEAL_ERROR', message: err.message });
    }
  });

  // 78. GET /api/v1/fleet/bitlocker/audit
  router.get('/api/v1/fleet/bitlocker/audit', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const device_id = url.searchParams.get('device_id') || undefined;
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    try {
      const db = getDb();
      const logs = bitlockerEngine.getAuditLogs(db, { device_id, limit, offset });
      sendJson(res, 200, { audit_logs: logs });
    } catch (err) {
      sendJson(res, 500, { error: 'BITLOCKER_AUDIT_ERROR', message: err.message });
    }
  });

  // 79. GET /api/v1/fleet/devices/:id/bitlocker
  router.get('/api/v1/fleet/devices/:id/bitlocker', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const posture = bitlockerEngine.getDeviceBitLockerPosture(db, id);
      if (!posture) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }
      sendJson(res, 200, posture);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_BITLOCKER_ERROR', message: err.message });
    }
  });

  // 80. POST /api/v1/fleet/devices/:id/bitlocker/rotate-keys
  router.post('/api/v1/fleet/devices/:id/bitlocker/rotate-keys', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = bitlockerEngine.queueKeyRotationCommand(db, id, body.mount_point || 'C:');
      broadcastEvent('bitlocker_rotation_dispatched', { device_id: id, mount_point: result.mount_point, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'KEY_ROTATION_DISPATCH_ERROR', message: err.message });
    }
  });

  // 81. POST /api/v1/fleet/devices/:id/bitlocker/enable
  router.post('/api/v1/fleet/devices/:id/bitlocker/enable', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = bitlockerEngine.queueEnableBitLockerCommand(db, id, body.mount_point || 'C:', body.encryption_method || 'XtsAes128');
      broadcastEvent('bitlocker_enable_dispatched', { device_id: id, mount_point: result.mount_point, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'BITLOCKER_ENABLE_DISPATCH_ERROR', message: err.message });
    }
  });

    // 82. POST /api/v1/fleet/devices/:id/bitlocker/backup-keys
  router.post('/api/v1/fleet/devices/:id/bitlocker/backup-keys', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = bitlockerEngine.queueForceEscrowCommand(db, id);
      broadcastEvent('bitlocker_escrow_dispatched', { device_id: id, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'BITLOCKER_ESCROW_DISPATCH_ERROR', message: err.message });
    }
  });

  // 83. GET /api/v1/fleet/laps/stats (Fleet-wide LAPS metrics)
  router.get('/api/v1/fleet/laps/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = lapsEngine.getLapsStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_STATS_ERROR', message: err.message });
    }
  });

  // 84. GET /api/v1/fleet/laps/policies (List all LAPS policies)
  router.get('/api/v1/fleet/laps/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = lapsEngine.getPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_POLICIES_ERROR', message: err.message });
    }
  });

  // 85. POST /api/v1/fleet/laps/policies (Create new LAPS policy)
  router.post('/api/v1/fleet/laps/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const created = lapsEngine.createPolicy(db, body);
      broadcastEvent('laps_policy_created', { policy_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'LAPS_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 86. GET /api/v1/fleet/laps/policies/:id (Get single LAPS policy)
  router.get('/api/v1/fleet/laps/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = lapsEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'LAPS policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_POLICY_GET_ERROR', message: err.message });
    }
  });

  // 87. PATCH /api/v1/fleet/laps/policies/:id (Update LAPS policy)
  router.patch('/api/v1/fleet/laps/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const updated = lapsEngine.updatePolicy(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'LAPS policy not found' });
        return;
      }
      broadcastEvent('laps_policy_updated', { policy_id: id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'LAPS_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 88. DELETE /api/v1/fleet/laps/policies/:id (Delete LAPS policy)
  router.delete('/api/v1/fleet/laps/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = lapsEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'LAPS policy not found' });
        return;
      }
      broadcastEvent('laps_policy_deleted', { policy_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 89. GET /api/v1/fleet/laps/passwords (List all managed passwords - zero-trust masked)
  router.get('/api/v1/fleet/laps/passwords', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const search = url.searchParams.get('query') || url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || '';
    try {
      const db = getDb();
      const passwords = lapsEngine.getAllPasswords(db, { search, status });
      sendJson(res, 200, { passwords, total: passwords.length });
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_PASSWORDS_ERROR', message: err.message });
    }
  });

  // 90. GET /api/v1/fleet/devices/:id/laps (Get device LAPS posture & history)
  router.get('/api/v1/fleet/devices/:id/laps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const posture = lapsEngine.getDeviceLapsPosture(db, id);
      sendJson(res, 200, posture);
    } catch (err) {
      sendJson(res, 404, { error: 'NOT_FOUND', message: err.message });
    }
  });

  // 91. POST /api/v1/fleet/devices/:id/laps/reveal (Reveal active password with audit)
  router.post('/api/v1/fleet/devices/:id/laps/reveal', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const clientIp = req.socket?.remoteAddress || '127.0.0.1';
      const result = lapsEngine.revealPassword(db, id, {
        accessed_by: body.accessed_by || 'Administrator',
        access_reason: body.access_reason || '',
        ip_address: clientIp
      });

      broadcastEvent('laps_password_revealed', {
        device_id: id,
        hostname: result.hostname,
        account_name: result.account_name,
        accessed_by: body.accessed_by || 'Administrator'
      });

      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'LAPS_REVEAL_ERROR', message: err.message });
    }
  });

  // 92. POST /api/v1/fleet/laps/history/:id/reveal (Reveal historical password with audit)
  router.post('/api/v1/fleet/laps/history/:id/reveal', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const clientIp = req.socket?.remoteAddress || '127.0.0.1';
      const result = lapsEngine.revealHistoricalPassword(db, id, {
        accessed_by: body.accessed_by || 'Administrator',
        access_reason: body.access_reason || '',
        ip_address: clientIp
      });

      broadcastEvent('laps_history_revealed', {
        history_id: id,
        device_id: result.device_id,
        accessed_by: body.accessed_by || 'Administrator'
      });

      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'LAPS_HISTORY_REVEAL_ERROR', message: err.message });
    }
  });

  // 93. POST /api/v1/fleet/devices/:id/laps/rotate (Trigger immediate on-demand rotation)
  router.post('/api/v1/fleet/devices/:id/laps/rotate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = lapsEngine.queuePasswordRotation(db, id, body.requested_by || 'Administrator');
      broadcastEvent('laps_rotation_dispatched', { device_id: id, command_id: result.command_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'LAPS_ROTATION_DISPATCH_ERROR', message: err.message });
    }
  });

  // 94. GET /api/v1/fleet/laps/audit (Get LAPS audit trail)
  router.get('/api/v1/fleet/laps/audit', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const limit = Math.min(500, parseInt(url.searchParams.get('limit') || '100', 10));
    try {
      const db = getDb();
      const logs = lapsEngine.getAuditLogs(db, limit);
      sendJson(res, 200, { audit_logs: logs, total: logs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'LAPS_AUDIT_ERROR', message: err.message });
    }
  });

  /* ── Endpoint Privilege Management (EPM) Endpoints ────────────────── */

  // 95. GET /api/v1/fleet/epm/stats
  router.get('/api/v1/fleet/epm/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = epmEngine.getEpmStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_STATS_ERROR', message: err.message });
    }
  });

  // 96. GET /api/v1/fleet/epm/policies
  router.get('/api/v1/fleet/epm/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = epmEngine.getEpmPolicies(db);
      sendJson(res, 200, { policies, total: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_POLICIES_ERROR', message: err.message });
    }
  });

  // 97. POST /api/v1/fleet/epm/policies
  router.post('/api/v1/fleet/epm/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = epmEngine.createEpmPolicy(db, body);
      broadcastEvent('epm_policy_created', { policy_id: policy.id, name: policy.name });
      sendJson(res, 201, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'EPM_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 98. GET /api/v1/fleet/epm/policies/:id
  router.get('/api/v1/fleet/epm/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = epmEngine.getEpmPolicy(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_POLICY_GET_ERROR', message: err.message });
    }
  });

  // 99. PATCH /api/v1/fleet/epm/policies/:id
  router.patch('/api/v1/fleet/epm/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = epmEngine.updateEpmPolicy(db, id, body);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM policy not found' });
        return;
      }
      broadcastEvent('epm_policy_updated', { policy_id: id, name: policy.name });
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'EPM_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 100. DELETE /api/v1/fleet/epm/policies/:id
  router.delete('/api/v1/fleet/epm/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const success = epmEngine.deleteEpmPolicy(db, id);
      if (!success) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM policy not found' });
        return;
      }
      broadcastEvent('epm_policy_deleted', { policy_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 101. GET /api/v1/fleet/epm/rules
  router.get('/api/v1/fleet/epm/rules', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const policyId = url.searchParams.get('policy_id') || undefined;
    const elevationType = url.searchParams.get('elevation_type') || undefined;
    const search = url.searchParams.get('search') || undefined;
    try {
      const db = getDb();
      const rules = epmEngine.getEpmRules(db, { policyId, elevationType, search });
      sendJson(res, 200, { rules, total: rules.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_RULES_GET_ERROR', message: err.message });
    }
  });

  // 102. POST /api/v1/fleet/epm/rules
  router.post('/api/v1/fleet/epm/rules', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const rule = epmEngine.createEpmRule(db, body);
      broadcastEvent('epm_rule_created', { rule_id: rule.id, name: rule.rule_name });
      sendJson(res, 201, rule);
    } catch (err) {
      sendJson(res, 400, { error: 'EPM_RULE_CREATE_ERROR', message: err.message });
    }
  });

  // 103. GET /api/v1/fleet/epm/rules/:id
  router.get('/api/v1/fleet/epm/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const rule = epmEngine.getEpmRule(db, id);
      if (!rule) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM elevation rule not found' });
        return;
      }
      sendJson(res, 200, rule);
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_RULE_GET_ERROR', message: err.message });
    }
  });

  // 104. PATCH /api/v1/fleet/epm/rules/:id
  router.patch('/api/v1/fleet/epm/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const rule = epmEngine.updateEpmRule(db, id, body);
      if (!rule) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM elevation rule not found' });
        return;
      }
      broadcastEvent('epm_rule_updated', { rule_id: id, name: rule.rule_name });
      sendJson(res, 200, rule);
    } catch (err) {
      sendJson(res, 400, { error: 'EPM_RULE_UPDATE_ERROR', message: err.message });
    }
  });

  // 105. DELETE /api/v1/fleet/epm/rules/:id
  router.delete('/api/v1/fleet/epm/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const success = epmEngine.deleteEpmRule(db, id);
      if (!success) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'EPM elevation rule not found' });
        return;
      }
      broadcastEvent('epm_rule_deleted', { rule_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_RULE_DELETE_ERROR', message: err.message });
    }
  });

  // 106. GET /api/v1/fleet/epm/requests
  router.get('/api/v1/fleet/epm/requests', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const deviceId = url.searchParams.get('device_id') || undefined;
    const status = url.searchParams.get('status') || undefined;
    const limit = Math.min(200, parseInt(url.searchParams.get('limit') || '50', 10));
    try {
      const db = getDb();
      const requests = epmEngine.getElevationRequests(db, { deviceId, status, limit });
      sendJson(res, 200, { requests, total: requests.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_REQUESTS_GET_ERROR', message: err.message });
    }
  });

  // 107. POST /api/v1/fleet/epm/requests/:id/review
  router.post('/api/v1/fleet/epm/requests/:id/review', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = epmEngine.reviewElevationRequest(db, id, {
        decision: body.decision,
        reviewedBy: body.reviewed_by || 'Fleet Administrator',
        notes: body.notes,
        validHours: body.valid_hours || 4
      });
      broadcastEvent('epm_request_reviewed', {
        request_id: id,
        decision: result.status,
        device_id: result.device_id,
        reviewed_by: result.reviewed_by
      });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'EPM_REQUEST_REVIEW_ERROR', message: err.message });
    }
  });

  // 108. GET /api/v1/fleet/epm/logs
  router.get('/api/v1/fleet/epm/logs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const deviceId = url.searchParams.get('device_id') || undefined;
    const limit = Math.min(500, parseInt(url.searchParams.get('limit') || '100', 10));
    try {
      const db = getDb();
      const logs = epmEngine.getElevationLogs(db, { deviceId, limit });
      sendJson(res, 200, { elevation_logs: logs, total: logs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EPM_LOGS_GET_ERROR', message: err.message });
    }
  });

  // 109. GET /api/v1/fleet/devices/:id/epm
  router.get('/api/v1/fleet/devices/:id/epm', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const posture = epmEngine.getDeviceEpmPosture(db, id);
      if (!posture) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }
      sendJson(res, 200, posture);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_EPM_POSTURE_ERROR', message: err.message });
    }
  });

  /* ── Windows Autopilot & Hardware Provisioning Endpoints ─────────── */

  // 110. GET /api/v1/fleet/autopilot/stats
  router.get('/api/v1/fleet/autopilot/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = autopilotEngine.getAutopilotStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_STATS_ERROR', message: err.message });
    }
  });

  // 111. GET /api/v1/fleet/autopilot/devices
  router.get('/api/v1/fleet/autopilot/devices', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const status = url.searchParams.get('status') || undefined;
    const groupTag = url.searchParams.get('group_tag') || undefined;
    const profileId = url.searchParams.get('profile_id') || undefined;
    const search = url.searchParams.get('search') || undefined;
    try {
      const db = getDb();
      const devices = autopilotEngine.getAutopilotDevices(db, { status, groupTag, profileId, search });
      sendJson(res, 200, { devices, total: devices.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_DEVICES_GET_ERROR', message: err.message });
    }
  });

  // 112. POST /api/v1/fleet/autopilot/devices
  router.post('/api/v1/fleet/autopilot/devices', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const device = autopilotEngine.registerAutopilotDevice(db, body);
      broadcastEvent('autopilot_device_registered', { device_id: device.id, serial_number: device.serial_number });
      sendJson(res, 201, device);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_DEVICE_REGISTER_ERROR', message: err.message });
    }
  });

  // 113. POST /api/v1/fleet/autopilot/devices/import-csv
  router.post('/api/v1/fleet/autopilot/devices/import-csv', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    const csvContent = body.csv_content || (typeof body === 'string' ? body : '');
    try {
      const db = getDb();
      const result = autopilotEngine.importAutopilotCsv(db, csvContent);
      broadcastEvent('autopilot_csv_imported', { imported: result.imported_count, updated: result.updated_count });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_CSV_IMPORT_ERROR', message: err.message });
    }
  });

  // 114. GET /api/v1/fleet/autopilot/devices/export-csv
  router.get('/api/v1/fleet/autopilot/devices/export-csv', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const filterStatus = url.searchParams.get('status') || undefined;
    const groupTag = url.searchParams.get('group_tag') || undefined;
    try {
      const db = getDb();
      const csvData = autopilotEngine.exportAutopilotCsv(db, { filterStatus, groupTag });
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="AutopilotDevices.csv"',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(csvData);
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_CSV_EXPORT_ERROR', message: err.message });
    }
  });

  // 115. GET /api/v1/fleet/autopilot/devices/:id
  router.get('/api/v1/fleet/autopilot/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const device = autopilotEngine.getAutopilotDevice(db, id);
      if (!device) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Autopilot device not found' });
        return;
      }
      sendJson(res, 200, device);
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_DEVICE_GET_ERROR', message: err.message });
    }
  });

  // 116. PATCH /api/v1/fleet/autopilot/devices/:id
  router.patch('/api/v1/fleet/autopilot/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const device = autopilotEngine.updateAutopilotDevice(db, id, body);
      broadcastEvent('autopilot_device_updated', { device_id: id, serial_number: device.serial_number });
      sendJson(res, 200, device);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_DEVICE_UPDATE_ERROR', message: err.message });
    }
  });

  // 117. DELETE /api/v1/fleet/autopilot/devices/:id
  router.delete('/api/v1/fleet/autopilot/devices/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = autopilotEngine.deleteAutopilotDevice(db, id);
      broadcastEvent('autopilot_device_deleted', { device_id: id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_DEVICE_DELETE_ERROR', message: err.message });
    }
  });

  // 118. POST /api/v1/fleet/autopilot/devices/:id/assign-profile
  router.post('/api/v1/fleet/autopilot/devices/:id/assign-profile', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const result = autopilotEngine.assignProfileToAutopilotDevice(db, id, body.profile_id);
      broadcastEvent('autopilot_profile_assigned', { device_id: id, profile_id: body.profile_id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_PROFILE_ASSIGN_ERROR', message: err.message });
    }
  });

  // 119. GET /api/v1/fleet/autopilot/devices/:id/events
  router.get('/api/v1/fleet/autopilot/devices/:id/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const events = autopilotEngine.getProvisioningEvents(db, id);
      sendJson(res, 200, { events, total: events.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_EVENTS_GET_ERROR', message: err.message });
    }
  });

  // 120. GET /api/v1/fleet/autopilot/profiles
  router.get('/api/v1/fleet/autopilot/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profiles = autopilotEngine.getAutopilotProfiles(db);
      sendJson(res, 200, { profiles, total: profiles.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_PROFILES_GET_ERROR', message: err.message });
    }
  });

  // 121. POST /api/v1/fleet/autopilot/profiles
  router.post('/api/v1/fleet/autopilot/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const profile = autopilotEngine.createAutopilotProfile(db, body);
      broadcastEvent('autopilot_profile_created', { profile_id: profile.id, name: profile.name });
      sendJson(res, 201, profile);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_PROFILE_CREATE_ERROR', message: err.message });
    }
  });

  // 122. GET /api/v1/fleet/autopilot/profiles/:id
  router.get('/api/v1/fleet/autopilot/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profile = autopilotEngine.getAutopilotProfile(db, id);
      if (!profile) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Autopilot profile not found' });
        return;
      }
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPILOT_PROFILE_GET_ERROR', message: err.message });
    }
  });

  // 123. PATCH /api/v1/fleet/autopilot/profiles/:id
  router.patch('/api/v1/fleet/autopilot/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const profile = autopilotEngine.updateAutopilotProfile(db, id, body);
      broadcastEvent('autopilot_profile_updated', { profile_id: id, name: profile.name });
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_PROFILE_UPDATE_ERROR', message: err.message });
    }
  });

  // 124. DELETE /api/v1/fleet/autopilot/profiles/:id
  router.delete('/api/v1/fleet/autopilot/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = autopilotEngine.deleteAutopilotProfile(db, id);
      broadcastEvent('autopilot_profile_deleted', { profile_id: id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'AUTOPILOT_PROFILE_DELETE_ERROR', message: err.message });
    }
  });

  // 125. GET /api/v1/fleet/autopilot/esp-policies
  router.get('/api/v1/fleet/autopilot/esp-policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = autopilotEngine.getEspPolicies(db);
      sendJson(res, 200, { esp_policies: policies, total: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'ESP_POLICIES_GET_ERROR', message: err.message });
    }
  });

  // 126. POST /api/v1/fleet/autopilot/esp-policies
  router.post('/api/v1/fleet/autopilot/esp-policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = autopilotEngine.createEspPolicy(db, body);
      broadcastEvent('esp_policy_created', { policy_id: policy.id, name: policy.name });
      sendJson(res, 201, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'ESP_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 127. GET /api/v1/fleet/autopilot/esp-policies/:id
  router.get('/api/v1/fleet/autopilot/esp-policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = autopilotEngine.getEspPolicy(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'ESP policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'ESP_POLICY_GET_ERROR', message: err.message });
    }
  });

  // 128. PATCH /api/v1/fleet/autopilot/esp-policies/:id
  router.patch('/api/v1/fleet/autopilot/esp-policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const policy = autopilotEngine.updateEspPolicy(db, id, body);
      broadcastEvent('esp_policy_updated', { policy_id: id, name: policy.name });
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'ESP_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 129. DELETE /api/v1/fleet/autopilot/esp-policies/:id
  router.delete('/api/v1/fleet/autopilot/esp-policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = autopilotEngine.deleteEspPolicy(db, id);
      broadcastEvent('esp_policy_deleted', { policy_id: id });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'ESP_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 130. GET /api/v1/fleet/devices/:id/autopilot
  router.get('/api/v1/fleet/devices/:id/autopilot', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const posture = autopilotEngine.getDeviceAutopilotPosture(db, id);
      if (!posture) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Device not found' });
        return;
      }
      sendJson(res, 200, posture);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_AUTOPILOT_POSTURE_ERROR', message: err.message });
    }
  });

  // 131. GET /api/v1/fleet/remote-actions/stats
  router.get('/api/v1/fleet/remote-actions/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = remoteActionEngine.getRemoteActionStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_ACTION_STATS_ERROR', message: err.message });
    }
  });

  // 132. GET /api/v1/fleet/remote-actions
  router.get('/api/v1/fleet/remote-actions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const limit = Number(req.query.limit || 100);
      const offset = Number(req.query.offset || 0);
      const { status, action_type, device_id } = req.query;
      const data = remoteActionEngine.getAllActions({
        status,
        actionType: action_type,
        deviceId: device_id,
        limit,
        offset
      });
      sendJson(res, 200, data);
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_ACTIONS_QUERY_ERROR', message: err.message });
    }
  });

  // 133. POST /api/v1/fleet/remote-actions
  router.post('/api/v1/fleet/remote-actions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const action = remoteActionEngine.queueRemoteAction({
        deviceId: body.device_id,
        actionType: body.action_type,
        parameters: body.parameters || {},
        initiatedBy: body.initiated_by || 'LocalPilot Administrator'
      });
      broadcastEvent('remote_action_dispatched', {
        action_id: action.id,
        device_id: action.device_id,
        action_type: action.action_type
      });
      sendJson(res, 201, action);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_ACTION_DISPATCH_ERROR', message: err.message });
    }
  });

  // 134. GET /api/v1/fleet/remote-actions/:id
  router.get('/api/v1/fleet/remote-actions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const action = remoteActionEngine.getRemoteAction(id);
      if (!action) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Remote action not found' });
        return;
      }
      sendJson(res, 200, action);
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_ACTION_FETCH_ERROR', message: err.message });
    }
  });

  // 135. POST /api/v1/fleet/remote-actions/:id/cancel
  router.post('/api/v1/fleet/remote-actions/:id/cancel', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const cancelled = remoteActionEngine.cancelRemoteAction(id);
      broadcastEvent('remote_action_cancelled', { action_id: id, device_id: cancelled.device_id });
      sendJson(res, 200, cancelled);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_ACTION_CANCEL_ERROR', message: err.message });
    }
  });

  // 136. GET /api/v1/fleet/devices/:id/remote-actions
  router.get('/api/v1/fleet/devices/:id/remote-actions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const limit = Number(req.query.limit || 50);
      const actions = remoteActionEngine.getDeviceActions(id, limit);
      sendJson(res, 200, { device_id: id, count: actions.length, actions });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_ACTIONS_ERROR', message: err.message });
    }
  });

  // 137. GET /api/v1/fleet/devices/:id/diagnostics
  router.get('/api/v1/fleet/devices/:id/diagnostics', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const bundles = remoteActionEngine.getDeviceDiagnosticsBundles(id);
      sendJson(res, 200, { device_id: id, count: bundles.length, bundles });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DIAGNOSTICS_ERROR', message: err.message });
    }
  });

  // 138. GET /api/v1/fleet/diagnostics/:id/download
  router.get('/api/v1/fleet/diagnostics/:id/download', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const { bundle, filePath } = remoteActionEngine.getDiagnosticsDownloadStream(id);
      const stat = fs.statSync(filePath);
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Length': stat.size,
        'Content-Disposition': `attachment; filename="${bundle.file_name}"`,
        'Access-Control-Allow-Origin': '*'
      });
      fs.createReadStream(filePath).pipe(res);
    } catch (err) {
      sendJson(res, 404, { error: 'DIAGNOSTICS_DOWNLOAD_ERROR', message: err.message });
    }
  });

  // 139. GET /api/v1/fleet/diagnostics/:id
  router.get('/api/v1/fleet/diagnostics/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const bundle = remoteActionEngine.getDiagnosticsBundle(id);
      if (!bundle) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Diagnostics bundle not found' });
        return;
      }
      sendJson(res, 200, bundle);
    } catch (err) {
      sendJson(res, 500, { error: 'DIAGNOSTICS_FETCH_ERROR', message: err.message });
    }
  });

  // 140. GET /api/v1/fleet/bulk-actions
  router.get('/api/v1/fleet/bulk-actions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const actions = remoteActionEngine.getBulkActions();
      sendJson(res, 200, { count: actions.length, bulk_actions: actions });
    } catch (err) {
      sendJson(res, 500, { error: 'BULK_ACTIONS_QUERY_ERROR', message: err.message });
    }
  });

  // 141. POST /api/v1/fleet/bulk-actions
  router.post('/api/v1/fleet/bulk-actions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const bulk = remoteActionEngine.createBulkAction({
        name: body.name,
        actionType: body.action_type,
        targetGroupId: body.target_group_id || 'grp-all',
        parameters: body.parameters || {},
        initiatedBy: body.initiated_by || 'LocalPilot Administrator'
      });
      broadcastEvent('bulk_action_dispatched', {
        bulk_id: bulk.id,
        action_type: bulk.action_type,
        total_devices: bulk.total_devices
      });
      sendJson(res, 201, bulk);
    } catch (err) {
      sendJson(res, 400, { error: 'BULK_ACTION_CREATE_ERROR', message: err.message });
    }
  });

  // 142. GET /api/v1/fleet/bulk-actions/:id
  router.get('/api/v1/fleet/bulk-actions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const bulk = remoteActionEngine.getBulkAction(id);
      if (!bulk) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Bulk action not found' });
        return;
      }
      sendJson(res, 200, bulk);
    } catch (err) {
      sendJson(res, 500, { error: 'BULK_ACTION_FETCH_ERROR', message: err.message });
    }
  });

  // 143. GET /api/v1/fleet/firewall/stats
  router.get('/api/v1/fleet/firewall/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = firewallEngine.getFleetFirewallStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_STATS_ERROR', message: err.message });
    }
  });

  // 144. GET /api/v1/fleet/firewall/rules
  router.get('/api/v1/fleet/firewall/rules', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const rules = firewallEngine.getRules(db, req.query || {});
      sendJson(res, 200, { count: rules.length, rules });
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_RULES_QUERY_ERROR', message: err.message });
    }
  });

  // 145. POST /api/v1/fleet/firewall/rules
  router.post('/api/v1/fleet/firewall/rules', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const body = req.body || {};
    try {
      const db = getDb();
      const created = firewallEngine.createRule(db, body);
      broadcastEvent('firewall_rule_created', { rule_id: created.id, name: created.name });
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'FIREWALL_RULE_CREATE_ERROR', message: err.message });
    }
  });

  // 146. GET /api/v1/fleet/firewall/rules/:id
  router.get('/api/v1/fleet/firewall/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const rule = firewallEngine.getRule(db, id);
      if (!rule) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Firewall rule not found' });
        return;
      }
      sendJson(res, 200, rule);
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_RULE_FETCH_ERROR', message: err.message });
    }
  });

  // 147. PATCH /api/v1/fleet/firewall/rules/:id
  router.patch('/api/v1/fleet/firewall/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const body = req.body || {};
    try {
      const db = getDb();
      const updated = firewallEngine.updateRule(db, id, body);
      if (!updated) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Firewall rule not found' });
        return;
      }
      broadcastEvent('firewall_rule_updated', { rule_id: id, name: updated.name });
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'FIREWALL_RULE_UPDATE_ERROR', message: err.message });
    }
  });

  // 148. DELETE /api/v1/fleet/firewall/rules/:id
  router.delete('/api/v1/fleet/firewall/rules/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = firewallEngine.deleteRule(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Firewall rule not found' });
        return;
      }
      broadcastEvent('firewall_rule_deleted', { rule_id: id });
      sendJson(res, 200, { success: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_RULE_DELETE_ERROR', message: err.message });
    }
  });

  // 149. GET /api/v1/fleet/firewall/ports
  router.get('/api/v1/fleet/firewall/ports', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const ports = firewallEngine.getFleetListeningPorts(db, req.query || {});
      sendJson(res, 200, { count: ports.length, ports });
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_PORTS_QUERY_ERROR', message: err.message });
    }
  });

  // 150. GET /api/v1/fleet/devices/:id/firewall
  router.get('/api/v1/fleet/devices/:id/firewall', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = firewallEngine.getDeviceFirewallStatus(db, id);
      const effectiveRules = firewallEngine.getEffectiveRulesForDevice(db, id);
      sendJson(res, 200, {
        device_id: id,
        status: status || { compliance_status: 'UNKNOWN', active_rules_count: 0 },
        effective_rules: effectiveRules
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_FIREWALL_STATUS_ERROR', message: err.message });
    }
  });

  // 151. GET /api/v1/fleet/devices/:id/listening-ports
  router.get('/api/v1/fleet/devices/:id/listening-ports', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const ports = firewallEngine.getDeviceListeningPorts(db, id);
      sendJson(res, 200, { device_id: id, count: ports.length, ports });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_LISTENING_PORTS_ERROR', message: err.message });
    }
  });

  // 152. POST /api/v1/fleet/devices/:id/firewall/enforce
  router.post('/api/v1/fleet/devices/:id/firewall/enforce', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const action = remoteActionEngine.queueRemoteAction({
        deviceId: id,
        actionType: 'SYNC_MDM',
        parameters: { trigger: 'FIREWALL_ENFORCE' },
        initiatedBy: 'Fleet Administrator'
      });
      broadcastEvent('firewall_enforce_dispatched', { device_id: id, action_id: action.id });
      sendJson(res, 202, { success: true, message: 'Firewall policy enforcement dispatched', action });
    } catch (err) {
      sendJson(res, 400, { error: 'FIREWALL_ENFORCE_DISPATCH_ERROR', message: err.message });
    }
  });

  // 153. GET /api/v1/fleet/scripts/stats
  router.get('/api/v1/fleet/scripts/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = scriptsEngine.getScriptStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPTS_STATS_ERROR', message: err.message });
    }
  });

  // 154. GET /api/v1/fleet/scripts
  router.get('/api/v1/fleet/scripts', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const search = url.searchParams.get('search') || undefined;
    const target_group_id = url.searchParams.get('target_group_id') || undefined;
    const enabled = url.searchParams.get('enabled') || undefined;
    const run_frequency = url.searchParams.get('run_frequency') || undefined;
    const run_as_account = url.searchParams.get('run_as_account') || undefined;
    try {
      const db = getDb();
      const scripts = scriptsEngine.getScripts(db, { search, target_group_id, enabled, run_frequency, run_as_account });
      sendJson(res, 200, { scripts, total: scripts.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPTS_GET_ERROR', message: err.message });
    }
  });

  // 155. POST /api/v1/fleet/scripts
  router.post('/api/v1/fleet/scripts', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const script = scriptsEngine.createScript(db, req.body || {});
      sendJson(res, 201, script);
    } catch (err) {
      sendJson(res, 400, { error: 'SCRIPT_CREATE_ERROR', message: err.message });
    }
  });

  // 156. GET /api/v1/fleet/scripts/runs
  router.get('/api/v1/fleet/scripts/runs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const device_id = url.searchParams.get('device_id') || undefined;
    const script_id = url.searchParams.get('script_id') || undefined;
    const status = url.searchParams.get('status') || undefined;
    const limit = url.searchParams.get('limit') || 50;
    const offset = url.searchParams.get('offset') || 0;
    try {
      const db = getDb();
      const result = scriptsEngine.getScriptRuns(db, { device_id, script_id, status, limit, offset });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPT_RUNS_GET_ERROR', message: err.message });
    }
  });

  // 157. GET /api/v1/fleet/scripts/:id
  router.get('/api/v1/fleet/scripts/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const script = scriptsEngine.getScript(db, id);
      if (!script) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Script not found' });
        return;
      }
      sendJson(res, 200, script);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPT_GET_ERROR', message: err.message });
    }
  });

  // 158. PATCH /api/v1/fleet/scripts/:id
  router.patch('/api/v1/fleet/scripts/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = scriptsEngine.updateScript(db, id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'SCRIPT_UPDATE_ERROR', message: err.message });
    }
  });

  // 159. DELETE /api/v1/fleet/scripts/:id
  router.delete('/api/v1/fleet/scripts/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = scriptsEngine.deleteScript(db, id);
      sendJson(res, 200, result);
    } catch (err) {
      const status = err.message && err.message.toLowerCase().includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'SCRIPT_DELETE_ERROR', message: err.message });
    }
  });

  // 160. POST /api/v1/fleet/scripts/:id/run
  router.post('/api/v1/fleet/scripts/:id/run', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { device_id, initiated_by } = req.body || {};
    if (!device_id) {
      sendJson(res, 400, { error: 'BAD_REQUEST', message: 'device_id is required' });
      return;
    }
    try {
      const db = getDb();
      const result = scriptsEngine.dispatchScriptRun(db, { scriptId: id, deviceId: device_id, initiatedBy: initiated_by });
      sendJson(res, 202, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SCRIPT_DISPATCH_ERROR', message: err.message });
    }
  });

  // 161. GET /api/v1/fleet/devices/:id/scripts
  router.get('/api/v1/fleet/devices/:id/scripts', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(id);
      if (!device) {
        sendJson(res, 404, { error: 'DEVICE_NOT_FOUND', message: 'Device not found' });
        return;
      }
      const status = scriptsEngine.getDeviceScriptStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_SCRIPTS_ERROR', message: err.message });
    }
  });

  // 162. POST /api/v1/fleet/devices/:id/scripts/:scriptId/run
  router.post('/api/v1/fleet/devices/:id/scripts/:scriptId/run', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id, scriptId } = req.params;
    try {
      const db = getDb();
      const result = scriptsEngine.dispatchScriptRun(db, { scriptId, deviceId: id, initiatedBy: req.body?.initiated_by });
      sendJson(res, 202, result);
    } catch (err) {
      sendJson(res, 400, { error: 'DEVICE_SCRIPT_RUN_ERROR', message: err.message });
    }
  });

  // 163. GET /api/v1/fleet/asr/stats
  router.get('/api/v1/fleet/asr/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      sendJson(res, 200, asrEngine.getASRPolicyStats(db));
    } catch (err) {
      sendJson(res, 500, { error: 'ASR_STATS_ERROR', message: err.message });
    }
  });

  // 164. GET /api/v1/fleet/asr/policies
  router.get('/api/v1/fleet/asr/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = asrEngine.getASRPolicies(db, req.query || {});
      sendJson(res, 200, { policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'ASR_POLICIES_ERROR', message: err.message });
    }
  });

  // 165. POST /api/v1/fleet/asr/policies
  router.post('/api/v1/fleet/asr/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policy = asrEngine.createASRPolicy(db, req.body || {});
      sendJson(res, 201, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'ASR_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 166. GET /api/v1/fleet/asr/policies/:id
  router.get('/api/v1/fleet/asr/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policy = asrEngine.getASRPolicy(db, req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: 'ASR_POLICY_NOT_FOUND', message: 'ASR policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'ASR_POLICY_GET_ERROR', message: err.message });
    }
  });

  // 167. PATCH /api/v1/fleet/asr/policies/:id
  router.patch('/api/v1/fleet/asr/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policy = asrEngine.updateASRPolicy(db, req.params.id, req.body || {});
      sendJson(res, 200, policy);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'ASR_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 168. DELETE /api/v1/fleet/asr/policies/:id
  router.delete('/api/v1/fleet/asr/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const result = asrEngine.deleteASRPolicy(db, req.params.id);
      sendJson(res, 200, result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'ASR_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 169. GET /api/v1/fleet/asr/events
  router.get('/api/v1/fleet/asr/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const result = asrEngine.getASREvents(db, req.query || {});
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 500, { error: 'ASR_EVENTS_ERROR', message: err.message });
    }
  });

  // 170. GET /api/v1/fleet/devices/:id/asr
  router.get('/api/v1/fleet/devices/:id/asr', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(id);
      if (!device) {
        sendJson(res, 404, { error: 'DEVICE_NOT_FOUND', message: 'Device not found' });
        return;
      }
      const status = asrEngine.getDeviceASRStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_ASR_ERROR', message: err.message });
    }
  });

  // 171. GET /api/v1/fleet/analytics/scores
  router.get('/api/v1/fleet/analytics/scores', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const scores = analyticsEngine.getFleetAnalyticsScores(db);
      sendJson(res, 200, scores);
    } catch (err) {
      sendJson(res, 500, { error: 'ANALYTICS_SCORES_ERROR', message: err.message });
    }
  });

  // 172. GET /api/v1/fleet/analytics/top-crashes
  router.get('/api/v1/fleet/analytics/top-crashes', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const crashes = analyticsEngine.getTopCrashingApps(db, req.query?.limit || 10);
      sendJson(res, 200, { top_crashes: crashes });
    } catch (err) {
      sendJson(res, 500, { error: 'ANALYTICS_CRASHES_ERROR', message: err.message });
    }
  });

  // 173. GET /api/v1/fleet/analytics/startup-performance
  router.get('/api/v1/fleet/analytics/startup-performance', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const startup = analyticsEngine.getStartupPerformanceSummary(db);
      sendJson(res, 200, startup);
    } catch (err) {
      sendJson(res, 500, { error: 'STARTUP_PERF_ERROR', message: err.message });
    }
  });

  // 174. GET /api/v1/fleet/reports
  router.get('/api/v1/fleet/reports', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const reports = analyticsEngine.getExecutiveReports(db, req.query?.limit || 20);
      sendJson(res, 200, { reports });
    } catch (err) {
      sendJson(res, 500, { error: 'REPORTS_LIST_ERROR', message: err.message });
    }
  });

  // 175. POST /api/v1/fleet/reports/generate
  router.post('/api/v1/fleet/reports/generate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { report_type, created_by } = req.body || {};
    try {
      const db = getDb();
      const report = analyticsEngine.generateExecutiveReport(db, report_type || 'FLEET_HEALTH', created_by || 'LocalPilot Administrator');
      sendJson(res, 201, report);
    } catch (err) {
      sendJson(res, 400, { error: 'REPORT_GENERATE_ERROR', message: err.message });
    }
  });

  // 176. GET /api/v1/fleet/reports/:id
  router.get('/api/v1/fleet/reports/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const row = db.prepare('SELECT * FROM executive_reports WHERE id = ?').get(id);
      if (!row) {
        sendJson(res, 404, { error: 'REPORT_NOT_FOUND', message: 'Report not found' });
        return;
      }
      sendJson(res, 200, {
        ...row,
        parameters: JSON.parse(row.parameters_json || '{}'),
        summary: JSON.parse(row.summary_json || '{}')
      });
    } catch (err) {
      sendJson(res, 500, { error: 'REPORT_FETCH_ERROR', message: err.message });
    }
  });

  // 177. GET /api/v1/fleet/devices/:id/analytics
  router.get('/api/v1/fleet/devices/:id/analytics', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const result = analyticsEngine.getDeviceAnalytics(db, id);
      sendJson(res, 200, result);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 500;
      sendJson(res, status, { error: 'DEVICE_ANALYTICS_ERROR', message: err.message });
    }
  });

  // 178. GET /api/v1/fleet/messages/stats
  router.get('/api/v1/fleet/messages/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = messagesEngine.getMessageStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'MESSAGE_STATS_ERROR', message: err.message });
    }
  });

  // 179. GET /api/v1/fleet/messages
  router.get('/api/v1/fleet/messages', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const messages = messagesEngine.getMessages(db, req.query || {});
      sendJson(res, 200, { messages });
    } catch (err) {
      sendJson(res, 500, { error: 'MESSAGES_LIST_ERROR', message: err.message });
    }
  });

  // 180. POST /api/v1/fleet/messages
  router.post('/api/v1/fleet/messages', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = messagesEngine.createMessage(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'MESSAGE_CREATE_ERROR', message: err.message });
    }
  });

  // 181. GET /api/v1/fleet/messages/deliveries
  router.get('/api/v1/fleet/messages/deliveries', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const deliveries = messagesEngine.getMessageDeliveries(db, req.query || {});
      sendJson(res, 200, { deliveries });
    } catch (err) {
      sendJson(res, 500, { error: 'DELIVERIES_LIST_ERROR', message: err.message });
    }
  });

  // 182. GET /api/v1/fleet/messages/:id
  router.get('/api/v1/fleet/messages/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const msg = messagesEngine.getMessage(db, id);
      if (!msg) {
        sendJson(res, 404, { error: 'MESSAGE_NOT_FOUND', message: 'Organizational message not found' });
        return;
      }
      sendJson(res, 200, msg);
    } catch (err) {
      sendJson(res, 500, { error: 'MESSAGE_FETCH_ERROR', message: err.message });
    }
  });

  // 183. PATCH /api/v1/fleet/messages/:id
  router.patch('/api/v1/fleet/messages/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = messagesEngine.updateMessage(db, id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'MESSAGE_UPDATE_ERROR', message: err.message });
    }
  });

  // 184. DELETE /api/v1/fleet/messages/:id
  router.delete('/api/v1/fleet/messages/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = messagesEngine.deleteMessage(db, id);
      sendJson(res, 200, deleted);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 500;
      sendJson(res, status, { error: 'MESSAGE_DELETE_ERROR', message: err.message });
    }
  });

  // 185. POST /api/v1/fleet/devices/:id/toast (Instant urgent toast)
  router.post('/api/v1/fleet/devices/:id/toast', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { title, message, theme, action_url, action_label } = req.body || {};
    try {
      const db = getDb();
      const result = messagesEngine.dispatchUrgentToast(db, {
        deviceId: id,
        title,
        messageBody: message,
        theme,
        actionUrl: action_url,
        actionLabel: action_label
      });
      sendJson(res, 202, result);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'TOAST_DISPATCH_ERROR', message: err.message });
    }
  });

  // 186. GET /api/v1/fleet/certificates/stats
  router.get('/api/v1/fleet/certificates/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = certificateEngine.getCertificateStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'CERTIFICATE_STATS_ERROR', message: err.message });
    }
  });

  // 187. GET /api/v1/fleet/certificates/profiles
  router.get('/api/v1/fleet/certificates/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profiles = certificateEngine.getCertificateProfiles(db, req.query || {});
      sendJson(res, 200, { profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'CERTIFICATE_PROFILES_ERROR', message: err.message });
    }
  });

  // 188. POST /api/v1/fleet/certificates/profiles
  router.post('/api/v1/fleet/certificates/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = certificateEngine.createCertificateProfile(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'CERTIFICATE_PROFILE_CREATE_ERROR', message: err.message });
    }
  });

  // 189. GET /api/v1/fleet/certificates/inventory
  router.get('/api/v1/fleet/certificates/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = certificateEngine.getCertificateInventory(db, req.query || {});
      sendJson(res, 200, { certificates: inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'CERTIFICATE_INVENTORY_ERROR', message: err.message });
    }
  });

  // 190. GET /api/v1/fleet/certificates/profiles/:id
  router.get('/api/v1/fleet/certificates/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profile = certificateEngine.getCertificateProfile(db, id);
      if (!profile) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Certificate profile not found' });
        return;
      }
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 500, { error: 'CERTIFICATE_PROFILE_FETCH_ERROR', message: err.message });
    }
  });

  // 191. PATCH /api/v1/fleet/certificates/profiles/:id
  router.patch('/api/v1/fleet/certificates/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = certificateEngine.updateCertificateProfile(db, id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 400;
      sendJson(res, status, { error: 'CERTIFICATE_PROFILE_UPDATE_ERROR', message: err.message });
    }
  });

  // 192. DELETE /api/v1/fleet/certificates/profiles/:id
  router.delete('/api/v1/fleet/certificates/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = certificateEngine.deleteCertificateProfile(db, id);
      sendJson(res, 200, deleted);
    } catch (err) {
      const status = err.message && err.message.includes('not found') ? 404 : 500;
      sendJson(res, status, { error: 'CERTIFICATE_PROFILE_DELETE_ERROR', message: err.message });
    }
  });

  // 193. GET /api/v1/fleet/devices/:id/certificates
  router.get('/api/v1/fleet/devices/:id/certificates', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const certs = certificateEngine.getDeviceCertificates(db, id, req.query || {});
      sendJson(res, 200, { device_id: id, certificates: certs });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_CERTIFICATES_FETCH_ERROR', message: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // WI-FI & VPN CONFIGURATION PROFILES & NETWORK POSTURE (194–201)
  // ══════════════════════════════════════════════════════════════════

  // 194. GET /api/v1/fleet/networks/stats
  router.get('/api/v1/fleet/networks/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = networkEngine.getNetworkStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_STATS_ERROR', message: err.message });
    }
  });

  // 195. GET /api/v1/fleet/networks/profiles
  router.get('/api/v1/fleet/networks/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profiles = networkEngine.getAllProfiles(db);
      sendJson(res, 200, { profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 196. POST /api/v1/fleet/networks/profiles
  router.post('/api/v1/fleet/networks/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = networkEngine.createProfile(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'NETWORK_PROFILE_CREATE_ERROR', message: err.message });
    }
  });

  // 197. GET /api/v1/fleet/networks/inventory
  router.get('/api/v1/fleet/networks/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = networkEngine.getFleetNetworkInventory(db, req.query || {});
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_INVENTORY_ERROR', message: err.message });
    }
  });

  // 198. GET /api/v1/fleet/networks/profiles/:id
  router.get('/api/v1/fleet/networks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profile = networkEngine.getProfileById(db, id);
      if (!profile) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Network profile not found' });
        return;
      }
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_PROFILE_FETCH_ERROR', message: err.message });
    }
  });

  // 199. PATCH /api/v1/fleet/networks/profiles/:id
  router.patch('/api/v1/fleet/networks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = networkEngine.updateProfile(db, id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Network profile not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'NETWORK_PROFILE_UPDATE_ERROR', message: err.message });
    }
  });

  // 200. DELETE /api/v1/fleet/networks/profiles/:id
  router.delete('/api/v1/fleet/networks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = networkEngine.deleteProfile(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Network profile not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'NETWORK_PROFILE_DELETE_ERROR', message: err.message });
    }
  });

  // 201. GET /api/v1/fleet/devices/:id/network
  router.get('/api/v1/fleet/devices/:id/network', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const posture = networkEngine.getDeviceNetworkPosture(db, id);
      const effectiveProfiles = networkEngine.getEffectiveProfilesForDevice(db, id);
      sendJson(res, 200, {
        device_id: id,
        posture: posture || null,
        assigned_profiles: effectiveProfiles
      });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_NETWORK_FETCH_ERROR', message: err.message });
    }
  });

  /* ── 22. Kiosk Mode & Multi-App Assigned Access Endpoints ─────── */

  // 202. GET /api/v1/fleet/kiosks/stats
  router.get('/api/v1/fleet/kiosks/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = kioskEngine.getKioskStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_STATS_ERROR', message: err.message });
    }
  });

  // 203. GET /api/v1/fleet/kiosks/profiles
  router.get('/api/v1/fleet/kiosks/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const profiles = kioskEngine.getAllProfiles(db);
      sendJson(res, 200, { profiles });
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_PROFILES_FETCH_ERROR', message: err.message });
    }
  });

  // 204. POST /api/v1/fleet/kiosks/profiles
  router.post('/api/v1/fleet/kiosks/profiles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = kioskEngine.createProfile(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'KIOSK_PROFILE_CREATE_ERROR', message: err.message });
    }
  });

  // 205. GET /api/v1/fleet/kiosks/inventory
  router.get('/api/v1/fleet/kiosks/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = kioskEngine.getFleetKioskInventory(db, req.query || {});
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_INVENTORY_ERROR', message: err.message });
    }
  });

  // 206. GET /api/v1/fleet/kiosks/profiles/:id
  router.get('/api/v1/fleet/kiosks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const profile = kioskEngine.getProfileById(db, id);
      if (!profile) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Kiosk profile not found' });
        return;
      }
      sendJson(res, 200, profile);
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_PROFILE_FETCH_ERROR', message: err.message });
    }
  });

  // 207. PATCH /api/v1/fleet/kiosks/profiles/:id
  router.patch('/api/v1/fleet/kiosks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = kioskEngine.updateProfile(db, id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Kiosk profile not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'KIOSK_PROFILE_UPDATE_ERROR', message: err.message });
    }
  });

  // 208. DELETE /api/v1/fleet/kiosks/profiles/:id
  router.delete('/api/v1/fleet/kiosks/profiles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = kioskEngine.deleteProfile(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'PROFILE_NOT_FOUND', message: 'Kiosk profile not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'KIOSK_PROFILE_DELETE_ERROR', message: err.message });
    }
  });

  // 209. GET /api/v1/fleet/devices/:id/kiosk
  router.get('/api/v1/fleet/devices/:id/kiosk', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = kioskEngine.getDeviceKioskStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_KIOSK_FETCH_ERROR', message: err.message });
    }
  });

  /* ── 23. Removable Storage Access Control & USB Device Governance ── */

  // 210. GET /api/v1/fleet/storage-access/stats
  router.get('/api/v1/fleet/storage-access/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = storageAccessEngine.getStorageStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_STATS_ERROR', message: err.message });
    }
  });

  // 211. GET /api/v1/fleet/storage-access/policies
  router.get('/api/v1/fleet/storage-access/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = storageAccessEngine.getAllPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 212. POST /api/v1/fleet/storage-access/policies
  router.post('/api/v1/fleet/storage-access/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = storageAccessEngine.createPolicy(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'STORAGE_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 213. GET /api/v1/fleet/storage-access/inventory
  router.get('/api/v1/fleet/storage-access/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = storageAccessEngine.getFleetStorageInventory(db, req.query || {});
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_INVENTORY_ERROR', message: err.message });
    }
  });

  // 214. GET /api/v1/fleet/storage-access/events
  router.get('/api/v1/fleet/storage-access/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const events = storageAccessEngine.getStorageEvents(db, req.query || {});
      sendJson(res, 200, { events });
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_EVENTS_ERROR', message: err.message });
    }
  });

  // 215. GET /api/v1/fleet/storage-access/policies/:id
  router.get('/api/v1/fleet/storage-access/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = storageAccessEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Storage policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 216. PATCH /api/v1/fleet/storage-access/policies/:id
  router.patch('/api/v1/fleet/storage-access/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = storageAccessEngine.updatePolicy(db, id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Storage policy not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'STORAGE_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 217. DELETE /api/v1/fleet/storage-access/policies/:id
  router.delete('/api/v1/fleet/storage-access/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = storageAccessEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Storage policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'STORAGE_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 218. GET /api/v1/fleet/devices/:id/storage-access
  router.get('/api/v1/fleet/devices/:id/storage-access', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = storageAccessEngine.getDeviceStorageStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_STORAGE_FETCH_ERROR', message: err.message });
    }
  });

  // 219. GET /api/v1/fleet/delivery-optimization/stats
  router.get('/api/v1/fleet/delivery-optimization/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = deliveryOptimizationEngine.getDOStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'DO_STATS_FETCH_ERROR', message: err.message });
    }
  });

  // 220. GET /api/v1/fleet/delivery-optimization/policies
  router.get('/api/v1/fleet/delivery-optimization/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = deliveryOptimizationEngine.getAllPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 221. POST /api/v1/fleet/delivery-optimization/policies
  router.post('/api/v1/fleet/delivery-optimization/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = deliveryOptimizationEngine.createPolicy(db, req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'DO_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 222. GET /api/v1/fleet/delivery-optimization/inventory
  router.get('/api/v1/fleet/delivery-optimization/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const download_mode = url.searchParams.get('download_mode') || undefined;
    const q = url.searchParams.get('q') || undefined;
    const limit = url.searchParams.get('limit') || undefined;
    try {
      const db = getDb();
      const inventory = deliveryOptimizationEngine.getDOInventory(db, { download_mode, q, limit });
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_INVENTORY_FETCH_ERROR', message: err.message });
    }
  });

  // 223. GET /api/v1/fleet/delivery-optimization/content-log
  router.get('/api/v1/fleet/delivery-optimization/content-log', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const device_id = url.searchParams.get('device_id') || undefined;
    const content_type = url.searchParams.get('content_type') || undefined;
    const limit = url.searchParams.get('limit') || undefined;
    try {
      const db = getDb();
      const content_log = deliveryOptimizationEngine.getContentLog(db, { device_id, content_type, limit });
      sendJson(res, 200, { content_log });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_CONTENT_LOG_FETCH_ERROR', message: err.message });
    }
  });

  // 224. GET /api/v1/fleet/delivery-optimization/policies/:id
  router.get('/api/v1/fleet/delivery-optimization/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = deliveryOptimizationEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Delivery Optimization policy not found' });
        return;
      }
      sendJson(res, 200, { policy, powershell_script: policy.powershell_script });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 225. PATCH /api/v1/fleet/delivery-optimization/policies/:id
  router.patch('/api/v1/fleet/delivery-optimization/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = deliveryOptimizationEngine.updatePolicy(db, id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Delivery Optimization policy not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'DO_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 226. DELETE /api/v1/fleet/delivery-optimization/policies/:id
  router.delete('/api/v1/fleet/delivery-optimization/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = deliveryOptimizationEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Delivery Optimization policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'DO_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 227. GET /api/v1/fleet/devices/:id/delivery-optimization
  router.get('/api/v1/fleet/devices/:id/delivery-optimization', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = deliveryOptimizationEngine.getDeviceDOStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DO_FETCH_ERROR', message: err.message });
    }
  });

  // 228. GET /api/v1/fleet/dfci/stats
  router.get('/api/v1/fleet/dfci/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = dfciEngine.getDfciStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_STATS_FETCH_ERROR', message: err.message });
    }
  });

  // 229. GET /api/v1/fleet/dfci/policies
  router.get('/api/v1/fleet/dfci/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = dfciEngine.getAllPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 230. POST /api/v1/fleet/dfci/policies
  router.post('/api/v1/fleet/dfci/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policy = dfciEngine.createPolicy(db, req.body || {});
      sendJson(res, 201, policy);
    } catch (err) {
      sendJson(res, 400, { error: 'DFCI_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 231. GET /api/v1/fleet/dfci/inventory
  router.get('/api/v1/fleet/dfci/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const compliance_status = url.searchParams.get('compliance_status') || undefined;
    const search = url.searchParams.get('search') || undefined;
    try {
      const db = getDb();
      const inventory = dfciEngine.getDfciInventory(db, { compliance_status, search });
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_INVENTORY_FETCH_ERROR', message: err.message });
    }
  });

  // 232. GET /api/v1/fleet/dfci/audit-log
  router.get('/api/v1/fleet/dfci/audit-log', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const url = new URL(req.url, 'http://localhost');
    const device_id = url.searchParams.get('device_id') || undefined;
    const event_type = url.searchParams.get('event_type') || undefined;
    try {
      const db = getDb();
      const logs = dfciEngine.getDfciAuditLog(db, { device_id, event_type });
      sendJson(res, 200, { logs });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_AUDIT_LOG_FETCH_ERROR', message: err.message });
    }
  });

  // 233. GET /api/v1/fleet/dfci/policies/:id
  router.get('/api/v1/fleet/dfci/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = dfciEngine.getPolicyById(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DFCI policy not found' });
        return;
      }
      sendJson(res, 200, { policy, powershell_script: policy.powershell_script });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 234. PATCH /api/v1/fleet/dfci/policies/:id
  router.patch('/api/v1/fleet/dfci/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = dfciEngine.updatePolicy(db, id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DFCI policy not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'DFCI_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 235. DELETE /api/v1/fleet/dfci/policies/:id
  router.delete('/api/v1/fleet/dfci/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = dfciEngine.deletePolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DFCI policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'DFCI_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 236. GET /api/v1/fleet/devices/:id/dfci
  router.get('/api/v1/fleet/devices/:id/dfci', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = dfciEngine.getDeviceDfciStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DFCI_FETCH_ERROR', message: err.message });
    }
  });

  // 237. GET /api/v1/fleet/wip/stats
  router.get('/api/v1/fleet/wip/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = wipEngine.getWipStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_STATS_ERROR', message: err.message });
    }
  });

  // 238. GET /api/v1/fleet/wip/policies
  router.get('/api/v1/fleet/wip/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = wipEngine.getWipPolicies(db, req.query);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_POLICIES_ERROR', message: err.message });
    }
  });

  // 239. POST /api/v1/fleet/wip/policies
  router.post('/api/v1/fleet/wip/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = wipEngine.createWipPolicy(db, req.body);
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'WIP_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 240. GET /api/v1/fleet/wip/inventory
  router.get('/api/v1/fleet/wip/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = wipEngine.getWipInventory(db, req.query);
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_INVENTORY_ERROR', message: err.message });
    }
  });

  // 241. GET /api/v1/fleet/wip/audit-log
  router.get('/api/v1/fleet/wip/audit-log', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const logs = wipEngine.getWipAuditLog(db, req.query);
      sendJson(res, 200, { logs });
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_AUDIT_LOG_ERROR', message: err.message });
    }
  });

  // 242. GET /api/v1/fleet/wip/policies/:id
  router.get('/api/v1/fleet/wip/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = wipEngine.getWipPolicy(db, id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'WIP policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 243. PATCH /api/v1/fleet/wip/policies/:id
  router.patch('/api/v1/fleet/wip/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = wipEngine.updateWipPolicy(db, id, req.body);
      if (!updated) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'WIP policy not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'WIP_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 244. DELETE /api/v1/fleet/wip/policies/:id
  router.delete('/api/v1/fleet/wip/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = wipEngine.deleteWipPolicy(db, id);
      if (!deleted) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'WIP policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, id });
    } catch (err) {
      sendJson(res, 500, { error: 'WIP_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 245. GET /api/v1/fleet/devices/:id/wip
  router.get('/api/v1/fleet/devices/:id/wip', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = wipEngine.getDeviceWipStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_WIP_FETCH_ERROR', message: err.message });
    }
  });

  // ── Windows Hello for Business (WHfB) & FIDO2 Routes (246–254) ──
  // 246. GET /api/v1/fleet/whfb/stats
  router.get('/api/v1/fleet/whfb/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = whfbEngine.getWhfbStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_STATS_ERROR', message: err.message });
    }
  });

  // 247. GET /api/v1/fleet/whfb/policies
  router.get('/api/v1/fleet/whfb/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = whfbEngine.getWhfbPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 248. POST /api/v1/fleet/whfb/policies
  router.post('/api/v1/fleet/whfb/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = whfbEngine.createWhfbPolicy(db, req.body);
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'WHFB_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 249. GET /api/v1/fleet/whfb/inventory
  router.get('/api/v1/fleet/whfb/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const inventory = whfbEngine.getWhfbInventory(db, req.query);
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_INVENTORY_ERROR', message: err.message });
    }
  });

  // 250. GET /api/v1/fleet/whfb/audit-log
  router.get('/api/v1/fleet/whfb/audit-log', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const logs = whfbEngine.getWhfbAuditLog(db, Number(req.query.limit) || 100);
      sendJson(res, 200, { audit_log: logs });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_AUDIT_LOG_ERROR', message: err.message });
    }
  });

  // 251. GET /api/v1/fleet/whfb/policies/:id
  router.get('/api/v1/fleet/whfb/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = whfbEngine.getWhfbPolicy(db, id);
      if (!policy) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `WHfB Policy '${id}' does not exist` });
      }
      const script = whfbEngine.generateWhfbRegistryScript(policy);
      sendJson(res, 200, { policy, script });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 252. PATCH /api/v1/fleet/whfb/policies/:id
  router.patch('/api/v1/fleet/whfb/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = whfbEngine.updateWhfbPolicy(db, id, req.body);
      if (!updated) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `WHfB Policy '${id}' does not exist` });
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'WHFB_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 253. DELETE /api/v1/fleet/whfb/policies/:id
  router.delete('/api/v1/fleet/whfb/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = whfbEngine.deleteWhfbPolicy(db, id);
      if (!deleted) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `WHfB Policy '${id}' does not exist` });
      }
      sendJson(res, 200, { ok: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'WHFB_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 254. GET /api/v1/fleet/devices/:id/whfb
  router.get('/api/v1/fleet/devices/:id/whfb', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const status = whfbEngine.getDeviceWhfbStatus(db, id);
      sendJson(res, 200, status);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_WHFB_FETCH_ERROR', message: err.message });
    }
  });

  // ── Windows Driver & Firmware Updates (WUfB) Routes (255–264) ──
  // 255. GET /api/v1/fleet/drivers/stats
  router.get('/api/v1/fleet/drivers/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = driverUpdateEngine.getDriverStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_STATS_ERROR', message: err.message });
    }
  });

  // 256. GET /api/v1/fleet/drivers/policies
  router.get('/api/v1/fleet/drivers/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const policies = driverUpdateEngine.getDriverPolicies(db);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 257. POST /api/v1/fleet/drivers/policies
  router.post('/api/v1/fleet/drivers/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const created = driverUpdateEngine.createDriverPolicy(db, req.body);
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'DRIVER_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 258. GET /api/v1/fleet/drivers/policies/:id
  router.get('/api/v1/fleet/drivers/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const policy = driverUpdateEngine.getDriverPolicy(db, id);
      if (!policy) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `Driver Policy '${id}' does not exist` });
      }
      const script = driverUpdateEngine.generateDriverRegistryScript(policy);
      sendJson(res, 200, { policy, script });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 259. PATCH /api/v1/fleet/drivers/policies/:id
  router.patch('/api/v1/fleet/drivers/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const updated = driverUpdateEngine.updateDriverPolicy(db, id, req.body);
      if (!updated) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `Driver Policy '${id}' does not exist` });
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'DRIVER_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 260. DELETE /api/v1/fleet/drivers/policies/:id
  router.delete('/api/v1/fleet/drivers/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const deleted = driverUpdateEngine.deleteDriverPolicy(db, id);
      if (!deleted) {
        return sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: `Driver Policy '${id}' does not exist` });
      }
      sendJson(res, 200, { ok: true, deleted_id: id });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 261. GET /api/v1/fleet/drivers/catalog
  router.get('/api/v1/fleet/drivers/catalog', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const catalog = driverUpdateEngine.getDriverCatalog(db, req.query);
      sendJson(res, 200, { catalog });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_CATALOG_FETCH_ERROR', message: err.message });
    }
  });

  // 262. PATCH /api/v1/fleet/drivers/catalog/:id/approval
  router.patch('/api/v1/fleet/drivers/catalog/:id/approval', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { status, approved_by } = req.body || {};
    try {
      const db = getDb();
      const updated = driverUpdateEngine.setDriverApprovalStatus(db, id, status, approved_by);
      if (!updated) {
        return sendJson(res, 404, { error: 'DRIVER_NOT_FOUND', message: `Driver package '${id}' does not exist` });
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'DRIVER_APPROVAL_ERROR', message: err.message });
    }
  });

  // 263. GET /api/v1/fleet/drivers/inventory
  router.get('/api/v1/fleet/drivers/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const overview = driverUpdateEngine.getDriverInventoryOverview(db);
      sendJson(res, 200, { inventory: overview });
    } catch (err) {
      sendJson(res, 500, { error: 'DRIVER_INVENTORY_FETCH_ERROR', message: err.message });
    }
  });

  // 264. GET /api/v1/fleet/devices/:id/drivers
  router.get('/api/v1/fleet/devices/:id/drivers', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const db = getDb();
      const data = driverUpdateEngine.getDeviceDrivers(db, id);
      sendJson(res, 200, data);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_DRIVERS_FETCH_ERROR', message: err.message });
    }
  });

  // ── Remote Help & Unattended Assistance Fleet Routes (265–278) ──
  // 265. GET /api/v1/fleet/remote-help/stats
  router.get('/api/v1/fleet/remote-help/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = remoteHelpEngine.getRemoteHelpStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_HELP_STATS_ERROR', message: err.message });
    }
  });

  // 266. GET /api/v1/fleet/remote-help/sessions
  router.get('/api/v1/fleet/remote-help/sessions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const sessions = remoteHelpEngine.getSessions(req.query);
      sendJson(res, 200, { sessions });
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_HELP_SESSIONS_FETCH_ERROR', message: err.message });
    }
  });

  // 267. POST /api/v1/fleet/remote-help/sessions
  router.post('/api/v1/fleet/remote-help/sessions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const session = remoteHelpEngine.createSession(req.body || {});
      broadcastEvent('remote_help_session_created', { session_id: session.id, device_id: session.device_id, code: session.session_code });
      sendJson(res, 201, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_SESSION_CREATE_ERROR', message: err.message });
    }
  });

  // 268. GET /api/v1/fleet/remote-help/sessions/:id
  router.get('/api/v1/fleet/remote-help/sessions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const session = remoteHelpEngine.getSession(id);
      if (!session) {
        return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Session not found' });
      }
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 500, { error: 'REMOTE_HELP_SESSION_FETCH_ERROR', message: err.message });
    }
  });

  // 269. POST /api/v1/fleet/remote-help/sessions/:id/connect
  router.post('/api/v1/fleet/remote-help/sessions/:id/connect', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const session = remoteHelpEngine.connectSession(id, req.body || {});
      broadcastEvent('remote_help_connected', { session_id: id, status: 'ACTIVE' });
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_CONNECT_ERROR', message: err.message });
    }
  });

  // 270. POST /api/v1/fleet/remote-help/sessions/:id/terminate
  router.post('/api/v1/fleet/remote-help/sessions/:id/terminate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { actor_user, reason } = req.body || {};
    try {
      const session = remoteHelpEngine.terminateSession(id, actor_user, reason);
      broadcastEvent('remote_help_terminated', { session_id: id, status: 'COMPLETED' });
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_TERMINATE_ERROR', message: err.message });
    }
  });

  // 271. POST /api/v1/fleet/remote-help/sessions/:id/control
  router.post('/api/v1/fleet/remote-help/sessions/:id/control', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { actor_user } = req.body || {};
    try {
      const session = remoteHelpEngine.grantControl(id, actor_user);
      broadcastEvent('remote_help_control_granted', { session_id: id, type: 'FULL_CONTROL' });
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_CONTROL_ERROR', message: err.message });
    }
  });

  // 272. POST /api/v1/fleet/remote-help/sessions/:id/elevation
  router.post('/api/v1/fleet/remote-help/sessions/:id/elevation', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    const { actor_user, details } = req.body || {};
    try {
      const session = remoteHelpEngine.triggerElevation(id, actor_user, details);
      broadcastEvent('remote_help_elevation_triggered', { session_id: id, device_id: session.device_id });
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 400, { error: 'REMOTE_HELP_ELEVATION_ERROR', message: err.message });
    }
  });

  // 273. GET /api/v1/fleet/remote-help/roles
  router.get('/api/v1/fleet/remote-help/roles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const roles = remoteHelpEngine.getRoles();
      sendJson(res, 200, { roles });
    } catch (err) {
      sendJson(res, 500, { error: 'ROLES_FETCH_ERROR', message: err.message });
    }
  });

  // 274. POST /api/v1/fleet/remote-help/roles
  router.post('/api/v1/fleet/remote-help/roles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const role = remoteHelpEngine.createRole(req.body || {});
      sendJson(res, 201, role);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_CREATE_ERROR', message: err.message });
    }
  });

  // 275. GET /api/v1/fleet/remote-help/roles/:id
  router.get('/api/v1/fleet/remote-help/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const role = remoteHelpEngine.getRole(id);
      if (!role) return sendJson(res, 404, { error: 'ROLE_NOT_FOUND', message: 'Role not found' });
      sendJson(res, 200, role);
    } catch (err) {
      sendJson(res, 500, { error: 'ROLE_FETCH_ERROR', message: err.message });
    }
  });

  // 276. PATCH /api/v1/fleet/remote-help/roles/:id
  router.patch('/api/v1/fleet/remote-help/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const role = remoteHelpEngine.updateRole(id, req.body || {});
      sendJson(res, 200, role);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_UPDATE_ERROR', message: err.message });
    }
  });

  // 277. DELETE /api/v1/fleet/remote-help/roles/:id
  router.delete('/api/v1/fleet/remote-help/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const result = remoteHelpEngine.deleteRole(id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_DELETE_ERROR', message: err.message });
    }
  });

  // 278. GET /api/v1/fleet/remote-help/audit-log
  router.get('/api/v1/fleet/remote-help/audit-log', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const logs = remoteHelpEngine.getAuditLog(req.query);
      sendJson(res, 200, { audit_log: logs });
    } catch (err) {
      sendJson(res, 500, { error: 'AUDIT_LOG_FETCH_ERROR', message: err.message });
    }
  });

  // 279. GET /api/v1/fleet/devices/:id/remote-help
  router.get('/api/v1/fleet/devices/:id/remote-help', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const data = remoteHelpEngine.getDeviceRemoteHelp(id);
      sendJson(res, 200, data);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_REMOTE_HELP_FETCH_ERROR', message: err.message });
    }
  });

  // ── Windows Feature Update Profiles & Expedited Quality Updates (280–292) ──
  // 280. GET /api/v1/fleet/feature-updates/stats
  router.get('/api/v1/fleet/feature-updates/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = featureUpdateEngine.getFeatureUpdateStats();
      sendJson(res, 200, { stats, ...stats });
    } catch (err) {
      sendJson(res, 500, { error: 'FEATURE_UPDATE_STATS_ERROR', message: err.message });
    }
  });

  // 281. GET /api/v1/fleet/feature-updates/policies
  router.get('/api/v1/fleet/feature-updates/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = featureUpdateEngine.getFeaturePolicies(req.query);
      sendJson(res, 200, { policies });
    } catch (err) {
      sendJson(res, 500, { error: 'FEATURE_POLICIES_FETCH_ERROR', message: err.message });
    }
  });

  // 282. POST /api/v1/fleet/feature-updates/policies
  router.post('/api/v1/fleet/feature-updates/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = featureUpdateEngine.createFeaturePolicy(req.body || {});
      sendJson(res, 201, { policy, ...policy });
    } catch (err) {
      sendJson(res, 400, { error: 'FEATURE_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 283. GET /api/v1/fleet/feature-updates/policies/:id
  router.get('/api/v1/fleet/feature-updates/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const policy = featureUpdateEngine.getFeaturePolicy(id);
      if (!policy) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Feature policy not found' });
      sendJson(res, 200, { policy, ...policy });
    } catch (err) {
      sendJson(res, 500, { error: 'FEATURE_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 284. PATCH & PUT /api/v1/fleet/feature-updates/policies/:id
  const handleUpdateFeaturePolicy = (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const policy = featureUpdateEngine.updateFeaturePolicy(id, req.body || {});
      sendJson(res, 200, { policy, ...policy });
    } catch (err) {
      sendJson(res, 400, { error: 'FEATURE_POLICY_UPDATE_ERROR', message: err.message });
    }
  };
  router.patch('/api/v1/fleet/feature-updates/policies/:id', handleUpdateFeaturePolicy);
  router.put('/api/v1/fleet/feature-updates/policies/:id', handleUpdateFeaturePolicy);

  // 285. DELETE /api/v1/fleet/feature-updates/policies/:id
  router.delete('/api/v1/fleet/feature-updates/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const result = featureUpdateEngine.deleteFeaturePolicy(id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'FEATURE_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 286. GET /api/v1/fleet/feature-updates/expedited
  router.get('/api/v1/fleet/feature-updates/expedited', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const expedited = featureUpdateEngine.getExpeditedUpdates(req.query);
      sendJson(res, 200, { expedited, expedited_updates: expedited });
    } catch (err) {
      sendJson(res, 500, { error: 'EXPEDITED_UPDATES_FETCH_ERROR', message: err.message });
    }
  });

  // 287. POST /api/v1/fleet/feature-updates/expedited
  router.post('/api/v1/fleet/feature-updates/expedited', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const exp = featureUpdateEngine.createExpeditedUpdate(req.body || {});
      sendJson(res, 201, { expedited_update: exp, ...exp });
    } catch (err) {
      sendJson(res, 400, { error: 'EXPEDITED_UPDATE_CREATE_ERROR', message: err.message });
    }
  });

  // 288. GET /api/v1/fleet/feature-updates/expedited/:id
  router.get('/api/v1/fleet/feature-updates/expedited/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const exp = featureUpdateEngine.getExpeditedUpdate(id);
      if (!exp) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Expedited update campaign not found' });
      sendJson(res, 200, { expedited_update: exp, ...exp });
    } catch (err) {
      sendJson(res, 500, { error: 'EXPEDITED_UPDATE_FETCH_ERROR', message: err.message });
    }
  });

  // 289. PATCH & PUT /api/v1/fleet/feature-updates/expedited/:id
  const handleUpdateExpeditedUpdate = (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const exp = featureUpdateEngine.updateExpeditedUpdate(id, req.body || {});
      sendJson(res, 200, { expedited_update: exp, ...exp });
    } catch (err) {
      sendJson(res, 400, { error: 'EXPEDITED_UPDATE_UPDATE_ERROR', message: err.message });
    }
  };
  router.patch('/api/v1/fleet/feature-updates/expedited/:id', handleUpdateExpeditedUpdate);
  router.put('/api/v1/fleet/feature-updates/expedited/:id', handleUpdateExpeditedUpdate);

  // 290. DELETE /api/v1/fleet/feature-updates/expedited/:id
  router.delete('/api/v1/fleet/feature-updates/expedited/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const result = featureUpdateEngine.deleteExpeditedUpdate(id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'EXPEDITED_UPDATE_DELETE_ERROR', message: err.message });
    }
  });

  // 291. GET /api/v1/fleet/feature-updates/inventory
  router.get('/api/v1/fleet/feature-updates/inventory', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const inventory = featureUpdateEngine.getFeatureInventoryOverview();
      sendJson(res, 200, { inventory });
    } catch (err) {
      sendJson(res, 500, { error: 'FEATURE_INVENTORY_FETCH_ERROR', message: err.message });
    }
  });

  // 292. GET /api/v1/fleet/devices/:id/feature-updates
  router.get('/api/v1/fleet/devices/:id/feature-updates', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const data = featureUpdateEngine.getDeviceFeatureUpdateStatus(id);
      sendJson(res, 200, data);
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_FEATURE_UPDATES_FETCH_ERROR', message: err.message });
    }
  });

  // 293. GET /api/v1/fleet/eam/stats
  router.get('/api/v1/fleet/eam/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = enterpriseAppEngine.getCatalogStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_STATS_ERROR', message: err.message });
    }
  });

  // 294. GET /api/v1/fleet/eam/catalog
  router.get('/api/v1/fleet/eam/catalog', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const apps = enterpriseAppEngine.getCatalogApps(getDb(), req.query);
      sendJson(res, 200, { apps, total: apps.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_CATALOG_FETCH_ERROR', message: err.message });
    }
  });

  // 295. POST /api/v1/fleet/eam/catalog
  router.post('/api/v1/fleet/eam/catalog', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const app = enterpriseAppEngine.createCatalogApp(getDb(), req.body);
      sendJson(res, 201, { success: true, app });
    } catch (err) {
      sendJson(res, 400, { error: 'EAM_CATALOG_CREATE_ERROR', message: err.message });
    }
  });

  // 296. GET /api/v1/fleet/eam/catalog/:id
  router.get('/api/v1/fleet/eam/catalog/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const app = enterpriseAppEngine.getCatalogApp(getDb(), req.params.id);
      if (!app) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Application not found' });
      sendJson(res, 200, { app });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_APP_FETCH_ERROR', message: err.message });
    }
  });

  // 297. PATCH & PUT /api/v1/fleet/eam/catalog/:id
  const handleUpdateApp = (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = enterpriseAppEngine.updateCatalogApp(getDb(), req.params.id, req.body);
      if (!updated) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Application not found' });
      sendJson(res, 200, { success: true, app: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'EAM_APP_UPDATE_ERROR', message: err.message });
    }
  };
  router.patch('/api/v1/fleet/eam/catalog/:id', handleUpdateApp);
  router.put('/api/v1/fleet/eam/catalog/:id', handleUpdateApp);

  // 298. DELETE /api/v1/fleet/eam/catalog/:id
  router.delete('/api/v1/fleet/eam/catalog/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = enterpriseAppEngine.deleteCatalogApp(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Application not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_APP_DELETE_ERROR', message: err.message });
    }
  });

  // 299. GET /api/v1/fleet/eam/requests
  router.get('/api/v1/fleet/eam/requests', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const requests = enterpriseAppEngine.getCompanyPortalRequests(getDb(), req.query);
      sendJson(res, 200, { requests, total: requests.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_REQUESTS_FETCH_ERROR', message: err.message });
    }
  });

  // 300. POST /api/v1/fleet/eam/requests/:id/review
  router.post('/api/v1/fleet/eam/requests/:id/review', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = enterpriseAppEngine.reviewCompanyPortalRequest(getDb(), req.params.id, req.body);
      sendJson(res, 200, { success: true, request: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'EAM_REQUEST_REVIEW_ERROR', message: err.message });
    }
  });

  // 301. GET /api/v1/fleet/eam/licenses
  router.get('/api/v1/fleet/eam/licenses', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const licenses = enterpriseAppEngine.getLicenseAllocations(getDb(), req.query);
      sendJson(res, 200, { licenses, total: licenses.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_LICENSES_FETCH_ERROR', message: err.message });
    }
  });

  // 302. POST /api/v1/fleet/eam/licenses
  router.post('/api/v1/fleet/eam/licenses', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const allocation = enterpriseAppEngine.allocateLicense(getDb(), req.body);
      sendJson(res, 201, { success: true, allocation });
    } catch (err) {
      sendJson(res, 400, { error: 'EAM_LICENSE_ALLOCATE_ERROR', message: err.message });
    }
  });

  // 303. POST /api/v1/fleet/eam/licenses/:id/revoke
  router.post('/api/v1/fleet/eam/licenses/:id/revoke', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = enterpriseAppEngine.revokeLicense(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'License allocation not found' });
      sendJson(res, 200, { success: true, revoked_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'EAM_LICENSE_REVOKE_ERROR', message: err.message });
    }
  });

  // 304. GET /api/v1/fleet/tvm/stats
  router.get('/api/v1/fleet/tvm/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = vulnerabilityEngine.getVulnerabilityStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_STATS_ERROR', message: err.message });
    }
  });

  // 305. GET /api/v1/fleet/tvm/vulnerabilities
  router.get('/api/v1/fleet/tvm/vulnerabilities', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const vulns = vulnerabilityEngine.getVulnerabilities(getDb(), req.query);
      sendJson(res, 200, { vulnerabilities: vulns, total: vulns.length });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_VULNS_FETCH_ERROR', message: err.message });
    }
  });

  // 306. POST /api/v1/fleet/tvm/vulnerabilities
  router.post('/api/v1/fleet/tvm/vulnerabilities', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const vuln = vulnerabilityEngine.createVulnerability(getDb(), req.body);
      sendJson(res, 201, { success: true, vulnerability: vuln });
    } catch (err) {
      sendJson(res, 400, { error: 'TVM_VULN_CREATE_ERROR', message: err.message });
    }
  });

  // 307. GET /api/v1/fleet/tvm/vulnerabilities/:cveId
  router.get('/api/v1/fleet/tvm/vulnerabilities/:cveId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const vuln = vulnerabilityEngine.getVulnerability(getDb(), req.params.cveId);
      if (!vuln) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Vulnerability not found' });
      sendJson(res, 200, { vulnerability: vuln });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_VULN_FETCH_ERROR', message: err.message });
    }
  });

  // 308. PATCH & PUT /api/v1/fleet/tvm/vulnerabilities/:cveId
  const handleUpdateVuln = (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = vulnerabilityEngine.updateVulnerability(getDb(), req.params.cveId, req.body);
      if (!updated) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Vulnerability not found' });
      sendJson(res, 200, { success: true, vulnerability: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'TVM_VULN_UPDATE_ERROR', message: err.message });
    }
  };
  router.patch('/api/v1/fleet/tvm/vulnerabilities/:cveId', handleUpdateVuln);
  router.put('/api/v1/fleet/tvm/vulnerabilities/:cveId', handleUpdateVuln);

  // 309. DELETE /api/v1/fleet/tvm/vulnerabilities/:cveId
  router.delete('/api/v1/fleet/tvm/vulnerabilities/:cveId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = vulnerabilityEngine.deleteVulnerability(getDb(), req.params.cveId);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Vulnerability not found' });
      sendJson(res, 200, { success: true, deleted_cve_id: req.params.cveId });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_VULN_DELETE_ERROR', message: err.message });
    }
  });

  // 310. GET /api/v1/fleet/tvm/baselines
  router.get('/api/v1/fleet/tvm/baselines', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const baselines = vulnerabilityEngine.getSecurityBaselines(getDb(), req.query);
      sendJson(res, 200, { baselines, total: baselines.length });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_BASELINES_FETCH_ERROR', message: err.message });
    }
  });

  // 311. POST /api/v1/fleet/tvm/baselines
  router.post('/api/v1/fleet/tvm/baselines', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const baseline = vulnerabilityEngine.createSecurityBaseline(getDb(), req.body);
      sendJson(res, 201, { success: true, baseline });
    } catch (err) {
      sendJson(res, 400, { error: 'TVM_BASELINE_CREATE_ERROR', message: err.message });
    }
  });

  // 312. GET /api/v1/fleet/tvm/baselines/:id
  router.get('/api/v1/fleet/tvm/baselines/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const baseline = vulnerabilityEngine.getSecurityBaseline(getDb(), req.params.id);
      if (!baseline) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Baseline not found' });
      const auditScript = vulnerabilityEngine.generateBaselineAuditScript(baseline);
      const remediationScript = vulnerabilityEngine.generateBaselineRemediationScript(baseline);
      sendJson(res, 200, { baseline, audit_script: auditScript, remediation_script: remediationScript });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_BASELINE_FETCH_ERROR', message: err.message });
    }
  });

  // 313. PATCH & PUT /api/v1/fleet/tvm/baselines/:id
  const handleUpdateBaseline = (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = vulnerabilityEngine.updateSecurityBaseline(getDb(), req.params.id, req.body);
      if (!updated) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Baseline not found' });
      sendJson(res, 200, { success: true, baseline: updated });
    } catch (err) {
      sendJson(res, 400, { error: 'TVM_BASELINE_UPDATE_ERROR', message: err.message });
    }
  };
  router.patch('/api/v1/fleet/tvm/baselines/:id', handleUpdateBaseline);
  router.put('/api/v1/fleet/tvm/baselines/:id', handleUpdateBaseline);

  // 314. DELETE /api/v1/fleet/tvm/baselines/:id
  router.delete('/api/v1/fleet/tvm/baselines/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = vulnerabilityEngine.deleteSecurityBaseline(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Baseline not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'TVM_BASELINE_DELETE_ERROR', message: err.message });
    }
  });

  // 315. GET /api/v1/fleet/devices/:id/vulnerabilities
  router.get('/api/v1/fleet/devices/:id/vulnerabilities', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const vulns = vulnerabilityEngine.getDeviceVulnerabilities(getDb(), id, req.query);
      sendJson(res, 200, { device_id: id, vulnerabilities: vulns, total: vulns.length });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_VULNS_FETCH_ERROR', message: err.message });
    }
  });

  // 316. POST /api/v1/fleet/devices/:id/assess-vulnerabilities
  router.post('/api/v1/fleet/devices/:id/assess-vulnerabilities', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { id } = req.params;
    try {
      const assessed = vulnerabilityEngine.assessDeviceVulnerabilities(getDb(), id, req.body.software || []);
      sendJson(res, 200, { success: true, device_id: id, active_vulnerabilities: assessed, total: assessed.length });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_VULNS_ASSESS_ERROR', message: err.message });
    }
  });

  // 317. GET /api/v1/fleet/autopatch/stats
  router.get('/api/v1/fleet/autopatch/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      sendJson(res, 200, autopatchEngine.getAutopatchStats(getDb()));
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_STATS_ERROR', message: err.message });
    }
  });

  // 318. GET /api/v1/fleet/autopatch/releases
  router.get('/api/v1/fleet/autopatch/releases', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const releases = autopatchEngine.getReleases(getDb(), req.query);
      sendJson(res, 200, { releases, count: releases.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_RELEASES_ERROR', message: err.message });
    }
  });

  // 319. POST /api/v1/fleet/autopatch/releases
  router.post('/api/v1/fleet/autopatch/releases', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const release = autopatchEngine.createRelease(getDb(), req.body || {});
      sendJson(res, 201, { success: true, release });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_CREATE_ERROR', message: err.message });
    }
  });

  // 320. GET /api/v1/fleet/autopatch/releases/:id
  router.get('/api/v1/fleet/autopatch/releases/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const release = autopatchEngine.getRelease(getDb(), req.params.id);
      if (!release) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Release not found' });
      sendJson(res, 200, release);
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_FETCH_ERROR', message: err.message });
    }
  });

  // 321. PUT /api/v1/fleet/autopatch/releases/:id
  router.put('/api/v1/fleet/autopatch/releases/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const release = autopatchEngine.updateRelease(getDb(), req.params.id, req.body || {});
      if (!release) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Release not found' });
      sendJson(res, 200, { success: true, release });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_UPDATE_ERROR', message: err.message });
    }
  });

  // 322. DELETE /api/v1/fleet/autopatch/releases/:id
  router.delete('/api/v1/fleet/autopatch/releases/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = autopatchEngine.deleteRelease(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Release not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_DELETE_ERROR', message: err.message });
    }
  });

  // 323. POST /api/v1/fleet/autopatch/releases/:id/progress
  router.post('/api/v1/fleet/autopatch/releases/:id/progress', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const release = autopatchEngine.progressReleasePhase(getDb(), req.params.id);
      if (!release) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Release not found' });
      sendJson(res, 200, { success: true, release, new_phase: release.active_phase });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_PROGRESS_ERROR', message: err.message });
    }
  });

  // 324. POST /api/v1/fleet/autopatch/releases/:id/rollback
  router.post('/api/v1/fleet/autopatch/releases/:id/rollback', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const reason = req.body?.reason || 'Administrator triggered rollback';
      const release = autopatchEngine.triggerPatchRollback(getDb(), req.params.id, reason);
      if (!release) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Release not found' });
      const rollbackScript = autopatchEngine.generateRollbackScript(release.target_kb_numbers);
      sendJson(res, 200, { success: true, release, rollback_script: rollbackScript });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_ROLLBACK_ERROR', message: err.message });
    }
  });

  // 325. GET /api/v1/fleet/autopatch/rings
  router.get('/api/v1/fleet/autopatch/rings', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const rings = autopatchEngine.getRings(getDb());
      sendJson(res, 200, { rings, count: rings.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_RINGS_ERROR', message: err.message });
    }
  });

  // 326. PUT /api/v1/fleet/autopatch/rings/:id
  router.put('/api/v1/fleet/autopatch/rings/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ring = autopatchEngine.updateRing(getDb(), req.params.id, req.body || {});
      if (!ring) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Ring not found' });
      sendJson(res, 200, { success: true, ring });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_RING_UPDATE_ERROR', message: err.message });
    }
  });

  // 327. GET /api/v1/fleet/autopatch/deployments
  router.get('/api/v1/fleet/autopatch/deployments', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const deployments = autopatchEngine.getDeviceDeployments(getDb(), req.query);
      sendJson(res, 200, { deployments, count: deployments.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AUTOPATCH_DEPLOYMENTS_ERROR', message: err.message });
    }
  });

  // 328. GET /api/v1/fleet/devices/:id/autopatch
  router.get('/api/v1/fleet/devices/:id/autopatch', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const status = autopatchEngine.getDeviceAutopatchStatus(getDb(), req.params.id);
      sendJson(res, 200, { device_id: req.params.id, autopatch: status });
    } catch (err) {
      sendJson(res, 500, { error: 'DEVICE_AUTOPATCH_ERROR', message: err.message });
    }
  });


  // 329. GET /api/v1/fleet/cloud-pc/stats
  router.get('/api/v1/fleet/cloud-pc/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      sendJson(res, 200, cloudPcEngine.getCloudPcStats(getDb()));
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_STATS_ERROR', message: err.message });
    }
  });

  // 330. GET /api/v1/fleet/cloud-pc/policies
  router.get('/api/v1/fleet/cloud-pc/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = cloudPcEngine.getProvisioningPolicies(getDb());
      sendJson(res, 200, { policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_POLICIES_ERROR', message: err.message });
    }
  });

  // 331. POST /api/v1/fleet/cloud-pc/policies
  router.post('/api/v1/fleet/cloud-pc/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = cloudPcEngine.createProvisioningPolicy(getDb(), req.body || {});
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 332. GET /api/v1/fleet/cloud-pc/policies/:id
  router.get('/api/v1/fleet/cloud-pc/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = cloudPcEngine.getProvisioningPolicy(getDb(), req.params.id);
      if (!policy) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Policy not found' });
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 333. PUT /api/v1/fleet/cloud-pc/policies/:id
  router.put('/api/v1/fleet/cloud-pc/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = cloudPcEngine.updateProvisioningPolicy(getDb(), req.params.id, req.body || {});
      if (!policy) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Policy not found' });
      sendJson(res, 200, { success: true, policy });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 334. DELETE /api/v1/fleet/cloud-pc/policies/:id
  router.delete('/api/v1/fleet/cloud-pc/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = cloudPcEngine.deleteProvisioningPolicy(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Policy not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 335. GET /api/v1/fleet/cloud-pc/instances
  router.get('/api/v1/fleet/cloud-pc/instances', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instances = cloudPcEngine.getCloudPcInstances(getDb(), req.query);
      sendJson(res, 200, { instances, count: instances.length });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_INSTANCES_ERROR', message: err.message });
    }
  });

  // 336. POST /api/v1/fleet/cloud-pc/instances
  router.post('/api/v1/fleet/cloud-pc/instances', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instance = cloudPcEngine.createCloudPcInstance(getDb(), req.body || {});
      sendJson(res, 201, { success: true, instance });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_INSTANCE_CREATE_ERROR', message: err.message });
    }
  });

  // 337. GET /api/v1/fleet/cloud-pc/instances/:id
  router.get('/api/v1/fleet/cloud-pc/instances/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instance = cloudPcEngine.getCloudPcInstance(getDb(), req.params.id);
      if (!instance) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Cloud PC instance not found' });
      sendJson(res, 200, instance);
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_INSTANCE_FETCH_ERROR', message: err.message });
    }
  });

  // 338. PUT /api/v1/fleet/cloud-pc/instances/:id
  router.put('/api/v1/fleet/cloud-pc/instances/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instance = cloudPcEngine.updateCloudPcInstance(getDb(), req.params.id, req.body || {});
      if (!instance) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Cloud PC instance not found' });
      sendJson(res, 200, { success: true, instance });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_INSTANCE_UPDATE_ERROR', message: err.message });
    }
  });

  // 339. DELETE /api/v1/fleet/cloud-pc/instances/:id
  router.delete('/api/v1/fleet/cloud-pc/instances/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = cloudPcEngine.deleteCloudPcInstance(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Cloud PC instance not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_INSTANCE_DELETE_ERROR', message: err.message });
    }
  });

  // 340. POST /api/v1/fleet/cloud-pc/instances/:id/reprovision
  router.post('/api/v1/fleet/cloud-pc/instances/:id/reprovision', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instance = cloudPcEngine.triggerReprovisioning(getDb(), req.params.id);
      if (!instance) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Cloud PC instance not found' });
      sendJson(res, 200, { success: true, instance });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_REPROVISION_ERROR', message: err.message });
    }
  });

  // 341. POST /api/v1/fleet/cloud-pc/instances/:id/grace-period
  router.post('/api/v1/fleet/cloud-pc/instances/:id/grace-period', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const days = parseInt(req.body?.days, 10) || 7;
      const instance = cloudPcEngine.setGracePeriod(getDb(), req.params.id, days);
      if (!instance) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Cloud PC instance not found' });
      sendJson(res, 200, { success: true, instance });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_GRACE_PERIOD_ERROR', message: err.message });
    }
  });

  // 342. GET /api/v1/fleet/cloud-pc/restore-points
  router.get('/api/v1/fleet/cloud-pc/restore-points', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const points = cloudPcEngine.getRestorePoints(getDb(), req.query);
      sendJson(res, 200, { restore_points: points, count: points.length });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_RESTORE_POINTS_ERROR', message: err.message });
    }
  });

  // 343. POST /api/v1/fleet/cloud-pc/restore-points
  router.post('/api/v1/fleet/cloud-pc/restore-points', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const point = cloudPcEngine.createRestorePoint(getDb(), req.body || {});
      sendJson(res, 201, { success: true, restore_point: point });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_RESTORE_POINT_CREATE_ERROR', message: err.message });
    }
  });

  // 344. POST /api/v1/fleet/cloud-pc/restore-points/:id/restore
  router.post('/api/v1/fleet/cloud-pc/restore-points/:id/restore', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const instance = cloudPcEngine.triggerRestorePointRecovery(getDb(), req.params.id);
      if (!instance) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Restore point not found' });
      sendJson(res, 200, { success: true, instance });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_RECOVER_ERROR', message: err.message });
    }
  });

  // 345. DELETE /api/v1/fleet/cloud-pc/restore-points/:id
  router.delete('/api/v1/fleet/cloud-pc/restore-points/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = cloudPcEngine.deleteRestorePoint(getDb(), req.params.id);
      if (!success) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Restore point not found' });
      sendJson(res, 200, { success: true, deleted_id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_RESTORE_POINT_DELETE_ERROR', message: err.message });
    }
  });

  // 346. GET /api/v1/fleet/cloud-pc/provision-script
  router.get('/api/v1/fleet/cloud-pc/provision-script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policyId = req.query.policy_id;
      const policy = policyId ? cloudPcEngine.getProvisioningPolicy(getDb(), policyId) : null;
      const vmName = req.query.name || 'CloudPC-NewVM';
      const script = cloudPcEngine.generateHyperVProvisionScript(policy, vmName);
      sendJson(res, 200, { success: true, script });
    } catch (err) {
      sendJson(res, 500, { error: 'CLOUD_PC_SCRIPT_ERROR', message: err.message });
    }
  });

  // 347. GET /api/v1/fleet/pki/stats
  router.get('/api/v1/fleet/pki/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = pkiSigningEngine.getPkiStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_STATS_ERROR', message: err.message });
    }
  });

  // 348. GET /api/v1/fleet/pki/keys
  router.get('/api/v1/fleet/pki/keys', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const keys = pkiSigningEngine.getSigningKeys(getDb(), true);
      sendJson(res, 200, { keys, count: keys.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_KEYS_ERROR', message: err.message });
    }
  });

  // 349. GET /api/v1/fleet/pki/keys/:id
  router.get('/api/v1/fleet/pki/keys/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const key = pkiSigningEngine.getSigningKeyById(getDb(), req.params.id, false);
      if (!key) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Signing key not found' });
      sendJson(res, 200, key);
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_KEY_FETCH_ERROR', message: err.message });
    }
  });

  // 350. POST /api/v1/fleet/pki/keys/generate
  router.post('/api/v1/fleet/pki/keys/generate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const body = req.body || {};
      const key = pkiSigningEngine.generateSigningKey(getDb(), body);
      sendJson(res, 201, { success: true, key });
    } catch (err) {
      sendJson(res, 400, { error: 'PKI_KEY_GENERATE_ERROR', message: err.message });
    }
  });

  // 351. POST /api/v1/fleet/pki/keys/rotate
  router.post('/api/v1/fleet/pki/keys/rotate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const body = req.body || {};
      const rotation = pkiSigningEngine.rotateSigningKey(getDb(), body);
      sendJson(res, 200, { success: true, ...rotation });
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_KEY_ROTATE_ERROR', message: err.message });
    }
  });

  // 352. POST /api/v1/fleet/pki/keys/:id/revoke
  router.post('/api/v1/fleet/pki/keys/:id/revoke', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const reason = req.body?.reason || 'Administrative revocation';
      const revoked = pkiSigningEngine.revokeSigningKey(getDb(), req.params.id, reason);
      if (!revoked) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Signing key not found' });
      sendJson(res, 200, { success: true, key: revoked });
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_KEY_REVOKE_ERROR', message: err.message });
    }
  });

  // 353. POST /api/v1/fleet/pki/sign
  router.post('/api/v1/fleet/pki/sign', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { payload, payload_type, target_id, wrap_envelope } = req.body || {};
      if (!payload) return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Payload is required' });

      if (wrap_envelope) {
        const result = pkiSigningEngine.wrapScriptWithSignature(getDb(), payload, {
          payloadType: payload_type || 'SCRIPT',
          targetId: target_id
        });
        sendJson(res, 200, { success: true, ...result });
      } else {
        const result = pkiSigningEngine.signPayload(getDb(), {
          payload,
          payloadType: payload_type || 'SCRIPT',
          targetId: target_id
        });
        sendJson(res, 200, { success: true, ...result });
      }
    } catch (err) {
      sendJson(res, 400, { error: 'PKI_SIGN_ERROR', message: err.message });
    }
  });

  // 354. POST /api/v1/fleet/pki/verify
  router.post('/api/v1/fleet/pki/verify', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { payload, signature_base64, signer_thumbprint, envelope_text } = req.body || {};
      if (envelope_text) {
        const result = pkiSigningEngine.extractAndVerifyScriptEnvelope(getDb(), envelope_text);
        sendJson(res, 200, result);
      } else {
        if (!payload || !signature_base64) {
          return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Payload and signature_base64 required' });
        }
        const result = pkiSigningEngine.verifyPayload(getDb(), {
          payload,
          signatureBase64: signature_base64,
          signerThumbprint: signer_thumbprint
        });
        sendJson(res, 200, result);
      }
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_VERIFY_ERROR', message: err.message });
    }
  });

  // 355. GET /api/v1/fleet/pki/manifests
  router.get('/api/v1/fleet/pki/manifests', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const manifests = pkiSigningEngine.getSigningManifests(getDb(), {
        payloadType: req.query.payload_type,
        limit: req.query.limit || 50
      });
      sendJson(res, 200, { manifests, count: manifests.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PKI_MANIFESTS_ERROR', message: err.message });
    }
  });

  // 356. GET /api/v1/fleet/push/stats
  router.get('/api/v1/fleet/push/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = realtimePushEngine.getPushStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_STATS_ERROR', message: err.message });
    }
  });

  // 357. GET /api/v1/fleet/push/channels
  router.get('/api/v1/fleet/push/channels', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const channels = realtimePushEngine.getActiveChannels(getDb(), {
        nodeId: req.query.node_id,
        status: req.query.status
      });
      sendJson(res, 200, { channels, count: channels.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_CHANNELS_ERROR', message: err.message });
    }
  });

  // 358. GET /api/v1/fleet/push/messages
  router.get('/api/v1/fleet/push/messages', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const messages = realtimePushEngine.getPushMessages(getDb(), {
        nodeId: req.query.node_id,
        status: req.query.status,
        topic: req.query.topic,
        limit: req.query.limit ? Number(req.query.limit) : 50
      });
      sendJson(res, 200, { messages, count: messages.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_MESSAGES_ERROR', message: err.message });
    }
  });

  // 359. POST /api/v1/fleet/push/dispatch
  router.post('/api/v1/fleet/push/dispatch', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { node_id, group_id, topic, payload, priority, ttl_seconds } = req.body || {};
      if (!topic) {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Topic is required' });
      }

      const db = getDb();
      const dispatched = [];

      if (group_id) {
        const members = db.prepare('SELECT device_id FROM group_memberships WHERE group_id = ?').all(group_id);
        for (const m of members) {
          const msg = realtimePushEngine.dispatchPushMessage(db, {
            nodeId: m.device_id,
            topic,
            payload: payload || {},
            priority: priority || 'HIGH',
            ttlSeconds: ttl_seconds || 300
          });
          dispatched.push(msg);
        }
      } else if (node_id) {
        const msg = realtimePushEngine.dispatchPushMessage(db, {
          nodeId: node_id,
          topic,
          payload: payload || {},
          priority: priority || 'HIGH',
          ttlSeconds: ttl_seconds || 300
        });
        dispatched.push(msg);
      } else {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'Either node_id or group_id must be specified' });
      }

      sendJson(res, 200, {
        success: true,
        dispatched_count: dispatched.length,
        messages: dispatched
      });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_DISPATCH_ERROR', message: err.message });
    }
  });

  // 360. POST /api/v1/fleet/push/channels/prune
  router.post('/api/v1/fleet/push/channels/prune', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const timeoutSec = req.body?.timeout_sec ? Number(req.body.timeout_sec) : 120;
      const pruned = realtimePushEngine.pruneStaleChannels(getDb(), timeoutSec);
      sendJson(res, 200, { success: true, pruned_channels: pruned });
    } catch (err) {
      sendJson(res, 500, { error: 'PUSH_PRUNE_ERROR', message: err.message });
    }
  });

  // 361. GET /api/v1/fleet/supervisor/stats
  router.get('/api/v1/fleet/supervisor/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = supervisorEngine.getSupervisorStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_STATS_ERROR', message: err.message });
    }
  });

  // 362. GET /api/v1/fleet/supervisor/nodes
  router.get('/api/v1/fleet/supervisor/nodes', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const nodes = supervisorEngine.getSupervisors(getDb(), {
        deviceId: req.query.device_id,
        status: req.query.status
      });
      sendJson(res, 200, { supervisors: nodes, count: nodes.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_NODES_ERROR', message: err.message });
    }
  });

  // 363. GET /api/v1/fleet/supervisor/nodes/:id
  router.get('/api/v1/fleet/supervisor/nodes/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const sup = supervisorEngine.getSupervisorByDeviceId(getDb(), req.params.id);
      if (!sup) return sendJson(res, 404, { error: 'NOT_FOUND', message: 'Supervisor not found for device' });
      sendJson(res, 200, sup);
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_FETCH_ERROR', message: err.message });
    }
  });

  // 364. GET /api/v1/fleet/supervisor/crashes
  router.get('/api/v1/fleet/supervisor/crashes', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const crashes = supervisorEngine.getCrashDumps(getDb(), {
        deviceId: req.query.device_id,
        crashType: req.query.crash_type,
        limit: req.query.limit ? Number(req.query.limit) : 50
      });
      sendJson(res, 200, { crashes, count: crashes.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_CRASHES_ERROR', message: err.message });
    }
  });

  // 365. POST /api/v1/fleet/supervisor/quotas
  router.post('/api/v1/fleet/supervisor/quotas', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { device_id, group_id, cpu_limit_percent, ram_limit_mb, job_object_active, tamper_protection_enabled } = req.body || {};
      const db = getDb();
      let updatedCount = 0;

      if (group_id) {
        const members = db.prepare('SELECT device_id FROM group_memberships WHERE group_id = ?').all(group_id);
        for (const m of members) {
          supervisorEngine.updateResourceQuotas(db, {
            deviceId: m.device_id,
            cpuLimitPercent: cpu_limit_percent ?? 5,
            ramLimitMb: ram_limit_mb ?? 150,
            jobObjectActive: job_object_active ?? 1,
            tamperProtectionEnabled: tamper_protection_enabled ?? 1
          });
          updatedCount++;
        }
      } else if (device_id) {
        supervisorEngine.updateResourceQuotas(db, {
          deviceId: device_id,
          cpuLimitPercent: cpu_limit_percent ?? 5,
          ramLimitMb: ram_limit_mb ?? 150,
          jobObjectActive: job_object_active ?? 1,
          tamperProtectionEnabled: tamper_protection_enabled ?? 1
        });
        updatedCount = 1;
      } else {
        return sendJson(res, 400, { error: 'BAD_REQUEST', message: 'device_id or group_id required' });
      }

      sendJson(res, 200, { success: true, updated_count: updatedCount });
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_QUOTA_ERROR', message: err.message });
    }
  });

  // 366. GET /api/v1/fleet/supervisor/script
  router.get('/api/v1/fleet/supervisor/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = supervisorEngine.generateSupervisorScript({
        deviceId: req.query.device_id || '',
        cpuLimit: req.query.cpu_limit ? Number(req.query.cpu_limit) : 5,
        ramLimitMb: req.query.ram_limit ? Number(req.query.ram_limit) : 150
      });
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: 'SUPERVISOR_SCRIPT_ERROR', message: err.message });
    }
  });


  // 367. GET /api/v1/fleet/rbac/stats
  router.get('/api/v1/fleet/rbac/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = rbacEngine.getGovernanceStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'RBAC_STATS_ERROR', message: err.message });
    }
  });

  // 368. GET /api/v1/fleet/rbac/roles
  router.get('/api/v1/fleet/rbac/roles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const roles = rbacEngine.getRoles(req.query);
      sendJson(res, 200, { roles, count: roles.length });
    } catch (err) {
      sendJson(res, 500, { error: 'RBAC_ROLES_FETCH_ERROR', message: err.message });
    }
  });

  // 369. GET /api/v1/fleet/rbac/roles/:id
  router.get('/api/v1/fleet/rbac/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const role = rbacEngine.getRoleById(req.params.id);
      if (!role) {
        return sendJson(res, 404, { error: 'ROLE_NOT_FOUND', message: `Role '${req.params.id}' does not exist` });
      }
      sendJson(res, 200, role);
    } catch (err) {
      sendJson(res, 500, { error: 'RBAC_ROLE_FETCH_ERROR', message: err.message });
    }
  });

  // 370. POST /api/v1/fleet/rbac/roles
  router.post('/api/v1/fleet/rbac/roles', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const created = rbacEngine.createRole(req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_CREATE_ERROR', message: err.message });
    }
  });

  // 371. PATCH /api/v1/fleet/rbac/roles/:id
  router.patch('/api/v1/fleet/rbac/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = rbacEngine.updateRole(req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_UPDATE_ERROR', message: err.message });
    }
  });

  // 372. DELETE /api/v1/fleet/rbac/roles/:id
  router.delete('/api/v1/fleet/rbac/roles/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const deleted = rbacEngine.deleteRole(req.params.id);
      sendJson(res, 200, deleted);
    } catch (err) {
      sendJson(res, 400, { error: 'ROLE_DELETE_ERROR', message: err.message });
    }
  });

  // 373. GET /api/v1/fleet/governance/approvals
  router.get('/api/v1/fleet/governance/approvals', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const approvals = rbacEngine.getDualCustodyApprovals(req.query);
      sendJson(res, 200, { approvals, count: approvals.length });
    } catch (err) {
      sendJson(res, 500, { error: 'APPROVALS_FETCH_ERROR', message: err.message });
    }
  });

  // 374. GET /api/v1/fleet/governance/approvals/:id
  router.get('/api/v1/fleet/governance/approvals/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const approval = rbacEngine.getApprovalById(req.params.id);
      if (!approval) {
        return sendJson(res, 404, { error: 'APPROVAL_NOT_FOUND', message: `Approval '${req.params.id}' does not exist` });
      }
      sendJson(res, 200, approval);
    } catch (err) {
      sendJson(res, 500, { error: 'APPROVAL_FETCH_ERROR', message: err.message });
    }
  });

  // 375. POST /api/v1/fleet/governance/approvals
  router.post('/api/v1/fleet/governance/approvals', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const created = rbacEngine.requestDualCustodyApproval(req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'APPROVAL_REQUEST_ERROR', message: err.message });
    }
  });

  // 376. POST /api/v1/fleet/governance/approvals/:id/review
  router.post('/api/v1/fleet/governance/approvals/:id/review', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const reviewed = rbacEngine.reviewDualCustodyApproval(req.params.id, req.body || {});
      sendJson(res, 200, reviewed);
    } catch (err) {
      sendJson(res, 400, { error: 'APPROVAL_REVIEW_ERROR', message: err.message });
    }
  });

  // 377. POST /api/v1/fleet/governance/approvals/:id/execute
  router.post('/api/v1/fleet/governance/approvals/:id/execute', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const executed = rbacEngine.executeDualCustodyApproval(req.params.id);
      sendJson(res, 200, { success: true, approval: executed });
    } catch (err) {
      sendJson(res, 400, { error: 'APPROVAL_EXECUTE_ERROR', message: err.message });
    }
  });

  // 378. GET /api/v1/fleet/siem/stats
  router.get('/api/v1/fleet/siem/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = siemForwarderEngine.getSiemStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'SIEM_STATS_ERROR', message: err.message });
    }
  });

  // 379. GET /api/v1/fleet/siem/forwarders
  router.get('/api/v1/fleet/siem/forwarders', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const forwarders = siemForwarderEngine.getForwarders(req.query);
      sendJson(res, 200, { forwarders, count: forwarders.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SIEM_FORWARDERS_FETCH_ERROR', message: err.message });
    }
  });

  // 380. GET /api/v1/fleet/siem/forwarders/:id
  router.get('/api/v1/fleet/siem/forwarders/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const forwarder = siemForwarderEngine.getForwarderById(req.params.id);
      if (!forwarder) {
        return sendJson(res, 404, { error: 'FORWARDER_NOT_FOUND', message: `Forwarder '${req.params.id}' does not exist` });
      }
      sendJson(res, 200, forwarder);
    } catch (err) {
      sendJson(res, 500, { error: 'SIEM_FORWARDER_FETCH_ERROR', message: err.message });
    }
  });

  // 381. POST /api/v1/fleet/siem/forwarders
  router.post('/api/v1/fleet/siem/forwarders', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const created = siemForwarderEngine.createForwarder(req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'SIEM_FORWARDER_CREATE_ERROR', message: err.message });
    }
  });

  // 382. PATCH /api/v1/fleet/siem/forwarders/:id
  router.patch('/api/v1/fleet/siem/forwarders/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = siemForwarderEngine.updateForwarder(req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'SIEM_FORWARDER_UPDATE_ERROR', message: err.message });
    }
  });

  // 383. DELETE /api/v1/fleet/siem/forwarders/:id
  router.delete('/api/v1/fleet/siem/forwarders/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const deleted = siemForwarderEngine.deleteForwarder(req.params.id);
      sendJson(res, 200, deleted);
    } catch (err) {
      sendJson(res, 400, { error: 'SIEM_FORWARDER_DELETE_ERROR', message: err.message });
    }
  });

  // 384. POST /api/v1/fleet/siem/forwarders/:id/test
  router.post('/api/v1/fleet/siem/forwarders/:id/test', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = siemForwarderEngine.testForwarderConnection(req.params.id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SIEM_TEST_ERROR', message: err.message });
    }
  });

  // 385. POST /api/v1/fleet/siem/forward
  router.post('/api/v1/fleet/siem/forward', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = siemForwarderEngine.forwardSecurityEvent(req.body?.event || req.body || {}, req.body?.forwarder_id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SIEM_FORWARD_ERROR', message: err.message });
    }
  });


  // 386. GET /api/v1/fleet/mdm/stats
  router.get('/api/v1/fleet/mdm/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = mdmCspEngine.getMdmStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'MDM_STATS_ERROR', message: err.message });
    }
  });

  // 387. GET /api/v1/fleet/mdm/csps
  router.get('/api/v1/fleet/mdm/csps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const csps = mdmCspEngine.getCspConfigurations(req.query);
      sendJson(res, 200, { csps, count: csps.length });
    } catch (err) {
      sendJson(res, 500, { error: 'CSP_FETCH_ERROR', message: err.message });
    }
  });

  // 388. GET /api/v1/fleet/mdm/csps/:id
  router.get('/api/v1/fleet/mdm/csps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const csp = mdmCspEngine.getCspConfigurationById(req.params.id);
      if (!csp) {
        return sendJson(res, 404, { error: 'CSP_NOT_FOUND', message: `CSP '${req.params.id}' does not exist` });
      }
      sendJson(res, 200, csp);
    } catch (err) {
      sendJson(res, 500, { error: 'CSP_FETCH_ERROR', message: err.message });
    }
  });

  // 389. POST /api/v1/fleet/mdm/csps
  router.post('/api/v1/fleet/mdm/csps', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const created = mdmCspEngine.createCspConfiguration(req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'CSP_CREATE_ERROR', message: err.message });
    }
  });

  // 390. PATCH /api/v1/fleet/mdm/csps/:id
  router.patch('/api/v1/fleet/mdm/csps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = mdmCspEngine.updateCspConfiguration(req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'CSP_UPDATE_ERROR', message: err.message });
    }
  });

  // 391. DELETE /api/v1/fleet/mdm/csps/:id
  router.delete('/api/v1/fleet/mdm/csps/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const deleted = mdmCspEngine.deleteCspConfiguration(req.params.id);
      sendJson(res, 200, deleted);
    } catch (err) {
      sendJson(res, 400, { error: 'CSP_DELETE_ERROR', message: err.message });
    }
  });

  // 392. GET /api/v1/fleet/mdm/autopilot-hashes
  router.get('/api/v1/fleet/mdm/autopilot-hashes', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const hashes = mdmCspEngine.getAutopilotHardwareHashes(req.query);
      sendJson(res, 200, { hashes, count: hashes.length });
    } catch (err) {
      sendJson(res, 500, { error: 'AP_HASHES_FETCH_ERROR', message: err.message });
    }
  });

  // 393. GET /api/v1/fleet/mdm/autopilot-hashes/:deviceId
  router.get('/api/v1/fleet/mdm/autopilot-hashes/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const hash = mdmCspEngine.getAutopilotHardwareHashByDeviceId(req.params.deviceId);
      if (!hash) {
        return sendJson(res, 404, { error: 'HASH_NOT_FOUND', message: `No 4K hardware hash recorded for '${req.params.deviceId}'` });
      }
      sendJson(res, 200, hash);
    } catch (err) {
      sendJson(res, 500, { error: 'AP_HASH_FETCH_ERROR', message: err.message });
    }
  });

  // 394. POST /api/v1/fleet/mdm/remote-wipe
  router.post('/api/v1/fleet/mdm/remote-wipe', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const wipe = mdmCspEngine.dispatchNativeRemoteWipe(req.body || {});
      sendJson(res, 200, wipe);
    } catch (err) {
      sendJson(res, 400, { error: 'WIPE_DISPATCH_ERROR', message: err.message });
    }
  });

  // 395. GET /api/v1/fleet/mdm/csps/:id/script
  router.get('/api/v1/fleet/mdm/csps/:id/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const csp = mdmCspEngine.getCspConfigurationById(req.params.id);
      if (!csp) {
        return sendJson(res, 404, { error: 'CSP_NOT_FOUND', message: `CSP '${req.params.id}' does not exist` });
      }
      const script = mdmCspEngine.generateCspWmiBridgePowerShellScript(csp);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: 'CSP_SCRIPT_ERROR', message: err.message });
    }
  });


  // ── Dimension 4 & 3: Content Distribution, BITS, P2P Mesh & Hardware TPM mTLS Routes (396–407) ──
  // 396. GET /api/v1/fleet/content-distribution/stats
  router.get('/api/v1/fleet/content-distribution/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const stats = contentDistributionEngine.getContentDistributionStats(db);
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'CONTENT_DIST_STATS_ERROR', message: err.message });
    }
  });

  // 397. GET /api/v1/fleet/bits/jobs
  router.get('/api/v1/fleet/bits/jobs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const jobs = contentDistributionEngine.getBitsJobs(db, req.query || {});
      sendJson(res, 200, { jobs, count: jobs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'BITS_JOBS_FETCH_ERROR', message: err.message });
    }
  });

  // 398. GET /api/v1/fleet/bits/jobs/:id
  router.get('/api/v1/fleet/bits/jobs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const job = contentDistributionEngine.getBitsJobById(db, req.params.id);
      if (!job) {
        return sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: `BITS job '${req.params.id}' not found` });
      }
      sendJson(res, 200, job);
    } catch (err) {
      sendJson(res, 500, { error: 'BITS_JOB_FETCH_ERROR', message: err.message });
    }
  });

  // 399. POST /api/v1/fleet/bits/jobs
  router.post('/api/v1/fleet/bits/jobs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const job = contentDistributionEngine.createBitsJob(db, req.body || {});
      sendJson(res, 201, job);
    } catch (err) {
      sendJson(res, 400, { error: 'BITS_JOB_CREATE_ERROR', message: err.message });
    }
  });

  // 400. PATCH /api/v1/fleet/bits/jobs/:id
  router.patch('/api/v1/fleet/bits/jobs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const updated = contentDistributionEngine.updateBitsJobProgress(db, req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'BITS_JOB_UPDATE_ERROR', message: err.message });
    }
  });

  // 401. DELETE /api/v1/fleet/bits/jobs/:id
  router.delete('/api/v1/fleet/bits/jobs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const cancelled = contentDistributionEngine.cancelBitsJob(db, req.params.id);
      sendJson(res, 200, { success: true, job: cancelled });
    } catch (err) {
      sendJson(res, 400, { error: 'BITS_JOB_CANCEL_ERROR', message: err.message });
    }
  });

  // 402. GET /api/v1/fleet/bits/jobs/:id/script
  router.get('/api/v1/fleet/bits/jobs/:id/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const job = contentDistributionEngine.getBitsJobById(db, req.params.id);
      if (!job) {
        return sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: `BITS job '${req.params.id}' not found` });
      }
      const script = contentDistributionEngine.generateBitsTransferScript(job);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: 'BITS_SCRIPT_ERROR', message: err.message });
    }
  });

  // 403. GET /api/v1/fleet/p2p/seeds
  router.get('/api/v1/fleet/p2p/seeds', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const seeds = contentDistributionEngine.getP2pSeeds(db, req.query || {});
      sendJson(res, 200, { seeds, count: seeds.length });
    } catch (err) {
      sendJson(res, 500, { error: 'P2P_SEEDS_FETCH_ERROR', message: err.message });
    }
  });

  // 404. GET /api/v1/fleet/mtls/certificates
  router.get('/api/v1/fleet/mtls/certificates', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const certs = contentDistributionEngine.getMtlsCertificates(db, req.query || {});
      sendJson(res, 200, { certificates: certs, count: certs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'MTLS_CERTS_FETCH_ERROR', message: err.message });
    }
  });

  // 405. POST /api/v1/fleet/mtls/enroll
  router.post('/api/v1/fleet/mtls/enroll', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const enrolled = contentDistributionEngine.enrollMtlsCertificate(db, req.body || {});
      sendJson(res, 201, enrolled);
    } catch (err) {
      sendJson(res, 400, { error: 'MTLS_ENROLL_ERROR', message: err.message });
    }
  });

  // 406. POST /api/v1/fleet/mtls/revoke
  router.post('/api/v1/fleet/mtls/revoke', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const target = req.body?.id || req.body?.cert_thumbprint;
      if (!target) {
        return sendJson(res, 400, { error: 'TARGET_REQUIRED', message: 'Certificate id or cert_thumbprint is required' });
      }
      const revoked = contentDistributionEngine.revokeMtlsCertificate(db, target, req.body?.reason);
      sendJson(res, 200, { success: true, certificate: revoked });
    } catch (err) {
      sendJson(res, 400, { error: 'MTLS_REVOKE_ERROR', message: err.message });
    }
  });

  // 407. POST /api/v1/fleet/mtls/verify
  router.post('/api/v1/fleet/mtls/verify', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const db = getDb();
      const thumbprint = req.body?.cert_thumbprint;
      const verification = contentDistributionEngine.verifyMtlsClientCert(db, thumbprint);
      sendJson(res, 200, verification);
    } catch (err) {
      sendJson(res, 400, { error: 'MTLS_VERIFY_ERROR', message: err.message });
    }
  });


  // ── Dimension 6: Multi-Tenancy (MSP Organizations, Sites & Collections) & Database HA (408–421) ──
  // 408. GET /api/v1/fleet/tenancy/stats
  router.get('/api/v1/fleet/tenancy/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = multiTenancyEngine.getMultiTenancyStats();
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'TENANCY_STATS_ERROR', message: err.message });
    }
  });

  // 409. GET /api/v1/fleet/tenancy/organizations
  router.get('/api/v1/fleet/tenancy/organizations', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const orgs = multiTenancyEngine.getOrganizations(req.query || {});
      sendJson(res, 200, { organizations: orgs, count: orgs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'ORGS_FETCH_ERROR', message: err.message });
    }
  });

  // 410. GET /api/v1/fleet/tenancy/organizations/:id
  router.get('/api/v1/fleet/tenancy/organizations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const org = multiTenancyEngine.getOrganizationById(req.params.id);
      if (!org) {
        return sendJson(res, 404, { error: 'ORG_NOT_FOUND', message: `Organization '${req.params.id}' not found` });
      }
      sendJson(res, 200, org);
    } catch (err) {
      sendJson(res, 500, { error: 'ORG_FETCH_ERROR', message: err.message });
    }
  });

  // 411. POST /api/v1/fleet/tenancy/organizations
  router.post('/api/v1/fleet/tenancy/organizations', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const org = multiTenancyEngine.createOrganization(req.body || {});
      sendJson(res, 201, org);
    } catch (err) {
      sendJson(res, 400, { error: 'ORG_CREATE_ERROR', message: err.message });
    }
  });

  // 412. PATCH /api/v1/fleet/tenancy/organizations/:id
  router.patch('/api/v1/fleet/tenancy/organizations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = multiTenancyEngine.updateOrganization(req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'ORG_UPDATE_ERROR', message: err.message });
    }
  });

  // 413. DELETE /api/v1/fleet/tenancy/organizations/:id
  router.delete('/api/v1/fleet/tenancy/organizations/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = multiTenancyEngine.deleteOrganization(req.params.id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'ORG_DELETE_ERROR', message: err.message });
    }
  });

  // 414. GET /api/v1/fleet/tenancy/sites
  router.get('/api/v1/fleet/tenancy/sites', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const sites = multiTenancyEngine.getSites(req.query?.org_id);
      sendJson(res, 200, { sites, count: sites.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SITES_FETCH_ERROR', message: err.message });
    }
  });

  // 415. POST /api/v1/fleet/tenancy/sites
  router.post('/api/v1/fleet/tenancy/sites', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const site = multiTenancyEngine.createSite(req.body || {});
      sendJson(res, 201, site);
    } catch (err) {
      sendJson(res, 400, { error: 'SITE_CREATE_ERROR', message: err.message });
    }
  });

  // 416. PATCH /api/v1/fleet/tenancy/sites/:id
  router.patch('/api/v1/fleet/tenancy/sites/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = multiTenancyEngine.updateSite(req.params.id, req.body || {});
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'SITE_UPDATE_ERROR', message: err.message });
    }
  });

  // 417. DELETE /api/v1/fleet/tenancy/sites/:id
  router.delete('/api/v1/fleet/tenancy/sites/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = multiTenancyEngine.deleteSite(req.params.id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'SITE_DELETE_ERROR', message: err.message });
    }
  });

  // 418. GET /api/v1/fleet/tenancy/collections
  router.get('/api/v1/fleet/tenancy/collections', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const collections = multiTenancyEngine.getScopedCollections(req.query?.org_id);
      sendJson(res, 200, { collections, count: collections.length });
    } catch (err) {
      sendJson(res, 500, { error: 'COLLECTIONS_FETCH_ERROR', message: err.message });
    }
  });

  // 419. POST /api/v1/fleet/tenancy/collections
  router.post('/api/v1/fleet/tenancy/collections', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const col = multiTenancyEngine.createScopedCollection(req.body || {});
      sendJson(res, 201, col);
    } catch (err) {
      sendJson(res, 400, { error: 'COLLECTION_CREATE_ERROR', message: err.message });
    }
  });

  // 420. DELETE /api/v1/fleet/tenancy/collections/:id
  router.delete('/api/v1/fleet/tenancy/collections/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = multiTenancyEngine.deleteScopedCollection(req.params.id);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: 'COLLECTION_DELETE_ERROR', message: err.message });
    }
  });

  // 421. GET /api/v1/fleet/tenancy/database-health
  router.get('/api/v1/fleet/tenancy/database-health', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const health = multiTenancyEngine.getDatabaseHealth();
      sendJson(res, 200, health);
    } catch (err) {
      sendJson(res, 500, { error: 'DB_HEALTH_ERROR', message: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // ENTERPRISE SECRETS VAULT & DPAPI-NG / HSM CREDENTIAL ESCROW (422–430)
  // ══════════════════════════════════════════════════════════════════

  // 422. GET /api/v1/fleet/vault/stats
  router.get('/api/v1/fleet/vault/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      sendJson(res, 200, engine.getVaultStats());
    } catch (err) {
      sendJson(res, 500, { error: 'VAULT_STATS_ERROR', message: err.message });
    }
  });

  // 423. GET /api/v1/fleet/vault/secrets
  router.get('/api/v1/fleet/vault/secrets', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const secrets = engine.getSecrets(req.query || {});
      sendJson(res, 200, { secrets, count: secrets.length });
    } catch (err) {
      sendJson(res, 500, { error: 'VAULT_SECRETS_FETCH_ERROR', message: err.message });
    }
  });

  // 424. GET /api/v1/fleet/vault/secrets/:id
  router.get('/api/v1/fleet/vault/secrets/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const secret = engine.getSecretById(req.params.id);
      if (!secret) {
        sendJson(res, 404, { error: 'SECRET_NOT_FOUND', message: 'Vault secret not found' });
        return;
      }
      sendJson(res, 200, secret);
    } catch (err) {
      sendJson(res, 500, { error: 'VAULT_SECRET_GET_ERROR', message: err.message });
    }
  });

  // 425. POST /api/v1/fleet/vault/secrets
  router.post('/api/v1/fleet/vault/secrets', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const stored = engine.storeSecret(req.body || {}, req.headers['x-actor'] || 'FleetAdmin');
      sendJson(res, 201, stored);
    } catch (err) {
      sendJson(res, 400, { error: 'VAULT_STORE_ERROR', message: err.message });
    }
  });

  // 426. POST /api/v1/fleet/vault/secrets/:id/decrypt
  router.post('/api/v1/fleet/vault/secrets/:id/decrypt', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { dual_custody_ref_id } = req.body || {};
    const actor = req.headers['x-actor'] || 'FleetAdmin';
    try {
      const engine = new VaultSecretsEngine(getDb());
      const decrypted = engine.decryptSecret(req.params.id, actor, dual_custody_ref_id);
      sendJson(res, 200, decrypted);
    } catch (err) {
      const status = err.message.includes('DUAL_CUSTODY_REQUIRED') ? 403 : 400;
      sendJson(res, status, { error: 'VAULT_DECRYPT_ERROR', message: err.message });
    }
  });

  // 427. POST /api/v1/fleet/vault/secrets/:id/rotate
  router.post('/api/v1/fleet/vault/secrets/:id/rotate', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    const { new_plaintext } = req.body || {};
    if (!new_plaintext) {
      sendJson(res, 400, { error: 'MISSING_PAYLOAD', message: 'Missing new_plaintext for rotation' });
      return;
    }
    try {
      const engine = new VaultSecretsEngine(getDb());
      const rotated = engine.rotateSecret(req.params.id, new_plaintext, req.headers['x-actor'] || 'FleetAdmin');
      sendJson(res, 200, rotated);
    } catch (err) {
      sendJson(res, 400, { error: 'VAULT_ROTATE_ERROR', message: err.message });
    }
  });

  // 428. DELETE /api/v1/fleet/vault/secrets/:id
  router.delete('/api/v1/fleet/vault/secrets/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const deleted = engine.deleteSecret(req.params.id, req.headers['x-actor'] || 'FleetAdmin');
      sendJson(res, 200, { success: deleted, secret_id: req.params.id });
    } catch (err) {
      sendJson(res, 400, { error: 'VAULT_DELETE_ERROR', message: err.message });
    }
  });

  // 429. GET /api/v1/fleet/vault/audits
  router.get('/api/v1/fleet/vault/audits', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const audits = engine.getVaultAudits(parseInt(req.query?.limit || '50', 10));
      sendJson(res, 200, { audits, count: audits.length });
    } catch (err) {
      sendJson(res, 500, { error: 'VAULT_AUDITS_ERROR', message: err.message });
    }
  });

  // 430. GET /api/v1/fleet/vault/powershell-snippet
  router.get('/api/v1/fleet/vault/powershell-snippet', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new VaultSecretsEngine(getDb());
      const script = engine.generateDpapiPowerShellSnippet(req.query?.scope || 'BITLOCKER_RECOVERY_KEY');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: 'SNIPPET_ERROR', message: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // OPENAPI 3.0 SPECIFICATION & INTERACTIVE SWAGGER UI DOCS (431–432)
  // ══════════════════════════════════════════════════════════════════

  // 431. GET /api/v1/openapi.json
  router.get('/api/v1/openapi.json', (req, res) => {
    try {
      const spec = openApiSpecEngine.getOpenApiSpec();
      sendJson(res, 200, spec);
    } catch (err) {
      sendJson(res, 500, { error: 'OPENAPI_SPEC_ERROR', message: err.message });
    }
  });

  // 432. GET /api/v1/docs
  router.get('/api/v1/docs', (req, res) => {
    try {
      const html = openApiSpecEngine.generateSwaggerHtml();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (err) {
      sendJson(res, 500, { error: 'DOCS_ERROR', message: err.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // LIVE DISTRIBUTED FLEET QUERY ENGINE (CMPIVOT / TANIUM SENSORS) (433–440)
  // ══════════════════════════════════════════════════════════════════

  // 433. GET /api/v1/fleet/queries/stats
  router.get('/api/v1/fleet/queries/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      sendJson(res, 200, engine.getLiveQueryStats());
    } catch (err) {
      sendJson(res, 500, { error: 'QUERY_STATS_ERROR', message: err.message });
    }
  });

  // 434. GET /api/v1/fleet/queries/entities
  router.get('/api/v1/fleet/queries/entities', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const entities = engine.getEntities(req.query?.category || null);
      sendJson(res, 200, { entities, count: entities.length });
    } catch (err) {
      sendJson(res, 500, { error: 'ENTITIES_FETCH_ERROR', message: err.message });
    }
  });

  // 435. GET /api/v1/fleet/queries/sessions
  router.get('/api/v1/fleet/queries/sessions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const sessions = engine.getSessions(parseInt(req.query?.limit || '50', 10));
      sendJson(res, 200, { sessions, count: sessions.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SESSIONS_FETCH_ERROR', message: err.message });
    }
  });

  // 436. GET /api/v1/fleet/queries/sessions/:id
  router.get('/api/v1/fleet/queries/sessions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const session = engine.getSessionById(req.params.id);
      if (!session) {
        sendJson(res, 404, { error: 'SESSION_NOT_FOUND', message: 'Query session not found' });
        return;
      }
      sendJson(res, 200, session);
    } catch (err) {
      sendJson(res, 500, { error: 'SESSION_GET_ERROR', message: err.message });
    }
  });

  // 437. POST /api/v1/fleet/queries/sessions
  router.post('/api/v1/fleet/queries/sessions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const created = engine.dispatchLiveQuery(req.body || {}, realtimePushEngine);
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'QUERY_DISPATCH_ERROR', message: err.message });
    }
  });

  // 438. POST /api/v1/fleet/queries/sessions/:id/cancel
  router.post('/api/v1/fleet/queries/sessions/:id/cancel', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const cancelled = engine.cancelQuery(req.params.id);
      sendJson(res, 200, { success: cancelled, query_id: req.params.id });
    } catch (err) {
      sendJson(res, 400, { error: 'QUERY_CANCEL_ERROR', message: err.message });
    }
  });

  // 439. GET /api/v1/fleet/queries/sessions/:id/results
  router.get('/api/v1/fleet/queries/sessions/:id/results', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const results = engine.getQueryResults(req.params.id, parseInt(req.query?.limit || '500', 10));
      sendJson(res, 200, { query_id: req.params.id, results, count: results.length });
    } catch (err) {
      sendJson(res, 500, { error: 'RESULTS_FETCH_ERROR', message: err.message });
    }
  });

  // 440. GET /api/v1/fleet/queries/sessions/:id/export
  router.get('/api/v1/fleet/queries/sessions/:id/export', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new LiveQueryEngine(getDb());
      const csv = engine.exportResultsToCsv(req.params.id);
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="cmpivot_query_${req.params.id}.csv"`
      });
      res.end(csv);
    } catch (err) {
      sendJson(res, 500, { error: 'EXPORT_ERROR', message: err.message });
    }
  });

  // ── INCIDENT RESPONSE & FORENSIC TRIAGE (Endpoints 441–452) ──────────────────

  // 441. GET /api/v1/fleet/ir/stats
  router.get('/api/v1/fleet/ir/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      sendJson(res, 200, engine.getIncidentResponseStats());
    } catch (err) {
      sendJson(res, 500, { error: 'IR_STATS_ERROR', message: err.message });
    }
  });

  // 442. GET /api/v1/fleet/ir/playbooks
  router.get('/api/v1/fleet/ir/playbooks', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const playbooks = engine.getPlaybooks();
      sendJson(res, 200, { playbooks, count: playbooks.length });
    } catch (err) {
      sendJson(res, 500, { error: 'PLAYBOOKS_FETCH_ERROR', message: err.message });
    }
  });

  // 443. POST /api/v1/fleet/ir/playbooks
  router.post('/api/v1/fleet/ir/playbooks', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const created = engine.createPlaybook(req.body || {});
      sendJson(res, 201, created);
    } catch (err) {
      sendJson(res, 400, { error: 'PLAYBOOK_CREATE_ERROR', message: err.message });
    }
  });

  // 444. GET /api/v1/fleet/ir/playbooks/:id
  router.get('/api/v1/fleet/ir/playbooks/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const playbook = engine.getPlaybookById(req.params.id);
      if (!playbook) {
        sendJson(res, 404, { error: 'PLAYBOOK_NOT_FOUND', message: 'Playbook not found' });
        return;
      }
      sendJson(res, 200, playbook);
    } catch (err) {
      sendJson(res, 500, { error: 'PLAYBOOK_FETCH_ERROR', message: err.message });
    }
  });

  // 445. PATCH /api/v1/fleet/ir/playbooks/:id
  router.patch('/api/v1/fleet/ir/playbooks/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const updated = engine.updatePlaybook(req.params.id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: 'PLAYBOOK_NOT_FOUND', message: 'Playbook not found' });
        return;
      }
      sendJson(res, 200, updated);
    } catch (err) {
      sendJson(res, 400, { error: 'PLAYBOOK_UPDATE_ERROR', message: err.message });
    }
  });

  // 446. DELETE /api/v1/fleet/ir/playbooks/:id
  router.delete('/api/v1/fleet/ir/playbooks/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const deleted = engine.deletePlaybook(req.params.id);
      if (!deleted) {
        sendJson(res, 404, { error: 'PLAYBOOK_NOT_FOUND', message: 'Playbook not found' });
        return;
      }
      sendJson(res, 200, { success: true, id: req.params.id });
    } catch (err) {
      sendJson(res, 500, { error: 'PLAYBOOK_DELETE_ERROR', message: err.message });
    }
  });

  // 447. GET /api/v1/fleet/ir/containment
  router.get('/api/v1/fleet/ir/containment', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const states = engine.getAllContainmentStates();
      sendJson(res, 200, { containment_states: states, count: states.length });
    } catch (err) {
      sendJson(res, 500, { error: 'CONTAINMENT_FETCH_ERROR', message: err.message });
    }
  });

  // 448. POST /api/v1/fleet/devices/:id/contain
  router.post('/api/v1/fleet/devices/:id/contain', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const status = engine.containHost(req.params.id, req.body || {});
      sendJson(res, 200, { success: true, containment: status });
    } catch (err) {
      sendJson(res, 400, { error: 'CONTAIN_HOST_ERROR', message: err.message });
    }
  });

  // 449. POST /api/v1/fleet/devices/:id/release
  router.post('/api/v1/fleet/devices/:id/release', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const status = engine.releaseHost(req.params.id, req.body || {});
      sendJson(res, 200, { success: true, containment: status });
    } catch (err) {
      sendJson(res, 400, { error: 'RELEASE_HOST_ERROR', message: err.message });
    }
  });

  // 450. GET /api/v1/fleet/ir/triage
  router.get('/api/v1/fleet/ir/triage', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const packages = engine.getTriagePackages(req.query?.device_id || null);
      sendJson(res, 200, { packages, count: packages.length });
    } catch (err) {
      sendJson(res, 500, { error: 'TRIAGE_FETCH_ERROR', message: err.message });
    }
  });

  // 451. POST /api/v1/fleet/devices/:id/triage
  router.post('/api/v1/fleet/devices/:id/triage', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const pkg = engine.createTriagePackage({
        device_id: req.params.id,
        hostname: req.body?.hostname || req.params.id,
        trigger_source: req.body?.trigger_source || 'MANUAL_ADMIN',
        artifacts: req.body?.artifacts
      });
      sendJson(res, 202, { success: true, package: pkg });
    } catch (err) {
      sendJson(res, 400, { error: 'TRIAGE_DISPATCH_ERROR', message: err.message });
    }
  });

  // 452. GET /api/v1/fleet/ir/triage/:id/download
  router.get('/api/v1/fleet/ir/triage/:id/download', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const engine = new IncidentResponseEngine(getDb());
      const pkg = engine.getTriagePackageById(req.params.id);
      if (!pkg) {
        sendJson(res, 404, { error: 'PACKAGE_NOT_FOUND', message: 'Triage package not found' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="' + (pkg.package_name || 'triage.zip') + '"',
        'X-Triage-Sha256': pkg.sha256_hash || ''
      });
      res.end(Buffer.from('PK\x03\x04LocalPilot-Forensic-Triage-Archive-Payload'));
    } catch (err) {
      sendJson(res, 500, { error: 'DOWNLOAD_ERROR', message: err.message });
    }
  });

  // 453. GET /api/v1/fleet/dha/stats
  router.get('/api/v1/fleet/dha/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = DeviceHealthAttestationEngine.getAttestationStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'DHA_STATS_ERROR', message: err.message });
    }
  });

  // 454. GET /api/v1/fleet/dha/policies
  router.get('/api/v1/fleet/dha/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = DeviceHealthAttestationEngine.getPolicies(getDb());
      sendJson(res, 200, { policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'DHA_POLICIES_ERROR', message: err.message });
    }
  });

  // 455. POST /api/v1/fleet/dha/policies
  router.post('/api/v1/fleet/dha/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: 'NAME_REQUIRED', message: 'Policy name is required' });
        return;
      }
      const policy = DeviceHealthAttestationEngine.createPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 456. GET /api/v1/fleet/dha/policies/:id
  router.get('/api/v1/fleet/dha/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = DeviceHealthAttestationEngine.getPolicyById(getDb(), req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DHA policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 457. PATCH /api/v1/fleet/dha/policies/:id
  router.patch('/api/v1/fleet/dha/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = DeviceHealthAttestationEngine.updatePolicy(getDb(), req.params.id, req.body || {});
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DHA policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 458. DELETE /api/v1/fleet/dha/policies/:id
  router.delete('/api/v1/fleet/dha/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = DeviceHealthAttestationEngine.deletePolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'DHA policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Policy deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 459. GET /api/v1/fleet/dha/reports
  router.get('/api/v1/fleet/dha/reports', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { device_id, status } = req.query || {};
      const reports = DeviceHealthAttestationEngine.getReports(getDb(), { deviceId: device_id, status });
      sendJson(res, 200, { reports, count: reports.length });
    } catch (err) {
      sendJson(res, 500, { error: 'DHA_REPORTS_ERROR', message: err.message });
    }
  });

  // 460. GET /api/v1/fleet/devices/:id/dha/report
  router.get('/api/v1/fleet/devices/:id/dha/report', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const report = DeviceHealthAttestationEngine.getReportByDeviceId(getDb(), req.params.id);
      if (!report) {
        sendJson(res, 404, { error: 'REPORT_NOT_FOUND', message: 'No DHA report found for device' });
        return;
      }
      sendJson(res, 200, report);
    } catch (err) {
      sendJson(res, 500, { error: 'REPORT_FETCH_ERROR', message: err.message });
    }
  });

  // 461. GET /api/v1/fleet/dha/microsegmentation
  router.get('/api/v1/fleet/dha/microsegmentation', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = DeviceHealthAttestationEngine.getMicrosegmentationPolicies(getDb());
      sendJson(res, 200, { policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'MSP_POLICIES_ERROR', message: err.message });
    }
  });

  // 462. POST /api/v1/fleet/dha/microsegmentation
  router.post('/api/v1/fleet/dha/microsegmentation', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: 'NAME_REQUIRED', message: 'Microsegmentation rule name is required' });
        return;
      }
      const policy = DeviceHealthAttestationEngine.createMicrosegmentationPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'MSP_CREATE_ERROR', message: err.message });
    }
  });

  // 463. PATCH /api/v1/fleet/dha/microsegmentation/:id
  router.patch('/api/v1/fleet/dha/microsegmentation/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = DeviceHealthAttestationEngine.updateMicrosegmentationPolicy(getDb(), req.params.id, req.body || {});
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Microsegmentation policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'MSP_UPDATE_ERROR', message: err.message });
    }
  });

  // 464. DELETE /api/v1/fleet/dha/microsegmentation/:id
  router.delete('/api/v1/fleet/dha/microsegmentation/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = DeviceHealthAttestationEngine.deleteMicrosegmentationPolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Microsegmentation policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Policy deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'MSP_DELETE_ERROR', message: err.message });
    }
  });

  // 465. GET /api/v1/fleet/devices/:id/dha/firewall-rules
  router.get('/api/v1/fleet/devices/:id/dha/firewall-rules', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const rules = DeviceHealthAttestationEngine.generateHostFirewallRules(getDb(), req.params.id);
      sendJson(res, 200, rules);
    } catch (err) {
      sendJson(res, 500, { error: 'FIREWALL_RULES_ERROR', message: err.message });
    }
  });


  // 466. GET /api/v1/fleet/hunting/stats
  router.get('/api/v1/fleet/hunting/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = ThreatHuntingEngine.getHuntingStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'HUNTING_STATS_ERROR', message: err.message });
    }
  });

  // 467. GET /api/v1/fleet/hunting/campaigns
  router.get('/api/v1/fleet/hunting/campaigns', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { status, hunt_type } = req.query || {};
      const campaigns = ThreatHuntingEngine.getCampaigns(getDb(), { status, hunt_type });
      sendJson(res, 200, { campaigns, count: campaigns.length });
    } catch (err) {
      sendJson(res, 500, { error: 'HUNTING_CAMPAIGNS_ERROR', message: err.message });
    }
  });

  // 468. POST /api/v1/fleet/hunting/campaigns
  router.post('/api/v1/fleet/hunting/campaigns', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name || !req.body?.pattern_definition) {
        sendJson(res, 400, { error: 'MISSING_FIELDS', message: 'Name and pattern_definition are required' });
        return;
      }
      const campaign = ThreatHuntingEngine.createCampaign(getDb(), req.body);
      sendJson(res, 201, { success: true, campaign });
    } catch (err) {
      sendJson(res, 400, { error: 'CAMPAIGN_CREATE_ERROR', message: err.message });
    }
  });

  // 469. GET /api/v1/fleet/hunting/campaigns/:id
  router.get('/api/v1/fleet/hunting/campaigns/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const campaign = ThreatHuntingEngine.getCampaignById(getDb(), req.params.id);
      if (!campaign) {
        sendJson(res, 404, { error: 'HUNT_NOT_FOUND', message: 'Threat hunt campaign not found' });
        return;
      }
      sendJson(res, 200, campaign);
    } catch (err) {
      sendJson(res, 500, { error: 'CAMPAIGN_FETCH_ERROR', message: err.message });
    }
  });

  // 470. POST /api/v1/fleet/hunting/campaigns/:id/cancel
  router.post('/api/v1/fleet/hunting/campaigns/:id/cancel', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = ThreatHuntingEngine.cancelCampaign(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'HUNT_NOT_FOUND', message: 'Threat hunt campaign not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Campaign cancelled' });
    } catch (err) {
      sendJson(res, 500, { error: 'CAMPAIGN_CANCEL_ERROR', message: err.message });
    }
  });

  // 471. DELETE /api/v1/fleet/hunting/campaigns/:id
  router.delete('/api/v1/fleet/hunting/campaigns/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = ThreatHuntingEngine.deleteCampaign(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'HUNT_NOT_FOUND', message: 'Threat hunt campaign not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Campaign deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'CAMPAIGN_DELETE_ERROR', message: err.message });
    }
  });

  // 472. GET /api/v1/fleet/hunting/matches
  router.get('/api/v1/fleet/hunting/matches', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const { hunt_id, device_id } = req.query || {};
      const matches = ThreatHuntingEngine.getMatches(getDb(), { huntId: hunt_id, deviceId: device_id });
      sendJson(res, 200, { matches, count: matches.length });
    } catch (err) {
      sendJson(res, 500, { error: 'MATCHES_FETCH_ERROR', message: err.message });
    }
  });

  // 473. GET /api/v1/fleet/hunting/campaigns/:id/matches
  router.get('/api/v1/fleet/hunting/campaigns/:id/matches', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const matches = ThreatHuntingEngine.getMatches(getDb(), { huntId: req.params.id });
      sendJson(res, 200, { matches, count: matches.length });
    } catch (err) {
      sendJson(res, 500, { error: 'HUNT_MATCHES_ERROR', message: err.message });
    }
  });

  // 474. GET /api/v1/fleet/hunting/iocs
  router.get('/api/v1/fleet/hunting/iocs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const iocs = ThreatHuntingEngine.getWatchlistIndicators(getDb());
      sendJson(res, 200, { iocs, count: iocs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'IOCS_FETCH_ERROR', message: err.message });
    }
  });

  // 475. POST /api/v1/fleet/hunting/iocs
  router.post('/api/v1/fleet/hunting/iocs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.indicator_value || !req.body?.threat_name) {
        sendJson(res, 400, { error: 'MISSING_FIELDS', message: 'indicator_value and threat_name are required' });
        return;
      }
      const ioc = ThreatHuntingEngine.createWatchlistIndicator(getDb(), req.body);
      sendJson(res, 201, { success: true, ioc });
    } catch (err) {
      sendJson(res, 400, { error: 'IOC_CREATE_ERROR', message: err.message });
    }
  });

  // 476. DELETE /api/v1/fleet/hunting/iocs/:id
  router.delete('/api/v1/fleet/hunting/iocs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = ThreatHuntingEngine.deleteWatchlistIndicator(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'IOC_NOT_FOUND', message: 'Indicator not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Indicator deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'IOC_DELETE_ERROR', message: err.message });
    }
  });

  // 477. GET /api/v1/fleet/hunting/campaigns/:id/script
  router.get('/api/v1/fleet/hunting/campaigns/:id/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const scriptPayload = ThreatHuntingEngine.generateHuntScript(getDb(), req.params.id);
      if (!scriptPayload) {
        sendJson(res, 404, { error: 'HUNT_NOT_FOUND', message: 'Campaign not found' });
        return;
      }
      sendJson(res, 200, scriptPayload);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPT_GEN_ERROR', message: err.message });
    }
  });

  // 478. GET /api/v1/fleet/sandbox/stats
  router.get('/api/v1/fleet/sandbox/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = SandboxDetonationEngine.getDetonationStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'SANDBOX_STATS_ERROR', message: err.message });
    }
  });

  // 479. GET /api/v1/fleet/sandbox/jobs
  router.get('/api/v1/fleet/sandbox/jobs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const jobs = SandboxDetonationEngine.getDetonationJobs(getDb(), req.query || {});
      sendJson(res, 200, { jobs, count: jobs.length });
    } catch (err) {
      sendJson(res, 500, { error: 'SANDBOX_JOBS_ERROR', message: err.message });
    }
  });

  // 480. POST /api/v1/fleet/sandbox/jobs
  router.post('/api/v1/fleet/sandbox/jobs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.sample_name || !req.body?.sample_sha256) {
        sendJson(res, 400, { error: 'MISSING_FIELDS', message: 'sample_name and sample_sha256 are required' });
        return;
      }
      const job = SandboxDetonationEngine.submitDetonationJob(getDb(), req.body);
      sendJson(res, 201, { success: true, job });
    } catch (err) {
      sendJson(res, 400, { error: 'SANDBOX_SUBMIT_ERROR', message: err.message });
    }
  });

  // 481. GET /api/v1/fleet/sandbox/jobs/:id
  router.get('/api/v1/fleet/sandbox/jobs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const job = SandboxDetonationEngine.getDetonationJobById(getDb(), req.params.id);
      if (!job) {
        sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: 'Detonation job not found' });
        return;
      }
      sendJson(res, 200, job);
    } catch (err) {
      sendJson(res, 500, { error: 'JOB_FETCH_ERROR', message: err.message });
    }
  });

  // 482. POST /api/v1/fleet/sandbox/jobs/:id/results
  router.post('/api/v1/fleet/sandbox/jobs/:id/results', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const job = SandboxDetonationEngine.ingestDetonationResult(getDb(), req.params.id, req.body || {});
      if (!job) {
        sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: 'Detonation job not found' });
        return;
      }
      sendJson(res, 200, { success: true, job });
    } catch (err) {
      sendJson(res, 500, { error: 'RESULT_INGEST_ERROR', message: err.message });
    }
  });

  // 483. POST /api/v1/fleet/sandbox/jobs/:id/cancel
  router.post('/api/v1/fleet/sandbox/jobs/:id/cancel', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = SandboxDetonationEngine.cancelDetonationJob(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: 'Detonation job not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Detonation job cancelled' });
    } catch (err) {
      sendJson(res, 500, { error: 'JOB_CANCEL_ERROR', message: err.message });
    }
  });

  // 484. DELETE /api/v1/fleet/sandbox/jobs/:id
  router.delete('/api/v1/fleet/sandbox/jobs/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = SandboxDetonationEngine.deleteDetonationJob(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: 'Detonation job not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Detonation job deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'JOB_DELETE_ERROR', message: err.message });
    }
  });

  // 485. GET /api/v1/fleet/sandbox/jobs/:id/graph
  router.get('/api/v1/fleet/sandbox/jobs/:id/graph', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const graph = SandboxDetonationEngine.getProcessLineageGraph(getDb(), { detonation_id: req.params.id });
      sendJson(res, 200, graph);
    } catch (err) {
      sendJson(res, 500, { error: 'GRAPH_FETCH_ERROR', message: err.message });
    }
  });

  // 486. GET /api/v1/fleet/sandbox/events
  router.get('/api/v1/fleet/sandbox/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const events = SandboxDetonationEngine.getBehavioralEvents(getDb(), req.query || {});
      sendJson(res, 200, { events, count: events.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EVENTS_FETCH_ERROR', message: err.message });
    }
  });

  // 487. POST /api/v1/fleet/sandbox/events
  router.post('/api/v1/fleet/sandbox/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const event = SandboxDetonationEngine.logBehavioralEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: 'EVENT_LOG_ERROR', message: err.message });
    }
  });

  // 488. GET /api/v1/fleet/sandbox/jobs/:id/script
  router.get('/api/v1/fleet/sandbox/jobs/:id/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const scriptPayload = SandboxDetonationEngine.generateDetonationScript(getDb(), req.params.id);
      if (!scriptPayload) {
        sendJson(res, 404, { error: 'JOB_NOT_FOUND', message: 'Detonation job not found' });
        return;
      }
      sendJson(res, 200, scriptPayload);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPT_GEN_ERROR', message: err.message });
    }
  });

  // 489. GET /api/v1/fleet/web-protection/stats
  router.get('/api/v1/fleet/web-protection/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = WebProtectionEngine.getWebProtectionStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: 'WEB_STATS_ERROR', message: err.message });
    }
  });

  // 490. GET /api/v1/fleet/web-protection/policies
  router.get('/api/v1/fleet/web-protection/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = WebProtectionEngine.getPolicies(getDb(), req.query || {});
      sendJson(res, 200, { policies, count: policies.length });
    } catch (err) {
      sendJson(res, 500, { error: 'WEB_POLICIES_ERROR', message: err.message });
    }
  });

  // 491. POST /api/v1/fleet/web-protection/policies
  router.post('/api/v1/fleet/web-protection/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: 'MISSING_FIELDS', message: 'name is required' });
        return;
      }
      const policy = WebProtectionEngine.createPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'WEB_POLICY_CREATE_ERROR', message: err.message });
    }
  });

  // 492. GET /api/v1/fleet/web-protection/policies/:id
  router.get('/api/v1/fleet/web-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = WebProtectionEngine.getPolicyById(getDb(), req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Policy not found' });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_FETCH_ERROR', message: err.message });
    }
  });

  // 493. PATCH /api/v1/fleet/web-protection/policies/:id
  router.patch('/api/v1/fleet/web-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = WebProtectionEngine.updatePolicy(getDb(), req.params.id, req.body || {});
      if (!policy) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: 'POLICY_UPDATE_ERROR', message: err.message });
    }
  });

  // 494. DELETE /api/v1/fleet/web-protection/policies/:id
  router.delete('/api/v1/fleet/web-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = WebProtectionEngine.deletePolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'POLICY_NOT_FOUND', message: 'Policy not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Policy deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'POLICY_DELETE_ERROR', message: err.message });
    }
  });

  // 495. GET /api/v1/fleet/web-protection/indicators
  router.get('/api/v1/fleet/web-protection/indicators', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const indicators = WebProtectionEngine.getIndicatorRules(getDb(), req.query || {});
      sendJson(res, 200, { indicators, count: indicators.length });
    } catch (err) {
      sendJson(res, 500, { error: 'INDICATORS_FETCH_ERROR', message: err.message });
    }
  });

  // 496. POST /api/v1/fleet/web-protection/indicators
  router.post('/api/v1/fleet/web-protection/indicators', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.indicator_value) {
        sendJson(res, 400, { error: 'MISSING_FIELDS', message: 'indicator_value is required' });
        return;
      }
      const indicator = WebProtectionEngine.createIndicatorRule(getDb(), req.body);
      sendJson(res, 201, { success: true, indicator });
    } catch (err) {
      sendJson(res, 400, { error: 'INDICATOR_CREATE_ERROR', message: err.message });
    }
  });

  // 497. DELETE /api/v1/fleet/web-protection/indicators/:id
  router.delete('/api/v1/fleet/web-protection/indicators/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = WebProtectionEngine.deleteIndicatorRule(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: 'INDICATOR_NOT_FOUND', message: 'Indicator not found' });
        return;
      }
      sendJson(res, 200, { success: true, message: 'Indicator deleted' });
    } catch (err) {
      sendJson(res, 500, { error: 'INDICATOR_DELETE_ERROR', message: err.message });
    }
  });

  // 498. GET /api/v1/fleet/web-protection/events
  router.get('/api/v1/fleet/web-protection/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const events = WebProtectionEngine.getWebProtectionEvents(getDb(), req.query || {});
      sendJson(res, 200, { events, count: events.length });
    } catch (err) {
      sendJson(res, 500, { error: 'EVENTS_FETCH_ERROR', message: err.message });
    }
  });

  // 499. POST /api/v1/fleet/web-protection/events
  router.post('/api/v1/fleet/web-protection/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const event = WebProtectionEngine.logWebProtectionEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: 'EVENT_LOG_ERROR', message: err.message });
    }
  });

  // 500. GET /api/v1/fleet/web-protection/script/:deviceId
  router.get('/api/v1/fleet/web-protection/script/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = WebProtectionEngine.generateWebProtectionScript(getDb(), req.params.deviceId);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: 'SCRIPT_GEN_ERROR', message: err.message });
    }
  });


  // --- Iteration 49: USB & Peripheral Device Control Endpoints (501-512) ---

  // 501. GET /api/v1/fleet/peripheral-control/stats
  router.get('/api/v1/fleet/peripheral-control/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = PeripheralControlEngine.getPeripheralControlStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "STATS_FETCH_ERROR", message: err.message });
    }
  });

  // 502. GET /api/v1/fleet/peripheral-control/policies
  router.get('/api/v1/fleet/peripheral-control/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = PeripheralControlEngine.getPolicies(getDb());
      sendJson(res, 200, policies);
    } catch (err) {
      sendJson(res, 500, { error: "POLICIES_FETCH_ERROR", message: err.message });
    }
  });

  // 503. POST /api/v1/fleet/peripheral-control/policies
  router.post('/api/v1/fleet/peripheral-control/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "Policy name is required" });
        return;
      }
      const policy = PeripheralControlEngine.createPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_CREATE_ERROR", message: err.message });
    }
  });

  // 504. GET /api/v1/fleet/peripheral-control/policies/:id
  router.get('/api/v1/fleet/peripheral-control/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = PeripheralControlEngine.getPolicyById(getDb(), req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_FETCH_ERROR", message: err.message });
    }
  });

  // 505. PATCH /api/v1/fleet/peripheral-control/policies/:id
  router.patch('/api/v1/fleet/peripheral-control/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = PeripheralControlEngine.updatePolicy(getDb(), req.params.id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, policy: updated });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_UPDATE_ERROR", message: err.message });
    }
  });

  // 506. DELETE /api/v1/fleet/peripheral-control/policies/:id
  router.delete('/api/v1/fleet/peripheral-control/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = PeripheralControlEngine.deletePolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Policy deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_DELETE_ERROR", message: err.message });
    }
  });

  // 507. GET /api/v1/fleet/peripheral-control/exceptions
  router.get('/api/v1/fleet/peripheral-control/exceptions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const exceptions = PeripheralControlEngine.getExceptions(getDb(), req.query?.policy_id);
      sendJson(res, 200, exceptions);
    } catch (err) {
      sendJson(res, 500, { error: "EXCEPTIONS_FETCH_ERROR", message: err.message });
    }
  });

  // 508. POST /api/v1/fleet/peripheral-control/exceptions
  router.post('/api/v1/fleet/peripheral-control/exceptions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.friendly_name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "friendly_name is required" });
        return;
      }
      const exception = PeripheralControlEngine.createException(getDb(), req.body);
      sendJson(res, 201, { success: true, exception });
    } catch (err) {
      sendJson(res, 400, { error: "EXCEPTION_CREATE_ERROR", message: err.message });
    }
  });

  // 509. DELETE /api/v1/fleet/peripheral-control/exceptions/:id
  router.delete('/api/v1/fleet/peripheral-control/exceptions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = PeripheralControlEngine.deleteException(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "EXCEPTION_NOT_FOUND", message: "Exception not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Exception deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "EXCEPTION_DELETE_ERROR", message: err.message });
    }
  });

  // 510. GET /api/v1/fleet/peripheral-control/events
  router.get('/api/v1/fleet/peripheral-control/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const events = PeripheralControlEngine.getPeripheralEvents(getDb(), req.query || {});
      sendJson(res, 200, { events, count: events.length });
    } catch (err) {
      sendJson(res, 500, { error: "EVENTS_FETCH_ERROR", message: err.message });
    }
  });

  // 511. POST /api/v1/fleet/peripheral-control/events
  router.post('/api/v1/fleet/peripheral-control/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.event_type) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id and event_type are required" });
        return;
      }
      const event = PeripheralControlEngine.logPeripheralEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: "EVENT_LOG_ERROR", message: err.message });
    }
  });

  // 512. GET /api/v1/fleet/peripheral-control/script/:deviceId
  router.get('/api/v1/fleet/peripheral-control/script/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = PeripheralControlEngine.generatePeripheralControlScript(getDb(), req.params.deviceId);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: "SCRIPT_GEN_ERROR", message: err.message });
    }
  });

  // --- Iteration 50: Tamper Protection & Exclusion Governance Endpoints (513-524) ---

  // 513. GET /api/v1/fleet/tamper-protection/stats
  router.get('/api/v1/fleet/tamper-protection/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = TamperProtectionEngine.getTamperProtectionStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "STATS_FETCH_ERROR", message: err.message });
    }
  });

  // 514. GET /api/v1/fleet/tamper-protection/policies
  router.get('/api/v1/fleet/tamper-protection/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = TamperProtectionEngine.getPolicies(getDb());
      sendJson(res, 200, policies);
    } catch (err) {
      sendJson(res, 500, { error: "POLICIES_FETCH_ERROR", message: err.message });
    }
  });

  // 515. POST /api/v1/fleet/tamper-protection/policies
  router.post('/api/v1/fleet/tamper-protection/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "Policy name is required" });
        return;
      }
      const policy = TamperProtectionEngine.createPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_CREATE_ERROR", message: err.message });
    }
  });

  // 516. GET /api/v1/fleet/tamper-protection/policies/:id
  router.get('/api/v1/fleet/tamper-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = TamperProtectionEngine.getPolicyById(getDb(), req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_FETCH_ERROR", message: err.message });
    }
  });

  // 517. PATCH /api/v1/fleet/tamper-protection/policies/:id
  router.patch('/api/v1/fleet/tamper-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = TamperProtectionEngine.updatePolicy(getDb(), req.params.id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, policy: updated });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_UPDATE_ERROR", message: err.message });
    }
  });

  // 518. DELETE /api/v1/fleet/tamper-protection/policies/:id
  router.delete('/api/v1/fleet/tamper-protection/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = TamperProtectionEngine.deletePolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Policy deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_DELETE_ERROR", message: err.message });
    }
  });

  // 519. GET /api/v1/fleet/tamper-protection/exclusions
  router.get('/api/v1/fleet/tamper-protection/exclusions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const exclusions = TamperProtectionEngine.getExclusions(getDb(), req.query?.policy_id);
      sendJson(res, 200, exclusions);
    } catch (err) {
      sendJson(res, 500, { error: "EXCLUSIONS_FETCH_ERROR", message: err.message });
    }
  });

  // 520. POST /api/v1/fleet/tamper-protection/exclusions
  router.post('/api/v1/fleet/tamper-protection/exclusions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.exclusion_value) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "exclusion_value is required" });
        return;
      }
      const exclusion = TamperProtectionEngine.createExclusion(getDb(), req.body);
      sendJson(res, 201, { success: true, exclusion });
    } catch (err) {
      sendJson(res, 400, { error: "EXCLUSION_CREATE_ERROR", message: err.message });
    }
  });

  // 521. DELETE /api/v1/fleet/tamper-protection/exclusions/:id
  router.delete('/api/v1/fleet/tamper-protection/exclusions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = TamperProtectionEngine.deleteExclusion(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "EXCLUSION_NOT_FOUND", message: "Exclusion not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Exclusion deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "EXCLUSION_DELETE_ERROR", message: err.message });
    }
  });

  // 522. GET /api/v1/fleet/tamper-protection/events
  router.get('/api/v1/fleet/tamper-protection/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const events = TamperProtectionEngine.getTamperEvents(getDb(), req.query || {});
      sendJson(res, 200, { events, count: events.length });
    } catch (err) {
      sendJson(res, 500, { error: "EVENTS_FETCH_ERROR", message: err.message });
    }
  });

  // 523. POST /api/v1/fleet/tamper-protection/events
  router.post('/api/v1/fleet/tamper-protection/events', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.event_type) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id and event_type are required" });
        return;
      }
      const event = TamperProtectionEngine.logTamperEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: "EVENT_LOG_ERROR", message: err.message });
    }
  });

  // 524. GET /api/v1/fleet/tamper-protection/script/:deviceId
  router.get('/api/v1/fleet/tamper-protection/script/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = TamperProtectionEngine.generateTamperProtectionScript(getDb(), req.params.deviceId);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: "SCRIPT_GEN_ERROR", message: err.message });
    }
  });

  // --- Iteration 51: Network Isolation & Host Quarantine Endpoints (525-538) ---

  // 525. GET /api/v1/fleet/network-isolation/stats
  router.get('/api/v1/fleet/network-isolation/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = NetworkIsolationEngine.getIsolationStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "STATS_FETCH_ERROR", message: err.message });
    }
  });

  // 526. GET /api/v1/fleet/network-isolation/policies
  router.get('/api/v1/fleet/network-isolation/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policies = NetworkIsolationEngine.getPolicies(getDb());
      sendJson(res, 200, policies);
    } catch (err) {
      sendJson(res, 500, { error: "POLICIES_FETCH_ERROR", message: err.message });
    }
  });

  // 527. POST /api/v1/fleet/network-isolation/policies
  router.post('/api/v1/fleet/network-isolation/policies', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "Policy name is required" });
        return;
      }
      const policy = NetworkIsolationEngine.createPolicy(getDb(), req.body);
      sendJson(res, 201, { success: true, policy });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_CREATE_ERROR", message: err.message });
    }
  });

  // 528. GET /api/v1/fleet/network-isolation/policies/:id
  router.get('/api/v1/fleet/network-isolation/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const policy = NetworkIsolationEngine.getPolicyById(getDb(), req.params.id);
      if (!policy) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, policy);
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_FETCH_ERROR", message: err.message });
    }
  });

  // 529. PATCH /api/v1/fleet/network-isolation/policies/:id
  router.patch('/api/v1/fleet/network-isolation/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = NetworkIsolationEngine.updatePolicy(getDb(), req.params.id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, policy: updated });
    } catch (err) {
      sendJson(res, 400, { error: "POLICY_UPDATE_ERROR", message: err.message });
    }
  });

  // 530. DELETE /api/v1/fleet/network-isolation/policies/:id
  router.delete('/api/v1/fleet/network-isolation/policies/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = NetworkIsolationEngine.deletePolicy(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "POLICY_NOT_FOUND", message: "Policy not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Policy deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "POLICY_DELETE_ERROR", message: err.message });
    }
  });

  // 531. GET /api/v1/fleet/network-isolation/exclusions
  router.get('/api/v1/fleet/network-isolation/exclusions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const exclusions = NetworkIsolationEngine.getExclusions(getDb(), req.query?.policy_id);
      sendJson(res, 200, exclusions);
    } catch (err) {
      sendJson(res, 500, { error: "EXCLUSIONS_FETCH_ERROR", message: err.message });
    }
  });

  // 532. POST /api/v1/fleet/network-isolation/exclusions
  router.post('/api/v1/fleet/network-isolation/exclusions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.friendly_name || !req.body?.endpoint_value) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "friendly_name and endpoint_value are required" });
        return;
      }
      const exclusion = NetworkIsolationEngine.createExclusion(getDb(), req.body);
      sendJson(res, 201, { success: true, exclusion });
    } catch (err) {
      sendJson(res, 400, { error: "EXCLUSION_CREATE_ERROR", message: err.message });
    }
  });

  // 533. DELETE /api/v1/fleet/network-isolation/exclusions/:id
  router.delete('/api/v1/fleet/network-isolation/exclusions/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const ok = NetworkIsolationEngine.deleteExclusion(getDb(), req.params.id);
      if (!ok) {
        sendJson(res, 404, { error: "EXCLUSION_NOT_FOUND", message: "Exclusion not found" });
        return;
      }
      sendJson(res, 200, { success: true, message: "Exclusion deleted" });
    } catch (err) {
      sendJson(res, 500, { error: "EXCLUSION_DELETE_ERROR", message: err.message });
    }
  });

  // 534. POST /api/v1/fleet/network-isolation/isolate/:deviceId
  router.post('/api/v1/fleet/network-isolation/isolate/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const state = NetworkIsolationEngine.isolateDevice(getDb(), req.params.deviceId, req.body || {});
      sendJson(res, 200, { success: true, state });
    } catch (err) {
      sendJson(res, 400, { error: "ISOLATION_ERROR", message: err.message });
    }
  });

  // 535. POST /api/v1/fleet/network-isolation/release/:deviceId
  router.post('/api/v1/fleet/network-isolation/release/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const state = NetworkIsolationEngine.releaseDevice(getDb(), req.params.deviceId, req.body || {});
      sendJson(res, 200, { success: true, state });
    } catch (err) {
      sendJson(res, 400, { error: "RELEASE_ERROR", message: err.message });
    }
  });

  // 536. GET /api/v1/fleet/network-isolation/logs
  router.get('/api/v1/fleet/network-isolation/logs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const logs = NetworkIsolationEngine.getIsolationLogs(getDb(), req.query || {});
      sendJson(res, 200, { logs, count: logs.length });
    } catch (err) {
      sendJson(res, 500, { error: "LOGS_FETCH_ERROR", message: err.message });
    }
  });

  // 537. POST /api/v1/fleet/network-isolation/logs
  router.post('/api/v1/fleet/network-isolation/logs', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.transition_type) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id and transition_type are required" });
        return;
      }
      const log = NetworkIsolationEngine.logIsolationEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, log });
    } catch (err) {
      sendJson(res, 400, { error: "LOG_CREATE_ERROR", message: err.message });
    }
  });

  // 538. GET /api/v1/fleet/network-isolation/script/:deviceId
  router.get('/api/v1/fleet/network-isolation/script/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = NetworkIsolationEngine.generateIsolationScript(getDb(), req.params.deviceId);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 500, { error: "SCRIPT_GEN_ERROR", message: err.message });
    }
  });

  // 539. GET /api/v1/fleet/live-response/stats
  router.get('/api/v1/fleet/live-response/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = LiveResponseEngine.getLiveResponseStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "LIVE_RESPONSE_STATS_ERROR", message: err.message });
    }
  });

  // 540. GET /api/v1/fleet/live-response/sessions/:sessionId/commands
  router.get('/api/v1/fleet/live-response/sessions/:sessionId/commands', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const commands = LiveResponseEngine.getSessionCommands(getDb(), req.params.sessionId);
      sendJson(res, 200, { session_id: req.params.sessionId, commands, count: commands.length });
    } catch (err) {
      sendJson(res, 500, { error: "SESSION_COMMANDS_ERROR", message: err.message });
    }
  });

  // 541. POST /api/v1/fleet/live-response/sessions
  router.post('/api/v1/fleet/live-response/sessions', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id is required" });
        return;
      }
      const session = LiveResponseEngine.startSession(getDb(), {
        deviceId: req.body.device_id,
        operator: req.body.operator || 'SecOps Analyst'
      });
      sendJson(res, 201, { success: true, session });
    } catch (err) {
      sendJson(res, 400, { error: "SESSION_CREATE_ERROR", message: err.message });
    }
  });

  // 542. POST /api/v1/fleet/live-response/sessions/:sessionId/commands
  router.post('/api/v1/fleet/live-response/sessions/:sessionId/commands', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.command_type || !req.body?.command_payload) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id, command_type, and command_payload are required" });
        return;
      }
      const command = LiveResponseEngine.queueCommand(getDb(), {
        sessionId: req.params.sessionId,
        deviceId: req.body.device_id,
        commandType: req.body.command_type,
        commandPayload: req.body.command_payload,
        operator: req.body.operator || 'SecOps Analyst'
      });
      sendJson(res, 201, { success: true, command });
    } catch (err) {
      sendJson(res, 400, { error: "COMMAND_QUEUE_ERROR", message: err.message });
    }
  });

  // 543. POST /api/v1/fleet/live-response/commands/:commandId/complete
  router.post('/api/v1/fleet/live-response/commands/:commandId/complete', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const command = LiveResponseEngine.completeCommand(getDb(), req.params.commandId, req.body || {});
      sendJson(res, 200, { success: true, command });
    } catch (err) {
      sendJson(res, 400, { error: "COMMAND_COMPLETE_ERROR", message: err.message });
    }
  });

  // 544. GET /api/v1/fleet/live-response/quarantine
  router.get('/api/v1/fleet/live-response/quarantine', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const files = LiveResponseEngine.getQuarantinedFiles(getDb(), req.query || {});
      sendJson(res, 200, { files, count: files.length });
    } catch (err) {
      sendJson(res, 500, { error: "QUARANTINE_FETCH_ERROR", message: err.message });
    }
  });

  // 545. POST /api/v1/fleet/live-response/quarantine
  router.post('/api/v1/fleet/live-response/quarantine', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.original_path || !req.body?.file_name) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id, original_path, and file_name are required" });
        return;
      }
      const item = LiveResponseEngine.quarantineFile(getDb(), req.body);
      sendJson(res, 201, { success: true, item });
    } catch (err) {
      sendJson(res, 400, { error: "QUARANTINE_ERROR", message: err.message });
    }
  });

  // 546. POST /api/v1/fleet/live-response/quarantine/:id/restore
  router.post('/api/v1/fleet/live-response/quarantine/:id/restore', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const item = LiveResponseEngine.restoreFile(getDb(), req.params.id, req.body || {});
      sendJson(res, 200, { success: true, item });
    } catch (err) {
      sendJson(res, 400, { error: "RESTORE_ERROR", message: err.message });
    }
  });

  // 547. GET /api/v1/fleet/remediation-packages
  router.get('/api/v1/fleet/remediation-packages', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const packages = LiveResponseEngine.getRemediationPackages(getDb(), req.query || {});
      sendJson(res, 200, { packages, count: packages.length });
    } catch (err) {
      sendJson(res, 500, { error: "PACKAGES_FETCH_ERROR", message: err.message });
    }
  });

  // 548. GET /api/v1/fleet/remediation-packages/:id
  router.get('/api/v1/fleet/remediation-packages/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const pkg = LiveResponseEngine.getRemediationPackageById(getDb(), req.params.id);
      if (!pkg) {
        sendJson(res, 404, { error: "PACKAGE_NOT_FOUND", message: "Remediation package not found" });
        return;
      }
      sendJson(res, 200, pkg);
    } catch (err) {
      sendJson(res, 500, { error: "PACKAGE_FETCH_ERROR", message: err.message });
    }
  });

  // 549. POST /api/v1/fleet/remediation-packages
  router.post('/api/v1/fleet/remediation-packages', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const pkg = LiveResponseEngine.createRemediationPackage(getDb(), req.body || {});
      sendJson(res, 201, { success: true, package: pkg });
    } catch (err) {
      sendJson(res, 400, { error: "PACKAGE_CREATE_ERROR", message: err.message });
    }
  });

  // 550. DELETE /api/v1/fleet/remediation-packages/:id
  router.delete('/api/v1/fleet/remediation-packages/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = LiveResponseEngine.deleteRemediationPackage(getDb(), req.params.id);
      sendJson(res, 200, { success });
    } catch (err) {
      sendJson(res, 500, { error: "PACKAGE_DELETE_ERROR", message: err.message });
    }
  });

  // GET /api/v1/fleet/remediation-packages/:id/script
  router.get('/api/v1/fleet/remediation-packages/:id/script', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const script = LiveResponseEngine.generateRemediationScript(getDb(), req.params.id);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(script);
    } catch (err) {
      sendJson(res, 404, { error: "SCRIPT_NOT_FOUND", message: err.message });
    }
  });

  // 553. GET /api/v1/fleet/incidents/stats
  router.get('/api/v1/fleet/incidents/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = IncidentCorrelationEngine.getIncidentStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "INCIDENT_STATS_ERROR", message: err.message });
    }
  });

  // 554. GET /api/v1/fleet/incidents
  router.get('/api/v1/fleet/incidents', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const incidents = IncidentCorrelationEngine.getIncidents(getDb(), req.query || {});
      sendJson(res, 200, { incidents, count: incidents.length });
    } catch (err) {
      sendJson(res, 500, { error: "INCIDENTS_FETCH_ERROR", message: err.message });
    }
  });

  // 555. POST /api/v1/fleet/incidents
  router.post('/api/v1/fleet/incidents', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.title || (!req.body?.primary_device_id && !req.body?.primaryDeviceId)) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "title and primary_device_id are required" });
        return;
      }
      const incident = IncidentCorrelationEngine.createIncident(getDb(), req.body || {});
      sendJson(res, 201, { success: true, incident });
    } catch (err) {
      sendJson(res, 400, { error: "INCIDENT_CREATE_ERROR", message: err.message });
    }
  });

  // 556. GET /api/v1/fleet/incidents/:id
  router.get('/api/v1/fleet/incidents/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const incident = IncidentCorrelationEngine.getIncidentById(getDb(), req.params.id);
      if (!incident) {
        sendJson(res, 404, { error: "INCIDENT_NOT_FOUND", message: "Incident not found" });
        return;
      }
      sendJson(res, 200, incident);
    } catch (err) {
      sendJson(res, 500, { error: "INCIDENT_FETCH_ERROR", message: err.message });
    }
  });

  // 557. PATCH /api/v1/fleet/incidents/:id
  router.patch('/api/v1/fleet/incidents/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const updated = IncidentCorrelationEngine.updateIncident(getDb(), req.params.id, req.body || {});
      if (!updated) {
        sendJson(res, 404, { error: "INCIDENT_NOT_FOUND", message: "Incident not found" });
        return;
      }
      sendJson(res, 200, { success: true, incident: updated });
    } catch (err) {
      sendJson(res, 400, { error: "INCIDENT_UPDATE_ERROR", message: err.message });
    }
  });

  // 558. POST /api/v1/fleet/incidents/:id/close
  router.post('/api/v1/fleet/incidents/:id/close', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const closed = IncidentCorrelationEngine.closeIncident(getDb(), req.params.id, req.body || {});
      sendJson(res, 200, { success: true, incident: closed });
    } catch (err) {
      sendJson(res, 400, { error: "INCIDENT_CLOSE_ERROR", message: err.message });
    }
  });

  // 559. GET /api/v1/fleet/incidents/:id/alerts
  router.get('/api/v1/fleet/incidents/:id/alerts', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const alerts = IncidentCorrelationEngine.getIncidentAlerts(getDb(), req.params.id);
      sendJson(res, 200, { incident_id: req.params.id, alerts, count: alerts.length });
    } catch (err) {
      sendJson(res, 500, { error: "ALERTS_FETCH_ERROR", message: err.message });
    }
  });

  // 560. POST /api/v1/fleet/incidents/:id/alerts
  router.post('/api/v1/fleet/incidents/:id/alerts', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.alert_source || !req.body?.alert_id || !req.body?.alert_summary) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "alert_source, alert_id, and alert_summary are required" });
        return;
      }
      const assoc = IncidentCorrelationEngine.associateAlert(getDb(), req.params.id, {
        alertSource: req.body.alert_source,
        alertId: req.body.alert_id,
        alertSummary: req.body.alert_summary
      });
      sendJson(res, 201, { success: true, association: assoc });
    } catch (err) {
      sendJson(res, 400, { error: "ALERT_ASSOCIATE_ERROR", message: err.message });
    }
  });

  // 561. GET /api/v1/fleet/incidents/:id/timeline
  router.get('/api/v1/fleet/incidents/:id/timeline', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const timeline = IncidentCorrelationEngine.getIncidentTimeline(getDb(), req.params.id);
      sendJson(res, 200, { incident_id: req.params.id, timeline, count: timeline.length });
    } catch (err) {
      sendJson(res, 500, { error: "TIMELINE_FETCH_ERROR", message: err.message });
    }
  });

  // 562. POST /api/v1/fleet/incidents/:id/timeline
  router.post('/api/v1/fleet/incidents/:id/timeline', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.phase_name || !req.body?.milestone_title) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "phase_name and milestone_title are required" });
        return;
      }
      const milestone = IncidentCorrelationEngine.addMilestone(getDb(), {
        incidentId: req.params.id,
        phaseName: req.body.phase_name,
        milestoneTitle: req.body.milestone_title,
        details: req.body.details,
        evidenceArtifact: req.body.evidence_artifact,
        mitreTechniqueId: req.body.mitre_technique_id,
        occurredAt: req.body.occurred_at
      });
      sendJson(res, 201, { success: true, milestone });
    } catch (err) {
      sendJson(res, 400, { error: "MILESTONE_CREATE_ERROR", message: err.message });
    }
  });

  // 563. GET /api/v1/fleet/incidents/:id/storyline
  router.get('/api/v1/fleet/incidents/:id/storyline', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const storyline = IncidentCorrelationEngine.generateAttackStorylineJson(getDb(), req.params.id);
      sendJson(res, 200, { incident_id: req.params.id, storyline, nodes: storyline.length });
    } catch (err) {
      sendJson(res, 500, { error: "STORYLINE_GEN_ERROR", message: err.message });
    }
  });

  // 564. POST /api/v1/fleet/incidents/correlate/:deviceId
  router.post('/api/v1/fleet/incidents/correlate/:deviceId', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const result = IncidentCorrelationEngine.correlateAlerts(getDb(), req.params.deviceId);
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: "CORRELATION_ERROR", message: err.message });
    }
  });

  // 567. GET /api/v1/fleet/threat-intel/stats
  router.get('/api/v1/fleet/threat-intel/stats', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const stats = ThreatIntelEngine.getThreatIntelStats(getDb());
      sendJson(res, 200, stats);
    } catch (err) {
      sendJson(res, 500, { error: "THREAT_INTEL_STATS_ERROR", message: err.message });
    }
  });

  // 568. GET /api/v1/fleet/threat-intel/feeds
  router.get('/api/v1/fleet/threat-intel/feeds', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const feeds = ThreatIntelEngine.getFeedSources(getDb(), req.query || {});
      sendJson(res, 200, { feeds, count: feeds.length });
    } catch (err) {
      sendJson(res, 500, { error: "FEEDS_FETCH_ERROR", message: err.message });
    }
  });

  // 569. POST /api/v1/fleet/threat-intel/feeds
  router.post('/api/v1/fleet/threat-intel/feeds', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.name || !req.body?.feed_url) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "name and feed_url are required" });
        return;
      }
      const feed = ThreatIntelEngine.createFeedSource(getDb(), req.body || {});
      sendJson(res, 201, { success: true, feed });
    } catch (err) {
      sendJson(res, 400, { error: "FEED_CREATE_ERROR", message: err.message });
    }
  });

  // 570. GET /api/v1/fleet/threat-intel/feeds/:id
  router.get('/api/v1/fleet/threat-intel/feeds/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const feed = ThreatIntelEngine.getFeedSourceById(getDb(), req.params.id);
      if (!feed) {
        sendJson(res, 404, { error: "FEED_NOT_FOUND", message: "Feed source not found" });
        return;
      }
      sendJson(res, 200, feed);
    } catch (err) {
      sendJson(res, 500, { error: "FEED_FETCH_ERROR", message: err.message });
    }
  });

  // 571. DELETE /api/v1/fleet/threat-intel/feeds/:id
  router.delete('/api/v1/fleet/threat-intel/feeds/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = ThreatIntelEngine.deleteFeedSource(getDb(), req.params.id);
      sendJson(res, 200, { success });
    } catch (err) {
      sendJson(res, 500, { error: "FEED_DELETE_ERROR", message: err.message });
    }
  });

  // 572. POST /api/v1/fleet/threat-intel/feeds/:id/sync
  router.post('/api/v1/fleet/threat-intel/feeds/:id/sync', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const feed = ThreatIntelEngine.syncFeedSource(getDb(), req.params.id);
      sendJson(res, 200, { success: true, feed });
    } catch (err) {
      sendJson(res, 400, { error: "FEED_SYNC_ERROR", message: err.message });
    }
  });

  // 573. GET /api/v1/fleet/threat-intel/indicators
  router.get('/api/v1/fleet/threat-intel/indicators', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const indicators = ThreatIntelEngine.getIndicators(getDb(), req.query || {});
      sendJson(res, 200, { indicators, count: indicators.length });
    } catch (err) {
      sendJson(res, 500, { error: "INDICATORS_FETCH_ERROR", message: err.message });
    }
  });

  // 574. POST /api/v1/fleet/threat-intel/indicators
  router.post('/api/v1/fleet/threat-intel/indicators', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.indicator_type || !req.body?.indicator_value) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "indicator_type and indicator_value are required" });
        return;
      }
      const indicator = ThreatIntelEngine.createIndicator(getDb(), req.body || {});
      sendJson(res, 201, { success: true, indicator });
    } catch (err) {
      sendJson(res, 400, { error: "INDICATOR_CREATE_ERROR", message: err.message });
    }
  });

  // 575. POST /api/v1/fleet/threat-intel/indicators/match
  router.post('/api/v1/fleet/threat-intel/indicators/match', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.indicator_type || !req.body?.indicator_value || !req.body?.device_id) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "indicator_type, indicator_value, and device_id are required" });
        return;
      }
      const result = ThreatIntelEngine.checkIndicatorMatch(getDb(), {
        indicatorType: req.body.indicator_type,
        indicatorValue: req.body.indicator_value,
        deviceId: req.body.device_id,
        context: req.body.context,
        actionTaken: req.body.action_taken || 'BLOCKED'
      });
      sendJson(res, 200, result);
    } catch (err) {
      sendJson(res, 400, { error: "MATCH_CHECK_ERROR", message: err.message });
    }
  });

  // 576. DELETE /api/v1/fleet/threat-intel/indicators/:id
  router.delete('/api/v1/fleet/threat-intel/indicators/:id', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const success = ThreatIntelEngine.deleteIndicator(getDb(), req.params.id);
      sendJson(res, 200, { success });
    } catch (err) {
      sendJson(res, 500, { error: "INDICATOR_DELETE_ERROR", message: err.message });
    }
  });

  // 577. GET /api/v1/fleet/threat-intel/matches
  router.get('/api/v1/fleet/threat-intel/matches', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      const matches = ThreatIntelEngine.getMatchEvents(getDb(), req.query || {});
      sendJson(res, 200, { matches, count: matches.length });
    } catch (err) {
      sendJson(res, 500, { error: "MATCHES_FETCH_ERROR", message: err.message });
    }
  });

  // 578. POST /api/v1/fleet/threat-intel/matches
  router.post('/api/v1/fleet/threat-intel/matches', (req, res) => {
    if (!requireFleetKey(req, res)) return;
    try {
      if (!req.body?.device_id || !req.body?.indicator_type || !req.body?.matched_value) {
        sendJson(res, 400, { error: "MISSING_FIELDS", message: "device_id, indicator_type, and matched_value are required" });
        return;
      }
      const event = ThreatIntelEngine.logMatchEvent(getDb(), req.body || {});
      sendJson(res, 201, { success: true, event });
    } catch (err) {
      sendJson(res, 400, { error: "MATCH_LOG_ERROR", message: err.message });
    }
  });
}
