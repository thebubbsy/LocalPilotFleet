/**
 * LocalPilot Fleet — Windows Information Protection (WIP) & Data Loss Prevention (DLP) Engine
 * server/src/services/wipEngine.js
 */

import crypto from 'node:crypto';
import { broadcastEvent } from '../routes/events.js';

/**
 * List all WIP Policies
 */
export function getWipPolicies(db, options = {}) {
  let query = `
    SELECT 
      p.*,
      g.name as target_group_name,
      (
        SELECT COUNT(DISTINCT gm.device_id)
        FROM group_memberships gm
        WHERE gm.group_id = p.target_group_id
      ) as assigned_devices_count
    FROM wip_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE 1=1
  `;
  const params = [];

  if (options.enabled !== undefined) {
    query += ' AND p.enabled = ?';
    params.push(options.enabled ? 1 : 0);
  }

  if (options.enforcement_level) {
    query += ' AND p.enforcement_level = ?';
    params.push(options.enforcement_level.toUpperCase());
  }

  if (options.search) {
    query += ' AND (p.name LIKE ? OR p.description LIKE ? OR p.enterprise_domain LIKE ?)';
    params.push(`%${options.search}%`, `%${options.search}%`, `%${options.search}%`);
  }

  query += ' ORDER BY p.created_at DESC';

  const rows = db.prepare(query).all(...params);
  return rows.map(r => ({
    ...r,
    protected_apps: JSON.parse(r.protected_apps_json || '[]'),
    network_boundaries: JSON.parse(r.network_boundaries_json || '[]'),
    enabled: Boolean(r.enabled),
    allow_user_decryption: Boolean(r.allow_user_decryption),
    show_wip_overlays: Boolean(r.show_wip_overlays),
    revoke_on_unenroll: Boolean(r.revoke_on_unenroll)
  }));
}

/**
 * Get a single WIP Policy by ID
 */
export function getWipPolicy(db, id) {
  const row = db.prepare(`
    SELECT 
      p.*,
      g.name as target_group_name,
      (
        SELECT COUNT(DISTINCT gm.device_id)
        FROM group_memberships gm
        WHERE gm.group_id = p.target_group_id
      ) as assigned_devices_count
    FROM wip_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);

  if (!row) return null;

  const policy = {
    ...row,
    protected_apps: JSON.parse(row.protected_apps_json || '[]'),
    network_boundaries: JSON.parse(row.network_boundaries_json || '[]'),
    enabled: Boolean(row.enabled),
    allow_user_decryption: Boolean(row.allow_user_decryption),
    show_wip_overlays: Boolean(row.show_wip_overlays),
    revoke_on_unenroll: Boolean(row.revoke_on_unenroll)
  };

  return {
    ...policy,
    powershell_script: generateWipRegistryScript(policy)
  };
}

/**
 * Create a new WIP Policy
 */
export function createWipPolicy(db, policyData) {
  const id = policyData.id || `wip-${crypto.randomBytes(6).toString('hex')}`;
  const name = policyData.name?.trim();
  if (!name) throw new Error('WIP policy name is required');

  const desc = policyData.description || '';
  const targetGroupId = policyData.target_group_id || 'grp-all';
  const enforcement = (policyData.enforcement_level || 'SILENT').toUpperCase();
  const domain = policyData.enterprise_domain || 'localpilot.internal';
  
  const apps = Array.isArray(policyData.protected_apps) 
    ? JSON.stringify(policyData.protected_apps) 
    : (policyData.protected_apps_json || '[]');
  
  const boundaries = Array.isArray(policyData.network_boundaries) 
    ? JSON.stringify(policyData.network_boundaries) 
    : (policyData.network_boundaries_json || '[]');

  const allowDecrypt = policyData.allow_user_decryption ? 1 : 0;
  const showOverlays = policyData.show_wip_overlays !== undefined ? (policyData.show_wip_overlays ? 1 : 0) : 1;
  const revokeOnUnenroll = policyData.revoke_on_unenroll !== undefined ? (policyData.revoke_on_unenroll ? 1 : 0) : 1;
  const enabled = policyData.enabled !== undefined ? (policyData.enabled ? 1 : 0) : 1;

  const stmt = db.prepare(`
    INSERT INTO wip_policies (
      id, name, description, target_group_id, enforcement_level, enterprise_domain,
      protected_apps_json, network_boundaries_json, allow_user_decryption,
      show_wip_overlays, revoke_on_unenroll, enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `);

  stmt.run(
    id, name, desc, targetGroupId, enforcement, domain,
    apps, boundaries, allowDecrypt, showOverlays, revokeOnUnenroll, enabled
  );

  broadcastEvent('wip:policy_created', { id, name, enforcement });
  return getWipPolicy(db, id);
}

/**
 * Update an existing WIP Policy
 */
export function updateWipPolicy(db, id, updateData) {
  const existing = getWipPolicy(db, id);
  if (!existing) return null;

  const name = updateData.name !== undefined ? updateData.name.trim() : existing.name;
  if (!name) throw new Error('Policy name cannot be empty');

  const desc = updateData.description !== undefined ? updateData.description : existing.description;
  const targetGroupId = updateData.target_group_id !== undefined ? updateData.target_group_id : existing.target_group_id;
  const enforcement = updateData.enforcement_level !== undefined ? updateData.enforcement_level.toUpperCase() : existing.enforcement_level;
  const domain = updateData.enterprise_domain !== undefined ? updateData.enterprise_domain : existing.enterprise_domain;

  const apps = updateData.protected_apps !== undefined 
    ? JSON.stringify(updateData.protected_apps) 
    : (updateData.protected_apps_json !== undefined ? updateData.protected_apps_json : existing.protected_apps_json);

  const boundaries = updateData.network_boundaries !== undefined 
    ? JSON.stringify(updateData.network_boundaries) 
    : (updateData.network_boundaries_json !== undefined ? updateData.network_boundaries_json : existing.network_boundaries_json);

  const allowDecrypt = updateData.allow_user_decryption !== undefined ? (updateData.allow_user_decryption ? 1 : 0) : (existing.allow_user_decryption ? 1 : 0);
  const showOverlays = updateData.show_wip_overlays !== undefined ? (updateData.show_wip_overlays ? 1 : 0) : (existing.show_wip_overlays ? 1 : 0);
  const revokeOnUnenroll = updateData.revoke_on_unenroll !== undefined ? (updateData.revoke_on_unenroll ? 1 : 0) : (existing.revoke_on_unenroll ? 1 : 0);
  const enabled = updateData.enabled !== undefined ? (updateData.enabled ? 1 : 0) : (existing.enabled ? 1 : 0);

  db.prepare(`
    UPDATE wip_policies SET
      name = ?,
      description = ?,
      target_group_id = ?,
      enforcement_level = ?,
      enterprise_domain = ?,
      protected_apps_json = ?,
      network_boundaries_json = ?,
      allow_user_decryption = ?,
      show_wip_overlays = ?,
      revoke_on_unenroll = ?,
      enabled = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    name, desc, targetGroupId, enforcement, domain,
    apps, boundaries, allowDecrypt, showOverlays, revokeOnUnenroll, enabled, id
  );

  broadcastEvent('wip:policy_updated', { id, name, enforcement });
  return getWipPolicy(db, id);
}

/**
 * Delete a WIP Policy
 */
export function deleteWipPolicy(db, id) {
  const existing = getWipPolicy(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM wip_policies WHERE id = ?').run(id);
  broadcastEvent('wip:policy_deleted', { id, name: existing.name });
  return true;
}

/**
 * Generate PowerShell & Registry Configuration for WIP
 */
export function generateWipRegistryScript(policy) {
  const enforcementMap = { 'OFF': 0, 'SILENT': 1, 'OVERRIDE': 2, 'BLOCK': 3 };
  const enforceNum = enforcementMap[policy.enforcement_level] ?? 1;

  let script = `# ==============================================================================
# LocalPilot Fleet — Windows Information Protection (WIP) & DLP Enforcement Script
# Policy: ${policy.name} (ID: ${policy.id})
# Mode: ${policy.enforcement_level} | Domain: ${policy.enterprise_domain}
# Generated: ${new Date().toISOString()}
# ==============================================================================

$ErrorActionPreference = 'Stop'
Write-Host "Enforcing Windows Information Protection (WIP) configuration: ${policy.name}..."

$edpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataProtection'
if (-not (Test-Path $edpPath)) {
    New-Item -Path $edpPath -Force | Out-Null
}

# 1. Configure EDP / WIP Enforcement Level (0=Off, 1=Silent, 2=Override, 3=Block)
Set-ItemProperty -Path $edpPath -Name 'Status' -Value ${enforceNum} -Type DWord
Set-ItemProperty -Path $edpPath -Name 'PrimaryDomainName' -Value '${policy.enterprise_domain}' -Type String
Set-ItemProperty -Path $edpPath -Name 'AllowUserDecryption' -Value ${policy.allow_user_decryption ? 1 : 0} -Type DWord
Set-ItemProperty -Path $edpPath -Name 'ShowIconOverlay' -Value ${policy.show_wip_overlays ? 1 : 0} -Type DWord
Set-ItemProperty -Path $edpPath -Name 'RevokeOnUnenroll' -Value ${policy.revoke_on_unenroll ? 1 : 0} -Type DWord

# 2. Configure Enterprise Network Boundaries
$boundPath = "$edpPath\EnterpriseProtectedDomains"
if (-not (Test-Path $boundPath)) {
    New-Item -Path $boundPath -Force | Out-Null
}
Set-ItemProperty -Path $boundPath -Name 'EnterpriseDomains' -Value '${policy.enterprise_domain}' -Type String

# 3. Configure Enterprise Protected App Boundaries
$appsPath = "$edpPath\AppLocker"
if (-not (Test-Path $appsPath)) {
    New-Item -Path $appsPath -Force | Out-Null
}
`;

  if (Array.isArray(policy.protected_apps)) {
    policy.protected_apps.forEach((app, idx) => {
      script += `
# Protected App: ${app.name} (${app.binary})
Set-ItemProperty -Path $appsPath -Name 'App_${idx}' -Value '${app.binary}' -Type String`;
    });
  }

  script += `

Write-Host "WIP & Endpoint DLP settings applied successfully."
`;

  return script;
}

/**
 * Get Effective WIP Policy for a Device
 */
export function getEffectiveWipPolicyForDevice(db, deviceId) {
  const query = `
    SELECT p.*
    FROM wip_policies p
    JOIN dynamic_groups g ON p.target_group_id = g.id
    JOIN group_memberships gm ON gm.group_id = g.id
    WHERE gm.device_id = ? AND p.enabled = 1
    ORDER BY g.priority ASC, p.created_at DESC
    LIMIT 1
  `;

  let row = db.prepare(query).get(deviceId);
  if (!row) {
    row = db.prepare(`
      SELECT * FROM wip_policies 
      WHERE (target_group_id = 'grp-all' OR target_group_id IS NULL) AND enabled = 1
      ORDER BY created_at DESC
      LIMIT 1
    `).get();
  }

  if (!row) return null;
  return {
    ...row,
    protected_apps: JSON.parse(row.protected_apps_json || '[]'),
    network_boundaries: JSON.parse(row.network_boundaries_json || '[]'),
    enabled: Boolean(row.enabled),
    allow_user_decryption: Boolean(row.allow_user_decryption),
    show_wip_overlays: Boolean(row.show_wip_overlays),
    revoke_on_unenroll: Boolean(row.revoke_on_unenroll)
  };
}

/**
 * Save Device WIP Telemetry Status
 */
export function saveDeviceWipStatus(db, deviceId, statusData) {
  const policy = getEffectiveWipPolicyForDevice(db, deviceId);
  const policyId = policy ? policy.id : null;

  const id = `devwip-${deviceId}`;
  const enforcementActive = (statusData.enforcement_active || policy?.enforcement_level || 'SILENT').toUpperCase();
  const protectedFiles = Number(statusData.protected_files_count) || 0;
  const encryptedBytes = Number(statusData.encrypted_bytes) || 0;
  const managedApps = Number(statusData.managed_apps_count) || 0;
  const clipViolations = Number(statusData.clipboard_violations_24h) || 0;
  const cloudAttempts = Number(statusData.cloud_exfiltration_attempts_24h) || 0;

  // Compliance check
  let complianceStatus = 'COMPLIANT';
  if (policy && policy.enforcement_level === 'BLOCK' && enforcementActive !== 'BLOCK') {
    complianceStatus = 'POLICY_DRIFT';
  } else if (clipViolations > 5 || cloudAttempts > 0) {
    complianceStatus = 'NON_COMPLIANT';
  }

  const stmt = db.prepare(`
    INSERT INTO device_wip_status (
      id, device_id, policy_id, enforcement_active, protected_files_count, encrypted_bytes,
      managed_apps_count, clipboard_violations_24h, cloud_exfiltration_attempts_24h,
      compliance_status, last_audit_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))
    ON CONFLICT(device_id) DO UPDATE SET
      policy_id = excluded.policy_id,
      enforcement_active = excluded.enforcement_active,
      protected_files_count = excluded.protected_files_count,
      encrypted_bytes = excluded.encrypted_bytes,
      managed_apps_count = excluded.managed_apps_count,
      clipboard_violations_24h = excluded.clipboard_violations_24h,
      cloud_exfiltration_attempts_24h = excluded.cloud_exfiltration_attempts_24h,
      compliance_status = excluded.compliance_status,
      last_audit_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `);

  stmt.run(
    id, deviceId, policyId, enforcementActive, protectedFiles, encryptedBytes,
    managedApps, clipViolations, cloudAttempts, complianceStatus
  );

  broadcastEvent('wip:status_updated', { deviceId, enforcementActive, complianceStatus, clipViolations });
  return getDeviceWipStatus(db, deviceId);
}

/**
 * Record a WIP Audit Event
 */
export function recordWipEvent(db, deviceId, eventData) {
  const id = `wipa-${crypto.randomBytes(6).toString('hex')}`;
  const eventType = eventData.event_type || 'ENTERPRISE_FILE_ACCESSED';
  const appName = eventData.app_name || 'System';
  const targetLoc = eventData.target_location || '';
  const fileName = eventData.file_name || '';
  const justification = eventData.user_justification || '';
  const details = eventData.details || '';

  db.prepare(`
    INSERT INTO wip_audit_log (
      id, device_id, event_type, app_name, target_location, file_name,
      user_justification, details, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
  `).run(id, deviceId, eventType, appName, targetLoc, fileName, justification, details);

  // If exfiltration attempt or data blocked, record security event in master ledger
  if (eventType === 'EXFILTRATION_ATTEMPT' || eventType === 'DATA_BLOCKED') {
    try {
      db.prepare(`
        INSERT INTO security_events (device_id, event_type, event_source, severity, summary, raw_payload_json, created_at)
        VALUES (?, 'POLICY_DRIFT', 'WIP_SUBSYSTEM', 'HIGH', ?, ?, DATETIME('now'))
      `).run(
        deviceId,
        `Corporate Data Exfiltration Intercepted: ${appName} tried writing ${fileName} to ${targetLoc}`,
        JSON.stringify({ appName, targetLoc, fileName, justification, details })
      );
      broadcastEvent('security:alert', { deviceId, eventType, severity: 'HIGH', appName });
    } catch (err) {
      console.error('[WIP] Failed to log security event:', err.message);
    }
  }

  broadcastEvent('wip:event_logged', { id, deviceId, eventType, appName });
  return { id, deviceId, event_type: eventType, app_name: appName, target_location: targetLoc, file_name: fileName, user_justification: justification, details, timestamp: new Date().toISOString() };
}

/**
 * Get WIP Inventory
 */
export function getWipInventory(db, options = {}) {
  let query = `
    SELECT 
      s.*,
      d.hostname,
      d.friendly_name,
      d.ip_address as device_ip,
      d.status as device_status,
      p.name as policy_name,
      p.enterprise_domain
    FROM device_wip_status s
    JOIN devices d ON s.device_id = d.id
    LEFT JOIN wip_policies p ON s.policy_id = p.id
    WHERE 1=1
  `;
  const params = [];

  if (options.compliance_status) {
    query += ' AND s.compliance_status = ?';
    params.push(options.compliance_status.toUpperCase());
  }

  if (options.enforcement_level) {
    query += ' AND s.enforcement_active = ?';
    params.push(options.enforcement_level.toUpperCase());
  }

  if (options.search) {
    query += ' AND (d.hostname LIKE ? OR d.friendly_name LIKE ? OR p.name LIKE ?)';
    params.push(`%${options.search}%`, `%${options.search}%`, `%${options.search}%`);
  }

  query += ' ORDER BY s.last_audit_at DESC';
  return db.prepare(query).all(...params);
}

/**
 * Get WIP Audit Log
 */
export function getWipAuditLog(db, options = {}) {
  let query = `
    SELECT 
      l.*,
      d.hostname,
      d.friendly_name
    FROM wip_audit_log l
    JOIN devices d ON l.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (options.device_id) {
    query += ' AND l.device_id = ?';
    params.push(options.device_id);
  }

  if (options.event_type) {
    query += ' AND l.event_type = ?';
    params.push(options.event_type.toUpperCase());
  }

  query += ' ORDER BY l.timestamp DESC LIMIT ? OFFSET ?';
  params.push(Number(options.limit) || 100, Number(options.offset) || 0);

  return db.prepare(query).all(...params);
}

/**
 * Get Fleet WIP Statistics
 */
export function getWipStats(db) {
  const polStats = db.prepare(`
    SELECT 
      COUNT(*) as total_policies,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as active_policies,
      SUM(CASE WHEN enforcement_level = 'BLOCK' THEN 1 ELSE 0 END) as block_policies
    FROM wip_policies
  `).get();

  const devStats = db.prepare(`
    SELECT 
      COUNT(*) as total_audited,
      SUM(CASE WHEN enforcement_active = 'BLOCK' THEN 1 ELSE 0 END) as block_enforced,
      SUM(CASE WHEN enforcement_active = 'OVERRIDE' THEN 1 ELSE 0 END) as override_enforced,
      SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count,
      SUM(protected_files_count) as total_protected_files,
      SUM(encrypted_bytes) as total_encrypted_bytes,
      SUM(clipboard_violations_24h) as total_clipboard_violations,
      SUM(cloud_exfiltration_attempts_24h) as total_cloud_attempts
    FROM device_wip_status
  `).get();

  const fleetTotal = db.prepare("SELECT COUNT(*) as c FROM devices WHERE status != 'DECOMMISSIONED'").get().c;
  const auditEvents = db.prepare("SELECT COUNT(*) as c FROM wip_audit_log").get().c;

  const auditedCount = devStats.total_audited || 0;
  const compliantCount = devStats.compliant_count || 0;

  return {
    total_policies: polStats.total_policies || 0,
    active_policies: polStats.active_policies || 0,
    block_policies: polStats.block_policies || 0,
    total_audited_devices: auditedCount,
    total_devices_in_fleet: fleetTotal,
    block_enforced_devices: devStats.block_enforced || 0,
    override_enforced_devices: devStats.override_enforced || 0,
    compliant_devices_count: compliantCount,
    compliance_pct: auditedCount > 0 ? Number(((compliantCount / auditedCount) * 100).toFixed(1)) : 100.0,
    total_protected_files: devStats.total_protected_files || 0,
    total_encrypted_bytes: devStats.total_encrypted_bytes || 0,
    total_clipboard_violations_24h: devStats.total_clipboard_violations || 0,
    total_cloud_attempts_24h: devStats.total_cloud_attempts || 0,
    total_audit_events: auditEvents
  };
}

/**
 * Get Device WIP Status & Effective Policy
 */
export function getDeviceWipStatus(db, deviceId) {
  const status = db.prepare('SELECT * FROM device_wip_status WHERE device_id = ?').get(deviceId);
  const policy = getEffectiveWipPolicyForDevice(db, deviceId);
  const recentLogs = db.prepare(`
    SELECT * FROM wip_audit_log 
    WHERE device_id = ? 
    ORDER BY timestamp DESC 
    LIMIT 10
  `).all(deviceId);

  return {
    status: status || null,
    effective_policy: policy || null,
    recent_logs: recentLogs
  };
}
