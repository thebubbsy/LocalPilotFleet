import { broadcastEvent } from '../routes/events.js';

/**
 * Enterprise Removable Storage Access Control & Peripheral Governance Engine
 * Microsoft Intune & Defender for Endpoint Device Control
 */

/**
 * Generate native Windows PowerShell script applying registry-based Device Control & BitLocker To Go
 */
export function generateRegistryScript(policy) {
  const denyWrite = policy.removable_disk_access === 'READ_ONLY' || policy.removable_disk_access === 'DENY_UNENCRYPTED';
  const denyAll = policy.removable_disk_access === 'DENY_ALL';
  const bitlockerToGo = policy.require_bitlocker_to_go !== 0;
  const blockWpd = policy.block_wpd_devices !== 0;

  return `# LocalPilot Fleet Removable Storage Device Control Script
# Policy: ${policy.name} (${policy.id})
# Mode: ${policy.removable_disk_access} | BitLocker To Go: ${bitlockerToGo}

$FveKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE"
$StorageKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices"
$WpdKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{6AC27878-A6FA-4155-BA85-F98F491D4F33}"

# 1. BitLocker To Go Write-Protection Configuration
if (-not (Test-Path $FveKey)) { New-Item -Path $FveKey -Force | Out-Null }
${bitlockerToGo ? `
Set-ItemProperty -Path $FveKey -Name "RDVDenyWriteAccess" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveKey -Name "RDVConfigureBDE" -Value 1 -Type DWord -Force
Write-Host "Enforced BitLocker To Go requirement for removable drives (RDVDenyWriteAccess=1)"` : `
Remove-ItemProperty -Path $FveKey -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
Write-Host "Cleared BitLocker To Go write restriction"`}

# 2. Removable Storage Devices Access Restrictions
if (-not (Test-Path $StorageKey)) { New-Item -Path $StorageKey -Force | Out-Null }
${denyAll ? `
Set-ItemProperty -Path $StorageKey -Name "Deny_All" -Value 1 -Type DWord -Force
Write-Host "Enforced complete block on all removable storage classes (Deny_All=1)"` : denyWrite ? `
Set-ItemProperty -Path $StorageKey -Name "Deny_Write" -Value 1 -Type DWord -Force
Write-Host "Enforced read-only policy on removable storage (Deny_Write=1)"` : `
Remove-ItemProperty -Path $StorageKey -Name "Deny_All" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $StorageKey -Name "Deny_Write" -ErrorAction SilentlyContinue
Write-Host "Allowed standard removable storage access"`}

# 3. Windows Portable Devices (MTP / Smartphones)
if (-not (Test-Path $WpdKey)) { New-Item -Path $WpdKey -Force | Out-Null }
${blockWpd ? `
Set-ItemProperty -Path $WpdKey -Name "Deny_All" -Value 1 -Type DWord -Force
Write-Host "Blocked Windows Portable Devices and Smartphones (WPD Deny_All=1)"` : `
Remove-ItemProperty -Path $WpdKey -Name "Deny_All" -ErrorAction SilentlyContinue
Write-Host "Allowed Windows Portable Devices"`}

Write-Host "Storage access control policies enforced successfully."
`.trim();
}

/**
 * Get all Storage Access Policies with assigned device counts
 */
export function getAllPolicies(db) {
  const policies = db.prepare(`
    SELECT sap.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM storage_access_policies sap
    LEFT JOIN dynamic_groups dg ON sap.target_group_id = dg.id
    ORDER BY sap.removable_disk_access ASC, sap.name ASC
  `).all();

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;

  return policies.map(p => {
    let assignedCount = 0;
    if (p.target_group_id === 'grp-all' || p.target_group_id === 'all-devices') {
      assignedCount = totalDevicesCount;
    } else {
      const row = db.prepare(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM group_memberships
        WHERE group_id = ?
      `).get(p.target_group_id);
      assignedCount = row ? row.count : 0;
    }

    let parsedHw = [];
    try {
      parsedHw = JSON.parse(p.allowed_hardware_ids_json || '[]');
    } catch {
      parsedHw = [];
    }

    return {
      ...p,
      enabled: Boolean(p.enabled),
      require_bitlocker_to_go: Boolean(p.require_bitlocker_to_go),
      block_wpd_devices: Boolean(p.block_wpd_devices),
      block_bluetooth: Boolean(p.block_bluetooth),
      audit_only: Boolean(p.audit_only),
      allowed_hardware_ids: parsedHw,
      assigned_devices_count: assignedCount
    };
  });
}

/**
 * Get a single policy by ID
 */
export function getPolicyById(db, id) {
  const policy = db.prepare(`
    SELECT sap.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM storage_access_policies sap
    LEFT JOIN dynamic_groups dg ON sap.target_group_id = dg.id
    WHERE sap.id = ?
  `).get(id);

  if (!policy) return null;

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;
  let assignedCount = 0;
  if (policy.target_group_id === 'grp-all' || policy.target_group_id === 'all-devices') {
    assignedCount = totalDevicesCount;
  } else {
    const row = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count
      FROM group_memberships
      WHERE group_id = ?
    `).get(policy.target_group_id);
    assignedCount = row ? row.count : 0;
  }

  let parsedHw = [];
  try {
    parsedHw = JSON.parse(policy.allowed_hardware_ids_json || '[]');
  } catch {
    parsedHw = [];
  }

  return {
    ...policy,
    enabled: Boolean(policy.enabled),
    require_bitlocker_to_go: Boolean(policy.require_bitlocker_to_go),
    block_wpd_devices: Boolean(policy.block_wpd_devices),
    block_bluetooth: Boolean(policy.block_bluetooth),
    audit_only: Boolean(policy.audit_only),
    allowed_hardware_ids: parsedHw,
    assigned_devices_count: assignedCount,
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Create a new Storage Access Policy
 */
export function createPolicy(db, data) {
  if (!data.name || !data.name.trim()) {
    throw new Error('Storage policy name is required');
  }

  const id = data.id || `storage-${data.name.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').slice(0, 32)}-${Date.now().toString(36)}`;
  const targetGroupId = data.target_group_id || 'grp-all';
  const diskAccess = data.removable_disk_access || 'ALLOW_ALL';
  const requireBde = data.require_bitlocker_to_go !== undefined ? (data.require_bitlocker_to_go ? 1 : 0) : 1;
  const blockWpd = data.block_wpd_devices !== undefined ? (data.block_wpd_devices ? 1 : 0) : 0;
  const blockBt = data.block_bluetooth !== undefined ? (data.block_bluetooth ? 1 : 0) : 0;
  const auditOnly = data.audit_only !== undefined ? (data.audit_only ? 1 : 0) : 0;
  const allowedHwJson = typeof data.allowed_hardware_ids === 'object' ? JSON.stringify(data.allowed_hardware_ids) : (data.allowed_hardware_ids_json || '[]');
  const enabled = data.enabled !== undefined ? (data.enabled ? 1 : 0) : 1;

  db.prepare(`
    INSERT INTO storage_access_policies (
      id, name, description, target_group_id,
      removable_disk_access, require_bitlocker_to_go, block_wpd_devices,
      block_bluetooth, allowed_hardware_ids_json, audit_only,
      enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, DATETIME('now'), DATETIME('now')
    )
  `).run(
    id, data.name.trim(), data.description || '', targetGroupId,
    diskAccess, requireBde, blockWpd,
    blockBt, allowedHwJson, auditOnly,
    enabled
  );

  broadcastEvent('storage_policy_created', { id, name: data.name });
  return getPolicyById(db, id);
}

/**
 * Update an existing policy
 */
export function updatePolicy(db, id, data) {
  const existing = db.prepare('SELECT id FROM storage_access_policies WHERE id = ?').get(id);
  if (!existing) return null;

  const updates = [];
  const params = [];

  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error('Storage policy name cannot be empty');
    updates.push('name = ?');
    params.push(data.name.trim());
  }
  if (data.description !== undefined) {
    updates.push('description = ?');
    params.push(data.description);
  }
  if (data.target_group_id !== undefined) {
    updates.push('target_group_id = ?');
    params.push(data.target_group_id);
  }
  if (data.removable_disk_access !== undefined) {
    updates.push('removable_disk_access = ?');
    params.push(data.removable_disk_access);
  }
  if (data.require_bitlocker_to_go !== undefined) {
    updates.push('require_bitlocker_to_go = ?');
    params.push(data.require_bitlocker_to_go ? 1 : 0);
  }
  if (data.block_wpd_devices !== undefined) {
    updates.push('block_wpd_devices = ?');
    params.push(data.block_wpd_devices ? 1 : 0);
  }
  if (data.block_bluetooth !== undefined) {
    updates.push('block_bluetooth = ?');
    params.push(data.block_bluetooth ? 1 : 0);
  }
  if (data.allowed_hardware_ids !== undefined) {
    updates.push('allowed_hardware_ids_json = ?');
    params.push(JSON.stringify(data.allowed_hardware_ids));
  } else if (data.allowed_hardware_ids_json !== undefined) {
    updates.push('allowed_hardware_ids_json = ?');
    params.push(data.allowed_hardware_ids_json);
  }
  if (data.audit_only !== undefined) {
    updates.push('audit_only = ?');
    params.push(data.audit_only ? 1 : 0);
  }
  if (data.enabled !== undefined) {
    updates.push('enabled = ?');
    params.push(data.enabled ? 1 : 0);
  }

  if (updates.length > 0) {
    updates.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE storage_access_policies SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    broadcastEvent('storage_policy_updated', { id });
  }

  return getPolicyById(db, id);
}

/**
 * Delete a policy
 */
export function deletePolicy(db, id) {
  const existing = db.prepare('SELECT id, name FROM storage_access_policies WHERE id = ?').get(id);
  if (!existing) return false;

  db.prepare('DELETE FROM storage_access_policies WHERE id = ?').run(id);
  broadcastEvent('storage_policy_deleted', { id, name: existing.name });
  return true;
}

/**
 * Resolve effective policy for device
 */
export function getEffectivePolicyForDevice(db, deviceId) {
  const groups = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
  const groupIds = groups.map(g => g.group_id);
  groupIds.push('grp-all', 'all-devices');

  const placeholders = groupIds.map(() => '?').join(',');
  const policy = db.prepare(`
    SELECT * FROM storage_access_policies
    WHERE enabled = 1 AND target_group_id IN (${placeholders})
    ORDER BY created_at DESC
    LIMIT 1
  `).get(...groupIds);

  if (!policy) return null;

  let parsedHw = [];
  try {
    parsedHw = JSON.parse(policy.allowed_hardware_ids_json || '[]');
  } catch {
    parsedHw = [];
  }

  return {
    ...policy,
    enabled: Boolean(policy.enabled),
    require_bitlocker_to_go: Boolean(policy.require_bitlocker_to_go),
    block_wpd_devices: Boolean(policy.block_wpd_devices),
    block_bluetooth: Boolean(policy.block_bluetooth),
    audit_only: Boolean(policy.audit_only),
    allowed_hardware_ids: parsedHw,
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Ingest live workstation removable storage & USB status
 */
export function saveDeviceStorageStatus(db, deviceId, statusData) {
  const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const id = `devstorage-${deviceId}`;
  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
  const policyId = effectivePolicy ? effectivePolicy.id : null;

  const connectedDrives = Array.isArray(statusData.connected_removable_drives) 
    ? statusData.connected_removable_drives 
    : (typeof statusData.connected_removable_drives_json === 'string' ? JSON.parse(statusData.connected_removable_drives_json || '[]') : []);

  const activeUsb = Array.isArray(statusData.active_usb_devices) 
    ? statusData.active_usb_devices 
    : (typeof statusData.active_usb_devices_json === 'string' ? JSON.parse(statusData.active_usb_devices_json || '[]') : []);

  const writeDenied = statusData.write_access_denied !== undefined ? (statusData.write_access_denied ? 1 : 0) : 0;

  // Evaluate compliance
  let complianceStatus = 'COMPLIANT';
  if (effectivePolicy && !effectivePolicy.audit_only) {
    if (effectivePolicy.removable_disk_access === 'DENY_ALL' && connectedDrives.length > 0) {
      complianceStatus = 'BLOCKED_DEVICE_DETECTED';
    } else if (effectivePolicy.require_bitlocker_to_go) {
      const unencrypted = connectedDrives.some(d => !d.is_bitlocker_protected);
      if (unencrypted) {
        complianceStatus = 'UNENCRYPTED_USB_DETECTED';
      }
    }
  }

  db.prepare(`
    INSERT INTO device_removable_storage_status (
      id, device_id, policy_id, connected_removable_drives_json,
      active_usb_devices_json, write_access_denied, compliance_status,
      last_audit_at, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      DATETIME('now'), DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(device_id) DO UPDATE SET
      policy_id = excluded.policy_id,
      connected_removable_drives_json = excluded.connected_removable_drives_json,
      active_usb_devices_json = excluded.active_usb_devices_json,
      write_access_denied = excluded.write_access_denied,
      compliance_status = excluded.compliance_status,
      last_audit_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `).run(
    id, deviceId, policyId,
    JSON.stringify(connectedDrives),
    JSON.stringify(activeUsb),
    writeDenied, complianceStatus
  );

  broadcastEvent('device_storage_posture_updated', { deviceId, complianceStatus, connectedDrivesCount: connectedDrives.length });
  return getDeviceStorageStatus(db, deviceId);
}

/**
 * Record a removable storage insertion, removal, or write blocked event
 */
export function recordStorageEvent(db, deviceId, eventData) {
  const id = `stor-evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const eventType = eventData.event_type || 'DRIVE_INSERTED';
  const driveLetter = eventData.drive_letter || '';
  const volumeName = eventData.volume_name || '';
  const hardwareId = eventData.hardware_id || '';
  const isEncrypted = eventData.is_encrypted ? 1 : 0;
  const actionTaken = eventData.action_taken || 'ALLOWED';

  db.prepare(`
    INSERT INTO removable_storage_events (
      id, device_id, event_type, drive_letter,
      volume_name, hardware_id, is_encrypted,
      action_taken, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
  `).run(id, deviceId, eventType, driveLetter, volumeName, hardwareId, isEncrypted, actionTaken);

  broadcastEvent('removable_storage_event', { id, deviceId, eventType, driveLetter, volumeName, actionTaken });
  return { id, device_id: deviceId, event_type: eventType, drive_letter: driveLetter, action_taken: actionTaken };
}

/**
 * Get device storage posture
 */
export function getDeviceStorageStatus(db, deviceId) {
  const row = db.prepare(`
    SELECT drss.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           sap.name as policy_name,
           sap.removable_disk_access as policy_access_mode,
           sap.require_bitlocker_to_go as policy_require_bde
    FROM device_removable_storage_status drss
    JOIN devices d ON drss.device_id = d.id
    LEFT JOIN storage_access_policies sap ON drss.policy_id = sap.id
    WHERE drss.device_id = ?
  `).get(deviceId);

  if (!row) {
    const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
    return {
      device_id: deviceId,
      policy_id: effectivePolicy ? effectivePolicy.id : null,
      policy_name: effectivePolicy ? effectivePolicy.name : null,
      connected_removable_drives: [],
      active_usb_devices: [],
      write_access_denied: false,
      compliance_status: 'COMPLIANT',
      effective_policy: effectivePolicy
    };
  }

  let connectedDrives = [];
  let activeUsb = [];
  try {
    connectedDrives = JSON.parse(row.connected_removable_drives_json || '[]');
  } catch {}
  try {
    activeUsb = JSON.parse(row.active_usb_devices_json || '[]');
  } catch {}

  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);

  return {
    ...row,
    write_access_denied: Boolean(row.write_access_denied),
    connected_removable_drives: connectedDrives,
    active_usb_devices: activeUsb,
    effective_policy: effectivePolicy
  };
}

/**
 * Get fleet-wide removable storage inventory
 */
export function getFleetStorageInventory(db, filters = {}) {
  let query = `
    SELECT drss.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           sap.name as policy_name,
           sap.removable_disk_access as policy_access_mode
    FROM device_removable_storage_status drss
    JOIN devices d ON drss.device_id = d.id
    LEFT JOIN storage_access_policies sap ON drss.policy_id = sap.id
    WHERE d.status != 'DECOMMISSIONED'
  `;
  const params = [];

  if (filters.compliance_status) {
    query += ' AND drss.compliance_status = ?';
    params.push(filters.compliance_status);
  }
  if (filters.q) {
    query += ' AND (d.hostname LIKE ? OR sap.name LIKE ? OR drss.connected_removable_drives_json LIKE ?)';
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
  }

  query += ' ORDER BY drss.last_audit_at DESC';

  if (filters.limit) {
    query += ' LIMIT ?';
    params.push(Number(filters.limit));
  }

  const rows = db.prepare(query).all(...params);
  return rows.map(r => {
    let drives = [];
    let usb = [];
    try { drives = JSON.parse(r.connected_removable_drives_json || '[]'); } catch {}
    try { usb = JSON.parse(r.active_usb_devices_json || '[]'); } catch {}
    return {
      ...r,
      write_access_denied: Boolean(r.write_access_denied),
      connected_removable_drives: drives,
      active_usb_devices: usb
    };
  });
}

/**
 * Get storage events ledger
 */
export function getStorageEvents(db, filters = {}) {
  let query = `
    SELECT rse.*,
           d.hostname
    FROM removable_storage_events rse
    JOIN devices d ON rse.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (filters.device_id) {
    query += ' AND rse.device_id = ?';
    params.push(filters.device_id);
  }
  if (filters.event_type) {
    query += ' AND rse.event_type = ?';
    params.push(filters.event_type);
  }

  query += ' ORDER BY rse.timestamp DESC';

  const limit = Math.min(Number(filters.limit) || 100, 500);
  query += ' LIMIT ?';
  params.push(limit);

  const rows = db.prepare(query).all(...params);
  return rows.map(r => ({
    ...r,
    is_encrypted: Boolean(r.is_encrypted)
  }));
}

/**
 * Compute KPI metrics for Removable Storage & Peripheral Access
 */
export function getStorageStats(db) {
  const policies = db.prepare('SELECT require_bitlocker_to_go, enabled FROM storage_access_policies').all();
  const totalPolicies = policies.length;
  const activePolicies = policies.filter(p => p.enabled === 1).length;
  const bitlockerToGoCount = policies.filter(p => p.require_bitlocker_to_go === 1 && p.enabled === 1).length;

  const postures = db.prepare(`
    SELECT drss.* FROM device_removable_storage_status drss
    JOIN devices d ON drss.device_id = d.id
    WHERE d.status != 'DECOMMISSIONED'
  `).all();

  const totalAudited = postures.length;
  let totalConnectedDrives = 0;
  let unencryptedAlerts = 0;

  for (const p of postures) {
    try {
      const drives = JSON.parse(p.connected_removable_drives_json || '[]');
      totalConnectedDrives += drives.length;
    } catch {}
    if (p.compliance_status === 'UNENCRYPTED_USB_DETECTED' || p.compliance_status === 'BLOCKED_DEVICE_DETECTED') {
      unencryptedAlerts++;
    }
  }

  const eventsCount = db.prepare('SELECT COUNT(*) as count FROM removable_storage_events').get().count;

  return {
    total_policies: totalPolicies,
    active_policies: activePolicies,
    bitlocker_to_go_enforced_count: bitlockerToGoCount,
    total_audited_workstations: totalAudited,
    connected_removable_drives_count: totalConnectedDrives,
    unencrypted_usb_alerts_count: unencryptedAlerts,
    total_storage_events_count: eventsCount
  };
}
