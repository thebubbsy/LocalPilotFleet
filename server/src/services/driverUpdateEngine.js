/**
 * server/src/services/driverUpdateEngine.js
 * 
 * Windows Driver & Firmware Update Profiles (WUfB Driver Policies) Governance Engine.
 * Implements Intune-grade driver discovery, approval workflows, OEM catalog tracking,
 * and automated or manual driver rollouts.
 */

import { randomUUID } from 'node:crypto';

/**
 * Get all driver update policies with assigned device count
 */
export function getDriverPolicies(db) {
  const policies = db.prepare(`
    SELECT p.*, g.name as target_group_name,
      (SELECT COUNT(DISTINCT dds.device_id) 
       FROM device_driver_status dds
       JOIN group_memberships gm ON dds.device_id = gm.device_id
       WHERE gm.group_id = p.target_group_id) as assigned_devices_count
    FROM driver_update_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    ORDER BY p.created_at ASC
  `).all();
  return policies;
}

/**
 * Get a single driver policy by ID
 */
export function getDriverPolicy(db, id) {
  const policy = db.prepare(`
    SELECT p.*, g.name as target_group_name
    FROM driver_update_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);
  return policy || null;
}

/**
 * Create a new driver update policy
 */
export function createDriverPolicy(db, data) {
  const id = data.id || `drv-pol-${randomUUID().slice(0, 8)}`;
  const stmt = db.prepare(`
    INSERT INTO driver_update_policies (
      id, name, description, target_group_id, approval_method,
      automatic_approval_delay_days, allow_optional_drivers, enabled,
      created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    data.name || 'Custom Driver Update Policy',
    data.description || '',
    data.target_group_id || 'grp-all',
    data.approval_method || 'MANUAL',
    data.automatic_approval_delay_days !== undefined ? Number(data.automatic_approval_delay_days) : 7,
    data.allow_optional_drivers !== undefined ? (data.allow_optional_drivers ? 1 : 0) : 1,
    data.enabled !== undefined ? (data.enabled ? 1 : 0) : 1
  );

  return getDriverPolicy(db, id);
}

/**
 * Update an existing driver update policy
 */
export function updateDriverPolicy(db, id, data) {
  const existing = getDriverPolicy(db, id);
  if (!existing) return null;

  const fields = [];
  const params = [];

  const allowedCols = [
    'name', 'description', 'target_group_id', 'approval_method',
    'automatic_approval_delay_days', 'allow_optional_drivers', 'enabled'
  ];

  for (const col of allowedCols) {
    if (data[col] !== undefined) {
      fields.push(`${col} = ?`);
      let val = data[col];
      if (['allow_optional_drivers', 'enabled'].includes(col)) {
        val = val ? 1 : 0;
      }
      params.push(val);
    }
  }

  if (fields.length === 0) return existing;

  fields.push("updated_at = DATETIME('now')");
  params.push(id);

  db.prepare(`UPDATE driver_update_policies SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  return getDriverPolicy(db, id);
}

/**
 * Delete a driver update policy
 */
export function deleteDriverPolicy(db, id) {
  const existing = getDriverPolicy(db, id);
  if (!existing) return false;
  db.prepare('DELETE FROM driver_update_policies WHERE id = ?').run(id);
  return true;
}

/**
 * Generate PowerShell deployment script setting Windows Update Driver policies in Registry
 */
export function generateDriverRegistryScript(policy) {
  if (!policy) return '# No policy provided';

  const isAuto = policy.approval_method === 'AUTOMATIC';
  const isEnabled = policy.enabled !== undefined ? (policy.enabled ? 1 : 0) : 1;
  const excludeDrivers = isEnabled ? 0 : 1;

  return `# =====================================================================
# LocalPilot Windows Driver & Firmware Update Enforcement Script
# Policy: ${policy.name} (${policy.id})
# Approval Method: ${policy.approval_method} | Generated: ${new Date().toISOString()}
# =====================================================================

$ErrorActionPreference = 'Stop'
Write-Host "Applying Windows Driver Update Policy [${policy.id}]..."

$wuPolicyKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'

if (-not (Test-Path $wuPolicyKey)) {
    New-Item -Path $wuPolicyKey -Force | Out-Null
}

# 1. Driver Exclusion toggle (0 = Include Drivers in Windows Update)
Set-ItemProperty -Path $wuPolicyKey -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value ${excludeDrivers}

# 2. Driver Approval Automation & Deferral
Set-ItemProperty -Path $wuPolicyKey -Name 'DriverUpdateApprovalMode' -Type DWord -Value ${isAuto ? 1 : 0}
Set-ItemProperty -Path $wuPolicyKey -Name 'DriverDeferralPeriodInDays' -Type DWord -Value ${policy.automatic_approval_delay_days || 0}
Set-ItemProperty -Path $wuPolicyKey -Name 'AllowOptionalDrivers' -Type DWord -Value ${policy.allow_optional_drivers ? 1 : 0}

Write-Host "Driver & firmware update governance configured successfully."
`;
}

/**
 * Resolve effective driver update policy for a device
 */
export function getEffectiveDriverPolicyForDevice(db, deviceId) {
  const match = db.prepare(`
    SELECT p.* 
    FROM driver_update_policies p
    JOIN group_memberships gm ON p.target_group_id = gm.group_id
    JOIN dynamic_groups g ON gm.group_id = g.id
    WHERE gm.device_id = ? AND p.enabled = 1
    ORDER BY g.priority ASC, p.created_at ASC
    LIMIT 1
  `).get(deviceId);

  if (match) return match;

  const fallback = db.prepare(`
    SELECT * FROM driver_update_policies
    WHERE (target_group_id = 'grp-all' OR target_group_id IS NULL) AND enabled = 1
    ORDER BY created_at ASC
    LIMIT 1
  `).get();

  return fallback || null;
}

/**
 * Get fleet driver catalog with optional filters
 */
export function getDriverCatalog(db, filter = {}) {
  let query = 'SELECT * FROM fleet_driver_catalog WHERE 1=1';
  const params = [];

  if (filter.driver_class) {
    query += ' AND driver_class = ?';
    params.push(filter.driver_class);
  }
  if (filter.approval_status) {
    query += ' AND approval_status = ?';
    params.push(filter.approval_status);
  }

  query += ' ORDER BY applicable_devices_count DESC, driver_name ASC';
  return db.prepare(query).all(...params);
}

/**
 * Get single catalog driver by ID
 */
export function getDriverCatalogItem(db, id) {
  return db.prepare('SELECT * FROM fleet_driver_catalog WHERE id = ?').get(id) || null;
}

/**
 * Set driver approval status (APPROVED, DECLINED, SUSPENDED)
 */
export function setDriverApprovalStatus(db, id, status, approvedBy = 'LocalPilot Administrator') {
  const existing = getDriverCatalogItem(db, id);
  if (!existing) return null;

  const approvedAt = status === 'APPROVED' ? new Date().toISOString() : null;

  db.prepare(`
    UPDATE fleet_driver_catalog
    SET approval_status = ?, approved_at = ?, approved_by = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(status, approvedAt, approvedBy, id);

  return getDriverCatalogItem(db, id);
}

/**
 * Upsert catalog driver discovered from workstation telemetry
 */
export function upsertCatalogDriver(db, data) {
  const id = data.id || `drv-${data.driver_provider.toLowerCase().replace(/[^a-z0-9]/g, '')}-${data.driver_name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16)}`;
  const driverName = data.driver_name;
  const driverClass = data.driver_class || 'OTHER';
  const driverProvider = data.driver_provider || 'OEM';
  const driverVersion = data.driver_version || '1.0.0.0';
  const driverDate = data.driver_date || '';
  const hardwareId = data.hardware_id || '';
  const approvalStatus = data.approval_status || 'PENDING_REVIEW';

  const stmt = db.prepare(`
    INSERT INTO fleet_driver_catalog (
      id, driver_name, driver_class, driver_provider, driver_version,
      driver_date, hardware_id, approval_status, applicable_devices_count,
      installed_devices_count, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, 1, 1, DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(id) DO UPDATE SET
      driver_version = excluded.driver_version,
      driver_date = excluded.driver_date,
      hardware_id = excluded.hardware_id,
      updated_at = DATETIME('now')
  `);

  stmt.run(id, driverName, driverClass, driverProvider, driverVersion, driverDate, hardwareId, approvalStatus);
  return getDriverCatalogItem(db, id);
}

/**
 * Ingest full driver inventory for a device
 */
export function saveDeviceDriverInventory(db, deviceId, drivers) {
  if (!Array.isArray(drivers)) return { count: 0 };

  const insertStatus = db.prepare(`
    INSERT INTO device_driver_status (
      id, device_id, driver_id, current_version, install_status,
      last_scanned_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    ON CONFLICT(device_id, driver_id) DO UPDATE SET
      current_version = excluded.current_version,
      install_status = excluded.install_status,
      last_scanned_at = excluded.last_scanned_at,
      updated_at = DATETIME('now')
  `);

  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

  db.exec('BEGIN IMMEDIATE;');
  try {
    for (const d of drivers) {
      // 1. Ensure driver is in catalog
      const catItem = upsertCatalogDriver(db, d);
      const statusId = `devdrv-${deviceId}-${catItem.id}`;
      const installStatus = d.install_status || 'INSTALLED';

      insertStatus.run(
        statusId,
        deviceId,
        catItem.id,
        d.driver_version || catItem.driver_version,
        installStatus,
        now
      );
    }

    // Recalculate applicable and installed counts in catalog
    db.prepare(`
      UPDATE fleet_driver_catalog
      SET installed_devices_count = (
        SELECT COUNT(*) FROM device_driver_status WHERE driver_id = fleet_driver_catalog.id AND install_status = 'INSTALLED'
      ),
      applicable_devices_count = (
        SELECT COUNT(DISTINCT device_id) FROM device_driver_status WHERE driver_id = fleet_driver_catalog.id
      )
    `).run();

    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }

  return { count: drivers.length, timestamp: now };
}

/**
 * Get installed drivers for a device with catalog alignment
 */
export function getDeviceDrivers(db, deviceId) {
  const drivers = db.prepare(`
    SELECT s.*, c.driver_name, c.driver_class, c.driver_provider,
           c.driver_version as latest_version, c.approval_status, c.approved_at
    FROM device_driver_status s
    JOIN fleet_driver_catalog c ON s.driver_id = c.id
    WHERE s.device_id = ?
    ORDER BY c.driver_class ASC, c.driver_name ASC
  `).all(deviceId);

  const effectivePolicy = getEffectiveDriverPolicyForDevice(db, deviceId);

  return {
    device_id: deviceId,
    effective_policy: effectivePolicy,
    drivers: drivers
  };
}

/**
 * Get fleet-wide workstation driver posture overview
 */
export function getDriverInventoryOverview(db) {
  return db.prepare(`
    SELECT d.id as device_id, d.hostname, d.friendly_name, d.ip_address as device_ip, d.status as device_status,
      COUNT(s.id) as total_drivers,
      SUM(CASE WHEN s.install_status = 'INSTALLED' THEN 1 ELSE 0 END) as installed_count,
      SUM(CASE WHEN s.install_status = 'NEEDS_UPDATE' THEN 1 ELSE 0 END) as needs_update_count,
      SUM(CASE WHEN c.approval_status = 'APPROVED' THEN 1 ELSE 0 END) as approved_drivers_installed,
      MAX(s.last_scanned_at) as last_scanned_at
    FROM devices d
    LEFT JOIN device_driver_status s ON d.id = s.device_id
    LEFT JOIN fleet_driver_catalog c ON s.driver_id = c.id
    GROUP BY d.id
    ORDER BY needs_update_count DESC, d.hostname ASC
  `).all();
}

/**
 * Get executive summary statistics for driver & firmware governance
 */
export function getDriverStats(db) {
  const polRow = db.prepare(`
    SELECT 
      COUNT(*) as total_policies,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as active_policies
    FROM driver_update_policies
  `).get();

  const catRow = db.prepare(`
    SELECT 
      COUNT(*) as total_catalog,
      SUM(CASE WHEN approval_status = 'APPROVED' THEN 1 ELSE 0 END) as approved_count,
      SUM(CASE WHEN approval_status = 'PENDING_REVIEW' THEN 1 ELSE 0 END) as pending_count,
      SUM(CASE WHEN approval_status = 'DECLINED' THEN 1 ELSE 0 END) as declined_count
    FROM fleet_driver_catalog
  `).get();

  const devRow = db.prepare(`
    SELECT 
      COUNT(DISTINCT device_id) as total_audited,
      SUM(CASE WHEN install_status = 'NEEDS_UPDATE' THEN 1 ELSE 0 END) as total_pending_updates
    FROM device_driver_status
  `).get();

  const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const auditedCount = devRow.total_audited || 0;
  const pendingUpdates = devRow.total_pending_updates || 0;

  const compliantDevices = Math.max(0, auditedCount - (pendingUpdates > 0 ? 1 : 0));
  const compliancePct = auditedCount > 0 ? Math.round((compliantDevices / auditedCount) * 100) : 100;

  return {
    total_policies: polRow.total_policies || 0,
    active_policies: polRow.active_policies || 0,
    total_catalog_drivers: catRow.total_catalog || 0,
    approved_drivers_count: catRow.approved_count || 0,
    pending_review_drivers_count: catRow.pending_count || 0,
    declined_drivers_count: catRow.declined_count || 0,
    total_audited_devices: auditedCount,
    total_devices_in_fleet: totalDevices,
    up_to_date_devices_count: compliantDevices,
    fleet_driver_compliance_pct: compliancePct
  };
}
