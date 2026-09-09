/**
 * LocalPilot Fleet — Windows 365 Cloud PC & Virtual Workstation Fleet Engine
 * server/src/services/cloudPcEngine.js
 *
 * Manages Cloud PC provisioning policies, virtual machine instances,
 * user assignments, grace periods, disaster recovery restore points, and Hyper-V automation.
 */

import crypto from 'node:crypto';

export function getCloudPcStats(db) {
  const totalInstances = db.prepare('SELECT COUNT(*) as c FROM cloud_pc_instances').get().c;
  const provisionedCount = db.prepare("SELECT COUNT(*) as c FROM cloud_pc_instances WHERE provisioning_status = 'PROVISIONED'").get().c;
  const graceCount = db.prepare("SELECT COUNT(*) as c FROM cloud_pc_instances WHERE provisioning_status = 'IN_GRACE_PERIOD'").get().c;
  const reprovCount = db.prepare("SELECT COUNT(*) as c FROM cloud_pc_instances WHERE provisioning_status = 'REPROVISIONING'").get().c;
  const offlineCount = db.prepare("SELECT COUNT(*) as c FROM cloud_pc_instances WHERE provisioning_status = 'OFFLINE'").get().c;

  const totalPolicies = db.prepare('SELECT COUNT(*) as c FROM cloud_pc_provisioning_policies').get().c;
  const totalRestorePoints = db.prepare('SELECT COUNT(*) as c FROM cloud_pc_restore_points').get().c;

  const storageSum = db.prepare(`
    SELECT COALESCE(SUM(p.storage_gb), 0) as total_gb
    FROM cloud_pc_instances i
    JOIN cloud_pc_provisioning_policies p ON i.policy_id = p.id
  `).get().total_gb;

  return {
    total_cloud_pcs: totalInstances,
    provisioned_count: provisionedCount,
    in_grace_period_count: graceCount,
    reprovisioning_count: reprovCount,
    offline_count: offlineCount,
    total_policies: totalPolicies,
    total_restore_points: totalRestorePoints,
    total_storage_allocated_gb: storageSum,
    health_status: offlineCount === 0 ? 'HEALTHY' : 'DEGRADED'
  };
}

/* ── Provisioning Policies ── */
export function getProvisioningPolicies(db) {
  return db.prepare(`
    SELECT p.*, g.name as target_group_name,
           (SELECT COUNT(*) FROM cloud_pc_instances WHERE policy_id = p.id) as assigned_instances_count
    FROM cloud_pc_provisioning_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    ORDER BY p.created_at DESC
  `).all();
}

export function getProvisioningPolicy(db, id) {
  return db.prepare(`
    SELECT p.*, g.name as target_group_name
    FROM cloud_pc_provisioning_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id) || null;
}

export function createProvisioningPolicy(db, data) {
  const id = data.id || ('cpc-pol-' + crypto.randomBytes(4).toString('hex'));
  const name = data.name || 'Standard Cloud PC Policy';
  const description = data.description || '';
  const sku_name = data.sku_name || 'Standard 2vCPU / 8GB RAM / 128GB Storage';
  const vcpu_count = parseInt(data.vcpu_count, 10) || 2;
  const ram_gb = parseInt(data.ram_gb, 10) || 8;
  const storage_gb = parseInt(data.storage_gb, 10) || 128;
  const os_image = data.os_image || 'Windows 11 Enterprise 24H2';
  const join_type = data.join_type || 'ENTRA_JOIN';
  const target_group_id = data.target_group_id || 'grp-all';

  db.prepare(`
    INSERT INTO cloud_pc_provisioning_policies (id, name, description, sku_name, vcpu_count, ram_gb, storage_gb, os_image, join_type, target_group_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, description, sku_name, vcpu_count, ram_gb, storage_gb, os_image, join_type, target_group_id);

  return getProvisioningPolicy(db, id);
}

export function updateProvisioningPolicy(db, id, data) {
  const existing = getProvisioningPolicy(db, id);
  if (!existing) return null;

  const name = data.name !== undefined ? data.name : existing.name;
  const description = data.description !== undefined ? data.description : existing.description;
  const sku_name = data.sku_name !== undefined ? data.sku_name : existing.sku_name;
  const vcpu_count = data.vcpu_count !== undefined ? parseInt(data.vcpu_count, 10) : existing.vcpu_count;
  const ram_gb = data.ram_gb !== undefined ? parseInt(data.ram_gb, 10) : existing.ram_gb;
  const storage_gb = data.storage_gb !== undefined ? parseInt(data.storage_gb, 10) : existing.storage_gb;
  const os_image = data.os_image !== undefined ? data.os_image : existing.os_image;
  const join_type = data.join_type !== undefined ? data.join_type : existing.join_type;
  const target_group_id = data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id;

  db.prepare(`
    UPDATE cloud_pc_provisioning_policies
    SET name = ?, description = ?, sku_name = ?, vcpu_count = ?, ram_gb = ?, storage_gb = ?, os_image = ?, join_type = ?, target_group_id = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(name, description, sku_name, vcpu_count, ram_gb, storage_gb, os_image, join_type, target_group_id, id);

  return getProvisioningPolicy(db, id);
}

export function deleteProvisioningPolicy(db, id) {
  const res = db.prepare('DELETE FROM cloud_pc_provisioning_policies WHERE id = ?').run(id);
  return res.changes > 0;
}

/* ── Cloud PC Instances ── */
export function getCloudPcInstances(db, filter = {}) {
  let query = `
    SELECT i.*, p.name as policy_name, p.sku_name, p.vcpu_count, p.ram_gb, p.storage_gb, p.os_image,
           d.hostname as host_device_name
    FROM cloud_pc_instances i
    JOIN cloud_pc_provisioning_policies p ON i.policy_id = p.id
    LEFT JOIN devices d ON i.host_device_id = d.id
  `;
  const conditions = [];
  const params = [];

  if (filter.provisioning_status) {
    conditions.push('i.provisioning_status = ?');
    params.push(filter.provisioning_status);
  }
  if (filter.policy_id) {
    conditions.push('i.policy_id = ?');
    params.push(filter.policy_id);
  }
  if (filter.primary_user) {
    conditions.push('i.primary_user LIKE ?');
    params.push(`%${filter.primary_user}%`);
  }

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }
  query += ' ORDER BY i.created_at DESC';

  return db.prepare(query).all(...params);
}

export function getCloudPcInstance(db, id) {
  const inst = db.prepare(`
    SELECT i.*, p.name as policy_name, p.sku_name, p.vcpu_count, p.ram_gb, p.storage_gb, p.os_image,
           d.hostname as host_device_name
    FROM cloud_pc_instances i
    JOIN cloud_pc_provisioning_policies p ON i.policy_id = p.id
    LEFT JOIN devices d ON i.host_device_id = d.id
    WHERE i.id = ?
  `).get(id);

  if (!inst) return null;

  const restorePoints = db.prepare(`
    SELECT * FROM cloud_pc_restore_points WHERE cloud_pc_id = ? ORDER BY captured_at DESC
  `).all(id);

  return { ...inst, restore_points: restorePoints };
}

export function createCloudPcInstance(db, data) {
  const id = data.id || ('cpc-inst-' + crypto.randomBytes(4).toString('hex'));
  const policy_id = data.policy_id;
  const name = data.name || ('CloudPC-' + crypto.randomBytes(3).toString('hex').toUpperCase());
  const hostname = data.hostname || ('CPC-' + crypto.randomBytes(4).toString('hex').toUpperCase());
  const primary_user = data.primary_user || 'FleetUser';
  const host_device_id = data.host_device_id || null;
  const provisioning_status = data.provisioning_status || 'PROVISIONED';
  const ip_address = data.ip_address || '192.168.1.200';
  const ram_bytes = data.ram_bytes || 8589934592;
  const disk_free_gb = data.disk_free_gb !== undefined ? data.disk_free_gb : 95.0;

  db.prepare(`
    INSERT INTO cloud_pc_instances (id, policy_id, name, hostname, primary_user, host_device_id, provisioning_status, ip_address, ram_bytes, disk_free_gb)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, policy_id, name, hostname, primary_user, host_device_id, provisioning_status, ip_address, ram_bytes, disk_free_gb);

  return getCloudPcInstance(db, id);
}

export function updateCloudPcInstance(db, id, data) {
  const existing = getCloudPcInstance(db, id);
  if (!existing) return null;

  const name = data.name !== undefined ? data.name : existing.name;
  const hostname = data.hostname !== undefined ? data.hostname : existing.hostname;
  const primary_user = data.primary_user !== undefined ? data.primary_user : existing.primary_user;
  const host_device_id = data.host_device_id !== undefined ? data.host_device_id : existing.host_device_id;
  const provisioning_status = data.provisioning_status !== undefined ? data.provisioning_status : existing.provisioning_status;
  const ip_address = data.ip_address !== undefined ? data.ip_address : existing.ip_address;
  const disk_free_gb = data.disk_free_gb !== undefined ? data.disk_free_gb : existing.disk_free_gb;

  db.prepare(`
    UPDATE cloud_pc_instances
    SET name = ?, hostname = ?, primary_user = ?, host_device_id = ?, provisioning_status = ?, ip_address = ?, disk_free_gb = ?, updated_at = DATETIME('now')
    WHERE id = ?
  `).run(name, hostname, primary_user, host_device_id, provisioning_status, ip_address, disk_free_gb, id);

  return getCloudPcInstance(db, id);
}

export function deleteCloudPcInstance(db, id) {
  const res = db.prepare('DELETE FROM cloud_pc_instances WHERE id = ?').run(id);
  return res.changes > 0;
}

export function triggerReprovisioning(db, id) {
  const existing = getCloudPcInstance(db, id);
  if (!existing) return null;

  // 1. Take safety snapshot
  const rpId = 'rp-reprov-' + crypto.randomBytes(4).toString('hex');
  db.prepare(`
    INSERT INTO cloud_pc_restore_points (id, cloud_pc_id, name, restore_point_type, status)
    VALUES (?, ?, ?, 'AUTOMATIC_DISASTER_RECOVERY', 'READY')
  `).run(rpId, id, 'Pre-Reprovisioning Automated Snapshot');

  // 2. Set to REPROVISIONING
  db.prepare(`
    UPDATE cloud_pc_instances
    SET provisioning_status = 'REPROVISIONING', updated_at = DATETIME('now')
    WHERE id = ?
  `).run(id);

  return getCloudPcInstance(db, id);
}

export function setGracePeriod(db, id, days = 7) {
  const existing = getCloudPcInstance(db, id);
  if (!existing) return null;

  db.prepare(`
    UPDATE cloud_pc_instances
    SET provisioning_status = 'IN_GRACE_PERIOD',
        grace_period_ends_at = DATETIME('now', '+${days} days'),
        updated_at = DATETIME('now')
    WHERE id = ?
  `).run(id);

  return getCloudPcInstance(db, id);
}

/* ── Restore Points ── */
export function getRestorePoints(db, filter = {}) {
  let query = `
    SELECT rp.*, i.name as cloud_pc_name, i.hostname
    FROM cloud_pc_restore_points rp
    JOIN cloud_pc_instances i ON rp.cloud_pc_id = i.id
  `;
  const conditions = [];
  const params = [];

  if (filter.cloud_pc_id) {
    conditions.push('rp.cloud_pc_id = ?');
    params.push(filter.cloud_pc_id);
  }
  if (filter.status) {
    conditions.push('rp.status = ?');
    params.push(filter.status);
  }

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }
  query += ' ORDER BY rp.captured_at DESC';

  return db.prepare(query).all(...params);
}

export function createRestorePoint(db, data) {
  const id = data.id || ('rp-snap-' + crypto.randomBytes(4).toString('hex'));
  const cloud_pc_id = data.cloud_pc_id;
  const name = data.name || ('Manual Checkpoint ' + new Date().toISOString().slice(0, 10));
  const restore_point_type = data.restore_point_type || 'USER_SNAPSHOT';
  const size_bytes = data.size_bytes || 10737418240;
  const status = data.status || 'READY';

  db.prepare(`
    INSERT INTO cloud_pc_restore_points (id, cloud_pc_id, name, restore_point_type, size_bytes, status)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, cloud_pc_id, name, restore_point_type, size_bytes, status);

  return db.prepare('SELECT * FROM cloud_pc_restore_points WHERE id = ?').get(id);
}

export function triggerRestorePointRecovery(db, pointId) {
  const rp = db.prepare('SELECT * FROM cloud_pc_restore_points WHERE id = ?').get(pointId);
  if (!rp) return null;

  db.prepare(`
    UPDATE cloud_pc_restore_points SET status = 'READY', captured_at = DATETIME('now') WHERE id = ?
  `).run(pointId);

  db.prepare(`
    UPDATE cloud_pc_instances SET provisioning_status = 'PROVISIONED', updated_at = DATETIME('now') WHERE id = ?
  `).run(rp.cloud_pc_id);

  return getCloudPcInstance(db, rp.cloud_pc_id);
}

export function deleteRestorePoint(db, id) {
  const res = db.prepare('DELETE FROM cloud_pc_restore_points WHERE id = ?').run(id);
  return res.changes > 0;
}

/* ── Hyper-V Automation Script Generator ── */
export function generateHyperVProvisionScript(policy, instanceName = 'CloudPC-NewVM') {
  const vcpu = policy?.vcpu_count || 4;
  const ramBytes = (policy?.ram_gb || 16) * 1024 * 1024 * 1024;
  const diskBytes = (policy?.storage_gb || 256) * 1024 * 1024 * 1024;
  const vmName = instanceName.replace(/[^a-zA-Z0-9_-]/g, '');

  return `# LocalPilot Fleet — Automated Hyper-V Cloud PC Provisioning Script
# Target VM: ${vmName} | SKU: ${policy?.sku_name || 'Standard'}
# Generated at: ${new Date().toISOString()}

$ErrorActionPreference = 'Stop'
Write-Host "Creating Virtual Workstation: ${vmName}..." -ForegroundColor Cyan

$vmPath = "C:\ProgramData\LocalPilotFleet\VirtualMachines\${vmName}"
if (-not (Test-Path $vmPath)) { New-Item -ItemType Directory -Path $vmPath -Force | Out-Null }

$vhdPath = "$vmPath\${vmName}.vhdx"
if (-not (Test-Path $vhdPath)) {
    Write-Host "Initializing Dynamic VHDX (${policy?.storage_gb || 256} GB)..."
    New-VHD -Path $vhdPath -SizeBytes ${diskBytes} -Dynamic | Out-Null
}

$existingVM = Get-VM -Name "${vmName}" -ErrorAction SilentlyContinue
if (-not $existingVM) {
    Write-Host "Provisioning Generation 2 Virtual Machine..."
    $vm = New-VM -Name "${vmName}" -Generation 2 -MemoryStartupBytes ${ramBytes} -VHDPath $vhdPath -Path $vmPath
    Set-VMProcessor -VMName "${vmName}" -Count ${vcpu}
    Set-VMFirmware -VMName "${vmName}" -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
    Write-Host "Virtual Machine ${vmName} successfully created and ready for OS deployment." -ForegroundColor Green
} else {
    Write-Host "Virtual Machine ${vmName} already exists in Hyper-V inventory." -ForegroundColor Yellow
}
`;
}
