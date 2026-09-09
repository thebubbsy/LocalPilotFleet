import { broadcastEvent } from '../routes/events.js';

/**
 * Enterprise Delivery Optimization & Peer-to-Peer Cache Governance Engine
 * Microsoft Intune & Windows Delivery Optimization (DO) Management
 */

/**
 * Generate native Windows PowerShell script applying registry-based Delivery Optimization policies
 */
export function generateRegistryScript(policy) {
  const modeMap = {
    HTTP_ONLY: 0,
    LAN_PEER: 1,
    GROUP_PEER: 2,
    INTERNET_PEER: 3,
    SIMPLE: 99,
    BYPASS: 100
  };

  const modeVal = modeMap[policy.download_mode] !== undefined ? modeMap[policy.download_mode] : 1;
  const maxCacheAgeSec = (policy.cache_retention_days || 7) * 86400;

  return `# LocalPilot Fleet Delivery Optimization Configuration Script
# Policy: ${policy.name} (${policy.id})
# Download Mode: ${policy.download_mode} (Value: ${modeVal})

$DoKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"
if (-not (Test-Path $DoKey)) { New-Item -Path $DoKey -Force | Out-Null }

# 1. Core Download Mode
Set-ItemProperty -Path $DoKey -Name "DODownloadMode" -Value ${modeVal} -Type DWord -Force
Write-Host "Configured Delivery Optimization Download Mode to ${policy.download_mode} (${modeVal})"` +

(policy.download_mode === 'GROUP_PEER' && policy.group_id_guid ? `
# Group ID Peering Domain
Set-ItemProperty -Path $DoKey -Name "DOGroupId" -Value "${policy.group_id_guid}" -Type String -Force
Write-Host "Configured Group ID GUID: ${policy.group_id_guid}"` : `
Remove-ItemProperty -Path $DoKey -Name "DOGroupId" -ErrorAction SilentlyContinue`) +

`
# 2. Cache Size & Disk Allocation
Set-ItemProperty -Path $DoKey -Name "DOMaxCacheSize" -Value ${policy.max_cache_size_pct || 20} -Type DWord -Force
Set-ItemProperty -Path $DoKey -Name "DOMaxCacheAge" -Value ${maxCacheAgeSec} -Type DWord -Force
Set-ItemProperty -Path $DoKey -Name "DOMinDiskSizeAllowedToPeer" -Value ${policy.min_disk_size_gb || 32} -Type DWord -Force
Set-ItemProperty -Path $DoKey -Name "DOMinRAMAllowedToPeer" -Value ${policy.min_ram_capacity_gb || 4} -Type DWord -Force
Set-ItemProperty -Path $DoKey -Name "DOMinFileSizeToCache" -Value ${policy.min_file_size_mb || 10} -Type DWord -Force

# 3. Bandwidth Throttling & Monthly Quota` +

(policy.max_background_download_pct > 0 ? `
Set-ItemProperty -Path $DoKey -Name "DOMaxBackgroundDownloadBandwidth" -Value ${policy.max_background_download_pct} -Type DWord -Force` : `
Remove-ItemProperty -Path $DoKey -Name "DOMaxBackgroundDownloadBandwidth" -ErrorAction SilentlyContinue`) +

(policy.max_foreground_download_pct > 0 ? `
Set-ItemProperty -Path $DoKey -Name "DOMaxForegroundDownloadBandwidth" -Value ${policy.max_foreground_download_pct} -Type DWord -Force` : `
Remove-ItemProperty -Path $DoKey -Name "DOMaxForegroundDownloadBandwidth" -ErrorAction SilentlyContinue`) +

(policy.max_upload_bandwidth_kbps > 0 ? `
Set-ItemProperty -Path $DoKey -Name "DOMaxUploadBandwidth" -Value ${policy.max_upload_bandwidth_kbps} -Type DWord -Force` : `
Remove-ItemProperty -Path $DoKey -Name "DOMaxUploadBandwidth" -ErrorAction SilentlyContinue`) +

(policy.monthly_upload_cap_gb > 0 ? `
Set-ItemProperty -Path $DoKey -Name "DOMonthlyUploadDataCap" -Value ${policy.monthly_upload_cap_gb} -Type DWord -Force` : `
Remove-ItemProperty -Path $DoKey -Name "DOMonthlyUploadDataCap" -ErrorAction SilentlyContinue`) +

`
# 4. Restart Delivery Optimization Service to apply settings
try {
    Restart-Service -Name dosvc -Force -ErrorAction SilentlyContinue
    Write-Host "Delivery Optimization service (dosvc) restarted successfully."
} catch {
    Write-Warning "Could not restart dosvc service: $_"
}
Write-Host "Delivery Optimization policy applied successfully."
`.trim();
}

/**
 * Get all Delivery Optimization Policies with assigned device counts
 */
export function getAllPolicies(db) {
  const policies = db.prepare(`
    SELECT dop.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM delivery_optimization_policies dop
    LEFT JOIN dynamic_groups dg ON dop.target_group_id = dg.id
    ORDER BY dop.name ASC
  `).all();

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;

  return policies.map(p => {
    let assignedCount = 0;
    if (p.target_group_id === 'grp-all' || p.target_group_id === 'all-devices') {
      assignedCount = totalDevicesCount;
    } else if (p.target_group_id) {
      const match = db.prepare('SELECT COUNT(DISTINCT device_id) as count FROM group_memberships WHERE group_id = ?').get(p.target_group_id);
      assignedCount = match ? match.count : 0;
    }

    return {
      ...p,
      assigned_devices_count: assignedCount,
      enabled: Boolean(p.enabled)
    };
  });
}

/**
 * Get single policy by ID
 */
export function getPolicyById(db, id) {
  const policy = db.prepare(`
    SELECT dop.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM delivery_optimization_policies dop
    LEFT JOIN dynamic_groups dg ON dop.target_group_id = dg.id
    WHERE dop.id = ?
  `).get(id);

  if (!policy) return null;

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;
  let assignedCount = 0;
  if (policy.target_group_id === 'grp-all' || policy.target_group_id === 'all-devices') {
    assignedCount = totalDevicesCount;
  } else if (policy.target_group_id) {
    const match = db.prepare('SELECT COUNT(DISTINCT device_id) as count FROM group_memberships WHERE group_id = ?').get(policy.target_group_id);
    assignedCount = match ? match.count : 0;
  }

  return {
    ...policy,
    assigned_devices_count: assignedCount,
    enabled: Boolean(policy.enabled),
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Create a new Delivery Optimization policy
 */
export function createPolicy(db, data) {
  const id = data.id || ('do-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8));
  const name = data.name ? data.name.trim() : '';
  if (!name) throw new Error('Policy name is required');

  const validModes = ['HTTP_ONLY', 'LAN_PEER', 'GROUP_PEER', 'INTERNET_PEER', 'SIMPLE', 'BYPASS'];
  const downloadMode = validModes.includes(data.download_mode) ? data.download_mode : 'LAN_PEER';

  const stmt = db.prepare(`
    INSERT INTO delivery_optimization_policies (
      id, name, description, target_group_id,
      download_mode, group_id_guid, max_cache_size_pct,
      min_disk_size_gb, min_ram_capacity_gb, min_file_size_mb,
      max_background_download_pct, max_foreground_download_pct,
      max_upload_bandwidth_kbps, monthly_upload_cap_gb,
      cache_retention_days, enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, ?,
      ?, ?,
      ?, ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    name,
    data.description || '',
    data.target_group_id || 'grp-all',
    downloadMode,
    data.group_id_guid || '',
    Number.isInteger(data.max_cache_size_pct) ? data.max_cache_size_pct : 20,
    Number.isInteger(data.min_disk_size_gb) ? data.min_disk_size_gb : 32,
    Number.isInteger(data.min_ram_capacity_gb) ? data.min_ram_capacity_gb : 4,
    Number.isInteger(data.min_file_size_mb) ? data.min_file_size_mb : 10,
    Number.isInteger(data.max_background_download_pct) ? data.max_background_download_pct : 0,
    Number.isInteger(data.max_foreground_download_pct) ? data.max_foreground_download_pct : 0,
    Number.isInteger(data.max_upload_bandwidth_kbps) ? data.max_upload_bandwidth_kbps : 0,
    Number.isInteger(data.monthly_upload_cap_gb) ? data.monthly_upload_cap_gb : 50,
    Number.isInteger(data.cache_retention_days) ? data.cache_retention_days : 7,
    data.enabled === 0 || data.enabled === false ? 0 : 1
  );

  broadcastEvent('delivery_optimization:policy_created', { id, name });
  return getPolicyById(db, id);
}

/**
 * Update an existing Delivery Optimization policy
 */
export function updatePolicy(db, id, data) {
  const existing = getPolicyById(db, id);
  if (!existing) return null;

  const validModes = ['HTTP_ONLY', 'LAN_PEER', 'GROUP_PEER', 'INTERNET_PEER', 'SIMPLE', 'BYPASS'];
  const name = data.name !== undefined ? data.name.trim() : existing.name;
  if (!name) throw new Error('Policy name cannot be empty');

  const downloadMode = data.download_mode !== undefined && validModes.includes(data.download_mode)
    ? data.download_mode
    : existing.download_mode;

  const stmt = db.prepare(`
    UPDATE delivery_optimization_policies SET
      name = ?,
      description = ?,
      target_group_id = ?,
      download_mode = ?,
      group_id_guid = ?,
      max_cache_size_pct = ?,
      min_disk_size_gb = ?,
      min_ram_capacity_gb = ?,
      min_file_size_mb = ?,
      max_background_download_pct = ?,
      max_foreground_download_pct = ?,
      max_upload_bandwidth_kbps = ?,
      monthly_upload_cap_gb = ?,
      cache_retention_days = ?,
      enabled = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `);

  stmt.run(
    name,
    data.description !== undefined ? data.description : existing.description,
    data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id,
    downloadMode,
    data.group_id_guid !== undefined ? data.group_id_guid : existing.group_id_guid,
    data.max_cache_size_pct !== undefined ? data.max_cache_size_pct : existing.max_cache_size_pct,
    data.min_disk_size_gb !== undefined ? data.min_disk_size_gb : existing.min_disk_size_gb,
    data.min_ram_capacity_gb !== undefined ? data.min_ram_capacity_gb : existing.min_ram_capacity_gb,
    data.min_file_size_mb !== undefined ? data.min_file_size_mb : existing.min_file_size_mb,
    data.max_background_download_pct !== undefined ? data.max_background_download_pct : existing.max_background_download_pct,
    data.max_foreground_download_pct !== undefined ? data.max_foreground_download_pct : existing.max_foreground_download_pct,
    data.max_upload_bandwidth_kbps !== undefined ? data.max_upload_bandwidth_kbps : existing.max_upload_bandwidth_kbps,
    data.monthly_upload_cap_gb !== undefined ? data.monthly_upload_cap_gb : existing.monthly_upload_cap_gb,
    data.cache_retention_days !== undefined ? data.cache_retention_days : existing.cache_retention_days,
    data.enabled !== undefined ? (data.enabled ? 1 : 0) : (existing.enabled ? 1 : 0),
    id
  );

  broadcastEvent('delivery_optimization:policy_updated', { id, name });
  return getPolicyById(db, id);
}

/**
 * Delete a Delivery Optimization policy
 */
export function deletePolicy(db, id) {
  const existing = getPolicyById(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM delivery_optimization_policies WHERE id = ?').run(id);
  broadcastEvent('delivery_optimization:policy_deleted', { id });
  return true;
}

/**
 * Resolve effective Delivery Optimization policy for a specific device based on group membership
 */
export function getEffectivePolicyForDevice(db, deviceId) {
  const groups = db.prepare(`
    SELECT group_id FROM group_memberships WHERE device_id = ?
  `).all(deviceId).map(r => r.group_id);

  groups.push('grp-all');

  const placeholders = groups.map(() => '?').join(',');
  const policy = db.prepare(`
    SELECT * FROM delivery_optimization_policies
    WHERE enabled = 1 AND target_group_id IN (${placeholders})
    ORDER BY created_at DESC
    LIMIT 1
  `).get(...groups);

  if (!policy) return null;

  return {
    ...policy,
    enabled: Boolean(policy.enabled),
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Save / Update Workstation Delivery Optimization Posture & P2P Telemetry
 */
export function saveDeviceDOStatus(db, deviceId, payload) {
  const existingDevice = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!existingDevice) throw new Error(`Device '${deviceId}' not found`);

  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
  const statusId = 'devdo-' + deviceId;

  const downloadModeActive = payload.download_mode_active || effectivePolicy?.download_mode || 'LAN_PEER';
  const httpBytes = Number(payload.bytes_downloaded_http) || 0;
  const p2pBytes = Number(payload.bytes_downloaded_p2p) || 0;
  const uploadedBytes = Number(payload.bytes_uploaded_p2p) || 0;
  const activePeers = Number(payload.active_peers_count) || 0;
  const cacheSize = Number(payload.cache_size_bytes) || 0;
  const cacheFiles = Number(payload.cache_file_count) || 0;

  const totalBytes = httpBytes + p2pBytes;
  const efficiency = totalBytes > 0 ? Number(((p2pBytes / totalBytes) * 100).toFixed(1)) : 0.0;

  const stmt = db.prepare(`
    INSERT INTO device_delivery_optimization_status (
      id, device_id, policy_id, download_mode_active,
      bytes_downloaded_http, bytes_downloaded_p2p, bytes_uploaded_p2p,
      p2p_efficiency_pct, active_peers_count, cache_size_bytes,
      cache_file_count, last_audit_at, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, DATETIME('now'), DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(device_id) DO UPDATE SET
      policy_id = excluded.policy_id,
      download_mode_active = excluded.download_mode_active,
      bytes_downloaded_http = excluded.bytes_downloaded_http,
      bytes_downloaded_p2p = excluded.bytes_downloaded_p2p,
      bytes_uploaded_p2p = excluded.bytes_uploaded_p2p,
      p2p_efficiency_pct = excluded.p2p_efficiency_pct,
      active_peers_count = excluded.active_peers_count,
      cache_size_bytes = excluded.cache_size_bytes,
      cache_file_count = excluded.cache_file_count,
      last_audit_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `);

  stmt.run(
    statusId,
    deviceId,
    effectivePolicy ? effectivePolicy.id : null,
    downloadModeActive,
    httpBytes,
    p2pBytes,
    uploadedBytes,
    efficiency,
    activePeers,
    cacheSize,
    cacheFiles
  );

  broadcastEvent('delivery_optimization:status_updated', {
    device_id: deviceId,
    hostname: existingDevice.hostname,
    p2p_efficiency_pct: efficiency,
    p2p_bytes: p2pBytes
  });

  return {
    device_id: deviceId,
    policy_id: effectivePolicy ? effectivePolicy.id : null,
    p2p_efficiency_pct: efficiency,
    status: 'SAVED'
  };
}

/**
 * Record a Delivery Optimization content transfer event
 */
export function recordContentTransfer(db, deviceId, payload) {
  const existingDevice = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!existingDevice) throw new Error(`Device '${deviceId}' not found`);

  const eventId = 'do-xfer-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8);
  const validTypes = ['WINDOWS_UPDATE', 'WINGET_APP', 'MICROSOFT_STORE', 'DEFENDER_SIGNATURE', 'OTHER'];
  const contentType = validTypes.includes(payload.content_type) ? payload.content_type : 'WINDOWS_UPDATE';

  const stmt = db.prepare(`
    INSERT INTO delivery_optimization_content_log (
      id, device_id, file_hash, content_type,
      file_size_bytes, bytes_from_peers, bytes_from_http,
      peer_source_ip, duration_ms, timestamp
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, DATETIME('now')
    )
  `);

  stmt.run(
    eventId,
    deviceId,
    payload.file_hash || '',
    contentType,
    Number(payload.file_size_bytes) || 0,
    Number(payload.bytes_from_peers) || 0,
    Number(payload.bytes_from_http) || 0,
    payload.peer_source_ip || '',
    Number(payload.duration_ms) || 0
  );

  return {
    id: eventId,
    device_id: deviceId,
    content_type: contentType,
    status: 'RECORDED'
  };
}

/**
 * Get fleet-wide Delivery Optimization inventory / device peering statuses
 */
export function getDOInventory(db, filters = {}) {
  let query = `
    SELECT dos.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           dop.name as policy_name,
           dop.download_mode as policy_download_mode
    FROM device_delivery_optimization_status dos
    JOIN devices d ON dos.device_id = d.id
    LEFT JOIN delivery_optimization_policies dop ON dos.policy_id = dop.id
    WHERE 1=1
  `;

  const params = [];

  if (filters.download_mode) {
    query += ' AND dos.download_mode_active = ?';
    params.push(filters.download_mode);
  }

  if (filters.q) {
    query += ' AND (d.hostname LIKE ? OR dos.device_id LIKE ?)';
    params.push(`%${filters.q}%`, `%${filters.q}%`);
  }

  query += ' ORDER BY dos.p2p_efficiency_pct DESC, dos.last_audit_at DESC';

  if (filters.limit) {
    query += ' LIMIT ?';
    params.push(Number(filters.limit));
  }

  return db.prepare(query).all(...params);
}

/**
 * Get Delivery Optimization content transfer log
 */
export function getContentLog(db, filters = {}) {
  let query = `
    SELECT dcl.*,
           d.hostname
    FROM delivery_optimization_content_log dcl
    JOIN devices d ON dcl.device_id = d.id
    WHERE 1=1
  `;

  const params = [];

  if (filters.device_id) {
    query += ' AND dcl.device_id = ?';
    params.push(filters.device_id);
  }

  if (filters.content_type) {
    query += ' AND dcl.content_type = ?';
    params.push(filters.content_type);
  }

  query += ' ORDER BY dcl.timestamp DESC';

  if (filters.limit) {
    query += ' LIMIT ?';
    params.push(Number(filters.limit));
  } else {
    query += ' LIMIT 100';
  }

  return db.prepare(query).all(...params);
}

/**
 * Get aggregated fleet Delivery Optimization statistics
 */
export function getDOStats(db) {
  const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM delivery_optimization_policies').get().count;
  const activePolicies = db.prepare('SELECT COUNT(*) as count FROM delivery_optimization_policies WHERE enabled = 1').get().count;
  const totalAudited = db.prepare('SELECT COUNT(*) as count FROM device_delivery_optimization_status').get().count;

  const sums = db.prepare(`
    SELECT
      COALESCE(SUM(bytes_downloaded_http), 0) as total_http_bytes,
      COALESCE(SUM(bytes_downloaded_p2p), 0) as total_p2p_bytes,
      COALESCE(SUM(bytes_uploaded_p2p), 0) as total_uploaded_bytes,
      COALESCE(SUM(cache_size_bytes), 0) as total_cache_bytes,
      COALESCE(SUM(cache_file_count), 0) as total_cache_files,
      COALESCE(SUM(active_peers_count), 0) as total_active_peers
    FROM device_delivery_optimization_status
  `).get();

  const totalDl = sums.total_http_bytes + sums.total_p2p_bytes;
  const fleetEfficiency = totalDl > 0 ? Number(((sums.total_p2p_bytes / totalDl) * 100).toFixed(1)) : 0.0;

  const peeringDevices = db.prepare(`
    SELECT COUNT(*) as count FROM device_delivery_optimization_status
    WHERE download_mode_active IN ('LAN_PEER', 'GROUP_PEER', 'INTERNET_PEER')
  `).get().count;

  const totalContentTransfers = db.prepare('SELECT COUNT(*) as count FROM delivery_optimization_content_log').get().count;

  return {
    total_policies: totalPolicies,
    active_policies: activePolicies,
    total_audited_devices: totalAudited,
    peering_devices_count: peeringDevices,
    fleet_p2p_efficiency_pct: fleetEfficiency,
    total_downloaded_http_bytes: sums.total_http_bytes,
    total_downloaded_p2p_bytes: sums.total_p2p_bytes,
    total_uploaded_p2p_bytes: sums.total_uploaded_bytes,
    total_cache_size_bytes: sums.total_cache_bytes,
    total_cached_files_count: sums.total_cache_files,
    total_active_peers: sums.total_active_peers,
    total_content_transfers: totalContentTransfers
  };
}

/**
 * Get device Delivery Optimization posture, effective policy, and recent content transfers
 */
export function getDeviceDOStatus(db, deviceId) {
  const status = db.prepare(`
    SELECT * FROM device_delivery_optimization_status WHERE device_id = ?
  `).get(deviceId);

  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
  const recentTransfers = db.prepare(`
    SELECT * FROM delivery_optimization_content_log
    WHERE device_id = ?
    ORDER BY timestamp DESC
    LIMIT 10
  `).all(deviceId);

  return {
    device_id: deviceId,
    status: status || null,
    effective_policy: effectivePolicy || null,
    recent_transfers: recentTransfers
  };
}

export default {
  generateRegistryScript,
  getAllPolicies,
  getPolicyById,
  createPolicy,
  updatePolicy,
  deletePolicy,
  getEffectivePolicyForDevice,
  saveDeviceDOStatus,
  recordContentTransfer,
  getDOInventory,
  getContentLog,
  getDOStats,
  getDeviceDOStatus
};
