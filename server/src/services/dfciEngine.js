import { broadcastEvent } from '../routes/events.js';

/**
 * Enterprise Device Firmware Configuration Interface (DFCI) & UEFI BIOS Governance Engine
 * Microsoft Intune UEFI & Hardware Root-of-Trust Management
 */

/**
 * Generate native Windows PowerShell script configuring and auditing UEFI / BIOS firmware
 */
export function generateRegistryScript(policy) {
  return `# LocalPilot Fleet Device Firmware Configuration Interface (DFCI) Script
# Policy: ${policy.name} (${policy.id})
# Target Group: ${policy.target_group_id}

$DfciKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\DFCI"
if (-not (Test-Path $DfciKey)) { New-Item -Path $DfciKey -Force | Out-Null }

# 1. Hardware Peripheral Restrictions at Motherboard Layer
Set-ItemProperty -Path $DfciKey -Name "CamerasEnabled" -Value ${policy.cameras_enabled ? 1 : 0} -Type DWord -Force
Set-ItemProperty -Path $DfciKey -Name "MicrophonesEnabled" -Value ${policy.microphones_enabled ? 1 : 0} -Type DWord -Force
Set-ItemProperty -Path $DfciKey -Name "RadiosEnabled" -Value ${policy.radios_enabled ? 1 : 0} -Type DWord -Force
Set-ItemProperty -Path $DfciKey -Name "ExternalMediaBootEnabled" -Value ${policy.external_media_boot_enabled ? 1 : 0} -Type DWord -Force
Set-ItemProperty -Path $DfciKey -Name "NetworkAdapterBootEnabled" -Value ${policy.network_adapter_boot_enabled ? 1 : 0} -Type DWord -Force
Set-ItemProperty -Path $DfciKey -Name "PreventUserBiosChanges" -Value ${policy.prevent_user_bios_changes ? 1 : 0} -Type DWord -Force

# 2. Hardware Security & Virtualization Mandates
$DgKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"
if (-not (Test-Path $DgKey)) { New-Item -Path $DgKey -Force | Out-Null }

${policy.require_vbs ? 'Set-ItemProperty -Path $DgKey -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force' : ''}
${policy.require_kernel_dma ? 'Set-ItemProperty -Path $DgKey -Name "KernelDmaProtection" -Value 1 -Type DWord -Force' : ''}

# 3. UEFI / BIOS Hardware Audit
Write-Host "Auditing UEFI Firmware & Hardware Root-of-Trust Posture..."
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
Write-Host "BIOS Vendor: $($bios.Manufacturer), Version: $($bios.SMBIOSBIOSVersion), Date: $($bios.ReleaseDate)"

$sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
Write-Host "Secure Boot State: $(if ($sb) { 'ENABLED' } else { 'DISABLED' })"

try {
    $tpm = Get-CimInstance -Namespace root\\cimv2\\security\\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        Write-Host "TPM Present: Spec Version $($tpm.SpecVersion), Activated: $($tpm.IsActivated_InitialValue)"
    } else {
        Write-Warning "No TPM chip detected on system motherboard."
    }
} catch {
    Write-Warning "Error checking TPM state: $_"
}

Write-Host "DFCI policy applied and audited successfully."
`.trim();
}

/**
 * Get all DFCI Policies with assigned device counts
 */
export function getAllPolicies(db) {
  const policies = db.prepare(`
    SELECT dp.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM dfci_policies dp
    LEFT JOIN dynamic_groups dg ON dp.target_group_id = dg.id
    ORDER BY dp.name ASC
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
      cameras_enabled: Boolean(p.cameras_enabled),
      microphones_enabled: Boolean(p.microphones_enabled),
      radios_enabled: Boolean(p.radios_enabled),
      external_media_boot_enabled: Boolean(p.external_media_boot_enabled),
      network_adapter_boot_enabled: Boolean(p.network_adapter_boot_enabled),
      prevent_user_bios_changes: Boolean(p.prevent_user_bios_changes),
      require_secure_boot: Boolean(p.require_secure_boot),
      require_tpm2: Boolean(p.require_tpm2),
      require_kernel_dma: Boolean(p.require_kernel_dma),
      require_vbs: Boolean(p.require_vbs),
      enabled: Boolean(p.enabled)
    };
  });
}

/**
 * Get single policy by ID
 */
export function getPolicyById(db, id) {
  const policy = db.prepare(`
    SELECT dp.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM dfci_policies dp
    LEFT JOIN dynamic_groups dg ON dp.target_group_id = dg.id
    WHERE dp.id = ?
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
    cameras_enabled: Boolean(policy.cameras_enabled),
    microphones_enabled: Boolean(policy.microphones_enabled),
    radios_enabled: Boolean(policy.radios_enabled),
    external_media_boot_enabled: Boolean(policy.external_media_boot_enabled),
    network_adapter_boot_enabled: Boolean(policy.network_adapter_boot_enabled),
    prevent_user_bios_changes: Boolean(policy.prevent_user_bios_changes),
    require_secure_boot: Boolean(policy.require_secure_boot),
    require_tpm2: Boolean(policy.require_tpm2),
    require_kernel_dma: Boolean(policy.require_kernel_dma),
    require_vbs: Boolean(policy.require_vbs),
    enabled: Boolean(policy.enabled),
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Create a new DFCI policy
 */
export function createPolicy(db, data) {
  const id = data.id || ('dfci-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8));
  const name = data.name ? data.name.trim() : '';
  if (!name) throw new Error('Policy name is required');

  const stmt = db.prepare(`
    INSERT INTO dfci_policies (
      id, name, description, target_group_id,
      cameras_enabled, microphones_enabled, radios_enabled,
      external_media_boot_enabled, network_adapter_boot_enabled,
      prevent_user_bios_changes, require_secure_boot, require_tpm2,
      require_kernel_dma, require_vbs, uefi_password_protection,
      enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    name,
    data.description || '',
    data.target_group_id || 'grp-all',
    data.cameras_enabled === 0 || data.cameras_enabled === false ? 0 : 1,
    data.microphones_enabled === 0 || data.microphones_enabled === false ? 0 : 1,
    data.radios_enabled === 0 || data.radios_enabled === false ? 0 : 1,
    data.external_media_boot_enabled === 0 || data.external_media_boot_enabled === false ? 0 : 1,
    data.network_adapter_boot_enabled === 0 || data.network_adapter_boot_enabled === false ? 0 : 1,
    data.prevent_user_bios_changes ? 1 : 0,
    data.require_secure_boot === 0 || data.require_secure_boot === false ? 0 : 1,
    data.require_tpm2 === 0 || data.require_tpm2 === false ? 0 : 1,
    data.require_kernel_dma ? 1 : 0,
    data.require_vbs ? 1 : 0,
    data.uefi_password_protection || 'NONE',
    data.enabled === 0 || data.enabled === false ? 0 : 1
  );

  broadcastEvent('dfci:policy_created', { id, name });
  return getPolicyById(db, id);
}

/**
 * Update an existing DFCI policy
 */
export function updatePolicy(db, id, data) {
  const existing = getPolicyById(db, id);
  if (!existing) return null;

  const name = data.name !== undefined ? data.name.trim() : existing.name;
  if (!name) throw new Error('Policy name cannot be empty');

  const stmt = db.prepare(`
    UPDATE dfci_policies SET
      name = ?,
      description = ?,
      target_group_id = ?,
      cameras_enabled = ?,
      microphones_enabled = ?,
      radios_enabled = ?,
      external_media_boot_enabled = ?,
      network_adapter_boot_enabled = ?,
      prevent_user_bios_changes = ?,
      require_secure_boot = ?,
      require_tpm2 = ?,
      require_kernel_dma = ?,
      require_vbs = ?,
      uefi_password_protection = ?,
      enabled = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `);

  stmt.run(
    name,
    data.description !== undefined ? data.description : existing.description,
    data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id,
    data.cameras_enabled !== undefined ? (data.cameras_enabled ? 1 : 0) : (existing.cameras_enabled ? 1 : 0),
    data.microphones_enabled !== undefined ? (data.microphones_enabled ? 1 : 0) : (existing.microphones_enabled ? 1 : 0),
    data.radios_enabled !== undefined ? (data.radios_enabled ? 1 : 0) : (existing.radios_enabled ? 1 : 0),
    data.external_media_boot_enabled !== undefined ? (data.external_media_boot_enabled ? 1 : 0) : (existing.external_media_boot_enabled ? 1 : 0),
    data.network_adapter_boot_enabled !== undefined ? (data.network_adapter_boot_enabled ? 1 : 0) : (existing.network_adapter_boot_enabled ? 1 : 0),
    data.prevent_user_bios_changes !== undefined ? (data.prevent_user_bios_changes ? 1 : 0) : (existing.prevent_user_bios_changes ? 1 : 0),
    data.require_secure_boot !== undefined ? (data.require_secure_boot ? 1 : 0) : (existing.require_secure_boot ? 1 : 0),
    data.require_tpm2 !== undefined ? (data.require_tpm2 ? 1 : 0) : (existing.require_tpm2 ? 1 : 0),
    data.require_kernel_dma !== undefined ? (data.require_kernel_dma ? 1 : 0) : (existing.require_kernel_dma ? 1 : 0),
    data.require_vbs !== undefined ? (data.require_vbs ? 1 : 0) : (existing.require_vbs ? 1 : 0),
    data.uefi_password_protection !== undefined ? data.uefi_password_protection : existing.uefi_password_protection,
    data.enabled !== undefined ? (data.enabled ? 1 : 0) : (existing.enabled ? 1 : 0),
    id
  );

  broadcastEvent('dfci:policy_updated', { id, name });
  return getPolicyById(db, id);
}

/**
 * Delete a DFCI policy
 */
export function deletePolicy(db, id) {
  const existing = getPolicyById(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM dfci_policies WHERE id = ?').run(id);
  broadcastEvent('dfci:policy_deleted', { id });
  return true;
}

/**
 * Resolve effective DFCI policy for a specific device based on group membership
 */
export function getEffectivePolicyForDevice(db, deviceId) {
  const groups = db.prepare(`
    SELECT group_id FROM group_memberships WHERE device_id = ?
  `).all(deviceId).map(r => r.group_id);

  groups.push('grp-all');

  const placeholders = groups.map(() => '?').join(',');
  const policy = db.prepare(`
    SELECT * FROM dfci_policies
    WHERE enabled = 1 AND target_group_id IN (${placeholders})
    ORDER BY created_at DESC
    LIMIT 1
  `).get(...groups);

  if (!policy) return null;

  return {
    ...policy,
    cameras_enabled: Boolean(policy.cameras_enabled),
    microphones_enabled: Boolean(policy.microphones_enabled),
    radios_enabled: Boolean(policy.radios_enabled),
    external_media_boot_enabled: Boolean(policy.external_media_boot_enabled),
    network_adapter_boot_enabled: Boolean(policy.network_adapter_boot_enabled),
    prevent_user_bios_changes: Boolean(policy.prevent_user_bios_changes),
    require_secure_boot: Boolean(policy.require_secure_boot),
    require_tpm2: Boolean(policy.require_tpm2),
    require_kernel_dma: Boolean(policy.require_kernel_dma),
    require_vbs: Boolean(policy.require_vbs),
    enabled: Boolean(policy.enabled),
    powershell_script: generateRegistryScript(policy)
  };
}

/**
 * Save / Update Workstation DFCI, UEFI, TPM & Hardware Root-of-Trust Posture
 */
export function saveDeviceDfciStatus(db, deviceId, payload) {
  const existingDevice = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
  if (!existingDevice) throw new Error(`Device '${deviceId}' not found`);

  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
  const statusId = 'devdfci-' + deviceId;

  const secureBoot = payload.secure_boot_enabled === 1 || payload.secure_boot_enabled === true ? 1 : 0;
  const tpmPresent = payload.tpm_present === 1 || payload.tpm_present === true ? 1 : 0;
  const tpmReady = payload.tpm_ready === 1 || payload.tpm_ready === true ? 1 : 0;
  const kernelDma = payload.kernel_dma_protection === 1 || payload.kernel_dma_protection === true ? 1 : 0;
  const tpmVersion = payload.tpm_version ? String(payload.tpm_version).trim() : '';

  // Calculate Hardware Root-of-Trust Readiness Score (0 to 100)
  let score = 0;
  if (secureBoot === 1) score += 30;
  if (tpmPresent === 1 && tpmReady === 1) {
    if (tpmVersion.includes('2.0') || parseFloat(tpmVersion) >= 2.0) {
      score += 30;
    } else {
      score += 15;
    }
  }
  if (kernelDma === 1) score += 20;
  if (payload.vbs_status === 'RUNNING' || payload.hvci_status === 'RUNNING' || payload.vbs_status === 'ACTIVE' || payload.hvci_status === 'ACTIVE') {
    score += 20;
  }

  // Evaluate Compliance against Effective Policy
  let compliance = 'COMPLIANT';
  if (effectivePolicy) {
    if (effectivePolicy.require_secure_boot && secureBoot !== 1) {
      compliance = 'SECUREBOOT_DISABLED';
    } else if (effectivePolicy.require_tpm2 && (tpmPresent !== 1 || !tpmVersion.includes('2.0'))) {
      compliance = 'TPM_MISSING';
    }
  }

  const stmt = db.prepare(`
    INSERT INTO device_dfci_status (
      id, device_id, policy_id, bios_vendor, bios_version, bios_release_date, uefi_version,
      secure_boot_enabled, tpm_present, tpm_version, tpm_ready, tpm_manufacturer,
      kernel_dma_protection, vbs_status, hvci_status, hardware_readiness_score,
      cameras_state, microphones_state, radios_state, external_boot_state, network_boot_state,
      compliance_status, last_audit_at, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, DATETIME('now'), DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(device_id) DO UPDATE SET
      policy_id = excluded.policy_id,
      bios_vendor = excluded.bios_vendor,
      bios_version = excluded.bios_version,
      bios_release_date = excluded.bios_release_date,
      uefi_version = excluded.uefi_version,
      secure_boot_enabled = excluded.secure_boot_enabled,
      tpm_present = excluded.tpm_present,
      tpm_version = excluded.tpm_version,
      tpm_ready = excluded.tpm_ready,
      tpm_manufacturer = excluded.tpm_manufacturer,
      kernel_dma_protection = excluded.kernel_dma_protection,
      vbs_status = excluded.vbs_status,
      hvci_status = excluded.hvci_status,
      hardware_readiness_score = excluded.hardware_readiness_score,
      cameras_state = excluded.cameras_state,
      microphones_state = excluded.microphones_state,
      radios_state = excluded.radios_state,
      external_boot_state = excluded.external_boot_state,
      network_boot_state = excluded.network_boot_state,
      compliance_status = excluded.compliance_status,
      last_audit_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `);

  stmt.run(
    statusId,
    deviceId,
    effectivePolicy?.id || null,
    payload.bios_vendor || '',
    payload.bios_version || '',
    payload.bios_release_date || '',
    payload.uefi_version || '',
    secureBoot,
    tpmPresent,
    tpmVersion,
    tpmReady,
    payload.tpm_manufacturer || '',
    kernelDma,
    payload.vbs_status || 'NOT_CONFIGURED',
    payload.hvci_status || 'NOT_CONFIGURED',
    score,
    payload.cameras_state || 'ENABLED',
    payload.microphones_state || 'ENABLED',
    payload.radios_state || 'ENABLED',
    payload.external_boot_state || 'ENABLED',
    payload.network_boot_state || 'ENABLED',
    compliance
  );

  broadcastEvent('dfci:status_updated', {
    device_id: deviceId,
    hostname: existingDevice.hostname,
    compliance_status: compliance,
    hardware_readiness_score: score,
    secure_boot_enabled: Boolean(secureBoot),
    tpm_version: tpmVersion
  });

  return getDeviceDfciStatus(db, deviceId);
}

/**
 * Record a Firmware / Hardware Root-of-Trust Audit Event
 */
export function recordDfciEvent(db, deviceId, eventData) {
  const id = 'dfcievt-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  const eventType = eventData.event_type || 'FIRMWARE_AUDIT';
  const settingName = eventData.setting_name || 'UEFI_CONFIG';
  const oldValue = eventData.old_value || '';
  const newValue = eventData.new_value || '';
  const details = eventData.details || '';

  const stmt = db.prepare(`
    INSERT INTO dfci_audit_log (
      id, device_id, event_type, setting_name, old_value, new_value, details, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
  `);

  stmt.run(id, deviceId, eventType, settingName, oldValue, newValue, details);

  // If critical security violation, also trigger master security event
  if (eventType === 'SECUREBOOT_VIOLATION' || eventType === 'HARDWARE_TAMPER_ALERT') {
    try {
      db.prepare(`
        INSERT INTO security_events (device_id, event_type, event_source, severity, summary, raw_payload_json, created_at)
        VALUES (?, 'SECUREBOOT_DISABLED', 'DFCI_SUBSYSTEM', 'CRITICAL', ?, ?, DATETIME('now'))
      `).run(
        deviceId,
        `UEFI Hardware Tamper Alert: ${settingName} changed to ${newValue}`,
        JSON.stringify({ settingName, oldValue, newValue, details })
      );
      broadcastEvent('security:alert', { deviceId, eventType, severity: 'CRITICAL', settingName });
    } catch (err) {
      console.error('[DFCI] Failed to log security_events:', err.message);
    }
  }

  broadcastEvent('dfci:event_logged', { id, deviceId, eventType, settingName });
  return { id, deviceId, event_type: eventType, setting_name: settingName, old_value: oldValue, new_value: newValue, details, timestamp: new Date().toISOString() };
}

/**
 * Get DFCI Inventory (Workstation Firmware Posture)
 */
export function getDfciInventory(db, params = {}) {
  let query = `
    SELECT dds.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           dp.name as policy_name
    FROM device_dfci_status dds
    JOIN devices d ON dds.device_id = d.id
    LEFT JOIN dfci_policies dp ON dds.policy_id = dp.id
    WHERE 1=1
  `;

  const args = [];
  if (params.compliance_status) {
    query += ' AND dds.compliance_status = ?';
    args.push(params.compliance_status);
  }
  if (params.search) {
    query += ' AND (d.hostname LIKE ? OR dds.bios_vendor LIKE ? OR dds.bios_version LIKE ?)';
    const term = `%${params.search}%`;
    args.push(term, term, term);
  }

  query += ' ORDER BY dds.last_audit_at DESC';

  const rows = db.prepare(query).all(...args);
  return rows.map(r => ({
    ...r,
    secure_boot_enabled: Boolean(r.secure_boot_enabled),
    tpm_present: Boolean(r.tpm_present),
    tpm_ready: Boolean(r.tpm_ready),
    kernel_dma_protection: Boolean(r.kernel_dma_protection)
  }));
}

/**
 * Get DFCI Audit Log
 */
export function getDfciAuditLog(db, params = {}) {
  let query = `
    SELECT dal.*,
           d.hostname
    FROM dfci_audit_log dal
    JOIN devices d ON dal.device_id = d.id
    WHERE 1=1
  `;

  const args = [];
  if (params.device_id) {
    query += ' AND dal.device_id = ?';
    args.push(params.device_id);
  }
  if (params.event_type) {
    query += ' AND dal.event_type = ?';
    args.push(params.event_type);
  }

  query += ' ORDER BY dal.timestamp DESC LIMIT 100';
  return db.prepare(query).all(...args);
}

/**
 * Get Fleet-Wide DFCI Statistics & Hardware Readiness Metrics
 */
export function getDfciStats(db) {
  const polCount = db.prepare('SELECT COUNT(*) as count FROM dfci_policies').get().count;
  const activePolCount = db.prepare('SELECT COUNT(*) as count FROM dfci_policies WHERE enabled = 1').get().count;

  const auditStats = db.prepare(`
    SELECT
      COUNT(*) as total_audited,
      SUM(CASE WHEN secure_boot_enabled = 1 THEN 1 ELSE 0 END) as secure_boot_count,
      SUM(CASE WHEN tpm_present = 1 AND tpm_ready = 1 AND tpm_version LIKE '%2.0%' THEN 1 ELSE 0 END) as tpm2_count,
      SUM(CASE WHEN kernel_dma_protection = 1 THEN 1 ELSE 0 END) as dma_count,
      AVG(hardware_readiness_score) as avg_score,
      SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count
    FROM device_dfci_status
  `).get();

  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM dfci_audit_log').get().count;
  const totalFleetDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;

  return {
    total_policies: polCount,
    active_policies: activePolCount,
    total_audited_devices: auditStats.total_audited || 0,
    total_devices_in_fleet: totalFleetDevices,
    secure_boot_enabled_devices: auditStats.secure_boot_count || 0,
    tpm2_verified_devices: auditStats.tpm2_count || 0,
    kernel_dma_protected_devices: auditStats.dma_count || 0,
    average_hardware_readiness_score: auditStats.avg_score ? Number(auditStats.avg_score.toFixed(1)) : 0.0,
    compliant_devices_count: auditStats.compliant_count || 0,
    total_audit_events: totalEvents
  };
}

/**
 * Get DFCI Status for a single device
 */
export function getDeviceDfciStatus(db, deviceId) {
  const status = db.prepare('SELECT * FROM device_dfci_status WHERE device_id = ?').get(deviceId);
  const effectivePolicy = getEffectivePolicyForDevice(db, deviceId);
  const recentEvents = db.prepare('SELECT * FROM dfci_audit_log WHERE device_id = ? ORDER BY timestamp DESC LIMIT 10').all(deviceId);

  return {
    device_id: deviceId,
    status: status ? {
      ...status,
      secure_boot_enabled: Boolean(status.secure_boot_enabled),
      tpm_present: Boolean(status.tpm_present),
      tpm_ready: Boolean(status.tpm_ready),
      kernel_dma_protection: Boolean(status.kernel_dma_protection)
    } : null,
    effective_policy: effectivePolicy,
    recent_events: recentEvents
  };
}
