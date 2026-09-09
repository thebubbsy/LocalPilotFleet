import crypto from 'node:crypto';
import { getDb } from '../db.js';

/**
 * Microsoft Intune Feature Update Profiles & Expedited Quality Updates Engine (WUfB)
 */

/**
 * Parse OS version string into product and release version info
 * e.g. "Windows 11, version 23H2" -> { product: "Windows 11", version: "23H2" }
 */
export function parseOsTargetVersion(targetOsVersion = '') {
  const str = String(targetOsVersion || '').trim();
  let product = 'Windows 11';
  let version = '23H2';

  if (str.toLowerCase().includes('windows 10')) {
    product = 'Windows 10';
  } else {
    product = 'Windows 11';
  }

  const verMatch = str.match(/(2[1-5]H[1-2])/i);
  if (verMatch) {
    version = verMatch[1].toUpperCase();
  }

  return { product, version };
}

/**
 * Generate PowerShell script enforcing TargetReleaseVersion registry keys
 */
export function generateFeatureRegistryScript(policy) {
  if (!policy) return '';

  const { product, version } = parseOsTargetVersion(policy.target_os_version);
  const safeguards = policy.safeguard_holds_enabled ? 0 : 1; // 0 = safeguards enabled, 1 = disabled

  return `# LocalPilot Fleet Windows Update for Business — Feature Update Version Lock
# Policy: ${policy.name} | Target: ${policy.target_os_version}

$wuPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
if (-not (Test-Path $wuPath)) {
    New-Item -Path $wuPath -Force | Out-Null
}

# 1. Enforce Target Release Version Locking
Set-ItemProperty -Path $wuPath -Name "TargetReleaseVersion" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $wuPath -Name "TargetReleaseVersionInfo" -Value "${version}" -Type String -Force
Set-ItemProperty -Path $wuPath -Name "ProductVersion" -Value "${product}" -Type String -Force

# 2. Safeguard Holds Configuration (0 = Respect Safeguards, 1 = Disable Safeguards)
Set-ItemProperty -Path $wuPath -Name "DisableWUfBSafeguards" -Value ${safeguards} -Type DWord -Force

Write-Host "[LocalPilot WUfB] Pinned target feature version to ${product} ${version} (Safeguards: ${safeguards === 0 ? 'Enforced' : 'Bypassed'})" -ForegroundColor Green
`;
}

/**
 * Generate PowerShell script for expediting quality updates / hotfixes
 */
export function generateExpeditedRegistryScript(expedited) {
  if (!expedited) return '';

  const kbNumber = expedited.target_kb_number.replace(/^KB/i, '');
  const overrideActive = expedited.override_active_hours ? 1 : 0;
  const deadlineDays = expedited.days_until_forced_reboot !== undefined ? expedited.days_until_forced_reboot : 1;

  return `# LocalPilot Fleet WUfB — Expedited Quality Update Enforcement
# Expedite: ${expedited.name} | KB${kbNumber} | CVE: ${expedited.cve_reference || 'Emergency'}

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " [LocalPilot] Expediting Critical Windows Security Hotfix" -ForegroundColor Yellow
Write-Host " Target KB: KB${kbNumber} | Deadline: ${deadlineDays} day(s)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Red

# Force Windows Update agent to check online against Microsoft Update catalog
try {
    Write-Host "[LocalPilot] Initiating expedited hotfix scan via USO Client..." -ForegroundColor Cyan
    Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -WindowStyle Hidden
    Start-Process -FilePath "usoclient.exe" -ArgumentList "StartDownload" -WindowStyle Hidden
    Start-Process -FilePath "usoclient.exe" -ArgumentList "StartInstall" -WindowStyle Hidden
} catch {
    Write-Host "[LocalPilot] Invoking native Windows Update COM session..." -ForegroundColor Yellow
}
`;
}

/**
 * Overview statistics for Feature Updates & Expedited Patching
 */
export function getFeatureUpdateStats() {
  const db = getDb();

  const totalFeaturePolicies = db.prepare('SELECT COUNT(*) as count FROM feature_update_policies').get().count;
  const activeFeaturePolicies = db.prepare('SELECT COUNT(*) as count FROM feature_update_policies WHERE enabled = 1').get().count;
  const totalExpeditedUpdates = db.prepare('SELECT COUNT(*) as count FROM expedited_quality_updates').get().count;
  const activeExpeditedUpdates = db.prepare("SELECT COUNT(*) as count FROM expedited_quality_updates WHERE status = 'ACTIVE'").get().count;

  const totalMonitoredDevices = db.prepare('SELECT COUNT(*) as count FROM device_feature_update_status').get().count;
  const upToDateDevices = db.prepare("SELECT COUNT(*) as count FROM device_feature_update_status WHERE feature_update_status = 'UP_TO_DATE'").get().count;
  const offeringDevices = db.prepare("SELECT COUNT(*) as count FROM device_feature_update_status WHERE feature_update_status IN ('OFFERING', 'INSTALLING')").get().count;
  const pendingRebootDevices = db.prepare("SELECT COUNT(*) as count FROM device_feature_update_status WHERE feature_update_status = 'PENDING_REBOOT'").get().count;
  const safeguardHoldDevices = db.prepare("SELECT COUNT(*) as count FROM device_feature_update_status WHERE feature_update_status = 'SAFEGUARD_HOLD'").get().count;
  const expeditedCompletedDevices = db.prepare("SELECT COUNT(*) as count FROM device_feature_update_status WHERE expedited_install_status = 'COMPLETED'").get().count;

  return {
    totalFeaturePolicies,
    activeFeaturePolicies,
    totalExpeditedUpdates,
    activeExpeditedUpdates,
    totalMonitoredDevices,
    upToDateDevices,
    offeringDevices,
    pendingRebootDevices,
    safeguardHoldDevices,
    expeditedCompletedDevices
  };
}

/**
 * List all feature update policies
 */
export function getFeaturePolicies(query = {}) {
  const db = getDb();
  let sql = `
    SELECT 
      p.*,
      g.name as target_group_name,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.feature_policy_id = p.id) as assigned_device_count
    FROM feature_update_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE 1=1
  `;
  const params = [];

  if (query.enabled !== undefined) {
    sql += ' AND p.enabled = ?';
    params.push(query.enabled ? 1 : 0);
  }

  sql += ' ORDER BY p.created_at DESC';
  return db.prepare(sql).all(...params);
}

/**
 * Get detailed feature update policy
 */
export function getFeaturePolicy(id) {
  const db = getDb();
  const policy = db.prepare(`
    SELECT 
      p.*,
      g.name as target_group_name,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.feature_policy_id = p.id) as assigned_device_count
    FROM feature_update_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);

  if (!policy) return null;

  return {
    ...policy,
    registry_script: generateFeatureRegistryScript(policy)
  };
}

/**
 * Create a new feature update policy
 */
export function createFeaturePolicy(data) {
  const db = getDb();
  const {
    name,
    description = '',
    target_group_id = null,
    target_os_version,
    rollout_type = 'IMMEDIATELY',
    rollout_start_date = null,
    rollout_end_date = null,
    days_between_groups = 0,
    safeguard_holds_enabled = 1,
    enabled = 1
  } = data;

  if (!name || !name.trim()) {
    throw new Error('Policy name is required');
  }
  if (!target_os_version || !target_os_version.trim()) {
    throw new Error('target_os_version is required (e.g., Windows 11, version 23H2)');
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO feature_update_policies (
      id, name, description, target_group_id, target_os_version,
      rollout_type, rollout_start_date, rollout_end_date, days_between_groups,
      safeguard_holds_enabled, enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    name.trim(),
    description,
    target_group_id || null,
    target_os_version.trim(),
    rollout_type,
    rollout_start_date,
    rollout_end_date,
    days_between_groups,
    safeguard_holds_enabled ? 1 : 0,
    enabled ? 1 : 0
  );

  return getFeaturePolicy(id);
}

/**
 * Update an existing feature update policy
 */
export function updateFeaturePolicy(id, data) {
  const db = getDb();
  const existing = getFeaturePolicy(id);
  if (!existing) throw new Error('Policy not found');

  const fields = [];
  const params = [];

  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error('Policy name cannot be empty');
    fields.push('name = ?');
    params.push(data.name.trim());
  }
  if (data.description !== undefined) {
    fields.push('description = ?');
    params.push(data.description);
  }
  if (data.target_group_id !== undefined) {
    fields.push('target_group_id = ?');
    params.push(data.target_group_id || null);
  }
  if (data.target_os_version !== undefined) {
    if (!data.target_os_version.trim()) throw new Error('target_os_version cannot be empty');
    fields.push('target_os_version = ?');
    params.push(data.target_os_version.trim());
  }
  if (data.rollout_type !== undefined) {
    fields.push('rollout_type = ?');
    params.push(data.rollout_type);
  }
  if (data.safeguard_holds_enabled !== undefined) {
    fields.push('safeguard_holds_enabled = ?');
    params.push(data.safeguard_holds_enabled ? 1 : 0);
  }
  if (data.enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(data.enabled ? 1 : 0);
  }

  if (fields.length > 0) {
    fields.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE feature_update_policies SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  }

  return getFeaturePolicy(id);
}

/**
 * Delete a custom feature update policy
 */
export function deleteFeaturePolicy(id) {
  const db = getDb();
  const existing = getFeaturePolicy(id);
  if (!existing) throw new Error('Policy not found');

  db.prepare('DELETE FROM feature_update_policies WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * List all expedited quality update campaigns
 */
export function getExpeditedUpdates(query = {}) {
  const db = getDb();
  let sql = `
    SELECT 
      e.*,
      g.name as target_group_name,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.expedited_update_id = e.id) as targeted_device_count,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.expedited_update_id = e.id AND s.expedited_install_status = 'COMPLETED') as completed_device_count
    FROM expedited_quality_updates e
    LEFT JOIN dynamic_groups g ON e.target_group_id = g.id
    WHERE 1=1
  `;
  const params = [];

  if (query.status) {
    sql += ' AND e.status = ?';
    params.push(query.status);
  }

  sql += ' ORDER BY e.created_at DESC';
  return db.prepare(sql).all(...params);
}

/**
 * Get detailed expedited quality update
 */
export function getExpeditedUpdate(id) {
  const db = getDb();
  const exp = db.prepare(`
    SELECT 
      e.*,
      g.name as target_group_name,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.expedited_update_id = e.id) as targeted_device_count,
      (SELECT COUNT(*) FROM device_feature_update_status s WHERE s.expedited_update_id = e.id AND s.expedited_install_status = 'COMPLETED') as completed_device_count
    FROM expedited_quality_updates e
    LEFT JOIN dynamic_groups g ON e.target_group_id = g.id
    WHERE e.id = ?
  `).get(id);

  if (!exp) return null;

  return {
    ...exp,
    expedite_script: generateExpeditedRegistryScript(exp)
  };
}

/**
 * Create a new expedited quality update campaign
 */
export function createExpeditedUpdate(data) {
  const db = getDb();
  const {
    name,
    description = '',
    target_group_id = null,
    target_kb_number,
    cve_reference = '',
    min_os_version = '',
    days_until_forced_reboot = 1,
    override_active_hours = 1,
    status = 'ACTIVE'
  } = data;

  if (!name || !name.trim()) {
    throw new Error('Update campaign name is required');
  }
  if (!target_kb_number || !target_kb_number.trim()) {
    throw new Error('target_kb_number is required (e.g. KB5044284)');
  }

  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO expedited_quality_updates (
      id, name, description, target_group_id, target_kb_number,
      cve_reference, min_os_version, days_until_forced_reboot,
      override_active_hours, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    name.trim(),
    description,
    target_group_id || null,
    target_kb_number.trim().toUpperCase(),
    cve_reference.trim(),
    min_os_version,
    days_until_forced_reboot,
    override_active_hours ? 1 : 0,
    status
  );

  return getExpeditedUpdate(id);
}

/**
 * Update an expedited quality update campaign
 */
export function updateExpeditedUpdate(id, data) {
  const db = getDb();
  const existing = getExpeditedUpdate(id);
  if (!existing) throw new Error('Expedited update campaign not found');

  const fields = [];
  const params = [];

  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error('Name cannot be empty');
    fields.push('name = ?');
    params.push(data.name.trim());
  }
  if (data.description !== undefined) {
    fields.push('description = ?');
    params.push(data.description);
  }
  if (data.status !== undefined) {
    fields.push('status = ?');
    params.push(data.status);
  }
  if (data.days_until_forced_reboot !== undefined) {
    fields.push('days_until_forced_reboot = ?');
    params.push(data.days_until_forced_reboot);
  }

  if (fields.length > 0) {
    fields.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE expedited_quality_updates SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  }

  return getExpeditedUpdate(id);
}

/**
 * Delete an expedited update campaign
 */
export function deleteExpeditedUpdate(id) {
  const db = getDb();
  const existing = getExpeditedUpdate(id);
  if (!existing) throw new Error('Expedited update not found');

  db.prepare('DELETE FROM expedited_quality_updates WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * Resolve effective feature update policy for a device
 */
export function getEffectiveFeaturePolicyForDevice(deviceId) {
  const db = getDb();

  const groupPolicy = db.prepare(`
    SELECT p.* FROM feature_update_policies p
    JOIN group_memberships gm ON p.target_group_id = gm.group_id
    WHERE gm.device_id = ? AND p.enabled = 1
    ORDER BY p.created_at DESC LIMIT 1
  `).get(deviceId);

  if (groupPolicy) return groupPolicy;

  return db.prepare(`
    SELECT * FROM feature_update_policies 
    WHERE target_group_id IS NULL AND enabled = 1
    ORDER BY created_at ASC LIMIT 1
  `).get() || null;
}

/**
 * Resolve active expedited update for a device
 */
export function getEffectiveExpeditedUpdateForDevice(deviceId) {
  const db = getDb();

  const groupExp = db.prepare(`
    SELECT e.* FROM expedited_quality_updates e
    JOIN group_memberships gm ON e.target_group_id = gm.group_id
    WHERE gm.device_id = ? AND e.status = 'ACTIVE'
    ORDER BY e.created_at DESC LIMIT 1
  `).get(deviceId);

  if (groupExp) return groupExp;

  return db.prepare(`
    SELECT * FROM expedited_quality_updates
    WHERE target_group_id IS NULL AND status = 'ACTIVE'
    ORDER BY created_at DESC LIMIT 1
  `).get() || null;
}

/**
 * Ingest or update device feature update & expedited hotfix status
 */
export function saveDeviceFeatureUpdateStatus(deviceId, data = {}) {
  const db = getDb();
  const {
    current_os_version = 'Windows 11',
    current_os_build = '22631.3007',
    target_os_version = '',
    feature_update_status = 'UP_TO_DATE',
    expedited_install_status = 'NOT_APPLICABLE',
    safeguard_hold_reasons = ''
  } = data;

  const effectivePolicy = getEffectiveFeaturePolicyForDevice(deviceId);
  const effectiveExpedited = getEffectiveExpeditedUpdateForDevice(deviceId);

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO device_feature_update_status (
      id, device_id, feature_policy_id, expedited_update_id,
      current_os_version, current_os_build, target_os_version,
      feature_update_status, expedited_install_status, safeguard_hold_reasons,
      last_scanned_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    ON CONFLICT(device_id) DO UPDATE SET
      feature_policy_id = excluded.feature_policy_id,
      expedited_update_id = excluded.expedited_update_id,
      current_os_version = excluded.current_os_version,
      current_os_build = excluded.current_os_build,
      target_os_version = excluded.target_os_version,
      feature_update_status = excluded.feature_update_status,
      expedited_install_status = excluded.expedited_install_status,
      safeguard_hold_reasons = excluded.safeguard_hold_reasons,
      last_scanned_at = excluded.last_scanned_at,
      updated_at = DATETIME('now')
  `).run(
    id,
    deviceId,
    effectivePolicy ? effectivePolicy.id : null,
    effectiveExpedited ? effectiveExpedited.id : null,
    current_os_version,
    current_os_build,
    target_os_version || (effectivePolicy ? effectivePolicy.target_os_version : ''),
    feature_update_status,
    expedited_install_status,
    safeguard_hold_reasons,
    now
  );

  return getDeviceFeatureUpdateStatus(deviceId);
}

/**
 * Get device feature update status
 */
export function getDeviceFeatureUpdateStatus(deviceId) {
  const db = getDb();
  const status = db.prepare(`
    SELECT 
      s.*,
      p.name as feature_policy_name,
      p.target_os_version as policy_target_version,
      e.name as expedited_update_name,
      e.target_kb_number
    FROM device_feature_update_status s
    LEFT JOIN feature_update_policies p ON s.feature_policy_id = p.id
    LEFT JOIN expedited_quality_updates e ON s.expedited_update_id = e.id
    WHERE s.device_id = ?
  `).get(deviceId);

  const effectivePolicy = getEffectiveFeaturePolicyForDevice(deviceId);
  const effectiveExpedited = getEffectiveExpeditedUpdateForDevice(deviceId);

  return {
    status: status || null,
    effective_feature_policy: effectivePolicy,
    effective_expedited_update: effectiveExpedited
  };
}

/**
 * Fleet-wide inventory overview
 */
export function getFeatureInventoryOverview() {
  const db = getDb();
  return db.prepare(`
    SELECT 
      s.*,
      d.hostname as device_hostname,
      d.friendly_name as device_friendly_name,
      d.status as device_status,
      p.name as policy_name,
      e.name as expedited_name,
      e.target_kb_number
    FROM device_feature_update_status s
    JOIN devices d ON s.device_id = d.id
    LEFT JOIN feature_update_policies p ON s.feature_policy_id = p.id
    LEFT JOIN expedited_quality_updates e ON s.expedited_update_id = e.id
    ORDER BY d.hostname ASC
  `).all();
}
