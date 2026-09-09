import { broadcastEvent } from '../routes/events.js';

/**
 * Enterprise Kiosk Mode & Multi-App Assigned Access Engine
 * Microsoft Intune Assigned Access & Windows Shell Launcher Governance
 */

/**
 * Generate native Windows AssignedAccessConfiguration XML
 * Conforms to http://schemas.microsoft.com/AssignedAccess/2017/config
 */
export function generateAssignedAccessXml(profile) {
  const user = profile.user_account || 'KioskUser0';
  const autoLogon = profile.logon_type === 'AUTO_LOGON';
  const idleTimeout = profile.edge_idle_timeout_min || 5;

  let allowedAppsXml = '';
  let defaultAppXml = '';

  if (profile.kiosk_mode === 'DIGITAL_SIGNAGE' || profile.kiosk_mode === 'SINGLE_APP') {
    const isEdge = profile.app_type === 'EDGE_BROWSER';
    const aumid = isEdge 
      ? 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App'
      : (profile.app_path_or_aumid || 'Microsoft.WindowsCalculator_8wekyb3d8bbwe!App');

    let edgeArgs = '';
    if (isEdge) {
      const url = profile.edge_kiosk_url || 'https://localpilot.internal';
      if (profile.edge_kiosk_type === 'DIGITAL_SIGNAGE') {
        edgeArgs = ` --kiosk "${url}" --edge-kiosk-type=fullscreen --no-first-run`;
      } else {
        edgeArgs = ` --kiosk "${url}" --edge-kiosk-type=public-browsing --kiosk-idle-timeout-minutes=${idleTimeout} --inprivate`;
      }
    }

    defaultAppXml = `
      <DefaultApp AUMID="${aumid}" Arguments="${edgeArgs.trim()}" />`;
    allowedAppsXml = `
        <App AUMID="${aumid}" />`;
  } else {
    // Multi-App
    let parsedApps = [];
    try {
      parsedApps = typeof profile.allowed_apps_json === 'string' 
        ? JSON.parse(profile.allowed_apps_json || '[]') 
        : (profile.allowed_apps_json || []);
    } catch {
      parsedApps = [];
    }

    if (parsedApps.length === 0) {
      parsedApps = [
        { name: 'Microsoft Edge', aumid: 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App' },
        { name: 'Calculator', aumid: 'Microsoft.WindowsCalculator_8wekyb3d8bbwe!App' }
      ];
    }

    allowedAppsXml = parsedApps.map(a => {
      if (a.aumid) {
        return `        <App AUMID="${a.aumid}" />`;
      } else if (a.path) {
        return `        <App Path="${a.path}" />`;
      }
      return '';
    }).filter(Boolean).join('\n');

    defaultAppXml = `
      <!-- Multi-App Desktop / Start Grid Environment -->`;
  }

  const showTaskbar = profile.disable_taskbar ? 'false' : 'true';

  return `<?xml version="1.0" encoding="utf-8"?>
<AssignedAccessConfiguration
    xmlns="http://schemas.microsoft.com/AssignedAccess/2017/config"
    xmlns:rs5="http://schemas.microsoft.com/AssignedAccess/201810/config">
    <Profiles>
        <Profile Id="{${profile.id || 'kiosk-profile-default'}}">
            <AllAppsList>
                <AllowedApps>${allowedAppsXml ? '\n' + allowedAppsXml : ''}
                </AllowedApps>
            </AllAppsList>${defaultAppXml}
            <Taskbar ShowTaskbar="${showTaskbar}" />
        </Profile>
    </Profiles>
    <Configs>
        <Config>
            ${autoLogon ? '<AutoLogonAccount />' : `<Account>${user}</Account>`}
            <DefaultProfile Id="{${profile.id || 'kiosk-profile-default'}}" />
        </Config>
    </Configs>
</AssignedAccessConfiguration>`.trim();
}

/**
 * Generate native Windows PowerShell Shell Launcher script
 * Compatible with Windows 10/11 Enterprise / IoT Enterprise
 */
export function generateShellLauncherScript(profile) {
  const shellPath = profile.app_path_or_aumid || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  const targetUser = profile.user_account || 'KioskUser0';
  const restartAction = profile.restart_on_exit !== 0 ? 0 : 3; // 0 = Restart Shell, 3 = Do nothing

  return `# LocalPilot Fleet Shell Launcher Deployment Script
# Target Profile: ${profile.name} (${profile.id})
# Mode: ${profile.kiosk_mode} | Shell: ${shellPath}

$Namespace = "root\\standardcimv2\\embedded"
$ShellLauncherClass = "WESL_UserSetting"

try {
    # Verify Shell Launcher feature is installed
    $feature = Get-WindowsOptionalFeature -Online -FeatureName "Client-EmbeddedShellLauncher"
    if ($feature.State -ne "Enabled") {
        Write-Host "Enabling Embedded Shell Launcher feature..."
        Enable-WindowsOptionalFeature -Online -FeatureName "Client-EmbeddedShellLauncher" -NoRestart -WarningAction SilentlyContinue
    }

    # Resolve User SID for ${targetUser}
    $account = New-Object System.Security.Principal.NTAccount("${targetUser}")
    $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value

    Write-Host "Configuring custom shell for SID $sid ($targetUser)..."
    
    # Configure custom shell via WMI
    $current = Get-CimInstance -Namespace $Namespace -ClassName $ShellLauncherClass -Filter "Sid = '$sid'" -ErrorAction SilentlyContinue
    if ($current) {
        $current | Remove-CimInstance
    }

    $shellParams = @{
        Sid = $sid
        Shell = "${shellPath.replace(/"/g, '`"')}"
        DefaultReturnCodeAction = ${restartAction}
    }
    New-CimInstance -Namespace $Namespace -ClassName $ShellLauncherClass -Property $shellParams | Out-Null

    # Enable Shell Launcher globally
    $globalConfig = Get-CimInstance -Namespace $Namespace -ClassName "WESL_ServerSetting"
    if ($globalConfig) {
        $globalConfig | Set-CimInstance -Property @{ ShellLauncherIsEnabled = $true }
    }

    Write-Host "Shell Launcher configured successfully for ${targetUser}."
} catch {
    Write-Error "Failed to configure Shell Launcher: $($_.Exception.Message)"
}
`.trim();
}

/**
 * Get all Kiosk Profiles with assigned device counts
 */
export function getAllProfiles(db) {
  const profiles = db.prepare(`
    SELECT kp.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM kiosk_profiles kp
    LEFT JOIN dynamic_groups dg ON kp.target_group_id = dg.id
    ORDER BY kp.kiosk_mode ASC, kp.name ASC
  `).all();

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;

  return profiles.map(p => {
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

    let parsedApps = [];
    try {
      parsedApps = JSON.parse(p.allowed_apps_json || '[]');
    } catch {
      parsedApps = [];
    }

    return {
      ...p,
      enabled: Boolean(p.enabled),
      disable_taskbar: Boolean(p.disable_taskbar),
      disable_cad_keys: Boolean(p.disable_cad_keys),
      restart_on_exit: Boolean(p.restart_on_exit),
      allowed_apps: parsedApps,
      assigned_devices_count: assignedCount
    };
  });
}

/**
 * Get a single Kiosk Profile by ID
 */
export function getProfileById(db, id) {
  const profile = db.prepare(`
    SELECT kp.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM kiosk_profiles kp
    LEFT JOIN dynamic_groups dg ON kp.target_group_id = dg.id
    WHERE kp.id = ?
  `).get(id);

  if (!profile) return null;

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;
  let assignedCount = 0;
  if (profile.target_group_id === 'grp-all' || profile.target_group_id === 'all-devices') {
    assignedCount = totalDevicesCount;
  } else {
    const row = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as count
      FROM group_memberships
      WHERE group_id = ?
    `).get(profile.target_group_id);
    assignedCount = row ? row.count : 0;
  }

  let parsedApps = [];
  try {
    parsedApps = JSON.parse(profile.allowed_apps_json || '[]');
  } catch {
    parsedApps = [];
  }

  return {
    ...profile,
    enabled: Boolean(profile.enabled),
    disable_taskbar: Boolean(profile.disable_taskbar),
    disable_cad_keys: Boolean(profile.disable_cad_keys),
    restart_on_exit: Boolean(profile.restart_on_exit),
    allowed_apps: parsedApps,
    assigned_devices_count: assignedCount,
    generated_xml: generateAssignedAccessXml(profile),
    shell_launcher_script: generateShellLauncherScript(profile)
  };
}

/**
 * Create a new Kiosk Profile
 */
export function createProfile(db, data) {
  if (!data.name || !data.name.trim()) {
    throw new Error('Kiosk profile name is required');
  }

  const id = data.id || `kiosk-${data.name.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').slice(0, 32)}-${Date.now().toString(36)}`;
  const kioskMode = data.kiosk_mode || 'SINGLE_APP';
  const targetGroupId = data.target_group_id || 'grp-all';
  const logonType = data.logon_type || 'AUTO_LOGON';
  const userAccount = data.user_account || 'KioskUser0';
  const appType = data.app_type || 'EDGE_BROWSER';
  const appPathOrAumid = data.app_path_or_aumid || '';
  const edgeKioskType = data.edge_kiosk_type || 'DIGITAL_SIGNAGE';
  const edgeKioskUrl = data.edge_kiosk_url || 'https://localpilot.internal';
  const edgeIdleTimeoutMin = typeof data.edge_idle_timeout_min === 'number' ? data.edge_idle_timeout_min : 5;
  const allowedAppsJson = typeof data.allowed_apps === 'object' ? JSON.stringify(data.allowed_apps) : (data.allowed_apps_json || '[]');
  const customLayoutXml = data.custom_layout_xml || '';
  const disableTaskbar = data.disable_taskbar !== undefined ? (data.disable_taskbar ? 1 : 0) : 1;
  const disableCadKeys = data.disable_cad_keys !== undefined ? (data.disable_cad_keys ? 1 : 0) : 1;
  const restartOnExit = data.restart_on_exit !== undefined ? (data.restart_on_exit ? 1 : 0) : 1;
  const enabled = data.enabled !== undefined ? (data.enabled ? 1 : 0) : 1;

  db.prepare(`
    INSERT INTO kiosk_profiles (
      id, name, description, kiosk_mode, target_group_id,
      logon_type, user_account, app_type, app_path_or_aumid,
      edge_kiosk_type, edge_kiosk_url, edge_idle_timeout_min,
      allowed_apps_json, custom_layout_xml, disable_taskbar,
      disable_cad_keys, restart_on_exit, enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?, DATETIME('now'), DATETIME('now')
    )
  `).run(
    id, data.name.trim(), data.description || '', kioskMode, targetGroupId,
    logonType, userAccount, appType, appPathOrAumid,
    edgeKioskType, edgeKioskUrl, edgeIdleTimeoutMin,
    allowedAppsJson, customLayoutXml, disableTaskbar,
    disableCadKeys, restartOnExit, enabled
  );

  broadcastEvent('kiosk_profile_created', { id, name: data.name });
  return getProfileById(db, id);
}

/**
 * Update an existing Kiosk Profile
 */
export function updateProfile(db, id, data) {
  const existing = db.prepare('SELECT id FROM kiosk_profiles WHERE id = ?').get(id);
  if (!existing) return null;

  const updates = [];
  const params = [];

  if (data.name !== undefined) {
    if (!data.name.trim()) throw new Error('Kiosk profile name cannot be empty');
    updates.push('name = ?');
    params.push(data.name.trim());
  }
  if (data.description !== undefined) {
    updates.push('description = ?');
    params.push(data.description);
  }
  if (data.kiosk_mode !== undefined) {
    updates.push('kiosk_mode = ?');
    params.push(data.kiosk_mode);
  }
  if (data.target_group_id !== undefined) {
    updates.push('target_group_id = ?');
    params.push(data.target_group_id);
  }
  if (data.logon_type !== undefined) {
    updates.push('logon_type = ?');
    params.push(data.logon_type);
  }
  if (data.user_account !== undefined) {
    updates.push('user_account = ?');
    params.push(data.user_account);
  }
  if (data.app_type !== undefined) {
    updates.push('app_type = ?');
    params.push(data.app_type);
  }
  if (data.app_path_or_aumid !== undefined) {
    updates.push('app_path_or_aumid = ?');
    params.push(data.app_path_or_aumid);
  }
  if (data.edge_kiosk_type !== undefined) {
    updates.push('edge_kiosk_type = ?');
    params.push(data.edge_kiosk_type);
  }
  if (data.edge_kiosk_url !== undefined) {
    updates.push('edge_kiosk_url = ?');
    params.push(data.edge_kiosk_url);
  }
  if (data.edge_idle_timeout_min !== undefined) {
    updates.push('edge_idle_timeout_min = ?');
    params.push(data.edge_idle_timeout_min);
  }
  if (data.allowed_apps !== undefined) {
    updates.push('allowed_apps_json = ?');
    params.push(JSON.stringify(data.allowed_apps));
  } else if (data.allowed_apps_json !== undefined) {
    updates.push('allowed_apps_json = ?');
    params.push(data.allowed_apps_json);
  }
  if (data.custom_layout_xml !== undefined) {
    updates.push('custom_layout_xml = ?');
    params.push(data.custom_layout_xml);
  }
  if (data.disable_taskbar !== undefined) {
    updates.push('disable_taskbar = ?');
    params.push(data.disable_taskbar ? 1 : 0);
  }
  if (data.disable_cad_keys !== undefined) {
    updates.push('disable_cad_keys = ?');
    params.push(data.disable_cad_keys ? 1 : 0);
  }
  if (data.restart_on_exit !== undefined) {
    updates.push('restart_on_exit = ?');
    params.push(data.restart_on_exit ? 1 : 0);
  }
  if (data.enabled !== undefined) {
    updates.push('enabled = ?');
    params.push(data.enabled ? 1 : 0);
  }

  if (updates.length > 0) {
    updates.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE kiosk_profiles SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    broadcastEvent('kiosk_profile_updated', { id });
  }

  return getProfileById(db, id);
}

/**
 * Delete a Kiosk Profile
 */
export function deleteProfile(db, id) {
  const existing = db.prepare('SELECT id, name FROM kiosk_profiles WHERE id = ?').get(id);
  if (!existing) return false;

  db.prepare('DELETE FROM kiosk_profiles WHERE id = ?').run(id);
  broadcastEvent('kiosk_profile_deleted', { id, name: existing.name });
  return true;
}

/**
 * Resolve effective Kiosk Profile for a device based on dynamic group memberships
 */
export function getEffectiveKioskProfileForDevice(db, deviceId) {
  const groups = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
  const groupIds = groups.map(g => g.group_id);
  groupIds.push('grp-all', 'all-devices');

  const placeholders = groupIds.map(() => '?').join(',');
  const profile = db.prepare(`
    SELECT * FROM kiosk_profiles
    WHERE enabled = 1 AND target_group_id IN (${placeholders})
    ORDER BY created_at DESC
    LIMIT 1
  `).get(...groupIds);

  if (!profile) return null;

  let parsedApps = [];
  try {
    parsedApps = JSON.parse(profile.allowed_apps_json || '[]');
  } catch {
    parsedApps = [];
  }

  return {
    ...profile,
    enabled: Boolean(profile.enabled),
    disable_taskbar: Boolean(profile.disable_taskbar),
    disable_cad_keys: Boolean(profile.disable_cad_keys),
    restart_on_exit: Boolean(profile.restart_on_exit),
    allowed_apps: parsedApps,
    generated_xml: generateAssignedAccessXml(profile),
    shell_launcher_script: generateShellLauncherScript(profile)
  };
}

/**
 * Ingest or update live workstation Kiosk & Assigned Access posture
 */
export function saveDeviceKioskStatus(db, deviceId, statusData) {
  const device = db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId);
  if (!device) throw new Error(`Device not found: ${deviceId}`);

  const id = `kioskstatus-${deviceId}`;
  const effectiveProfile = getEffectiveKioskProfileForDevice(db, deviceId);
  const profileId = effectiveProfile ? effectiveProfile.id : (statusData.profile_id || null);

  const assignedAccessSupported = statusData.assigned_access_supported !== undefined ? (statusData.assigned_access_supported ? 1 : 0) : 1;
  const shellLauncherSupported = statusData.shell_launcher_supported !== undefined ? (statusData.shell_launcher_supported ? 1 : 0) : 1;
  const currentShell = statusData.current_shell || 'explorer.exe';
  const kioskActive = statusData.kiosk_active !== undefined ? (statusData.kiosk_active ? 1 : 0) : (currentShell.toLowerCase() !== 'explorer.exe' ? 1 : 0);
  const activeKioskUser = statusData.active_kiosk_user || '';

  let lockdownStatus = 'STANDARD_SHELL';
  if (kioskActive) {
    lockdownStatus = 'KIOSK_ACTIVE';
  } else if (effectiveProfile) {
    lockdownStatus = 'KIOSK_CONFIGURED';
  }

  db.prepare(`
    INSERT INTO device_kiosk_status (
      id, device_id, profile_id, assigned_access_supported,
      shell_launcher_supported, current_shell, kiosk_active,
      active_kiosk_user, lockdown_status, last_scanned_at,
      created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, DATETIME('now'),
      DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(device_id) DO UPDATE SET
      profile_id = excluded.profile_id,
      assigned_access_supported = excluded.assigned_access_supported,
      shell_launcher_supported = excluded.shell_launcher_supported,
      current_shell = excluded.current_shell,
      kiosk_active = excluded.kiosk_active,
      active_kiosk_user = excluded.active_kiosk_user,
      lockdown_status = excluded.lockdown_status,
      last_scanned_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `).run(
    id, deviceId, profileId, assignedAccessSupported,
    shellLauncherSupported, currentShell, kioskActive,
    activeKioskUser, lockdownStatus
  );

  broadcastEvent('device_kiosk_posture_updated', { deviceId, lockdownStatus, kioskActive });
  return getDeviceKioskStatus(db, deviceId);
}

/**
 * Get device Kiosk status and assigned profile
 */
export function getDeviceKioskStatus(db, deviceId) {
  const row = db.prepare(`
    SELECT dks.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           kp.name as profile_name,
           kp.kiosk_mode as profile_kiosk_mode,
           kp.app_type as profile_app_type
    FROM device_kiosk_status dks
    JOIN devices d ON dks.device_id = d.id
    LEFT JOIN kiosk_profiles kp ON dks.profile_id = kp.id
    WHERE dks.device_id = ?
  `).get(deviceId);

  if (!row) {
    const effectiveProfile = getEffectiveKioskProfileForDevice(db, deviceId);
    return {
      device_id: deviceId,
      assigned_access_supported: true,
      shell_launcher_supported: true,
      current_shell: 'explorer.exe',
      kiosk_active: false,
      active_kiosk_user: '',
      lockdown_status: effectiveProfile ? 'KIOSK_CONFIGURED' : 'STANDARD_SHELL',
      profile_id: effectiveProfile ? effectiveProfile.id : null,
      profile_name: effectiveProfile ? effectiveProfile.name : null,
      effective_profile: effectiveProfile
    };
  }

  const effectiveProfile = getEffectiveKioskProfileForDevice(db, deviceId);

  return {
    ...row,
    assigned_access_supported: Boolean(row.assigned_access_supported),
    shell_launcher_supported: Boolean(row.shell_launcher_supported),
    kiosk_active: Boolean(row.kiosk_active),
    effective_profile: effectiveProfile
  };
}

/**
 * Get fleet-wide Kiosk inventory
 */
export function getFleetKioskInventory(db, filters = {}) {
  let query = `
    SELECT dks.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status,
           kp.name as profile_name,
           kp.kiosk_mode as profile_kiosk_mode,
           kp.app_type as profile_app_type
    FROM device_kiosk_status dks
    JOIN devices d ON dks.device_id = d.id
    LEFT JOIN kiosk_profiles kp ON dks.profile_id = kp.id
    WHERE d.status != 'DECOMMISSIONED'
  `;
  const params = [];

  if (filters.lockdown_status) {
    query += ' AND dks.lockdown_status = ?';
    params.push(filters.lockdown_status);
  }
  if (filters.kiosk_active !== undefined) {
    query += ' AND dks.kiosk_active = ?';
    params.push(filters.kiosk_active ? 1 : 0);
  }
  if (filters.q) {
    query += ' AND (d.hostname LIKE ? OR kp.name LIKE ? OR dks.current_shell LIKE ?)';
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
  }

  query += ' ORDER BY dks.last_scanned_at DESC';

  if (filters.limit) {
    query += ' LIMIT ?';
    params.push(Number(filters.limit));
  }

  const rows = db.prepare(query).all(...params);
  return rows.map(r => ({
    ...r,
    assigned_access_supported: Boolean(r.assigned_access_supported),
    shell_launcher_supported: Boolean(r.shell_launcher_supported),
    kiosk_active: Boolean(r.kiosk_active)
  }));
}

/**
 * Compute Kiosk KPI Statistics for the Fleet
 */
export function getKioskStats(db) {
  const profiles = db.prepare('SELECT kiosk_mode, enabled FROM kiosk_profiles').all();
  const totalProfiles = profiles.length;
  const activeProfiles = profiles.filter(p => p.enabled === 1).length;
  const singleAppCount = profiles.filter(p => p.kiosk_mode === 'SINGLE_APP' || p.kiosk_mode === 'DIGITAL_SIGNAGE').length;
  const multiAppCount = profiles.filter(p => p.kiosk_mode === 'MULTI_APP' || p.kiosk_mode === 'SHELL_LAUNCHER').length;

  const postures = db.prepare(`
    SELECT dks.* FROM device_kiosk_status dks
    JOIN devices d ON dks.device_id = d.id
    WHERE d.status != 'DECOMMISSIONED'
  `).all();

  const totalAudited = postures.length;
  const kioskActiveCount = postures.filter(p => p.kiosk_active === 1).length;
  const configuredCount = postures.filter(p => p.lockdown_status === 'KIOSK_CONFIGURED').length;
  const standardShellCount = postures.filter(p => p.lockdown_status === 'STANDARD_SHELL').length;

  return {
    total_profiles: totalProfiles,
    active_profiles: activeProfiles,
    single_app_count: singleAppCount,
    multi_app_count: multiAppCount,
    total_audited_workstations: totalAudited,
    kiosk_active_count: kioskActiveCount,
    kiosk_configured_count: configuredCount,
    standard_shell_count: standardShellCount
  };
}
