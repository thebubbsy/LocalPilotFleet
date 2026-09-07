/**
 * LocalPilot Fleet — Windows Autopilot & Hardware Provisioning Engine
 * server/src/services/autopilotEngine.js
 *
 * Implements Microsoft Intune Windows Autopilot capabilities:
 * - Genuine Windows Hardware Hash harvesting & registration
 * - Official Microsoft Intune CSV bulk import & export (RFC 4180 compliant)
 * - Out-of-Box Experience (OOBE) Deployment Profiles (User-Driven vs Self-Deploying)
 * - Enrollment Status Page (ESP) Phase Orchestration & Progress Tracking
 * - Zero-Touch Device Provisioning Lifecycle (Unassigned -> Assigned -> Provisioning -> Enrolled)
 * - Dynamic Group Tag & Automated Profile Synchronization
 */

import crypto from 'node:crypto';

/**
 * Get fleet-wide Autopilot statistics and executive KPI cards
 */
export function getAutopilotStats(db) {
  const devStats = db.prepare(`
    SELECT
      COUNT(*) as total_devices,
      COALESCE(SUM(CASE WHEN deployment_status = 'UNASSIGNED' THEN 1 ELSE 0 END), 0) as unassigned_devices,
      COALESCE(SUM(CASE WHEN deployment_status = 'ASSIGNED' THEN 1 ELSE 0 END), 0) as assigned_devices,
      COALESCE(SUM(CASE WHEN deployment_status = 'PROVISIONING' THEN 1 ELSE 0 END), 0) as provisioning_devices,
      COALESCE(SUM(CASE WHEN deployment_status = 'ENROLLED' THEN 1 ELSE 0 END), 0) as enrolled_devices,
      COALESCE(SUM(CASE WHEN deployment_status = 'FAILED' THEN 1 ELSE 0 END), 0) as failed_devices
    FROM autopilot_devices
  `).get() || { total_devices: 0, unassigned_devices: 0, assigned_devices: 0, provisioning_devices: 0, enrolled_devices: 0, failed_devices: 0 };

  const profStats = db.prepare(`
    SELECT
      COUNT(*) as total_profiles,
      COALESCE(SUM(CASE WHEN deployment_mode = 'USER_DRIVEN' THEN 1 ELSE 0 END), 0) as user_driven_profiles,
      COALESCE(SUM(CASE WHEN deployment_mode = 'SELF_DEPLOYING' THEN 1 ELSE 0 END), 0) as self_deploying_profiles
    FROM autopilot_profiles
  `).get() || { total_profiles: 0, user_driven_profiles: 0, self_deploying_profiles: 0 };

  const espStats = db.prepare(`
    SELECT COUNT(*) as total_esp_policies FROM enrollment_status_page_policies
  `).get() || { total_esp_policies: 0 };

  const recentEvents = db.prepare(`
    SELECT COUNT(DISTINCT autopilot_device_id) as active_24h
    FROM autopilot_provisioning_events
    WHERE timestamp >= DATETIME('now', '-24 hours')
  `).get() || { active_24h: 0 };

  return {
    total_devices: devStats.total_devices,
    unassigned_devices: devStats.unassigned_devices,
    assigned_devices: devStats.assigned_devices,
    provisioning_devices: devStats.provisioning_devices,
    enrolled_devices: devStats.enrolled_devices,
    failed_devices: devStats.failed_devices,
    total_profiles: profStats.total_profiles,
    user_driven_profiles: profStats.user_driven_profiles,
    self_deploying_profiles: profStats.self_deploying_profiles,
    total_esp_policies: espStats.total_esp_policies,
    active_provisioning_24h: recentEvents.active_24h
  };
}

/**
 * List all Autopilot deployment profiles with target groups and device counts
 */
export function getAutopilotProfiles(db) {
  return db.prepare(`
    SELECT
      p.*,
      g.name as target_group_name,
      g.color as target_group_color,
      (SELECT COUNT(*) FROM autopilot_devices d WHERE d.profile_id = p.id) as assigned_device_count
    FROM autopilot_profiles p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    ORDER BY p.is_default DESC, p.created_at DESC
  `).all();
}

/**
 * Get single Autopilot profile by ID with assigned devices list
 */
export function getAutopilotProfile(db, id) {
  const profile = db.prepare(`
    SELECT
      p.*,
      g.name as target_group_name,
      g.color as target_group_color,
      (SELECT COUNT(*) FROM autopilot_devices d WHERE d.profile_id = p.id) as assigned_device_count
    FROM autopilot_profiles p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);

  if (!profile) return null;

  const devices = db.prepare(`
    SELECT
      d.id, d.serial_number, d.model, d.manufacturer, d.group_tag,
      d.assigned_user, d.deployment_status, d.device_id, d.last_contact_at
    FROM autopilot_devices d
    WHERE d.profile_id = ?
    ORDER BY d.serial_number ASC
  `).all(id);

  return { ...profile, devices };
}

/**
 * Create a new Autopilot deployment profile
 */
export function createAutopilotProfile(db, data) {
  if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
    throw new Error('Profile name is required');
  }

  const validModes = ['USER_DRIVEN', 'SELF_DEPLOYING'];
  const deploymentMode = (data.deployment_mode || 'USER_DRIVEN').toUpperCase();
  if (!validModes.includes(deploymentMode)) {
    throw new Error(`Invalid deployment_mode. Must be one of: ${validModes.join(', ')}`);
  }

  const validJoins = ['WORKGROUP_LOCAL', 'ENTRA_CLOUD', 'HYBRID_DOMAIN'];
  const joinType = (data.join_type || 'WORKGROUP_LOCAL').toUpperCase();
  if (!validJoins.includes(joinType)) {
    throw new Error(`Invalid join_type. Must be one of: ${validJoins.join(', ')}`);
  }

  const validAccounts = ['STANDARD', 'ADMINISTRATOR'];
  const accountType = (data.account_type || 'STANDARD').toUpperCase();
  if (!validAccounts.includes(accountType)) {
    throw new Error(`Invalid account_type. Must be one of: ${validAccounts.join(', ')}`);
  }

  const id = data.id || `ap-prof-${crypto.randomUUID().slice(0, 8)}`;
  const isDefault = data.is_default ? 1 : 0;

  if (isDefault) {
    db.prepare('UPDATE autopilot_profiles SET is_default = 0').run();
  }

  db.prepare(`
    INSERT INTO autopilot_profiles (
      id, name, description, deployment_mode, join_type, account_type,
      language_locale, keyboard_layout, device_name_template,
      skip_eula, skip_privacy_settings, skip_user_licensing,
      target_group_id, is_default, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    data.name.trim(),
    data.description || '',
    deploymentMode,
    joinType,
    accountType,
    data.language_locale || 'os-default',
    data.keyboard_layout || 'os-default',
    data.device_name_template || 'FLEET-%RAND:4%',
    data.skip_eula !== undefined ? (data.skip_eula ? 1 : 0) : 1,
    data.skip_privacy_settings !== undefined ? (data.skip_privacy_settings ? 1 : 0) : 1,
    data.skip_user_licensing !== undefined ? (data.skip_user_licensing ? 1 : 0) : 1,
    data.target_group_id || 'grp-all',
    isDefault
  );

  return getAutopilotProfile(db, id);
}

/**
 * Update an existing Autopilot profile
 */
export function updateAutopilotProfile(db, id, data) {
  const existing = db.prepare('SELECT * FROM autopilot_profiles WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`Autopilot profile with id '${id}' not found`);
  }

  if (data.deployment_mode) {
    const validModes = ['USER_DRIVEN', 'SELF_DEPLOYING'];
    if (!validModes.includes(data.deployment_mode.toUpperCase())) {
      throw new Error(`Invalid deployment_mode: ${data.deployment_mode}`);
    }
  }

  if (data.join_type) {
    const validJoins = ['WORKGROUP_LOCAL', 'ENTRA_CLOUD', 'HYBRID_DOMAIN'];
    if (!validJoins.includes(data.join_type.toUpperCase())) {
      throw new Error(`Invalid join_type: ${data.join_type}`);
    }
  }

  if (data.account_type) {
    const validAccounts = ['STANDARD', 'ADMINISTRATOR'];
    if (!validAccounts.includes(data.account_type.toUpperCase())) {
      throw new Error(`Invalid account_type: ${data.account_type}`);
    }
  }

  if (data.is_default) {
    db.prepare('UPDATE autopilot_profiles SET is_default = 0 WHERE id != ?').run(id);
  }

  db.prepare(`
    UPDATE autopilot_profiles SET
      name = COALESCE(?, name),
      description = COALESCE(?, description),
      deployment_mode = COALESCE(?, deployment_mode),
      join_type = COALESCE(?, join_type),
      account_type = COALESCE(?, account_type),
      language_locale = COALESCE(?, language_locale),
      keyboard_layout = COALESCE(?, keyboard_layout),
      device_name_template = COALESCE(?, device_name_template),
      skip_eula = COALESCE(?, skip_eula),
      skip_privacy_settings = COALESCE(?, skip_privacy_settings),
      skip_user_licensing = COALESCE(?, skip_user_licensing),
      target_group_id = COALESCE(?, target_group_id),
      is_default = COALESCE(?, is_default),
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    data.name ? data.name.trim() : null,
    data.description !== undefined ? data.description : null,
    data.deployment_mode ? data.deployment_mode.toUpperCase() : null,
    data.join_type ? data.join_type.toUpperCase() : null,
    data.account_type ? data.account_type.toUpperCase() : null,
    data.language_locale !== undefined ? data.language_locale : null,
    data.keyboard_layout !== undefined ? data.keyboard_layout : null,
    data.device_name_template !== undefined ? data.device_name_template : null,
    data.skip_eula !== undefined ? (data.skip_eula ? 1 : 0) : null,
    data.skip_privacy_settings !== undefined ? (data.skip_privacy_settings ? 1 : 0) : null,
    data.skip_user_licensing !== undefined ? (data.skip_user_licensing ? 1 : 0) : null,
    data.target_group_id !== undefined ? data.target_group_id : null,
    data.is_default !== undefined ? (data.is_default ? 1 : 0) : null,
    id
  );

  return getAutopilotProfile(db, id);
}

/**
 * Delete an Autopilot profile
 */
export function deleteAutopilotProfile(db, id) {
  const existing = db.prepare('SELECT id FROM autopilot_profiles WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`Autopilot profile with id '${id}' not found`);
  }

  // Set profile_id to NULL on assigned devices
  db.prepare("UPDATE autopilot_devices SET profile_id = NULL, deployment_status = CASE WHEN deployment_status = 'ASSIGNED' THEN 'UNASSIGNED' ELSE deployment_status END WHERE profile_id = ?").run(id);

  db.prepare('DELETE FROM autopilot_profiles WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * List all registered Autopilot devices with attached profiles and live fleet status
 */
export function getAutopilotDevices(db, { status, groupTag, search, profileId } = {}) {
  let query = `
    SELECT
      ad.*,
      ap.name as profile_name,
      ap.deployment_mode as profile_deployment_mode,
      ap.join_type as profile_join_type,
      dev.hostname as live_hostname,
      dev.status as live_status,
      dev.ip_address as live_ip,
      dev.os_version as live_os
    FROM autopilot_devices ad
    LEFT JOIN autopilot_profiles ap ON ad.profile_id = ap.id
    LEFT JOIN devices dev ON ad.device_id = dev.id
    WHERE 1=1
  `;
  const params = [];

  if (status) {
    query += ` AND ad.deployment_status = ?`;
    params.push(status.toUpperCase());
  }

  if (groupTag) {
    query += ` AND ad.group_tag = ?`;
    params.push(groupTag);
  }

  if (profileId) {
    query += ` AND ad.profile_id = ?`;
    params.push(profileId);
  }

  if (search) {
    query += ` AND (ad.serial_number LIKE ? OR ad.model LIKE ? OR ad.group_tag LIKE ? OR ad.assigned_user LIKE ? OR dev.hostname LIKE ?)`;
    const term = `%${search}%`;
    params.push(term, term, term, term, term);
  }

  query += ` ORDER BY ad.created_at DESC`;
  return db.prepare(query).all(...params);
}

/**
 * Get a single Autopilot device by ID with attached profile and provisioning events
 */
export function getAutopilotDevice(db, id) {
  const device = db.prepare(`
    SELECT
      ad.*,
      ap.name as profile_name,
      ap.deployment_mode as profile_deployment_mode,
      ap.join_type as profile_join_type,
      ap.account_type as profile_account_type,
      ap.device_name_template as profile_name_template,
      dev.hostname as live_hostname,
      dev.status as live_status,
      dev.ip_address as live_ip,
      dev.os_version as live_os
    FROM autopilot_devices ad
    LEFT JOIN autopilot_profiles ap ON ad.profile_id = ap.id
    LEFT JOIN devices dev ON ad.device_id = dev.id
    WHERE ad.id = ?
  `).get(id);

  if (!device) return null;

  const events = db.prepare(`
    SELECT *
    FROM autopilot_provisioning_events
    WHERE autopilot_device_id = ?
    ORDER BY timestamp ASC
  `).all(id);

  return { ...device, provisioning_events: events };
}

/**
 * Register a single Autopilot device
 */
export function registerAutopilotDevice(db, data) {
  if (!data.serial_number || typeof data.serial_number !== 'string' || !data.serial_number.trim()) {
    throw new Error('Device serial_number is required');
  }

  if (!data.hardware_hash || typeof data.hardware_hash !== 'string' || !data.hardware_hash.trim()) {
    throw new Error('Hardware hash is required for Autopilot registration');
  }

  const serial = data.serial_number.trim();
  const existing = db.prepare('SELECT id FROM autopilot_devices WHERE serial_number = ?').get(serial);
  if (existing) {
    throw new Error(`Device with serial number '${serial}' is already registered in Autopilot`);
  }

  const id = data.id || `ap-dev-${crypto.randomUUID().slice(0, 8)}`;

  // Determine profile
  let profileId = data.profile_id || null;
  if (!profileId) {
    // Check if a default profile exists
    const defaultProf = db.prepare('SELECT id FROM autopilot_profiles WHERE is_default = 1').get();
    if (defaultProf) {
      profileId = defaultProf.id;
    }
  }

  // Check if device is already enrolled in fleet
  const enrolledDevice = db.prepare('SELECT id, hostname FROM devices WHERE serial_number = ?').get(serial);
  let initialStatus = 'UNASSIGNED';
  let deviceId = null;

  if (enrolledDevice) {
    deviceId = enrolledDevice.id;
    initialStatus = profileId ? 'ENROLLED' : 'UNASSIGNED';
  } else if (profileId) {
    initialStatus = 'ASSIGNED';
  }

  db.prepare(`
    INSERT INTO autopilot_devices (
      id, serial_number, hardware_hash, windows_product_id, model, manufacturer,
      group_tag, assigned_user, profile_id, deployment_status, device_id,
      last_contact_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    serial,
    data.hardware_hash.trim(),
    data.windows_product_id || '',
    data.model || 'Generic PC',
    data.manufacturer || 'OEM',
    data.group_tag || '',
    data.assigned_user || '',
    profileId,
    initialStatus,
    deviceId,
    enrolledDevice ? new Date().toISOString() : null
  );

  return getAutopilotDevice(db, id);
}

/**
 * Update an existing Autopilot device
 */
export function updateAutopilotDevice(db, id, data) {
  const existing = db.prepare('SELECT * FROM autopilot_devices WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`Autopilot device with id '${id}' not found`);
  }

  if (data.deployment_status) {
    const validStatuses = ['UNASSIGNED', 'ASSIGNED', 'PROVISIONING', 'ENROLLED', 'FAILED'];
    if (!validStatuses.includes(data.deployment_status.toUpperCase())) {
      throw new Error(`Invalid deployment_status: ${data.deployment_status}`);
    }
  }

  db.prepare(`
    UPDATE autopilot_devices SET
      model = COALESCE(?, model),
      manufacturer = COALESCE(?, manufacturer),
      group_tag = COALESCE(?, group_tag),
      assigned_user = COALESCE(?, assigned_user),
      profile_id = COALESCE(?, profile_id),
      deployment_status = COALESCE(?, deployment_status),
      windows_product_id = COALESCE(?, windows_product_id),
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    data.model !== undefined ? data.model : null,
    data.manufacturer !== undefined ? data.manufacturer : null,
    data.group_tag !== undefined ? data.group_tag : null,
    data.assigned_user !== undefined ? data.assigned_user : null,
    data.profile_id !== undefined ? data.profile_id : null,
    data.deployment_status ? data.deployment_status.toUpperCase() : null,
    data.windows_product_id !== undefined ? data.windows_product_id : null,
    id
  );

  return getAutopilotDevice(db, id);
}

/**
 * Delete an Autopilot device
 */
export function deleteAutopilotDevice(db, id) {
  const existing = db.prepare('SELECT id FROM autopilot_devices WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`Autopilot device with id '${id}' not found`);
  }

  db.prepare('DELETE FROM autopilot_devices WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * Assign or unassign an Autopilot profile to a registered device
 */
export function assignProfileToAutopilotDevice(db, deviceId, profileId) {
  const dev = db.prepare('SELECT * FROM autopilot_devices WHERE id = ?').get(deviceId);
  if (!dev) {
    throw new Error(`Autopilot device with id '${deviceId}' not found`);
  }

  let newStatus = dev.deployment_status;

  if (profileId) {
    const prof = db.prepare('SELECT id, name FROM autopilot_profiles WHERE id = ?').get(profileId);
    if (!prof) {
      throw new Error(`Autopilot profile with id '${profileId}' not found`);
    }
    if (newStatus === 'UNASSIGNED') {
      newStatus = dev.device_id ? 'ENROLLED' : 'ASSIGNED';
    }
  } else {
    profileId = null;
    if (newStatus === 'ASSIGNED') {
      newStatus = 'UNASSIGNED';
    }
  }

  db.prepare(`
    UPDATE autopilot_devices SET
      profile_id = ?,
      deployment_status = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(profileId, newStatus, deviceId);

  // Dispatch Security Event
  try {
    if (dev.device_id) {
      const devRow = db.prepare('SELECT id FROM devices WHERE id = ?').get(dev.device_id);
      if (devRow) {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          dev.device_id,
          'AUTOPILOT_PROFILE_ASSIGNED',
          5201,
          'AutopilotEngine',
          'INFO',
          `Autopilot profile ${profileId ? 'assigned' : 'removed'} for serial ${dev.serial_number}`,
          JSON.stringify({ device_id: deviceId, profile_id: profileId, new_status: newStatus })
        );
      }
    }
  } catch (evErr) {
    console.warn('[Autopilot Security Event Warning]:', evErr.message);
  }

  return getAutopilotDevice(db, deviceId);
}

/**
 * Import devices from Microsoft Intune standard CSV format
 *
 * Official Microsoft Intune Header:
 * Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
 */
export function importAutopilotCsv(db, csvContent) {
  if (!csvContent || typeof csvContent !== 'string') {
    throw new Error('CSV content must be a non-empty string');
  }

  const lines = csvContent.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length === 0) {
    throw new Error('CSV content is empty');
  }

  // Parse header
  const headerLine = lines[0];
  const headerTokens = headerLine.split(',').map(h => h.trim().replace(/^["']|["']$/g, '').toLowerCase());

  // Find column indices
  let serialIdx = headerTokens.findIndex(h => h.includes('serial') || h === 'sn');
  let productIdx = headerTokens.findIndex(h => h.includes('product') || h === 'pki');
  let hashIdx = headerTokens.findIndex(h => h.includes('hash') || h.includes('hardware'));
  let tagIdx = headerTokens.findIndex(h => h.includes('tag') || h.includes('group'));
  let userIdx = headerTokens.findIndex(h => h.includes('user') || h.includes('assigned'));

  // Fallback to default positional column indices if no matching headers found
  if (serialIdx === -1 && hashIdx === -1 && lines.length > 0) {
    serialIdx = 0;
    productIdx = 1;
    hashIdx = 2;
    tagIdx = 3;
    userIdx = 4;
  }

  if (serialIdx === -1 || hashIdx === -1) {
    throw new Error('CSV missing required headers: "Device Serial Number" and "Hardware Hash"');
  }

  // Default profile if available
  const defaultProf = db.prepare('SELECT id FROM autopilot_profiles WHERE is_default = 1').get();
  const defaultProfileId = defaultProf ? defaultProf.id : null;

  let importedCount = 0;
  let updatedCount = 0;
  const errors = [];
  const startRow = (headerTokens.some(h => h.includes('serial') || h.includes('hash'))) ? 1 : 0;

  for (let i = startRow; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine) continue;

    // Handle quoted fields
    const tokens = [];
    let cur = '';
    let inQuotes = false;
    for (let c = 0; c < rawLine.length; c++) {
      const char = rawLine[c];
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        tokens.push(cur.trim());
        cur = '';
      } else {
        cur += char;
      }
    }
    tokens.push(cur.trim());

    const cleanTokens = tokens.map(t => t.replace(/^["']|["']$/g, '').trim());

    const serialNumber = cleanTokens[serialIdx];
    const hardwareHash = cleanTokens[hashIdx];
    const windowsProductId = productIdx >= 0 && cleanTokens[productIdx] ? cleanTokens[productIdx] : '';
    const groupTag = tagIdx >= 0 && cleanTokens[tagIdx] ? cleanTokens[tagIdx] : '';
    const assignedUser = userIdx >= 0 && cleanTokens[userIdx] ? cleanTokens[userIdx] : '';

    if (!serialNumber || !hardwareHash) {
      errors.push({ row: i + 1, error: 'Missing serial number or hardware hash' });
      continue;
    }

    try {
      const existing = db.prepare('SELECT id, profile_id, device_id FROM autopilot_devices WHERE serial_number = ?').get(serialNumber);

      if (existing) {
        db.prepare(`
          UPDATE autopilot_devices SET
            hardware_hash = ?,
            windows_product_id = CASE WHEN ? != '' THEN ? ELSE windows_product_id END,
            group_tag = CASE WHEN ? != '' THEN ? ELSE group_tag END,
            assigned_user = CASE WHEN ? != '' THEN ? ELSE assigned_user END,
            updated_at = DATETIME('now')
          WHERE id = ?
        `).run(hardwareHash, windowsProductId, windowsProductId, groupTag, groupTag, assignedUser, assignedUser, existing.id);
        updatedCount++;
      } else {
        const id = `ap-dev-${crypto.randomUUID().slice(0, 8)}`;
        const enrolledNode = db.prepare('SELECT id FROM devices WHERE serial_number = ?').get(serialNumber);
        const deviceId = enrolledNode ? enrolledNode.id : null;
        const initialStatus = deviceId ? (defaultProfileId ? 'ENROLLED' : 'UNASSIGNED') : (defaultProfileId ? 'ASSIGNED' : 'UNASSIGNED');

        db.prepare(`
          INSERT INTO autopilot_devices (
            id, serial_number, hardware_hash, windows_product_id, model, manufacturer,
            group_tag, assigned_user, profile_id, deployment_status, device_id,
            last_contact_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'Imported Hardware', 'OEM', ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
        `).run(
          id,
          serialNumber,
          hardwareHash,
          windowsProductId,
          groupTag,
          assignedUser,
          defaultProfileId,
          initialStatus,
          deviceId,
          deviceId ? new Date().toISOString() : null
        );
        importedCount++;
      }
    } catch (rowErr) {
      errors.push({ row: i + 1, error: rowErr.message });
    }
  }

  // Raise Security Audit Event
  try {
    const anyDev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    if (anyDev) {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        anyDev.id,
        'AUTOPILOT_DEVICE_IMPORTED',
        5200,
        'AutopilotEngine',
        'INFO',
        `Imported ${importedCount} new Autopilot devices, updated ${updatedCount} records`,
        JSON.stringify({ imported: importedCount, updated: updatedCount, errors_count: errors.length })
      );
    }
  } catch (evErr) {
    console.warn('[Autopilot Event Warning]:', evErr.message);
  }

  return {
    total_parsed: lines.length - startRow,
    imported_count: importedCount,
    updated_count: updatedCount,
    errors
  };
}

/**
 * Export registered devices into Microsoft Intune compatible RFC 4180 CSV format
 */
export function exportAutopilotCsv(db, { filterStatus, groupTag } = {}) {
  let query = `
    SELECT
      serial_number,
      windows_product_id,
      hardware_hash,
      group_tag,
      assigned_user
    FROM autopilot_devices
    WHERE 1=1
  `;
  const params = [];

  if (filterStatus) {
    query += ` AND deployment_status = ?`;
    params.push(filterStatus.toUpperCase());
  }

  if (groupTag) {
    query += ` AND group_tag = ?`;
    params.push(groupTag);
  }

  query += ` ORDER BY serial_number ASC`;
  const devices = db.prepare(query).all(...params);

  const header = 'Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User\r\n';

  const escapeCsv = (val) => {
    if (val === null || val === undefined) return '';
    const str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = devices.map(d => [
    escapeCsv(d.serial_number),
    escapeCsv(d.windows_product_id || ''),
    escapeCsv(d.hardware_hash),
    escapeCsv(d.group_tag || ''),
    escapeCsv(d.assigned_user || '')
  ].join(','));

  return header + rows.join('\r\n') + '\r\n';
}

/**
 * List all Enrollment Status Page (ESP) policies
 */
export function getEspPolicies(db) {
  return db.prepare(`
    SELECT
      esp.*,
      g.name as target_group_name,
      g.color as target_group_color
    FROM enrollment_status_page_policies esp
    LEFT JOIN dynamic_groups g ON esp.target_group_id = g.id
    ORDER BY esp.is_default DESC, esp.created_at DESC
  `).all();
}

/**
 * Get single ESP policy by ID
 */
export function getEspPolicy(db, id) {
  return db.prepare(`
    SELECT
      esp.*,
      g.name as target_group_name,
      g.color as target_group_color
    FROM enrollment_status_page_policies esp
    LEFT JOIN dynamic_groups g ON esp.target_group_id = g.id
    WHERE esp.id = ?
  `).get(id);
}

/**
 * Create a new Enrollment Status Page (ESP) policy
 */
export function createEspPolicy(db, data) {
  if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
    throw new Error('ESP policy name is required');
  }

  const timeoutMinutes = data.timeout_minutes !== undefined ? parseInt(data.timeout_minutes, 10) : 60;
  if (isNaN(timeoutMinutes) || timeoutMinutes < 10 || timeoutMinutes > 1440) {
    throw new Error('Timeout minutes must be between 10 and 1440');
  }

  const id = data.id || `esp-${crypto.randomUUID().slice(0, 8)}`;
  const isDefault = data.is_default ? 1 : 0;

  if (isDefault) {
    db.prepare('UPDATE enrollment_status_page_policies SET is_default = 0').run();
  }

  db.prepare(`
    INSERT INTO enrollment_status_page_policies (
      id, name, description, show_progress, block_until_completed,
      allow_user_reset_on_failure, timeout_minutes, required_app_ids_json,
      required_script_ids_json, target_group_id, is_default,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `).run(
    id,
    data.name.trim(),
    data.description || '',
    data.show_progress !== undefined ? (data.show_progress ? 1 : 0) : 1,
    data.block_until_completed !== undefined ? (data.block_until_completed ? 1 : 0) : 1,
    data.allow_user_reset_on_failure !== undefined ? (data.allow_user_reset_on_failure ? 1 : 0) : 1,
    timeoutMinutes,
    JSON.stringify(data.required_app_ids || []),
    JSON.stringify(data.required_script_ids || []),
    data.target_group_id || 'grp-all',
    isDefault
  );

  return getEspPolicy(db, id);
}

/**
 * Update an existing ESP policy
 */
export function updateEspPolicy(db, id, data) {
  const existing = db.prepare('SELECT id FROM enrollment_status_page_policies WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`ESP policy with id '${id}' not found`);
  }

  if (data.timeout_minutes !== undefined) {
    const t = parseInt(data.timeout_minutes, 10);
    if (isNaN(t) || t < 10 || t > 1440) {
      throw new Error('Timeout minutes must be between 10 and 1440');
    }
  }

  if (data.is_default) {
    db.prepare('UPDATE enrollment_status_page_policies SET is_default = 0 WHERE id != ?').run(id);
  }

  db.prepare(`
    UPDATE enrollment_status_page_policies SET
      name = COALESCE(?, name),
      description = COALESCE(?, description),
      show_progress = COALESCE(?, show_progress),
      block_until_completed = COALESCE(?, block_until_completed),
      allow_user_reset_on_failure = COALESCE(?, allow_user_reset_on_failure),
      timeout_minutes = COALESCE(?, timeout_minutes),
      required_app_ids_json = COALESCE(?, required_app_ids_json),
      required_script_ids_json = COALESCE(?, required_script_ids_json),
      target_group_id = COALESCE(?, target_group_id),
      is_default = COALESCE(?, is_default),
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    data.name ? data.name.trim() : null,
    data.description !== undefined ? data.description : null,
    data.show_progress !== undefined ? (data.show_progress ? 1 : 0) : null,
    data.block_until_completed !== undefined ? (data.block_until_completed ? 1 : 0) : null,
    data.allow_user_reset_on_failure !== undefined ? (data.allow_user_reset_on_failure ? 1 : 0) : null,
    data.timeout_minutes !== undefined ? parseInt(data.timeout_minutes, 10) : null,
    data.required_app_ids !== undefined ? JSON.stringify(data.required_app_ids) : null,
    data.required_script_ids !== undefined ? JSON.stringify(data.required_script_ids) : null,
    data.target_group_id !== undefined ? data.target_group_id : null,
    data.is_default !== undefined ? (data.is_default ? 1 : 0) : null,
    id
  );

  return getEspPolicy(db, id);
}

/**
 * Delete an ESP policy
 */
export function deleteEspPolicy(db, id) {
  const existing = db.prepare('SELECT id FROM enrollment_status_page_policies WHERE id = ?').get(id);
  if (!existing) {
    throw new Error(`ESP policy with id '${id}' not found`);
  }

  db.prepare('DELETE FROM enrollment_status_page_policies WHERE id = ?').run(id);
  return { success: true, deleted_id: id };
}

/**
 * Get effective ESP policy for a specific device based on group priority
 */
export function getEffectiveEspForDevice(db, deviceId) {
  const policy = db.prepare(`
    SELECT esp.*
    FROM group_memberships gm
    JOIN dynamic_groups dg ON gm.group_id = dg.id
    JOIN enrollment_status_page_policies esp ON esp.target_group_id = dg.id
    WHERE gm.device_id = ?
    ORDER BY dg.priority ASC
    LIMIT 1
  `).get(deviceId);

  if (policy) return policy;

  // Fallback to default ESP policy
  return db.prepare('SELECT * FROM enrollment_status_page_policies WHERE is_default = 1 LIMIT 1').get() || null;
}

/**
 * Record a provisioning event from a device executing OOBE or ESP phases
 */
export function logProvisioningEvent(db, { autopilot_device_id, device_id, phase, step_name, status, error_code, details }) {
  if (!autopilot_device_id || !phase || !step_name || !status) {
    throw new Error('autopilot_device_id, phase, step_name, and status are required');
  }

  const validPhases = ['DEVICE_PREPARATION', 'DEVICE_SETUP', 'ACCOUNT_SETUP'];
  if (!validPhases.includes(phase.toUpperCase())) {
    throw new Error(`Invalid phase: ${phase}. Must be one of: ${validPhases.join(', ')}`);
  }

  const validStatuses = ['IN_PROGRESS', 'COMPLETED', 'FAILED', 'SKIPPED'];
  if (!validStatuses.includes(status.toUpperCase())) {
    throw new Error(`Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
  }

  const eventId = `ap-ev-${crypto.randomUUID().slice(0, 8)}`;
  const normPhase = phase.toUpperCase();
  const normStatus = status.toUpperCase();

  db.prepare(`
    INSERT INTO autopilot_provisioning_events (
      id, autopilot_device_id, device_id, phase, step_name, status, error_code, details, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
  `).run(
    eventId,
    autopilot_device_id,
    device_id || null,
    normPhase,
    step_name,
    normStatus,
    error_code || null,
    details || null
  );

  // Update device deployment_status based on progress
  let updatedStatus = null;
  if (normStatus === 'FAILED') {
    updatedStatus = 'FAILED';
  } else if (normPhase === 'ACCOUNT_SETUP' && normStatus === 'COMPLETED' && step_name.toLowerCase().includes('account')) {
    updatedStatus = 'ENROLLED';
  } else {
    updatedStatus = 'PROVISIONING';
  }

  db.prepare(`
    UPDATE autopilot_devices SET
      deployment_status = ?,
      device_id = COALESCE(?, device_id),
      last_contact_at = DATETIME('now'),
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(updatedStatus, device_id || null, autopilot_device_id);

  // Security event logging on milestone
  try {
    let eventType = null;
    let severity = 'INFO';
    if (normStatus === 'FAILED') {
      eventType = 'AUTOPILOT_PROVISIONING_FAILED';
      severity = 'HIGH';
    } else if (updatedStatus === 'ENROLLED') {
      eventType = 'AUTOPILOT_PROVISIONING_COMPLETED';
      severity = 'INFO';
    } else if (normPhase === 'DEVICE_PREPARATION' && normStatus === 'IN_PROGRESS') {
      eventType = 'AUTOPILOT_PROVISIONING_STARTED';
      severity = 'INFO';
    }

    if (eventType && device_id) {
      const devRow = db.prepare('SELECT id FROM devices WHERE id = ?').get(device_id);
      if (devRow) {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          device_id,
          eventType,
          5202,
          'AutopilotProvisioning',
          severity,
          `Autopilot provisioning [${normPhase}] ${step_name}: ${normStatus}${error_code ? ` (Error: ${error_code})` : ''}`,
          JSON.stringify({ autopilot_device_id, phase: normPhase, step_name, status: normStatus, error_code })
        );
      }
    }
  } catch (evErr) {
    console.warn('[Autopilot Provisioning Event Warning]:', evErr.message);
  }

  return { id: eventId, autopilot_device_id, phase: normPhase, status: normStatus, deployment_status: updatedStatus };
}

/**
 * Synchronize an enrolled fleet node with pre-registered Autopilot hardware hash
 */
export function syncDeviceWithAutopilot(db, deviceId, serialNumber, hardwareHash = null) {
  if (!serialNumber) return null;

  const apDev = db.prepare('SELECT * FROM autopilot_devices WHERE serial_number = ?').get(serialNumber);
  if (!apDev) return null;

  // Link node ID and transition to ENROLLED if a profile is assigned
  const newStatus = apDev.profile_id ? 'ENROLLED' : apDev.deployment_status;

  db.prepare(`
    UPDATE autopilot_devices SET
      device_id = ?,
      deployment_status = ?,
      hardware_hash = CASE WHEN hardware_hash LIKE '%SAMPLE%' AND ? IS NOT NULL THEN ? ELSE hardware_hash END,
      last_contact_at = DATETIME('now'),
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(deviceId, newStatus, hardwareHash, hardwareHash, apDev.id);

  return getAutopilotDevice(db, apDev.id);
}

/**
 * Get comprehensive Autopilot posture for a specific fleet device
 */
export function getDeviceAutopilotPosture(db, deviceId) {
  const device = db.prepare('SELECT id, hostname, serial_number, friendly_name FROM devices WHERE id = ?').get(deviceId);
  if (!device) return null;

  const apRecord = db.prepare(`
    SELECT
      ad.*,
      ap.name as profile_name,
      ap.deployment_mode,
      ap.join_type,
      ap.account_type,
      ap.device_name_template
    FROM autopilot_devices ad
    LEFT JOIN autopilot_profiles ap ON ad.profile_id = ap.id
    WHERE ad.device_id = ? OR (ad.serial_number = ? AND ad.serial_number != '')
  `).get(deviceId, device.serial_number);

  const effectiveEsp = getEffectiveEspForDevice(db, deviceId);

  let events = [];
  if (apRecord) {
    events = db.prepare(`
      SELECT * FROM autopilot_provisioning_events
      WHERE autopilot_device_id = ?
      ORDER BY timestamp ASC
    `).all(apRecord.id);
  }

  return {
    is_registered: !!apRecord,
    autopilot_device: apRecord || null,
    effective_esp: effectiveEsp,
    provisioning_events: events
  };
}
