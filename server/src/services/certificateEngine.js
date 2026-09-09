/**
 * LocalPilot Fleet — Certificate Management & SCEP/PKCS Service Engine
 * server/src/services/certificateEngine.js
 *
 * Implements full Microsoft Intune Certificate Lifecycle Management:
 * - Trusted Root, Intermediate CA, SCEP, and PKCS Certificate Profiles
 * - Dynamic Group Scoping & Heartbeat Delivery
 * - Workstation Certificate Store Inventory & Telemetry Ingestion
 * - Proactive Expiry Monitoring (Expiring Soon <= 30 days, Expired)
 * - Fleet-Wide Certificate Posture & Compliance Analytics
 */

import { broadcastEvent } from '../routes/events.js';

const VALID_TYPES = new Set(['TRUSTED_ROOT', 'INTERMEDIATE_CA', 'SCEP', 'PKCS']);
const VALID_STORES = new Set(['LOCAL_MACHINE_ROOT', 'LOCAL_MACHINE_CA', 'LOCAL_MACHINE_MY', 'CURRENT_USER_MY']);
const VALID_KSP = new Set(['RSA', 'ECDSA', 'MS_SOFTWARE_KSP']);

function genId(prefix = 'cert') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

/**
 * Calculate certificate expiry status and days remaining
 */
export function evaluateExpiry(notAfterStr) {
  if (!notAfterStr) return { daysToExpiry: 9999, status: 'VALID' };
  const expiryDate = new Date(notAfterStr);
  if (isNaN(expiryDate.getTime())) return { daysToExpiry: 9999, status: 'VALID' };

  const now = new Date();
  const diffMs = expiryDate.getTime() - now.getTime();
  const daysToExpiry = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  let status = 'VALID';
  if (daysToExpiry < 0) {
    status = 'EXPIRED';
  } else if (daysToExpiry <= 30) {
    status = 'EXPIRING_SOON';
  }

  return { daysToExpiry, status };
}

/**
 * List all certificate profiles
 */
export function getCertificateProfiles(db, options = {}) {
  const { certificateType, enabled, targetGroupId } = options;
  let sql = 'SELECT * FROM certificate_profiles WHERE 1=1';
  const params = [];

  if (certificateType) {
    sql += ' AND certificate_type = ?';
    params.push(certificateType);
  }
  if (enabled !== undefined) {
    sql += ' AND enabled = ?';
    params.push(enabled ? 1 : 0);
  }
  if (targetGroupId) {
    sql += ' AND target_group_id = ?';
    params.push(targetGroupId);
  }

  sql += ' ORDER BY created_at DESC';
  const profiles = db.prepare(sql).all(...params);

  return profiles.map(p => {
    // Count targeted devices
    let targetedCount = 0;
    if (p.target_group_id === 'grp-all') {
      targetedCount = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
    } else {
      targetedCount = db.prepare('SELECT COUNT(*) as c FROM group_memberships WHERE group_id = ?').get(p.target_group_id).c;
    }

    // Count installed devices
    const installedCount = db.prepare(`
      SELECT COUNT(DISTINCT device_id) as c FROM device_certificates WHERE profile_id = ?
    `).get(p.id).c;

    return {
      ...p,
      targeted_devices_count: targetedCount,
      installed_devices_count: installedCount
    };
  });
}

/**
 * Get a single certificate profile
 */
export function getCertificateProfile(db, id) {
  const profile = db.prepare('SELECT * FROM certificate_profiles WHERE id = ?').get(id);
  if (!profile) return null;

  let targetedCount = 0;
  if (profile.target_group_id === 'grp-all') {
    targetedCount = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  } else {
    targetedCount = db.prepare('SELECT COUNT(*) as c FROM group_memberships WHERE group_id = ?').get(profile.target_group_id).c;
  }

  const installedCount = db.prepare(`
    SELECT COUNT(DISTINCT device_id) as c FROM device_certificates WHERE profile_id = ?
  `).get(profile.id).c;

  return {
    ...profile,
    targeted_devices_count: targetedCount,
    installed_devices_count: installedCount
  };
}

/**
 * Create a new certificate profile
 */
export function createCertificateProfile(db, payload) {
  const {
    name,
    description = '',
    certificateType = 'TRUSTED_ROOT',
    targetStore = 'LOCAL_MACHINE_ROOT',
    targetGroupId = 'grp-all',
    certificateDataBase64 = '',
    thumbprint = '',
    subjectName = '',
    validityPeriodDays = 365,
    keyStorageProvider = 'RSA',
    keySize = 2048,
    scepServerUrl = '',
    renewalThresholdPct = 20,
    enabled = 1
  } = payload;

  if (!name || typeof name !== 'string' || !name.trim()) {
    throw new Error('Profile name is required');
  }
  if (!VALID_TYPES.has(certificateType)) {
    throw new Error(`Invalid certificate type: ${certificateType}. Must be one of: ${[...VALID_TYPES].join(', ')}`);
  }
  if (!VALID_STORES.has(targetStore)) {
    throw new Error(`Invalid target store: ${targetStore}. Must be one of: ${[...VALID_STORES].join(', ')}`);
  }
  if (!VALID_KSP.has(keyStorageProvider)) {
    throw new Error(`Invalid key storage provider: ${keyStorageProvider}. Must be one of: ${[...VALID_KSP].join(', ')}`);
  }

  const id = genId('cert');
  const stmt = db.prepare(`
    INSERT INTO certificate_profiles (
      id, name, description, certificate_type, target_store, target_group_id,
      certificate_data_base64, thumbprint, subject_name, validity_period_days,
      key_storage_provider, key_size, scep_server_url, renewal_threshold_pct,
      enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    name.trim(),
    description.trim(),
    certificateType,
    targetStore,
    targetGroupId || 'grp-all',
    certificateDataBase64 ? certificateDataBase64.trim() : '',
    thumbprint ? thumbprint.trim().toUpperCase() : '',
    subjectName ? subjectName.trim() : '',
    validityPeriodDays ? parseInt(validityPeriodDays, 10) : 365,
    keyStorageProvider,
    keySize ? parseInt(keySize, 10) : 2048,
    scepServerUrl ? scepServerUrl.trim() : '',
    renewalThresholdPct ? parseInt(renewalThresholdPct, 10) : 20,
    enabled ? 1 : 0
  );

  broadcastEvent('certificate_profile_created', { id, name });
  return getCertificateProfile(db, id);
}

/**
 * Update an existing certificate profile
 */
export function updateCertificateProfile(db, id, payload) {
  const existing = getCertificateProfile(db, id);
  if (!existing) throw new Error(`Certificate profile not found: ${id}`);

  const fields = [];
  const params = [];

  if (payload.name !== undefined) {
    if (!payload.name.trim()) throw new Error('Profile name cannot be empty');
    fields.push('name = ?');
    params.push(payload.name.trim());
  }
  if (payload.description !== undefined) {
    fields.push('description = ?');
    params.push(payload.description);
  }
  if (payload.certificate_type !== undefined || payload.certificateType !== undefined) {
    const ct = payload.certificate_type || payload.certificateType;
    if (!VALID_TYPES.has(ct)) throw new Error(`Invalid certificate type: ${ct}`);
    fields.push('certificate_type = ?');
    params.push(ct);
  }
  if (payload.target_store !== undefined || payload.targetStore !== undefined) {
    const ts = payload.target_store || payload.targetStore;
    if (!VALID_STORES.has(ts)) throw new Error(`Invalid target store: ${ts}`);
    fields.push('target_store = ?');
    params.push(ts);
  }
  if (payload.target_group_id !== undefined || payload.targetGroupId !== undefined) {
    fields.push('target_group_id = ?');
    params.push(payload.target_group_id || payload.targetGroupId);
  }
  if (payload.certificate_data_base64 !== undefined || payload.certificateDataBase64 !== undefined) {
    fields.push('certificate_data_base64 = ?');
    params.push(payload.certificate_data_base64 || payload.certificateDataBase64);
  }
  if (payload.thumbprint !== undefined) {
    fields.push('thumbprint = ?');
    params.push(payload.thumbprint.toUpperCase());
  }
  if (payload.subject_name !== undefined || payload.subjectName !== undefined) {
    fields.push('subject_name = ?');
    params.push(payload.subject_name || payload.subjectName);
  }
  if (payload.validity_period_days !== undefined || payload.validityPeriodDays !== undefined) {
    fields.push('validity_period_days = ?');
    params.push(parseInt(payload.validity_period_days || payload.validityPeriodDays, 10));
  }
  if (payload.scep_server_url !== undefined || payload.scepServerUrl !== undefined) {
    fields.push('scep_server_url = ?');
    params.push(payload.scep_server_url || payload.scepServerUrl);
  }
  if (payload.renewal_threshold_pct !== undefined || payload.renewalThresholdPct !== undefined) {
    fields.push('renewal_threshold_pct = ?');
    params.push(parseInt(payload.renewal_threshold_pct || payload.renewalThresholdPct, 10));
  }
  if (payload.enabled !== undefined) {
    fields.push('enabled = ?');
    params.push(payload.enabled ? 1 : 0);
  }

  if (fields.length > 0) {
    fields.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE certificate_profiles SET ${fields.join(', ')} WHERE id = ?`).run(...params);
    broadcastEvent('certificate_profile_updated', { id });
  }

  return getCertificateProfile(db, id);
}

/**
 * Delete a certificate profile
 */
export function deleteCertificateProfile(db, id) {
  const existing = getCertificateProfile(db, id);
  if (!existing) throw new Error(`Certificate profile not found: ${id}`);
  db.prepare('DELETE FROM certificate_profiles WHERE id = ?').run(id);
  broadcastEvent('certificate_profile_deleted', { id });
  return { success: true, id };
}

/**
 * Get effective certificate profiles assigned to a device
 */
export function getEffectiveProfilesForDevice(db, deviceId) {
  try {
    const groupRows = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
    const groupIds = new Set(groupRows.map(r => r.group_id));
    groupIds.add('grp-all');

    const profiles = db.prepare('SELECT * FROM certificate_profiles WHERE enabled = 1').all();
    return profiles.filter(p => groupIds.has(p.target_group_id));
  } catch (err) {
    return [];
  }
}

/**
 * Ingest discovered certificate inventory from agent scan
 */
export function saveDeviceCertificates(db, deviceId, certList) {
  if (!deviceId) throw new Error('deviceId is required');
  if (!Array.isArray(certList)) throw new Error('certList must be an array');

  // Verify device exists
  const dev = db.prepare('SELECT id FROM devices WHERE id = ?').get(deviceId);
  if (!dev) throw new Error(`Device not found: ${deviceId}`);

  const upsertStmt = db.prepare(`
    INSERT INTO device_certificates (
      id, device_id, profile_id, thumbprint, subject, issuer,
      store_location, store_name, not_before, not_after,
      days_to_expiry, has_private_key, status, last_scanned_at,
      created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, DATETIME('now'),
      DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(id) DO UPDATE SET
      profile_id = excluded.profile_id,
      subject = excluded.subject,
      issuer = excluded.issuer,
      store_location = excluded.store_location,
      store_name = excluded.store_name,
      not_before = excluded.not_before,
      not_after = excluded.not_after,
      days_to_expiry = excluded.days_to_expiry,
      has_private_key = excluded.has_private_key,
      status = excluded.status,
      last_scanned_at = DATETIME('now'),
      updated_at = DATETIME('now')
  `);

  let count = 0;
  for (const cert of certList) {
    const thumb = (cert.thumbprint || cert.Thumbprint || '').trim().toUpperCase();
    if (!thumb) continue;

    const subject = (cert.subject || cert.Subject || 'Unknown Subject').trim();
    const issuer = (cert.issuer || cert.Issuer || subject).trim();
    const storeLocation = (cert.store_location || cert.StoreLocation || 'LOCAL_MACHINE').toUpperCase();
    const storeName = (cert.store_name || cert.StoreName || 'My').trim();
    const notBefore = cert.not_before || cert.NotBefore || null;
    const notAfter = cert.not_after || cert.NotAfter || null;
    const hasPrivateKey = cert.has_private_key || cert.HasPrivateKey ? 1 : 0;

    const { daysToExpiry, status } = evaluateExpiry(notAfter);

    // Look for matching profile by thumbprint
    const matchProfile = db.prepare('SELECT id FROM certificate_profiles WHERE thumbprint = ? LIMIT 1').get(thumb);
    const profileId = matchProfile ? matchProfile.id : null;

    // Check if certificate record exists for this device + thumbprint + store
    const existing = db.prepare(`
      SELECT id FROM device_certificates
      WHERE device_id = ? AND thumbprint = ? AND store_location = ? AND store_name = ?
      LIMIT 1
    `).get(deviceId, thumb, storeLocation, storeName);

    const id = existing ? existing.id : genId('dcert');

    upsertStmt.run(
      id,
      deviceId,
      profileId,
      thumb,
      subject,
      issuer,
      storeLocation === 'CURRENT_USER' ? 'CURRENT_USER' : 'LOCAL_MACHINE',
      storeName,
      notBefore,
      notAfter,
      daysToExpiry,
      hasPrivateKey,
      status
    );
    count++;
  }

  broadcastEvent('device_certificates_updated', { device_id: deviceId, count });
  return { device_id: deviceId, saved_count: count };
}

/**
 * Get certificates installed on a specific device
 */
export function getDeviceCertificates(db, deviceId, options = {}) {
  const { storeLocation, status } = options;
  let sql = 'SELECT dc.*, cp.name as profile_name FROM device_certificates dc LEFT JOIN certificate_profiles cp ON dc.profile_id = cp.id WHERE dc.device_id = ?';
  const params = [deviceId];

  if (storeLocation) {
    sql += ' AND dc.store_location = ?';
    params.push(storeLocation);
  }
  if (status) {
    sql += ' AND dc.status = ?';
    params.push(status);
  }

  sql += ' ORDER BY dc.days_to_expiry ASC';
  return db.prepare(sql).all(...params);
}

/**
 * Get all installed certificates across the entire fleet
 */
export function getCertificateInventory(db, options = {}) {
  const { status, storeLocation, search, limit = 100 } = options;
  let sql = `
    SELECT dc.*, d.hostname, d.primary_user, cp.name as profile_name
    FROM device_certificates dc
    JOIN devices d ON dc.device_id = d.id
    LEFT JOIN certificate_profiles cp ON dc.profile_id = cp.id
    WHERE 1=1
  `;
  const params = [];

  if (status) {
    sql += ' AND dc.status = ?';
    params.push(status);
  }
  if (storeLocation) {
    sql += ' AND dc.store_location = ?';
    params.push(storeLocation);
  }
  if (search) {
    sql += ' AND (dc.subject LIKE ? OR dc.issuer LIKE ? OR dc.thumbprint LIKE ? OR d.hostname LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s, s);
  }

  sql += ' ORDER BY dc.days_to_expiry ASC LIMIT ?';
  params.push(parseInt(limit, 10) || 100);

  return db.prepare(sql).all(...params);
}

/**
 * Calculate certificate KPIs and fleet posture statistics
 */
export function getCertificateStats(db) {
  const totalProfiles = db.prepare('SELECT COUNT(*) as c FROM certificate_profiles').get().c;
  const activeProfiles = db.prepare('SELECT COUNT(*) as c FROM certificate_profiles WHERE enabled = 1').get().c;
  const totalCertificates = db.prepare('SELECT COUNT(*) as c FROM device_certificates').get().c;

  const validCount = db.prepare("SELECT COUNT(*) as c FROM device_certificates WHERE status = 'VALID'").get().c;
  const expiringSoonCount = db.prepare("SELECT COUNT(*) as c FROM device_certificates WHERE status = 'EXPIRING_SOON'").get().c;
  const expiredCount = db.prepare("SELECT COUNT(*) as c FROM device_certificates WHERE status = 'EXPIRED'").get().c;

  const rootCAsCount = db.prepare(`
    SELECT COUNT(*) as c FROM device_certificates WHERE store_name = 'Root'
  `).get().c;

  const privateKeyCertsCount = db.prepare(`
    SELECT COUNT(*) as c FROM device_certificates WHERE has_private_key = 1
  `).get().c;

  const expiringSoonList = db.prepare(`
    SELECT dc.id, dc.thumbprint, dc.subject, dc.days_to_expiry, dc.not_after, d.hostname
    FROM device_certificates dc
    JOIN devices d ON dc.device_id = d.id
    WHERE dc.status IN ('EXPIRING_SOON', 'EXPIRED')
    ORDER BY dc.days_to_expiry ASC
    LIMIT 5
  `).all();

  return {
    total_profiles: totalProfiles,
    active_profiles: activeProfiles,
    total_certificates: totalCertificates,
    valid_count: validCount,
    expiring_soon_count: expiringSoonCount,
    expired_count: expiredCount,
    root_cas_count: rootCAsCount,
    private_key_certs_count: privateKeyCertsCount,
    expiring_soon_preview: expiringSoonList
  };
}
