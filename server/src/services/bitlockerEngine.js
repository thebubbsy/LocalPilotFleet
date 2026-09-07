/**
 * LocalPilot Fleet - BitLocker Drive Encryption & Recovery Vault Engine
 * 
 * Provides enterprise-grade BitLocker disk encryption governance, 48-digit recovery password escrow,
 * tamper-evident key reveal audit trails, dynamic group policy resolution, and remote rotation.
 */

import crypto from 'node:crypto';

class BitLockerEngine {
  /**
   * List all BitLocker policies with target counts and compliance stats.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getPolicies(db) {
    const policies = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM bitlocker_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.created_at DESC
    `).all();

    const devices = db.prepare(`
      SELECT d.id, d.bitlocker_status, gm.group_id
      FROM devices d
      LEFT JOIN group_memberships gm ON d.id = gm.device_id
    `).all();

    return policies.map(p => {
      let targeted = 0;
      let encrypted = 0;

      const matchedDevices = new Set();
      for (const d of devices) {
        if (p.target_group_id === 'grp-all' || d.group_id === p.target_group_id) {
          if (!matchedDevices.has(d.id)) {
            matchedDevices.add(d.id);
            targeted++;
            if (d.bitlocker_status === 'FullyEncrypted') {
              encrypted++;
            }
          }
        }
      }

      return {
        ...p,
        require_tpm: p.require_tpm === 1,
        recovery_key_rotation: p.recovery_key_rotation === 1,
        hide_recovery_options_in_wizard: p.hide_recovery_options_in_wizard === 1,
        silent_encryption_enabled: p.silent_encryption_enabled === 1,
        is_enabled: p.is_enabled === 1,
        targeted_devices_count: targeted,
        encrypted_devices_count: encrypted,
        encryption_rate_percent: targeted > 0 ? Math.round((encrypted / targeted) * 1000) / 10 : 100.0
      };
    });
  }

  /**
   * Get a BitLocker policy by ID.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getPolicyById(db, id) {
    const p = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM bitlocker_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.id = ?
    `).get(id);

    if (!p) return null;

    return {
      ...p,
      require_tpm: p.require_tpm === 1,
      recovery_key_rotation: p.recovery_key_rotation === 1,
      hide_recovery_options_in_wizard: p.hide_recovery_options_in_wizard === 1,
      silent_encryption_enabled: p.silent_encryption_enabled === 1,
      is_enabled: p.is_enabled === 1
    };
  }

  /**
   * Create a new BitLocker policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} payload
   * @returns {object}
   */
  createPolicy(db, payload) {
    const {
      name,
      description = '',
      target_group_id = 'grp-all',
      encryption_method_os = 'XtsAes128',
      encryption_method_fixed = 'XtsAes128',
      require_tpm = true,
      recovery_key_rotation = true,
      hide_recovery_options_in_wizard = true,
      silent_encryption_enabled = true,
      is_enabled = true
    } = payload;

    if (!name || typeof name !== 'string' || !name.trim()) {
      throw new Error('Policy name is required');
    }

    const id = `bit-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO bitlocker_policies (
        id, name, description, target_group_id, encryption_method_os, encryption_method_fixed,
        require_tpm, recovery_key_rotation, hide_recovery_options_in_wizard, silent_encryption_enabled, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, name.trim(), description.trim(), target_group_id,
      encryption_method_os, encryption_method_fixed,
      require_tpm ? 1 : 0,
      recovery_key_rotation ? 1 : 0,
      hide_recovery_options_in_wizard ? 1 : 0,
      silent_encryption_enabled ? 1 : 0,
      is_enabled ? 1 : 0
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing BitLocker policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} payload
   * @returns {object|null}
   */
  updatePolicy(db, id, payload) {
    const existing = this.getPolicyById(db, id);
    if (!existing) return null;

    const {
      name = existing.name,
      description = existing.description,
      target_group_id = existing.target_group_id,
      encryption_method_os = existing.encryption_method_os,
      encryption_method_fixed = existing.encryption_method_fixed,
      require_tpm = existing.require_tpm,
      recovery_key_rotation = existing.recovery_key_rotation,
      hide_recovery_options_in_wizard = existing.hide_recovery_options_in_wizard,
      silent_encryption_enabled = existing.silent_encryption_enabled,
      is_enabled = existing.is_enabled
    } = payload;

    db.prepare(`
      UPDATE bitlocker_policies
      SET name = ?, description = ?, target_group_id = ?,
          encryption_method_os = ?, encryption_method_fixed = ?,
          require_tpm = ?, recovery_key_rotation = ?,
          hide_recovery_options_in_wizard = ?, silent_encryption_enabled = ?,
          is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, target_group_id,
      encryption_method_os, encryption_method_fixed,
      require_tpm ? 1 : 0,
      recovery_key_rotation ? 1 : 0,
      hide_recovery_options_in_wizard ? 1 : 0,
      silent_encryption_enabled ? 1 : 0,
      is_enabled ? 1 : 0,
      id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete a BitLocker policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM bitlocker_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get effective BitLocker policy for a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object|null}
   */
  getEffectivePolicyForDevice(db, deviceId) {
    const policies = db.prepare(`
      SELECT p.*, g.priority as group_priority
      FROM bitlocker_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.is_enabled = 1 AND (
        p.target_group_id = 'grp-all' OR
        EXISTS (SELECT 1 FROM group_memberships gm WHERE gm.device_id = ? AND gm.group_id = p.target_group_id)
      )
      ORDER BY COALESCE(g.priority, 999) ASC, p.created_at DESC
    `).all(deviceId);

    if (policies.length === 0) return null;

    const base = policies[0];
    return {
      id: base.id,
      name: base.name,
      encryption_method_os: base.encryption_method_os,
      encryption_method_fixed: base.encryption_method_fixed,
      require_tpm: base.require_tpm === 1,
      recovery_key_rotation: base.recovery_key_rotation === 1,
      hide_recovery_options_in_wizard: base.hide_recovery_options_in_wizard === 1,
      silent_encryption_enabled: base.silent_encryption_enabled === 1,
      applied_policies_count: policies.length
    };
  }

  /**
   * Record or update per-volume BitLocker telemetry from endpoint agent.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  recordVolumeStatus(db, deviceId, payload) {
    const {
      mount_point = 'C:',
      volume_type = 'OperatingSystem',
      protection_status = 'Off',
      volume_status = 'FullyDecrypted',
      encryption_percentage = 0.0,
      encryption_method = 'None',
      lock_status = 'Unlocked',
      key_protector_types = []
    } = payload;

    const mp = mount_point.toUpperCase().trim();
    const id = `vol-${deviceId.slice(0, 8)}-${mp.replace(':', '')}`;

    const prot = ['On', 'Off', 'Unknown'].includes(protection_status) ? protection_status : 'Unknown';
    const volStat = ['FullyEncrypted', 'FullyDecrypted', 'EncryptionInProgress', 'DecryptionInProgress', 'Unknown'].includes(volume_status)
      ? volume_status
      : 'Unknown';
    const lockStat = ['Locked', 'Unlocked'].includes(lock_status) ? lock_status : 'Unlocked';

    // Check if recovery key exists in vault for this volume
    const existingKey = db.prepare(`
      SELECT id FROM bitlocker_recovery_keys
      WHERE device_id = ? AND volume_mount_point = ?
    `).get(deviceId, mp);
    const hasRecoveryKey = existingKey ? 1 : 0;

    db.prepare(`
      INSERT INTO device_bitlocker_volumes (
        id, device_id, mount_point, volume_type, protection_status, volume_status,
        encryption_percentage, encryption_method, lock_status, key_protector_types_json,
        has_recovery_key, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
      ON CONFLICT(device_id, mount_point) DO UPDATE SET
        volume_type = excluded.volume_type,
        protection_status = excluded.protection_status,
        volume_status = excluded.volume_status,
        encryption_percentage = excluded.encryption_percentage,
        encryption_method = excluded.encryption_method,
        lock_status = excluded.lock_status,
        key_protector_types_json = excluded.key_protector_types_json,
        has_recovery_key = CASE WHEN device_bitlocker_volumes.has_recovery_key = 1 THEN 1 ELSE excluded.has_recovery_key END,
        updated_at = DATETIME('now')
    `).run(
      id, deviceId, mp, volume_type, prot, volStat,
      Number(encryption_percentage) || 0.0, encryption_method,
      lockStat, JSON.stringify(key_protector_types),
      hasRecoveryKey
    );

    // If this is the OS drive (C: or OperatingSystem), reflect in devices.bitlocker_status
    if (mp === 'C:' || volume_type === 'OperatingSystem') {
      const normalizedStatus = volStat === 'FullyEncrypted' && prot === 'On'
        ? 'FullyEncrypted'
        : (volStat === 'EncryptionInProgress' ? 'EncryptionInProgress' : (volStat === 'FullyDecrypted' ? 'Disabled' : 'Disabled'));

      db.prepare(`
        UPDATE devices
        SET bitlocker_status = ?, updated_at = DATETIME('now')
        WHERE id = ?
      `).run(normalizedStatus, deviceId);
    }

    return db.prepare('SELECT * FROM device_bitlocker_volumes WHERE device_id = ? AND mount_point = ?').get(deviceId, mp);
  }

  /**
   * Escrow a 48-digit recovery password into the secure recovery vault.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  escrowRecoveryKey(db, deviceId, payload) {
    const {
      volume_mount_point = 'C:',
      volume_type = 'OperatingSystem',
      key_protector_id,
      key_protector_type = 'RecoveryPassword',
      recovery_password,
      encryption_method = 'XtsAes128'
    } = payload;

    if (!key_protector_id || typeof key_protector_id !== 'string') {
      throw new Error('Key protector ID (GUID) is required');
    }
    if (!recovery_password || typeof recovery_password !== 'string') {
      throw new Error('Recovery password is required');
    }

    const cleanPw = recovery_password.trim();
    const cleanProtId = key_protector_id.trim();
    const mp = volume_mount_point.toUpperCase().trim();
    const id = `key-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO bitlocker_recovery_keys (
        id, device_id, volume_mount_point, volume_type, key_protector_id,
        key_protector_type, recovery_password, encryption_method, backup_timestamp, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))
      ON CONFLICT(device_id, key_protector_id) DO UPDATE SET
        recovery_password = excluded.recovery_password,
        volume_mount_point = excluded.volume_mount_point,
        volume_type = excluded.volume_type,
        encryption_method = excluded.encryption_method,
        updated_at = DATETIME('now')
    `).run(
      id, deviceId, mp, volume_type, cleanProtId,
      key_protector_type, cleanPw, encryption_method
    );

    // Update volume has_recovery_key flag
    db.prepare(`
      UPDATE device_bitlocker_volumes
      SET has_recovery_key = 1, updated_at = DATETIME('now')
      WHERE device_id = ? AND mount_point = ?
    `).run(deviceId, mp);

    // Log security event for audit trail
    const dev = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
    const host = dev?.hostname || deviceId;

    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
      ) VALUES (?, 'BITLOCKER_KEY_ESCROWED', 844, 'Microsoft-Windows-BitLocker-Driver', 'INFO', ?, ?, 0)
    `).run(
      deviceId,
      `BitLocker recovery key escrowed for volume ${mp} on ${host} (ID: ${cleanProtId.slice(0, 8)})`,
      JSON.stringify({ device_id: deviceId, mount_point: mp, key_protector_id: cleanProtId })
    );

    const saved = db.prepare('SELECT * FROM bitlocker_recovery_keys WHERE device_id = ? AND key_protector_id = ?').get(deviceId, cleanProtId);
    return {
      ...saved,
      recovery_password_masked: this.maskPassword(saved.recovery_password),
      key_id_short: this.extractShortKeyId(saved.key_protector_id)
    };
  }

  /**
   * Helper to mask a 48-digit recovery password for safe display.
   * @param {string} pw
   * @returns {string}
   */
  maskPassword(pw) {
    if (!pw) return '••••••-••••••-••••••-••••••-••••••-••••••-••••••-••••••';
    // Format: 123456-••••••-••••••-••••••-••••••-••••••-••••••-789012
    const parts = pw.split('-');
    if (parts.length === 8) {
      return `${parts[0]}-••••••-••••••-••••••-••••••-••••••-••••••-${parts[7]}`;
    }
    return '••••••-••••••-••••••-••••••-••••••-••••••-••••••-••••••';
  }

  /**
   * Extract first 8 alphanumeric characters of key protector GUID.
   * @param {string} protId
   * @returns {string}
   */
  extractShortKeyId(protId) {
    if (!protId) return '';
    const cleaned = protId.replace(/[{}-]/g, '');
    return cleaned.slice(0, 8).toUpperCase();
  }

  /**
   * Get escrowed keys across the fleet or for a device with masked passwords.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} options
   * @returns {Array<object>}
   */
  getRecoveryKeys(db, options = {}) {
    const { device_id, query = '', limit = 50, offset = 0 } = options;

    const conditions = [];
    const params = [];

    if (device_id) {
      conditions.push('k.device_id = ?');
      params.push(device_id);
    }

    if (query && query.trim()) {
      const q = `%${query.trim()}%`;
      conditions.push('(d.hostname LIKE ? OR d.friendly_name LIKE ? OR k.key_protector_id LIKE ? OR k.volume_mount_point LIKE ?)');
      params.push(q, q, q, q);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const rows = db.prepare(`
      SELECT k.*, d.hostname, d.friendly_name, d.primary_user
      FROM bitlocker_recovery_keys k
      JOIN devices d ON k.device_id = d.id
      ${whereClause}
      ORDER BY k.backup_timestamp DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    return rows.map(r => ({
      id: r.id,
      device_id: r.device_id,
      hostname: r.hostname,
      friendly_name: r.friendly_name,
      primary_user: r.primary_user,
      volume_mount_point: r.volume_mount_point,
      volume_type: r.volume_type,
      key_protector_id: r.key_protector_id,
      key_id_short: this.extractShortKeyId(r.key_protector_id),
      key_protector_type: r.key_protector_type,
      recovery_password_masked: this.maskPassword(r.recovery_password),
      encryption_method: r.encryption_method,
      backup_timestamp: r.backup_timestamp,
      last_accessed_at: r.last_accessed_at,
      access_count: r.access_count
    }));
  }

  /**
   * Reveal an escrowed recovery password and log an immutable access audit entry.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} keyId
   * @param {object} auditInfo
   * @returns {object}
   */
  revealRecoveryKey(db, keyId, auditInfo = {}) {
    const key = db.prepare(`
      SELECT k.*, d.hostname, d.friendly_name
      FROM bitlocker_recovery_keys k
      JOIN devices d ON k.device_id = d.id
      WHERE k.id = ?
    `).get(keyId);

    if (!key) {
      throw new Error(`Recovery key ${keyId} not found`);
    }

    const {
      accessed_by = 'Administrator',
      access_reason = 'BitLocker recovery password lookup for endpoint rescue',
      ip_address = '127.0.0.1'
    } = auditInfo;

    const auditId = `audit-${crypto.randomUUID().slice(0, 8)}`;

    // Insert audit log
    db.prepare(`
      INSERT INTO bitlocker_audit_logs (
        id, key_id, device_id, accessed_by, access_reason, ip_address, accessed_at
      ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'))
    `).run(auditId, keyId, key.device_id, accessed_by, access_reason, ip_address);

    // Update key access counters
    db.prepare(`
      UPDATE bitlocker_recovery_keys
      SET access_count = access_count + 1, last_accessed_at = DATETIME('now')
      WHERE id = ?
    `).run(keyId);

    // Raise critical security event
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
      ) VALUES (?, 'BITLOCKER_KEY_REVEALED', 845, 'Microsoft-Windows-BitLocker-Driver', 'HIGH', ?, ?, 0)
    `).run(
      key.device_id,
      `BitLocker recovery password revealed for ${key.volume_mount_point} on ${key.hostname} by ${accessed_by}`,
      JSON.stringify({ key_id: keyId, key_protector_id: key.key_protector_id, accessed_by, access_reason, ip_address })
    );

    return {
      id: key.id,
      device_id: key.device_id,
      hostname: key.hostname,
      friendly_name: key.friendly_name,
      volume_mount_point: key.volume_mount_point,
      volume_type: key.volume_type,
      key_protector_id: key.key_protector_id,
      key_id_short: this.extractShortKeyId(key.key_protector_id),
      recovery_password: key.recovery_password,
      encryption_method: key.encryption_method,
      audit_record_id: auditId,
      revealed_at: new Date().toISOString()
    };
  }

  /**
   * Get BitLocker key access audit trail.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} options
   * @returns {Array<object>}
   */
  getAuditLogs(db, options = {}) {
    const { device_id, limit = 50, offset = 0 } = options;

    const conditions = [];
    const params = [];

    if (device_id) {
      conditions.push('a.device_id = ?');
      params.push(device_id);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    return db.prepare(`
      SELECT a.*, d.hostname, d.friendly_name, k.volume_mount_point, k.key_protector_id
      FROM bitlocker_audit_logs a
      JOIN devices d ON a.device_id = d.id
      JOIN bitlocker_recovery_keys k ON a.key_id = k.id
      ${whereClause}
      ORDER BY a.accessed_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
  }

  /**
   * Get fleet-wide BitLocker statistics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getBitLockerStats(db) {
    const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;

    const volumeStats = db.prepare(`
      SELECT 
        COUNT(*) as total_volumes,
        SUM(CASE WHEN protection_status = 'On' THEN 1 ELSE 0 END) as protected_volumes,
        SUM(CASE WHEN protection_status = 'Off' THEN 1 ELSE 0 END) as unprotected_volumes,
        SUM(CASE WHEN volume_status = 'FullyEncrypted' THEN 1 ELSE 0 END) as fully_encrypted_volumes,
        SUM(CASE WHEN volume_status = 'EncryptionInProgress' THEN 1 ELSE 0 END) as in_progress_volumes,
        SUM(CASE WHEN has_recovery_key = 1 THEN 1 ELSE 0 END) as volumes_with_escrowed_key
      FROM device_bitlocker_volumes
    `).get();

    const totalKeys = db.prepare('SELECT COUNT(*) as c FROM bitlocker_recovery_keys').get().c;
    const totalAuditEvents = db.prepare('SELECT COUNT(*) as c FROM bitlocker_audit_logs').get().c;

    const devicePosture = db.prepare(`
      SELECT 
        SUM(CASE WHEN bitlocker_status = 'FullyEncrypted' THEN 1 ELSE 0 END) as encrypted_devices,
        SUM(CASE WHEN bitlocker_status != 'FullyEncrypted' OR bitlocker_status IS NULL THEN 1 ELSE 0 END) as unencrypted_devices
      FROM devices
    `).get();

    const encryptedCount = devicePosture?.encrypted_devices || 0;
    const encryptionRate = totalDevices > 0 ? Math.round((encryptedCount / totalDevices) * 1000) / 10 : 100.0;

    const ciphers = db.prepare(`
      SELECT encryption_method, COUNT(*) as count
      FROM device_bitlocker_volumes
      WHERE encryption_method IS NOT NULL AND encryption_method != ''
      GROUP BY encryption_method
    `).all();

    const cipherMap = {};
    for (const c of ciphers) {
      cipherMap[c.encryption_method] = c.count;
    }

    return {
      total_devices: totalDevices,
      encrypted_devices: encryptedCount,
      unencrypted_devices: devicePosture?.unencrypted_devices || 0,
      encryption_rate_percent: encryptionRate,
      total_volumes: volumeStats?.total_volumes || 0,
      protected_volumes: volumeStats?.protected_volumes || 0,
      unprotected_volumes: volumeStats?.unprotected_volumes || 0,
      fully_encrypted_volumes: volumeStats?.fully_encrypted_volumes || 0,
      in_progress_volumes: volumeStats?.in_progress_volumes || 0,
      volumes_with_escrowed_key: volumeStats?.volumes_with_escrowed_key || 0,
      total_escrowed_keys: totalKeys,
      total_audit_events: totalAuditEvents,
      ciphers_breakdown: cipherMap
    };
  }

  /**
   * Get device BitLocker detailed posture (all volumes, key protectors, effective policy).
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object}
   */
  getDeviceBitLockerPosture(db, deviceId) {
    const dev = db.prepare('SELECT id, hostname, friendly_name, bitlocker_status FROM devices WHERE id = ?').get(deviceId);
    if (!dev) return null;

    const volumes = db.prepare(`
      SELECT * FROM device_bitlocker_volumes
      WHERE device_id = ?
      ORDER BY mount_point ASC
    `).all(deviceId);

    const keys = db.prepare(`
      SELECT id, volume_mount_point, volume_type, key_protector_id, key_protector_type,
             backup_timestamp, last_accessed_at, access_count, encryption_method
      FROM bitlocker_recovery_keys
      WHERE device_id = ?
      ORDER BY backup_timestamp DESC
    `).all(deviceId);

    const parsedVolumes = volumes.map(v => {
      let protectors = [];
      try { protectors = JSON.parse(v.key_protector_types_json); } catch {}
      return {
        ...v,
        key_protectors: protectors,
        is_protected: v.protection_status === 'On',
        is_encrypted: v.volume_status === 'FullyEncrypted'
      };
    });

    const parsedKeys = keys.map(k => ({
      ...k,
      key_id_short: this.extractShortKeyId(k.key_protector_id)
    }));

    const effectivePolicy = this.getEffectivePolicyForDevice(db, deviceId);

    return {
      device_id: dev.id,
      hostname: dev.hostname,
      friendly_name: dev.friendly_name,
      bitlocker_status: dev.bitlocker_status,
      volumes: parsedVolumes,
      recovery_keys: parsedKeys,
      effective_policy: effectivePolicy
    };
  }

  /**
   * Queue a remote BitLocker key rotation command.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} mountPoint
   * @returns {object}
   */
  queueKeyRotationCommand(db, deviceId, mountPoint = 'C:') {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);

    const commandId = `cmd-rotate-${crypto.randomUUID().slice(0, 8)}`;
    const mp = mountPoint.toUpperCase().trim();

    // PowerShell script to generate new recovery protector, backup to authority, remove old
    const script = `
$v = Get-BitLockerVolume -MountPoint '${mp}' -ErrorAction Stop;
$oldKeys = @($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' });
$newProtector = Add-BitLockerKeyProtector -MountPoint '${mp}' -RecoveryPasswordProtector -ErrorAction Stop;
$fresh = Get-BitLockerVolume -MountPoint '${mp}';
$activeKey = $fresh.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' -and $_.KeyProtectorId -eq $newProtector.KeyProtectorId };
if ($activeKey -and $activeKey.RecoveryPassword) {
  # Post to local escrow
  $payload = @{
    volume_mount_point = '${mp}';
    volume_type = [string]$fresh.VolumeType;
    key_protector_id = [string]$activeKey.KeyProtectorId;
    recovery_password = [string]$activeKey.RecoveryPassword;
    encryption_method = [string]$fresh.EncryptionMethod;
  };
  # Remove superseded recovery protectors
  foreach ($ok in $oldKeys) {
    if ($ok.KeyProtectorId -ne $activeKey.KeyProtectorId) {
      Remove-BitLockerKeyProtector -MountPoint '${mp}' -KeyProtectorId $ok.KeyProtectorId -ErrorAction SilentlyContinue;
    }
  }
  Write-Output ($payload | ConvertTo-Json -Compress);
} else {
  throw 'Failed to generate active recovery password protector';
}
`.trim();

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'BitLockerAdmin', 'PENDING', DATETIME('now'))
    `).run(commandId, deviceId, script);

    return {
      command_id: commandId,
      device_id: deviceId,
      command_type: 'ROTATE_BITLOCKER_KEY',
      mount_point: mp,
      status: 'PENDING'
    };
  }

  /**
   * Queue a remote silent BitLocker drive encryption command.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} mountPoint
   * @param {string} encryptionMethod
   * @returns {object}
   */
  queueEnableBitLockerCommand(db, deviceId, mountPoint = 'C:', encryptionMethod = 'XtsAes128') {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);

    const commandId = `cmd-encrypt-${crypto.randomUUID().slice(0, 8)}`;
    const mp = mountPoint.toUpperCase().trim();
    const em = ['XtsAes128', 'XtsAes256', 'Aes128', 'Aes256'].includes(encryptionMethod) ? encryptionMethod : 'XtsAes128';

    const script = `
$v = Get-BitLockerVolume -MountPoint '${mp}' -ErrorAction Stop;
if ($v.ProtectionStatus -eq 'Off') {
  Enable-BitLocker -MountPoint '${mp}' -EncryptionMethod ${em} -UsedSpaceOnly -TpmProtector -SkipHardwareTest -ErrorAction Stop;
  Add-BitLockerKeyProtector -MountPoint '${mp}' -RecoveryPasswordProtector -ErrorAction SilentlyContinue;
}
Get-BitLockerVolume -MountPoint '${mp}' | Select-Object MountPoint, ProtectionStatus, VolumeStatus, EncryptionPercentage, EncryptionMethod | ConvertTo-Json -Compress;
`.trim();

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'BitLockerAdmin', 'PENDING', DATETIME('now'))
    `).run(commandId, deviceId, script);

    // Raise audit event
    db.prepare(`
      INSERT INTO security_events (
        device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
      ) VALUES (?, 'BITLOCKER_ENCRYPTION_TRIGGERED', 846, 'LocalPilot-Fleet-Authority', 'MEDIUM', ?, ?, 0)
    `).run(
      deviceId,
      `Remote BitLocker silent encryption triggered for ${mp} on ${dev.hostname} (${em})`,
      JSON.stringify({ device_id: deviceId, mount_point: mp, encryption_method: em })
    );

    return {
      command_id: commandId,
      device_id: deviceId,
      command_type: 'ENABLE_BITLOCKER',
      mount_point: mp,
      encryption_method: em,
      status: 'PENDING'
    };
  }

  /**
   * Queue a command to query and escrow all BitLocker recovery keys on a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object}
   */
  queueForceEscrowCommand(db, deviceId) {
    const dev = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);

    const commandId = `cmd-escrow-${crypto.randomUUID().slice(0, 8)}`;

    const script = `
$vols = Get-BitLockerVolume -ErrorAction SilentlyContinue;
$keys = @();
foreach ($v in $vols) {
  foreach ($kp in $v.KeyProtector) {
    if ($kp.KeyProtectorType -eq 'RecoveryPassword' -and $kp.RecoveryPassword) {
      $keys += @{
        mount_point = [string]$v.MountPoint;
        volume_type = [string]$v.VolumeType;
        key_protector_id = [string]$kp.KeyProtectorId;
        recovery_password = [string]$kp.RecoveryPassword;
        encryption_method = [string]$v.EncryptionMethod;
      };
    }
  }
}
Write-Output ($keys | ConvertTo-Json -Compress);
`.trim();

    db.prepare(`
      INSERT INTO device_commands (
        id, device_id, command_text, created_by, status, created_at
      ) VALUES (?, ?, ?, 'BitLockerAdmin', 'PENDING', DATETIME('now'))
    `).run(commandId, deviceId, script);

    return {
      command_id: commandId,
      device_id: deviceId,
      command_type: 'ESCROW_BITLOCKER_KEYS',
      status: 'PENDING'
    };
  }
}

export const bitlockerEngine = new BitLockerEngine();
