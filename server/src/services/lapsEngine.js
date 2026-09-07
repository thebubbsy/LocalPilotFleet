/**
 * LocalPilot Fleet - Windows LAPS (Local Administrator Password Solution) Engine
 * server/src/services/lapsEngine.js
 * 
 * Provides enterprise-grade Local Administrator Password Solution governance:
 * - Dynamic group policy evaluation (complexity, length, age, post-auth reset)
 * - AES-256-GCM encrypted password vault with zero-trust masked APIs
 * - Audited password reveal with mandatory justification paper trail
 * - Historical credential archive for disaster recovery and forensic rollbacks
 * - Remote on-demand rotation command dispatch via device_commands
 * - Fleet-wide LAPS coverage and expiration analytics
 */

import crypto from 'node:crypto';

class LapsEngine {
  constructor() {
    this._encryptionKey = null;
  }

  /**
   * Derive a stable 256-bit key from the server fleet key.
   * @private
   */
  _getKey() {
    if (!this._encryptionKey) {
      const secret = process.env.FLEET_KEY || 'localpilot-secret-key-2026';
      this._encryptionKey = crypto.createHash('sha256').update(secret).digest();
    }
    return this._encryptionKey;
  }

  /**
   * Encrypt plaintext password using AES-256-GCM.
   * Format: iv:authTag:ciphertext (hex encoded)
   * @param {string} plaintext
   * @returns {string}
   */
  encryptPassword(plaintext) {
    if (!plaintext) return '';
    const key = this._getKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${ciphertext}`;
  }

  /**
   * Decrypt AES-256-GCM encrypted password.
   * Gracefully handles unencrypted legacy strings if encountered.
   * @param {string} encrypted
   * @returns {string}
   */
  decryptPassword(encrypted) {
    if (!encrypted) return '';
    const parts = encrypted.split(':');
    if (parts.length !== 3) {
      // Return as-is if unencrypted seed data
      return encrypted;
    }
    try {
      const [ivHex, tagHex, cipherHex] = parts;
      const key = this._getKey();
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(tagHex, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(cipherHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (err) {
      // Fallback if decryption fails
      return encrypted;
    }
  }

  /**
   * Generate a cryptographically secure random password matching policy complexity.
   * @param {number} length
   * @param {'NUMERIC'|'ALPHABETICAL'|'ALPHANUMERIC'|'COMPLEX'} complexity
   * @returns {string}
   */
  generatePassword(length = 16, complexity = 'COMPLEX') {
    const len = Math.max(12, Math.min(64, Number(length) || 16));
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghijkmnopqrstuvwxyz';
    const digits = '23456789';
    const symbols = '!@#$%^&*()_+~|}{[]:;?><,./-=';

    let pool = '';
    const required = [];

    switch (complexity) {
      case 'NUMERIC':
        pool = digits;
        break;
      case 'ALPHABETICAL':
        pool = upper + lower;
        required.push(upper, lower);
        break;
      case 'ALPHANUMERIC':
        pool = upper + lower + digits;
        required.push(upper, lower, digits);
        break;
      case 'COMPLEX':
      default:
        pool = upper + lower + digits + symbols;
        required.push(upper, lower, digits, symbols);
        break;
    }

    const chars = [];
    // Ensure at least one character from each required category
    for (const reqSet of required) {
      const byte = crypto.randomBytes(1)[0];
      chars.push(reqSet[byte % reqSet.length]);
    }

    // Fill the remainder
    const remaining = len - chars.length;
    if (remaining > 0) {
      const randomBytes = crypto.randomBytes(remaining);
      for (let i = 0; i < remaining; i++) {
        chars.push(pool[randomBytes[i] % pool.length]);
      }
    }

    // Shuffle characters using Fisher-Yates
    for (let i = chars.length - 1; i > 0; i--) {
      const j = crypto.randomBytes(1)[0] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
  }

  /**
   * Mask a password for zero-trust API exposure.
   * @param {string} password
   * @param {number} length
   * @param {string} complexity
   * @returns {string}
   */
  maskPassword(password, length = 16, complexity = 'COMPLEX') {
    const len = length || (password ? password.length : 16);
    return '•'.repeat(Math.min(len, 20)) + ` (${len} chars, ${complexity})`;
  }

  /**
   * List all LAPS policies with target group info and device counts.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {Array<object>}
   */
  getPolicies(db) {
    const policies = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM laps_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      ORDER BY p.created_at DESC
    `).all();

    const devices = db.prepare(`
      SELECT d.id, gm.group_id
      FROM devices d
      LEFT JOIN group_memberships gm ON d.id = gm.device_id
    `).all();

    const passwords = db.prepare(`
      SELECT device_id, expires_at, rotation_status
      FROM laps_passwords
    `).all();

    const passMap = new Map();
    for (const pw of passwords) {
      passMap.set(pw.device_id, pw);
    }

    const now = new Date();

    return policies.map(p => {
      let targeted = 0;
      let compliant = 0;
      let expired = 0;

      const matchedDevices = new Set();
      for (const d of devices) {
        if (p.target_group_id === 'grp-all' || d.group_id === p.target_group_id) {
          if (!matchedDevices.has(d.id)) {
            matchedDevices.add(d.id);
            targeted++;

            const pw = passMap.get(d.id);
            if (pw) {
              const expDate = new Date(pw.expires_at);
              if (expDate > now && pw.rotation_status === 'ACTIVE') {
                compliant++;
              } else {
                expired++;
              }
            }
          }
        }
      }

      return {
        ...p,
        post_auth_reset_enabled: p.post_auth_reset_enabled === 1,
        auto_enable_account: p.auto_enable_account === 1,
        is_enabled: p.is_enabled === 1,
        targeted_devices_count: targeted,
        compliant_devices_count: compliant,
        expired_devices_count: expired,
        coverage_percent: targeted > 0 ? Math.round((compliant / targeted) * 100) : 100
      };
    });
  }

  /**
   * Get single LAPS policy by ID.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {object|null}
   */
  getPolicyById(db, id) {
    const policy = db.prepare(`
      SELECT p.*, g.name as target_group_name, g.color as target_group_color
      FROM laps_policies p
      LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
      WHERE p.id = ?
    `).get(id);

    if (!policy) return null;

    return {
      ...policy,
      post_auth_reset_enabled: policy.post_auth_reset_enabled === 1,
      auto_enable_account: policy.auto_enable_account === 1,
      is_enabled: policy.is_enabled === 1
    };
  }

  /**
   * Create new LAPS policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} data
   * @returns {object}
   */
  createPolicy(db, data) {
    const id = data.id || `laps-pol-${crypto.randomUUID().slice(0, 8)}`;
    const name = data.name?.trim() || 'New LAPS Policy';
    const description = data.description?.trim() || null;
    const targetGroupId = data.target_group_id || 'grp-all';
    const adminAccountName = data.admin_account_name?.trim() || 'Administrator';
    const passwordComplexity = ['NUMERIC', 'ALPHABETICAL', 'ALPHANUMERIC', 'COMPLEX'].includes(data.password_complexity)
      ? data.password_complexity
      : 'COMPLEX';
    const passwordLength = Math.max(12, Math.min(64, Number(data.password_length) || 16));
    const passwordAgeDays = Math.max(1, Math.min(365, Number(data.password_age_days) || 30));
    const postAuthResetEnabled = data.post_auth_reset_enabled ? 1 : 0;
    const postAuthResetDelayHours = Math.max(1, Math.min(24, Number(data.post_auth_reset_delay_hours) || 4));
    const autoEnableAccount = data.auto_enable_account === false ? 0 : 1;
    const isEnabled = data.is_enabled === false ? 0 : 1;

    db.prepare(`
      INSERT INTO laps_policies (
        id, name, description, target_group_id, admin_account_name, password_complexity,
        password_length, password_age_days, post_auth_reset_enabled, post_auth_reset_delay_hours, auto_enable_account, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, name, description, targetGroupId, adminAccountName, passwordComplexity,
      passwordLength, passwordAgeDays, postAuthResetEnabled, postAuthResetDelayHours, autoEnableAccount, isEnabled
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update existing LAPS policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @param {object} data
   * @returns {object|null}
   */
  updatePolicy(db, id, data) {
    const existing = this.getPolicyById(db, id);
    if (!existing) return null;

    const name = data.name !== undefined ? data.name.trim() : existing.name;
    const description = data.description !== undefined ? data.description : existing.description;
    const targetGroupId = data.target_group_id !== undefined ? data.target_group_id : existing.target_group_id;
    const adminAccountName = data.admin_account_name !== undefined ? data.admin_account_name.trim() : existing.admin_account_name;
    const passwordComplexity = data.password_complexity !== undefined ? data.password_complexity : existing.password_complexity;
    const passwordLength = data.password_length !== undefined ? Math.max(12, Math.min(64, Number(data.password_length))) : existing.password_length;
    const passwordAgeDays = data.password_age_days !== undefined ? Math.max(1, Math.min(365, Number(data.password_age_days))) : existing.password_age_days;
    const postAuthResetEnabled = data.post_auth_reset_enabled !== undefined ? (data.post_auth_reset_enabled ? 1 : 0) : (existing.post_auth_reset_enabled ? 1 : 0);
    const postAuthResetDelayHours = data.post_auth_reset_delay_hours !== undefined ? Number(data.post_auth_reset_delay_hours) : existing.post_auth_reset_delay_hours;
    const autoEnableAccount = data.auto_enable_account !== undefined ? (data.auto_enable_account ? 1 : 0) : (existing.auto_enable_account ? 1 : 0);
    const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : (existing.is_enabled ? 1 : 0);

    db.prepare(`
      UPDATE laps_policies SET
        name = ?, description = ?, target_group_id = ?, admin_account_name = ?,
        password_complexity = ?, password_length = ?, password_age_days = ?,
        post_auth_reset_enabled = ?, post_auth_reset_delay_hours = ?, auto_enable_account = ?,
        is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, targetGroupId, adminAccountName,
      passwordComplexity, passwordLength, passwordAgeDays,
      postAuthResetEnabled, postAuthResetDelayHours, autoEnableAccount,
      isEnabled, id
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Delete a LAPS policy.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} id
   * @returns {boolean}
   */
  deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM laps_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Calculate effective LAPS policy for a device based on priority.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object|null}
   */
  getEffectivePolicyForDevice(db, deviceId) {
    const policies = db.prepare(`
      SELECT p.*, g.priority as group_priority, g.name as group_name
      FROM laps_policies p
      INNER JOIN dynamic_groups g ON p.target_group_id = g.id
      INNER JOIN group_memberships gm ON g.id = gm.group_id
      WHERE gm.device_id = ? AND p.is_enabled = 1
      ORDER BY g.priority ASC
      LIMIT 1
    `).get(deviceId);

    if (policies) {
      return {
        ...policies,
        post_auth_reset_enabled: policies.post_auth_reset_enabled === 1,
        auto_enable_account: policies.auto_enable_account === 1,
        is_enabled: policies.is_enabled === 1
      };
    }

    // Fallback to grp-all policy if active
    const fallback = db.prepare(`
      SELECT * FROM laps_policies
      WHERE target_group_id = 'grp-all' AND is_enabled = 1
      ORDER BY created_at DESC
      LIMIT 1
    `).get();

    if (fallback) {
      return {
        ...fallback,
        post_auth_reset_enabled: fallback.post_auth_reset_enabled === 1,
        auto_enable_account: fallback.auto_enable_account === 1,
        is_enabled: fallback.is_enabled === 1
      };
    }

    return null;
  }

  /**
   * Escrow newly generated or rotated LAPS password into vault.
   * Automatically moves older active password into historical archive.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} payload
   * @returns {object}
   */
  escrowPassword(db, deviceId, payload) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    const accountName = payload.account_name?.trim() || 'Administrator';
    const rawPassword = payload.password || '';
    if (!rawPassword) {
      throw new Error('Password payload cannot be empty');
    }

    const passwordLength = payload.password_length || rawPassword.length;
    const complexity = payload.complexity_level || 'COMPLEX';
    const rotationReason = payload.rotation_reason || 'SCHEDULED_EXPIRATION';

    const policy = this.getEffectivePolicyForDevice(db, deviceId);
    const ageDays = policy?.password_age_days || 30;

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ageDays * 24 * 60 * 60 * 1000).toISOString();

    // Check if previous active password exists
    const existing = db.prepare('SELECT * FROM laps_passwords WHERE device_id = ?').get(deviceId);
    if (existing) {
      // Archive into laps_password_history
      const historyId = `laps-hist-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(`
        INSERT INTO laps_password_history (
          id, device_id, account_name, encrypted_password, password_length,
          complexity_level, rotated_at, retired_at, rotation_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'), ?)
      `).run(
        historyId, deviceId, existing.account_name, existing.encrypted_password,
        existing.password_length, existing.complexity_level, existing.last_rotated_at,
        rotationReason
      );
    }

    const encrypted = this.encryptPassword(rawPassword);
    const passwordId = existing ? existing.id : `laps-pwd-${crypto.randomUUID().slice(0, 8)}`;

    db.prepare(`
      INSERT INTO laps_passwords (
        id, device_id, account_name, encrypted_password, password_length,
        complexity_level, last_rotated_at, expires_at, rotation_status,
        last_accessed_at, access_count, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'), ?, 'ACTIVE', NULL, 0, DATETIME('now'))
      ON CONFLICT(device_id) DO UPDATE SET
        account_name = excluded.account_name,
        encrypted_password = excluded.encrypted_password,
        password_length = excluded.password_length,
        complexity_level = excluded.complexity_level,
        last_rotated_at = excluded.last_rotated_at,
        expires_at = excluded.expires_at,
        rotation_status = 'ACTIVE',
        updated_at = DATETIME('now')
    `).run(
      passwordId, deviceId, accountName, encrypted, passwordLength, complexity, expiresAt
    );

    // Record audit event
    const auditId = `laps-audit-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO laps_audit_logs (
        id, device_id, account_name, action, accessed_by, access_reason, ip_address, accessed_at
      ) VALUES (?, ?, ?, 'ESCROW', 'LocalPilot Agent', ?, '127.0.0.1', DATETIME('now'))
    `).run(auditId, deviceId, accountName, `Automated credential escrow (${rotationReason})`);

    // Record Security Event
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_source, severity, summary, raw_payload_json
        ) VALUES (?, 'LAPS_PASSWORD_ESCROWED', 'LocalPilot LAPS Engine', 'INFO', ?, ?)
      `).run(
        deviceId,
        `New local administrator password escrowed for [${accountName}] on ${device.hostname}`,
        JSON.stringify({
          account_name: accountName,
          password_length: passwordLength,
          complexity: complexity,
          expires_at: expiresAt,
          rotation_reason: rotationReason
        })
      );
    } catch (_) {}

    return {
      id: passwordId,
      device_id: deviceId,
      account_name: accountName,
      password_masked: this.maskPassword(rawPassword, passwordLength, complexity),
      password_length: passwordLength,
      complexity_level: complexity,
      expires_at: expiresAt,
      rotation_status: 'ACTIVE'
    };
  }

  /**
   * List all managed LAPS passwords with zero-trust masking.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {object} filters
   * @returns {Array<object>}
   */
  getAllPasswords(db, filters = {}) {
    let sql = `
      SELECT lp.*, d.hostname, d.friendly_name, d.ip_address, d.status as device_status,
             d.os_name, d.primary_user
      FROM laps_passwords lp
      INNER JOIN devices d ON lp.device_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (filters.search) {
      sql += ` AND (d.hostname LIKE ? OR d.friendly_name LIKE ? OR lp.account_name LIKE ?)`;
      const q = `%${filters.search}%`;
      params.push(q, q, q);
    }

    if (filters.status) {
      sql += ` AND lp.rotation_status = ?`;
      params.push(filters.status);
    }

    sql += ` ORDER BY lp.expires_at ASC`;

    const rows = db.prepare(sql).all(...params);
    const now = new Date();

    return rows.map(r => {
      const expDate = new Date(r.expires_at);
      const diffMs = expDate.getTime() - now.getTime();
      const daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

      let health = 'HEALTHY';
      if (daysRemaining <= 0 || r.rotation_status === 'EXPIRED') {
        health = 'EXPIRED';
      } else if (daysRemaining <= 7) {
        health = 'EXPIRING_SOON';
      }

      if (r.rotation_status === 'ROTATION_PENDING') {
        health = 'ROTATION_PENDING';
      }

      return {
        id: r.id,
        device_id: r.device_id,
        hostname: r.hostname,
        friendly_name: r.friendly_name,
        ip_address: r.ip_address,
        device_status: r.device_status,
        account_name: r.account_name,
        password_masked: this.maskPassword(null, r.password_length, r.complexity_level),
        password_length: r.password_length,
        complexity_level: r.complexity_level,
        last_rotated_at: r.last_rotated_at,
        expires_at: r.expires_at,
        days_remaining: daysRemaining,
        health_status: health,
        rotation_status: r.rotation_status,
        last_accessed_at: r.last_accessed_at,
        access_count: r.access_count
      };
    });
  }

  /**
   * Get device LAPS posture and history.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @returns {object}
   */
  getDeviceLapsPosture(db, deviceId) {
    const device = db.prepare('SELECT id, hostname, friendly_name FROM devices WHERE id = ?').get(deviceId);
    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    const active = db.prepare('SELECT * FROM laps_passwords WHERE device_id = ?').get(deviceId);
    const history = db.prepare(`
      SELECT id, account_name, password_length, complexity_level, rotated_at, retired_at, rotation_reason
      FROM laps_password_history
      WHERE device_id = ?
      ORDER BY retired_at DESC
      LIMIT 10
    `).all(deviceId);

    const policy = this.getEffectivePolicyForDevice(db, deviceId);
    const now = new Date();

    let activeData = null;
    if (active) {
      const expDate = new Date(active.expires_at);
      const diffMs = expDate.getTime() - now.getTime();
      const daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

      let health = 'HEALTHY';
      if (daysRemaining <= 0 || active.rotation_status === 'EXPIRED') {
        health = 'EXPIRED';
      } else if (daysRemaining <= 7) {
        health = 'EXPIRING_SOON';
      }

      if (active.rotation_status === 'ROTATION_PENDING') {
        health = 'ROTATION_PENDING';
      }

      activeData = {
        id: active.id,
        account_name: active.account_name,
        password_masked: this.maskPassword(null, active.password_length, active.complexity_level),
        password_length: active.password_length,
        complexity_level: active.complexity_level,
        last_rotated_at: active.last_rotated_at,
        expires_at: active.expires_at,
        days_remaining: daysRemaining,
        health_status: health,
        rotation_status: active.rotation_status,
        last_accessed_at: active.last_accessed_at,
        access_count: active.access_count
      };
    }

    return {
      device_id: deviceId,
      hostname: device.hostname,
      friendly_name: device.friendly_name,
      active_credential: activeData,
      history: history.map(h => ({
        ...h,
        password_masked: this.maskPassword(null, h.password_length, h.complexity_level)
      })),
      effective_policy: policy
    };
  }

  /**
   * Reveal active LAPS password with mandatory operator justification audit.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {object} auditParams
   * @returns {object}
   */
  revealPassword(db, deviceId, { accessed_by = 'Administrator', access_reason = '', ip_address = '127.0.0.1' } = {}) {
    const reason = access_reason?.trim();
    if (!reason || reason.length < 5) {
      throw new Error('Valid justification reason (minimum 5 characters) is required to reveal LAPS administrator password');
    }

    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    const record = db.prepare('SELECT * FROM laps_passwords WHERE device_id = ?').get(deviceId);
    if (!record) {
      throw new Error(`No LAPS password escrowed for device: ${device.hostname}`);
    }

    const decrypted = this.decryptPassword(record.encrypted_password);

    // Update access counter and timestamp
    db.prepare(`
      UPDATE laps_passwords
      SET access_count = access_count + 1, last_accessed_at = DATETIME('now')
      WHERE id = ?
    `).run(record.id);

    // Insert into audit logs
    const auditId = `laps-audit-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO laps_audit_logs (
        id, device_id, account_name, action, accessed_by, access_reason, ip_address, accessed_at
      ) VALUES (?, ?, ?, 'REVEAL', ?, ?, ?, DATETIME('now'))
    `).run(auditId, deviceId, record.account_name, accessed_by, reason, ip_address);

    // Dispatch Security Event (HIGH severity)
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_source, severity, summary, raw_payload_json
        ) VALUES (?, 'LAPS_PASSWORD_REVEALED', 'LocalPilot LAPS Vault', 'HIGH', ?, ?)
      `).run(
        deviceId,
        `LAPS administrator password for [${record.account_name}] revealed on ${device.hostname} by ${accessed_by}`,
        JSON.stringify({
          account_name: record.account_name,
          revealed_by: accessed_by,
          reason,
          ip_address,
          revealed_at: new Date().toISOString()
        })
      );
    } catch (_) {}

    return {
      device_id: deviceId,
      hostname: device.hostname,
      account_name: record.account_name,
      password: decrypted,
      password_length: record.password_length,
      complexity_level: record.complexity_level,
      last_rotated_at: record.last_rotated_at,
      expires_at: record.expires_at,
      audit_record_id: auditId,
      revealed_at: new Date().toISOString()
    };
  }

  /**
   * Reveal archived historical LAPS password.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} historyId
   * @param {object} auditParams
   * @returns {object}
   */
  revealHistoricalPassword(db, historyId, { accessed_by = 'Administrator', access_reason = '', ip_address = '127.0.0.1' } = {}) {
    const reason = access_reason?.trim();
    if (!reason || reason.length < 5) {
      throw new Error('Valid justification reason (minimum 5 characters) is required to reveal historical password');
    }

    const hist = db.prepare(`
      SELECT h.*, d.hostname
      FROM laps_password_history h
      INNER JOIN devices d ON h.device_id = d.id
      WHERE h.id = ?
    `).get(historyId);

    if (!hist) {
      throw new Error(`Historical password record not found: ${historyId}`);
    }

    const decrypted = this.decryptPassword(hist.encrypted_password);

    // Record audit log
    const auditId = `laps-audit-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO laps_audit_logs (
        id, device_id, account_name, action, accessed_by, access_reason, ip_address, accessed_at
      ) VALUES (?, ?, ?, 'HISTORY_REVEAL', ?, ?, ?, DATETIME('now'))
    `).run(auditId, hist.device_id, hist.account_name, accessed_by, reason, ip_address);

    return {
      history_id: historyId,
      device_id: hist.device_id,
      hostname: hist.hostname,
      account_name: hist.account_name,
      password: decrypted,
      password_length: hist.password_length,
      complexity_level: hist.complexity_level,
      rotated_at: hist.rotated_at,
      retired_at: hist.retired_at,
      rotation_reason: hist.rotation_reason,
      audit_record_id: auditId,
      revealed_at: new Date().toISOString()
    };
  }

  /**
   * Queue an immediate on-demand password rotation command for a device.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {string} deviceId
   * @param {string} requestedBy
   * @returns {object}
   */
  queuePasswordRotation(db, deviceId, requestedBy = 'Administrator') {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) {
      throw new Error(`Device not found: ${deviceId}`);
    }

    const cmdId = `cmd-${crypto.randomUUID()}`;
    const commandText = 'Invoke-LapsRotation -Force';

    // Insert command
    db.prepare(`
      INSERT INTO device_commands (id, device_id, command_text, created_by, status)
      VALUES (?, ?, ?, ?, 'PENDING')
    `).run(cmdId, deviceId, commandText, requestedBy);

    // Mark password record as rotation pending
    db.prepare(`
      UPDATE laps_passwords
      SET rotation_status = 'ROTATION_PENDING', updated_at = DATETIME('now')
      WHERE device_id = ?
    `).run(deviceId);

    // Audit log
    const auditId = `laps-audit-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(`
      INSERT INTO laps_audit_logs (
        id, device_id, account_name, action, accessed_by, access_reason, ip_address, accessed_at
      ) VALUES (?, ?, 'Administrator', 'ROTATE_REQUEST', ?, 'Manual rotation command dispatched from console', '127.0.0.1', DATETIME('now'))
    `).run(auditId, deviceId, requestedBy);

    // Security event
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_source, severity, summary, raw_payload_json
        ) VALUES (?, 'LAPS_PASSWORD_ROTATED', 'LocalPilot LAPS Engine', 'INFO', ?, ?)
      `).run(
        deviceId,
        `Immediate LAPS password rotation dispatched to ${device.hostname} by ${requestedBy}`,
        JSON.stringify({ command_id: cmdId, requested_by: requestedBy })
      );
    } catch (_) {}

    return {
      command_id: cmdId,
      device_id: deviceId,
      hostname: device.hostname,
      status: 'ROTATION_PENDING',
      dispatched_at: new Date().toISOString()
    };
  }

  /**
   * Get fleet-wide LAPS metrics.
   * @param {import('node:sqlite').DatabaseSync} db
   * @returns {object}
   */
  getLapsStats(db) {
    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
    const passwords = db.prepare('SELECT * FROM laps_passwords').all();
    const totalAuditEvents = db.prepare('SELECT COUNT(*) as count FROM laps_audit_logs').get().count;
    const totalHistory = db.prepare('SELECT COUNT(*) as count FROM laps_password_history').get().count;
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM laps_policies WHERE is_enabled = 1').get().count;

    const now = new Date();
    let healthyCount = 0;
    let expiringSoonCount = 0;
    let expiredCount = 0;
    let rotationPendingCount = 0;

    for (const pw of passwords) {
      if (pw.rotation_status === 'ROTATION_PENDING') {
        rotationPendingCount++;
      }

      const expDate = new Date(pw.expires_at);
      const diffMs = expDate.getTime() - now.getTime();
      const daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

      if (daysRemaining <= 0 || pw.rotation_status === 'EXPIRED') {
        expiredCount++;
      } else if (daysRemaining <= 7) {
        expiringSoonCount++;
      } else {
        healthyCount++;
      }
    }

    const managedDevices = passwords.length;
    const coveragePercent = totalDevices > 0 ? Math.round((managedDevices / totalDevices) * 100) : 100;

    return {
      total_devices: totalDevices,
      managed_devices: managedDevices,
      unmanaged_devices: Math.max(0, totalDevices - managedDevices),
      coverage_percent: coveragePercent,
      healthy_passwords: healthyCount,
      expiring_soon_passwords: expiringSoonCount,
      expired_passwords: expiredCount,
      pending_rotations: rotationPendingCount,
      total_audit_events: totalAuditEvents,
      total_historical_passwords: totalHistory,
      active_policies_count: totalPolicies
    };
  }

  /**
   * Get LAPS audit logs.
   * @param {import('node:sqlite').DatabaseSync} db
   * @param {number} limit
   * @returns {Array<object>}
   */
  getAuditLogs(db, limit = 100) {
    return db.prepare(`
      SELECT l.*, d.hostname, d.friendly_name
      FROM laps_audit_logs l
      LEFT JOIN devices d ON l.device_id = d.id
      ORDER BY l.accessed_at DESC
      LIMIT ?
    `).all(limit);
  }
}

export const lapsEngine = new LapsEngine();
