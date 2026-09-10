/**
 * LocalPilot Fleet — Mobile Application Management (MAM) & App Protection Engine
 * server/src/services/mamAppProtectionEngine.js
 *
 * Implements enterprise-grade application containment, clipboard DLP sandboxing,
 * app-level biometric/PIN locks, offline grace period governance, and selective corporate wipe
 * matching Microsoft Intune MAM-WE and Jamf Protect for iOS, Android, and Windows.
 */

import crypto from 'node:crypto';

export class MamAppProtectionEngine {

  /**
   * Get fleet-wide MAM metrics and summary statistics
   */
  static getMamStats(db) {
    if (!db) return {};

    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM mam_app_protection_policies').get()?.count || 0;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM mam_app_protection_policies WHERE is_active = 1').get()?.count || 0;
    const totalApps = db.prepare('SELECT COUNT(*) as count FROM mam_managed_apps_catalog').get()?.count || 0;
    const enlightenedApps = db.prepare('SELECT COUNT(*) as count FROM mam_managed_apps_catalog WHERE is_enlightened = 1').get()?.count || 0;
    const totalWipes = db.prepare('SELECT COUNT(*) as count FROM mam_selective_wipe_requests').get()?.count || 0;
    const pendingWipes = db.prepare("SELECT COUNT(*) as count FROM mam_selective_wipe_requests WHERE status = 'PENDING'").get()?.count || 0;
    const completedWipes = db.prepare("SELECT COUNT(*) as count FROM mam_selective_wipe_requests WHERE status = 'COMPLETED'").get()?.count || 0;

    return {
      total_policies: totalPolicies,
      active_policies: activePolicies,
      total_managed_apps: totalApps,
      enlightened_apps: enlightenedApps,
      total_selective_wipes: totalWipes,
      pending_selective_wipes: pendingWipes,
      completed_selective_wipes: completedWipes,
      calculated_at: new Date().toISOString()
    };
  }

  /**
   * List all MAM App Protection Policies
   */
  static getPolicies(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM mam_app_protection_policies WHERE 1=1';
    const params = [];

    if (query.platform) {
      sql += " AND (platform = ? OR platform = 'COMBINED')";
      params.push(query.platform.toUpperCase());
    }

    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(Number(query.is_active));
    }

    sql += ' ORDER BY created_at DESC';
    const policies = db.prepare(sql).all(...params);

    return policies.map(p => {
      const apps = db.prepare('SELECT COUNT(*) as count FROM mam_managed_apps_catalog WHERE policy_id = ?').get(p.id)?.count || 0;
      return {
        ...p,
        prevent_save_as: Boolean(p.prevent_save_as),
        prevent_screen_capture: Boolean(p.prevent_screen_capture),
        require_pin_or_biometrics: Boolean(p.require_pin_or_biometrics),
        block_jailbroken_rooted: Boolean(p.block_jailbroken_rooted),
        is_active: Boolean(p.is_active),
        assigned_apps_count: apps
      };
    });
  }

  /**
   * Retrieve single MAM Policy with detailed managed apps
   */
  static getPolicy(db, id) {
    if (!db || !id) return null;

    const policy = db.prepare('SELECT * FROM mam_app_protection_policies WHERE id = ?').get(id);
    if (!policy) return null;

    const apps = db.prepare('SELECT * FROM mam_managed_apps_catalog WHERE policy_id = ? ORDER BY app_name ASC').all(id);

    return {
      ...policy,
      prevent_save_as: Boolean(policy.prevent_save_as),
      prevent_screen_capture: Boolean(policy.prevent_screen_capture),
      require_pin_or_biometrics: Boolean(policy.require_pin_or_biometrics),
      block_jailbroken_rooted: Boolean(policy.block_jailbroken_rooted),
      is_active: Boolean(policy.is_active),
      apps: apps.map(a => ({
        ...a,
        is_enlightened: Boolean(a.is_enlightened),
        is_blocked: Boolean(a.is_blocked)
      }))
    };
  }

  /**
   * Create new MAM App Protection Policy
   */
  static createPolicy(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.name) throw new Error('Policy name is required');

    const id = data.id || ('mam-pol-' + crypto.randomBytes(4).toString('hex'));
    const platform = (data.platform || 'COMBINED').toUpperCase();
    const storageMode = data.allowed_data_storage || 'MANAGED_STORAGE_ONLY';
    const clipboardMode = data.clipboard_sharing_mode || 'POLICY_MANAGED_APPS_ONLY';

    const stmt = db.prepare(`
      INSERT INTO mam_app_protection_policies (
        id, name, description, platform, allowed_data_storage, prevent_save_as,
        clipboard_sharing_mode, prevent_screen_capture, require_pin_or_biometrics,
        min_pin_length, max_offline_grace_minutes, block_jailbroken_rooted, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.description || 'Enterprise mobile application data containment policy',
      platform,
      storageMode,
      data.prevent_save_as !== undefined ? (data.prevent_save_as ? 1 : 0) : 1,
      clipboardMode,
      data.prevent_screen_capture !== undefined ? (data.prevent_screen_capture ? 1 : 0) : 1,
      data.require_pin_or_biometrics !== undefined ? (data.require_pin_or_biometrics ? 1 : 0) : 1,
      Number(data.min_pin_length) || 6,
      Number(data.max_offline_grace_minutes) || 720,
      data.block_jailbroken_rooted !== undefined ? (data.block_jailbroken_rooted ? 1 : 0) : 1,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return this.getPolicy(db, id);
  }

  /**
   * Update existing MAM App Protection Policy
   */
  static updatePolicy(db, id, data = {}) {
    if (!db || !id) throw new Error('Valid database and policy ID required');

    const existing = db.prepare('SELECT * FROM mam_app_protection_policies WHERE id = ?').get(id);
    if (!existing) throw new Error(`MAM Policy ${id} not found`);

    const stmt = db.prepare(`
      UPDATE mam_app_protection_policies SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        platform = COALESCE(?, platform),
        allowed_data_storage = COALESCE(?, allowed_data_storage),
        prevent_save_as = COALESCE(?, prevent_save_as),
        clipboard_sharing_mode = COALESCE(?, clipboard_sharing_mode),
        prevent_screen_capture = COALESCE(?, prevent_screen_capture),
        require_pin_or_biometrics = COALESCE(?, require_pin_or_biometrics),
        min_pin_length = COALESCE(?, min_pin_length),
        max_offline_grace_minutes = COALESCE(?, max_offline_grace_minutes),
        block_jailbroken_rooted = COALESCE(?, block_jailbroken_rooted),
        is_active = COALESCE(?, is_active),
        updated_at = DATETIME('now')
      WHERE id = ?
    `);

    stmt.run(
      data.name || null,
      data.description || null,
      data.platform ? data.platform.toUpperCase() : null,
      data.allowed_data_storage || null,
      data.prevent_save_as !== undefined ? (data.prevent_save_as ? 1 : 0) : null,
      data.clipboard_sharing_mode || null,
      data.prevent_screen_capture !== undefined ? (data.prevent_screen_capture ? 1 : 0) : null,
      data.require_pin_or_biometrics !== undefined ? (data.require_pin_or_biometrics ? 1 : 0) : null,
      data.min_pin_length !== undefined ? Number(data.min_pin_length) : null,
      data.max_offline_grace_minutes !== undefined ? Number(data.max_offline_grace_minutes) : null,
      data.block_jailbroken_rooted !== undefined ? (data.block_jailbroken_rooted ? 1 : 0) : null,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : null,
      id
    );

    return this.getPolicy(db, id);
  }

  /**
   * Delete MAM App Protection Policy
   */
  static deletePolicy(db, id) {
    if (!db || !id) return false;
    const res = db.prepare('DELETE FROM mam_app_protection_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * List Managed Corporate Apps Catalog
   */
  static getManagedApps(db, query = {}) {
    if (!db) return [];

    let sql = `
      SELECT a.*, p.name as policy_name, p.clipboard_sharing_mode
      FROM mam_managed_apps_catalog a
      JOIN mam_app_protection_policies p ON a.policy_id = p.id
      WHERE 1=1
    `;
    const params = [];

    if (query.policy_id) {
      sql += ' AND a.policy_id = ?';
      params.push(query.policy_id);
    }

    if (query.platform) {
      sql += " AND (a.platform = ? OR a.platform = 'COMBINED')";
      params.push(query.platform.toUpperCase());
    }

    if (query.bundle_id) {
      sql += ' AND a.bundle_id = ?';
      params.push(query.bundle_id);
    }

    sql += ' ORDER BY a.app_name ASC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => ({
      ...r,
      is_enlightened: Boolean(r.is_enlightened),
      is_blocked: Boolean(r.is_blocked)
    }));
  }

  /**
   * Register App in MAM Catalog
   */
  static registerManagedApp(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.policy_id) throw new Error('policy_id is required');
    if (!data.app_name) throw new Error('app_name is required');
    if (!data.bundle_id) throw new Error('bundle_id is required');

    const id = data.id || ('mam-app-' + crypto.randomBytes(4).toString('hex'));
    const platform = (data.platform || 'IOS').toUpperCase();

    const stmt = db.prepare(`
      INSERT INTO mam_managed_apps_catalog (
        id, policy_id, app_name, bundle_id, platform, is_enlightened, min_app_version, is_blocked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.policy_id,
      data.app_name,
      data.bundle_id,
      platform,
      data.is_enlightened !== undefined ? (data.is_enlightened ? 1 : 0) : 1,
      data.min_app_version || '1.0.0',
      data.is_blocked !== undefined ? (data.is_blocked ? 1 : 0) : 0
    );

    return db.prepare('SELECT * FROM mam_managed_apps_catalog WHERE id = ?').get(id);
  }

  /**
   * Delete Managed App from Catalog
   */
  static deleteManagedApp(db, id) {
    if (!db || !id) return false;
    const res = db.prepare('DELETE FROM mam_managed_apps_catalog WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * List Selective Wipe Requests
   */
  static getSelectiveWipes(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM mam_selective_wipe_requests WHERE 1=1';
    const params = [];

    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status.toUpperCase());
    }

    if (query.user_email) {
      sql += ' AND target_user_email = ?';
      params.push(query.user_email.toLowerCase());
    }

    sql += ' ORDER BY issued_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Issue Selective Corporate Wipe Request (without touching personal photos/apps)
   */
  static requestSelectiveWipe(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.target_user_email) throw new Error('target_user_email is required');

    const id = data.id || ('wipe-' + crypto.randomBytes(4).toString('hex'));
    const userEmail = data.target_user_email.toLowerCase().trim();
    const reason = data.wipe_reason || 'ADMIN_REQUEST';

    const stmt = db.prepare(`
      INSERT INTO mam_selective_wipe_requests (
        id, target_user_email, target_device_id, wipe_reason, status, issued_by, details_json
      ) VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
    `);

    stmt.run(
      id,
      userEmail,
      data.target_device_id || null,
      reason,
      data.issued_by || 'Enterprise MAM Administrator',
      JSON.stringify(data.details || {})
    );

    return db.prepare('SELECT * FROM mam_selective_wipe_requests WHERE id = ?').get(id);
  }

  /**
   * Cancel pending Selective Wipe Request
   */
  static cancelSelectiveWipe(db, id) {
    if (!db || !id) return false;
    const res = db.prepare("UPDATE mam_selective_wipe_requests SET status = 'CANCELLED' WHERE id = ? AND status = 'PENDING'").run(id);
    return res.changes > 0;
  }

  /**
   * Complete Selective Wipe Request (called when client SDK wipes corporate container)
   */
  static completeSelectiveWipe(db, id, result = {}) {
    if (!db || !id) return false;

    const stmt = db.prepare(`
      UPDATE mam_selective_wipe_requests SET
        status = 'COMPLETED',
        completed_at = DATETIME('now'),
        details_json = ?
      WHERE id = ?
    `);

    const res = stmt.run(JSON.stringify(result || {}), id);
    return res.changes > 0;
  }

  /**
   * Query pending selective wipe orders for an endpoint or user account
   */
  static getPendingWipesForNodeOrUser(db, { userEmail, deviceId }) {
    if (!db) return [];

    let sql = "SELECT * FROM mam_selective_wipe_requests WHERE status = 'PENDING' AND (";
    const conditions = [];
    const params = [];

    if (userEmail) {
      conditions.push('target_user_email = ?');
      params.push(userEmail.toLowerCase().trim());
    }

    if (deviceId) {
      conditions.push('target_device_id = ?');
      params.push(deviceId);
    }

    if (conditions.length === 0) return [];

    sql += conditions.join(' OR ') + ')';
    return db.prepare(sql).all(...params);
  }

  /**
   * Evaluate App Posture against MAM Protection Policies
   */
  static evaluateAppCompliance(db, telemetry = {}) {
    if (!db) throw new Error('Database handle required');

    const {
      bundle_id,
      platform = 'IOS',
      is_jailbroken = false,
      is_rooted = false,
      offline_minutes = 0,
      app_version = '1.0.0',
      user_email
    } = telemetry;

    const violations = [];
    let action = 'ALLOW';

    // 1. Check for Pending Selective Wipe Orders
    if (user_email) {
      const pendingWipes = this.getPendingWipesForNodeOrUser(db, { userEmail: user_email, deviceId: telemetry.device_id });
      if (pendingWipes.length > 0) {
        return {
          compliant: false,
          action: 'WIPE',
          reason: 'PENDING_SELECTIVE_WIPE',
          wipe_requests: pendingWipes,
          violations: ['Corporate account marked for immediate selective wipe']
        };
      }
    }

    // 2. Lookup Managed App Catalog & Attached Policy
    let appRecord = null;
    if (bundle_id) {
      appRecord = db.prepare(`
        SELECT a.*, p.name as policy_name, p.block_jailbroken_rooted, p.max_offline_grace_minutes,
               p.require_pin_or_biometrics, p.min_pin_length, p.clipboard_sharing_mode, p.prevent_save_as
        FROM mam_managed_apps_catalog a
        JOIN mam_app_protection_policies p ON a.policy_id = p.id
        WHERE a.bundle_id = ? AND p.is_active = 1
      `).get(bundle_id);
    }

    if (!appRecord) {
      // Unmanaged / unknown app
      return {
        compliant: false,
        action: 'BLOCK',
        reason: 'UNMANAGED_APPLICATION',
        violations: [`Application ${bundle_id || 'unknown'} is not registered in corporate MAM catalog`]
      };
    }

    if (appRecord.is_blocked) {
      return {
        compliant: false,
        action: 'BLOCK',
        reason: 'APP_EXPLICITLY_BLOCKED',
        violations: [`Application ${appRecord.app_name} is explicitly blocked by enterprise policy`]
      };
    }

    // 3. Jailbreak / Root detection
    if ((is_jailbroken || is_rooted) && appRecord.block_jailbroken_rooted) {
      violations.push('Device is jailbroken/rooted: zero-trust integrity failure');
      action = 'WIPE';
    }

    // 4. Offline Grace Period check
    if (offline_minutes > appRecord.max_offline_grace_minutes) {
      violations.push(`Maximum offline grace period exceeded (${offline_minutes}m > ${appRecord.max_offline_grace_minutes}m)`);
      if (action !== 'WIPE') action = 'BLOCK';
    }

    // 5. Version check
    if (appRecord.min_app_version && this.compareVersions(app_version, appRecord.min_app_version) < 0) {
      violations.push(`App version ${app_version} is below required minimum ${appRecord.min_app_version}`);
      if (action !== 'WIPE') action = 'BLOCK';
    }

    // 6. Access requirements
    const pinRequired = Boolean(appRecord.require_pin_or_biometrics);

    const isCompliant = violations.length === 0;

    return {
      compliant: isCompliant,
      action: isCompliant ? (pinRequired ? 'PIN_REQUIRED' : 'ALLOW') : action,
      policy_id: appRecord.policy_id,
      policy_name: appRecord.policy_name,
      app_name: appRecord.app_name,
      clipboard_sharing_mode: appRecord.clipboard_sharing_mode,
      prevent_save_as: Boolean(appRecord.prevent_save_as),
      require_pin_or_biometrics: pinRequired,
      min_pin_length: appRecord.min_pin_length,
      violations
    };
  }

  /**
   * Helper: Semver comparison
   */
  static compareVersions(v1, v2) {
    const parts1 = (v1 || '0').split('.').map(n => parseInt(n, 10) || 0);
    const parts2 = (v2 || '0').split('.').map(n => parseInt(n, 10) || 0);
    const maxLen = Math.max(parts1.length, parts2.length);

    for (let i = 0; i < maxLen; i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;
      if (p1 > p2) return 1;
      if (p1 < p2) return -1;
    }
    return 0;
  }

  /**
   * Generate MAM SDK client configuration JSON payload
   */
  static generateMamClientConfig(db, policyId) {
    const policy = this.getPolicy(db, policyId);
    if (!policy) return null;

    return {
      mam_schema_version: '2.0-localpilot',
      policy_id: policy.id,
      policy_name: policy.name,
      target_platform: policy.platform,
      data_protection: {
        allowed_data_storage: policy.allowed_data_storage,
        prevent_save_as: policy.prevent_save_as,
        clipboard_sharing_mode: policy.clipboard_sharing_mode,
        prevent_screen_capture: policy.prevent_screen_capture
      },
      access_control: {
        require_pin_or_biometrics: policy.require_pin_or_biometrics,
        min_pin_length: policy.min_pin_length,
        max_offline_grace_minutes: policy.max_offline_grace_minutes,
        block_jailbroken_rooted: policy.block_jailbroken_rooted
      },
      managed_apps: (policy.apps || []).map(a => ({
        app_name: a.app_name,
        bundle_id: a.bundle_id,
        min_app_version: a.min_app_version,
        is_blocked: a.is_blocked
      })),
      generated_at: new Date().toISOString()
    };
  }
}
