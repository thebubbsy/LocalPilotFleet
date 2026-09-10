/**
 * LocalPilot Fleet — Cloud App Discovery & Shadow SaaS Governance Engine (Endpoint CASB)
 * server/src/services/cloudAppDiscoveryEngine.js
 *
 * Implements Microsoft Defender for Cloud Apps (MDCA) & Intune Cloud App Security equivalent
 * shadow IT discovery, SaaS application risk rating (0-100), sanctioned/unsanctioned governance,
 * endpoint cloud usage telemetry aggregation, and automated access blocking policies.
 */

import crypto from 'node:crypto';

export class CloudAppDiscoveryEngine {
  /**
   * Aggregate fleet-wide Cloud App Discovery and Shadow IT metrics
   */
  static getCloudAppStats(db) {
    const totalApps = db.prepare('SELECT COUNT(*) as count FROM cloud_app_catalog').get()?.count || 0;
    const sanctionedApps = db.prepare("SELECT COUNT(*) as count FROM cloud_app_catalog WHERE sanctioned_status = 'SANCTIONED'").get()?.count || 0;
    const unsanctionedApps = db.prepare("SELECT COUNT(*) as count FROM cloud_app_catalog WHERE sanctioned_status = 'UNSANCTIONED'").get()?.count || 0;
    const monitoredApps = db.prepare("SELECT COUNT(*) as count FROM cloud_app_catalog WHERE sanctioned_status = 'MONITORED'").get()?.count || 0;

    const totalBytesRow = db.prepare('SELECT SUM(total_bytes_transferred) as totalBytes FROM cloud_app_catalog').get();
    const totalBytesTransferred = totalBytesRow?.totalBytes || 0;

    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM cloud_app_access_policies WHERE is_active = 1').get()?.count || 0;
    const totalTelemetryEvents = db.prepare('SELECT COUNT(*) as count FROM endpoint_cloud_usage_telemetry').get()?.count || 0;

    return {
      totalApps,
      sanctionedApps,
      unsanctionedApps,
      monitoredApps,
      totalBytesTransferred,
      activePolicies,
      totalTelemetryEvents,
      cloudDiscoveryOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve cloud applications catalog
   */
  static getCatalog(db, query = {}) {
    let sql = 'SELECT * FROM cloud_app_catalog WHERE 1=1';
    const params = [];

    if (query.category) {
      sql += ' AND category = ?';
      params.push(query.category);
    }
    if (query.sanctioned_status) {
      sql += ' AND sanctioned_status = ?';
      params.push(query.sanctioned_status);
    }
    if (query.min_risk) {
      sql += ' AND risk_score >= ?';
      params.push(parseInt(query.min_risk, 10));
    }

    sql += ' ORDER BY total_bytes_transferred DESC, risk_score DESC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => {
      let compliance = [];
      try { compliance = JSON.parse(r.compliance_certifications || '[]'); } catch {}
      return { ...r, compliance_certifications: compliance };
    });
  }

  /**
   * Retrieve single cloud application
   */
  static getAppById(db, id) {
    const app = db.prepare('SELECT * FROM cloud_app_catalog WHERE id = ?').get(id);
    if (!app) return null;

    let compliance = [];
    try { compliance = JSON.parse(app.compliance_certifications || '[]'); } catch {}

    const usage = db.prepare('SELECT * FROM endpoint_cloud_usage_telemetry WHERE app_id = ? ORDER BY last_observed_at DESC LIMIT 50').all(id);

    return {
      ...app,
      compliance_certifications: compliance,
      usage_telemetry: usage
    };
  }

  /**
   * Create cloud application in catalog
   */
  static createApp(db, data) {
    const id = data.id || ('cac-' + crypto.randomBytes(4).toString('hex'));
    const compliance = typeof data.compliance_certifications === 'string' ?
      data.compliance_certifications : JSON.stringify(data.compliance_certifications || []);

    const stmt = db.prepare(`
      INSERT INTO cloud_app_catalog (
        id, app_name, category, domain_name, description, risk_score, sanctioned_status,
        compliance_certifications, total_users_count, total_bytes_transferred
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.app_name,
      data.category || 'COLLABORATION',
      data.domain_name.toLowerCase(),
      data.description || '',
      data.risk_score !== undefined ? data.risk_score : 50,
      data.sanctioned_status || 'MONITORED',
      compliance,
      data.total_users_count || 0,
      data.total_bytes_transferred || 0
    );

    return this.getAppById(db, id);
  }

  /**
   * Update cloud application
   */
  static updateApp(db, id, data) {
    const existing = db.prepare('SELECT * FROM cloud_app_catalog WHERE id = ?').get(id);
    if (!existing) return null;

    const compliance = data.compliance_certifications !== undefined ? (
      typeof data.compliance_certifications === 'string' ?
        data.compliance_certifications : JSON.stringify(data.compliance_certifications)
    ) : existing.compliance_certifications;

    const updated = {
      app_name: data.app_name !== undefined ? data.app_name : existing.app_name,
      category: data.category !== undefined ? data.category : existing.category,
      domain_name: data.domain_name !== undefined ? data.domain_name.toLowerCase() : existing.domain_name,
      description: data.description !== undefined ? data.description : existing.description,
      risk_score: data.risk_score !== undefined ? data.risk_score : existing.risk_score,
      sanctioned_status: data.sanctioned_status !== undefined ? data.sanctioned_status : existing.sanctioned_status
    };

    db.prepare(`
      UPDATE cloud_app_catalog SET
        app_name = ?, category = ?, domain_name = ?, description = ?, risk_score = ?,
        sanctioned_status = ?, compliance_certifications = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      updated.app_name, updated.category, updated.domain_name, updated.description,
      updated.risk_score, updated.sanctioned_status, compliance, id
    );

    return this.getAppById(db, id);
  }

  /**
   * Delete cloud application
   */
  static deleteApp(db, id) {
    const existing = db.prepare('SELECT id FROM cloud_app_catalog WHERE id = ?').get(id);
    if (!existing) return false;

    db.prepare('DELETE FROM endpoint_cloud_usage_telemetry WHERE app_id = ?').run(id);
    db.prepare('DELETE FROM cloud_app_access_policies WHERE app_id = ?').run(id);
    db.prepare('DELETE FROM cloud_app_catalog WHERE id = ?').run(id);
    return true;
  }

  /**
   * Update sanction status (SANCTIONED, UNSANCTIONED, MONITORED)
   */
  static updateSanctionStatus(db, id, sanctionedStatus) {
    const existing = db.prepare('SELECT id FROM cloud_app_catalog WHERE id = ?').get(id);
    if (!existing) return null;

    db.prepare(`
      UPDATE cloud_app_catalog SET
        sanctioned_status = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(sanctionedStatus, id);

    return this.getAppById(db, id);
  }

  /**
   * Retrieve endpoint cloud usage telemetry
   */
  static getUsageTelemetry(db, query = {}) {
    let sql = 'SELECT * FROM endpoint_cloud_usage_telemetry WHERE 1=1';
    const params = [];

    if (query.app_id) {
      sql += ' AND app_id = ?';
      params.push(query.app_id);
    }
    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.user_principal) {
      sql += ' AND user_principal = ?';
      params.push(query.user_principal);
    }

    sql += ' ORDER BY last_observed_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Record endpoint cloud usage telemetry and update cumulative metrics
   */
  static recordUsageTelemetry(db, data) {
    const id = data.id || ('ecut-' + crypto.randomBytes(4).toString('hex'));
    const bytesUp = data.bytes_uploaded || 0;
    const bytesDown = data.bytes_downloaded || 0;
    const totalNewBytes = bytesUp + bytesDown;

    const stmt = db.prepare(`
      INSERT INTO endpoint_cloud_usage_telemetry (
        id, app_id, app_name, device_id, hostname, user_principal,
        bytes_uploaded, bytes_downloaded, session_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.app_id,
      data.app_name,
      data.device_id,
      data.hostname,
      data.user_principal.toLowerCase(),
      bytesUp,
      bytesDown,
      data.session_count || 1
    );

    // Update cumulative app stats
    db.prepare(`
      UPDATE cloud_app_catalog SET
        total_bytes_transferred = total_bytes_transferred + ?,
        total_users_count = (SELECT COUNT(DISTINCT user_principal) FROM endpoint_cloud_usage_telemetry WHERE app_id = ?),
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(totalNewBytes, data.app_id, data.app_id);

    return db.prepare('SELECT * FROM endpoint_cloud_usage_telemetry WHERE id = ?').get(id);
  }

  /**
   * Retrieve cloud app access policies
   */
  static getAccessPolicies(db, query = {}) {
    let sql = 'SELECT p.*, a.domain_name, a.sanctioned_status FROM cloud_app_access_policies p LEFT JOIN cloud_app_catalog a ON p.app_id = a.id WHERE 1=1';
    const params = [];

    if (query.enforcement_action) {
      sql += ' AND p.enforcement_action = ?';
      params.push(query.enforcement_action);
    }
    if (query.is_active !== undefined) {
      sql += ' AND p.is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    sql += ' ORDER BY p.created_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Create cloud app access policy
   */
  static createAccessPolicy(db, data) {
    const id = data.id || ('caap-' + crypto.randomBytes(4).toString('hex'));
    const stmt = db.prepare(`
      INSERT INTO cloud_app_access_policies (
        id, name, target_scope, target_id, app_id, category_filter, enforcement_action, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.app_id || null,
      data.category_filter || null,
      data.enforcement_action || 'BLOCK',
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return db.prepare('SELECT * FROM cloud_app_access_policies WHERE id = ?').get(id);
  }

  /**
   * Delete cloud app access policy
   */
  static deleteAccessPolicy(db, id) {
    const res = db.prepare('DELETE FROM cloud_app_access_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Generate unsanctioned domain blocklist for endpoint network protection
   */
  static generateBlocklist(db) {
    // Collect all apps marked as UNSANCTIONED or targeted by an active BLOCK policy
    const rows = db.prepare(`
      SELECT DISTINCT c.domain_name, c.app_name, c.risk_score
      FROM cloud_app_catalog c
      LEFT JOIN cloud_app_access_policies p ON c.id = p.app_id
      WHERE c.sanctioned_status = 'UNSANCTIONED' OR (p.enforcement_action = 'BLOCK' AND p.is_active = 1)
    `).all();

    return {
      total_blocked_domains: rows.length,
      domains: rows.map(r => r.domain_name),
      blocked_apps: rows,
      generated_at: new Date().toISOString()
    };
  }
}
