/**
 * LocalPilot Fleet — Apple Declarative Device Management (DDM) Engine (Iteration 70)
 * server/src/services/declarativeDeviceManagementEngine.js
 *
 * Implements Apple Declarative Device Management (DDM) protocol (macOS 13+, iOS 15+),
 * autonomous client-side predicate evaluation, declaration items manifest generation,
 * composite sync token calculation, status channel telemetry ingestion, and
 * self-healing compliance tracking.
 */

import crypto from 'node:crypto';

export class DeclarativeDeviceManagementEngine {
  /**
   * Aggregate DDM Fleet KPIs & Telemetry
   */
  static getDdmStats(db) {
    if (!db) return null;

    const totalDecs = db.prepare("SELECT count(1) as c FROM ddm_declarations").get().c;
    const activeDecs = db.prepare("SELECT count(1) as c FROM ddm_declarations WHERE is_active = 1").get().c;
    const totalManifests = db.prepare("SELECT count(1) as c FROM ddm_device_manifests").get().c;
    const syncedManifests = db.prepare("SELECT count(1) as c FROM ddm_device_manifests WHERE sync_status = 'SYNCHRONIZED'").get().c;
    const totalReports = db.prepare("SELECT count(1) as c FROM ddm_status_reports").get().c;

    const uniqueDevices = db.prepare("SELECT count(DISTINCT device_id) as c FROM ddm_device_manifests").get().c;

    const typeRows = db.prepare(`
      SELECT declaration_type, count(1) as count 
      FROM ddm_declarations 
      GROUP BY declaration_type
    `).all();

    const byType = {
      configuration: 0,
      activation: 0,
      asset: 0,
      management: 0
    };
    for (const r of typeRows) {
      if (r.declaration_type in byType) {
        byType[r.declaration_type] = r.count;
      }
    }

    return {
      total_declarations: totalDecs,
      active_declarations: activeDecs,
      total_manifests: totalManifests,
      synchronized_manifests: syncedManifests,
      enrolled_ddm_devices: uniqueDevices,
      total_status_reports: totalReports,
      by_type: byType
    };
  }

  /**
   * List Declarations with Filtering
   */
  static getDeclarations(db, filter = {}) {
    if (!db) return [];

    let query = "SELECT * FROM ddm_declarations WHERE 1=1";
    const params = [];

    if (filter.declaration_type) {
      query += " AND declaration_type = ?";
      params.push(filter.declaration_type.toLowerCase());
    }

    if (filter.is_active !== undefined) {
      query += " AND is_active = ?";
      params.push(filter.is_active ? 1 : 0);
    }

    query += " ORDER BY created_at DESC";

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      payload: typeof r.payload_json === 'string' ? JSON.parse(r.payload_json || '{}') : (r.payload_json || {})
    }));
  }

  /**
   * Get Single Declaration by ID or Reverse-DNS Identifier
   */
  static getDeclaration(db, idOrIdentifier) {
    if (!db || !idOrIdentifier) return null;

    const row = db.prepare(`
      SELECT * FROM ddm_declarations 
      WHERE id = ? OR identifier = ?
    `).get(idOrIdentifier, idOrIdentifier);

    if (!row) return null;

    return {
      ...row,
      payload: typeof row.payload_json === 'string' ? JSON.parse(row.payload_json || '{}') : (row.payload_json || {})
    };
  }

  /**
   * Create or Update a Declaration Item
   */
  static createDeclaration(db, data) {
    if (!db || !data) throw new Error('Database and declaration data required');
    if (!data.declaration_type || !data.identifier) {
      throw new Error('declaration_type and identifier are required');
    }

    const type = data.declaration_type.toLowerCase();
    const validTypes = ['configuration', 'activation', 'asset', 'management'];
    if (!validTypes.includes(type)) {
      throw new Error(`Invalid declaration_type. Must be one of: ${validTypes.join(', ')}`);
    }

    const id = data.id || ('ddm-dec-' + crypto.randomBytes(4).toString('hex'));
    const payloadObj = typeof data.payload === 'object' 
      ? data.payload 
      : (typeof data.payload_json === 'object' ? data.payload_json : JSON.parse(data.payload_json || '{}'));
    
    const payloadJson = JSON.stringify(payloadObj);
    const serverToken = crypto.createHash('sha256').update(data.identifier + ':' + payloadJson).digest('hex').slice(0, 32);
    const isActive = data.is_active === undefined ? 1 : (data.is_active ? 1 : 0);

    const stmt = db.prepare(`
      INSERT INTO ddm_declarations (
        id, declaration_type, identifier, server_token, payload_json, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
      ON CONFLICT(identifier) DO UPDATE SET
        declaration_type = excluded.declaration_type,
        server_token = excluded.server_token,
        payload_json = excluded.payload_json,
        is_active = excluded.is_active,
        updated_at = DATETIME('now')
    `);

    stmt.run(id, type, data.identifier, serverToken, payloadJson, isActive);
    return this.getDeclaration(db, data.identifier);
  }

  /**
   * Delete Declaration
   */
  static deleteDeclaration(db, id) {
    if (!db || !id) return false;

    const row = this.getDeclaration(db, id);
    if (!row) return false;

    db.prepare("DELETE FROM ddm_declarations WHERE id = ?").run(row.id);
    return true;
  }

  /**
   * Query Device Manifests (Assignments)
   */
  static getManifests(db, filter = {}) {
    if (!db) return [];

    let query = `
      SELECT m.*, d.declaration_type, d.identifier, d.server_token as latest_server_token, d.is_active
      FROM ddm_device_manifests m
      JOIN ddm_declarations d ON m.declaration_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (filter.device_id) {
      query += " AND m.device_id = ?";
      params.push(filter.device_id);
    }

    if (filter.sync_status) {
      query += " AND m.sync_status = ?";
      params.push(filter.sync_status);
    }

    query += " ORDER BY m.last_synced_at DESC";

    return db.prepare(query).all(...params);
  }

  /**
   * Assign Declaration to Device
   */
  static assignDeclarationToDevice(db, deviceId, declarationId) {
    if (!db || !deviceId || !declarationId) throw new Error('deviceId and declarationId required');

    const dec = this.getDeclaration(db, declarationId);
    if (!dec) throw new Error(`Declaration ${declarationId} not found`);

    const id = 'ddm-man-' + crypto.randomBytes(4).toString('hex');

    const existing = db.prepare(`
      SELECT id FROM ddm_device_manifests 
      WHERE device_id = ? AND declaration_id = ?
    `).get(deviceId, dec.id);

    if (existing) {
      db.prepare(`
        UPDATE ddm_device_manifests 
        SET sync_status = 'PENDING', last_synced_at = DATETIME('now')
        WHERE id = ?
      `).run(existing.id);
      return { id: existing.id, device_id: deviceId, declaration_id: dec.id, sync_status: 'PENDING' };
    }

    db.prepare(`
      INSERT INTO ddm_device_manifests (
        id, device_id, declaration_id, sync_status, applied_server_token, last_synced_at
      ) VALUES (?, ?, ?, 'PENDING', NULL, DATETIME('now'))
    `).run(id, deviceId, dec.id);

    return { id, device_id: deviceId, declaration_id: dec.id, sync_status: 'PENDING' };
  }

  /**
   * Unassign Declaration from Device
   */
  static unassignDeclaration(db, manifestId) {
    if (!db || !manifestId) return false;

    const res = db.prepare("DELETE FROM ddm_device_manifests WHERE id = ?").run(manifestId);
    return res.changes > 0;
  }

  /**
   * Calculate Composite Tokens for RFC DDM /tokens endpoint
   */
  static getDeviceTokens(db, deviceId) {
    if (!db || !deviceId) return null;

    const manifests = db.prepare(`
      SELECT d.identifier, d.server_token 
      FROM ddm_device_manifests m
      JOIN ddm_declarations d ON m.declaration_id = d.id
      WHERE m.device_id = ? AND d.is_active = 1
      ORDER BY d.identifier ASC
    `).all(deviceId);

    const raw = manifests.map(m => `${m.identifier}:${m.server_token}`).join('|');
    const compositeToken = crypto.createHash('sha256').update(raw || 'empty').digest('hex').slice(0, 32);

    return {
      SyncTokens: {
        DeclarationsToken: compositeToken,
        Timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Generate RFC Apple DDM Declaration Items Manifest for /declaration-items
   */
  static getDeviceDeclarationItemsManifest(db, deviceId) {
    if (!db || !deviceId) return null;

    const manifests = db.prepare(`
      SELECT d.declaration_type, d.identifier, d.server_token 
      FROM ddm_device_manifests m
      JOIN ddm_declarations d ON m.declaration_id = d.id
      WHERE m.device_id = ? AND d.is_active = 1
      ORDER BY d.identifier ASC
    `).all(deviceId);

    const activations = [];
    const configurations = [];
    const assets = [];
    const management = [];
    const allIdentifiers = [];

    for (const item of manifests) {
      const entry = {
        Identifier: item.identifier,
        ServerToken: item.server_token
      };
      allIdentifiers.push(item.identifier);

      if (item.declaration_type === 'activation') activations.push(entry);
      else if (item.declaration_type === 'configuration') configurations.push(entry);
      else if (item.declaration_type === 'asset') assets.push(entry);
      else if (item.declaration_type === 'management') management.push(entry);
    }

    const tokens = this.getDeviceTokens(db, deviceId);

    return {
      Declarations: {
        Activations: activations,
        Configurations: configurations,
        Assets: assets,
        Management: management
      },
      DeclarationIdentifiers: allIdentifiers,
      SyncTokens: tokens.SyncTokens
    };
  }

  /**
   * Ingest Status Channel Telemetry (RFC DDM /status endpoint)
   */
  static ingestStatusReport(db, deviceId, payload) {
    if (!db || !deviceId) throw new Error('deviceId and status payload required');

    const statusItems = [];
    const timestamp = new Date().toISOString();

    // Payload can be structured as { StatusItems: { "key": value } } or direct dictionary
    const itemsMap = payload?.StatusItems || payload?.status_items || payload || {};

    for (const [key, value] of Object.entries(itemsMap)) {
      if (typeof key === 'string' && key !== 'StatusItems' && key !== 'status_items') {
        const id = 'ddm-stat-' + crypto.randomBytes(4).toString('hex');
        const valJson = typeof value === 'object' ? JSON.stringify(value) : JSON.stringify({ value });

        db.prepare(`
          INSERT INTO ddm_status_reports (
            id, device_id, status_key, status_value_json, received_at
          ) VALUES (?, ?, ?, ?, DATETIME('now'))
        `).run(id, deviceId, key, valJson);

        statusItems.push({ id, status_key: key, status_value: value });

        // If client reports active declarations, reconcile manifest sync_status to SYNCHRONIZED
        if (key === 'management.declarations.active' && Array.isArray(value)) {
          for (const activeItem of value) {
            const ident = typeof activeItem === 'string' ? activeItem : activeItem.identifier;
            if (ident) {
              const dec = this.getDeclaration(db, ident);
              if (dec) {
                db.prepare(`
                  UPDATE ddm_device_manifests 
                  SET sync_status = 'SYNCHRONIZED', applied_server_token = ?, last_synced_at = DATETIME('now')
                  WHERE device_id = ? AND declaration_id = ?
                `).run(dec.server_token, deviceId, dec.id);
              }
            }
          }
        }
      }
    }

    return {
      device_id: deviceId,
      ingested_count: statusItems.length,
      items: statusItems,
      timestamp
    };
  }

  /**
   * List Status Reports
   */
  static getStatusReports(db, filter = {}) {
    if (!db) return [];

    let query = "SELECT * FROM ddm_status_reports WHERE 1=1";
    const params = [];

    if (filter.device_id) {
      query += " AND device_id = ?";
      params.push(filter.device_id);
    }

    if (filter.status_key) {
      query += " AND status_key LIKE ?";
      params.push(`%${filter.status_key}%`);
    }

    query += " ORDER BY received_at DESC";

    if (filter.limit) {
      query += " LIMIT ?";
      params.push(parseInt(filter.limit, 10) || 50);
    } else {
      query += " LIMIT 100";
    }

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      value: typeof r.status_value_json === 'string' ? JSON.parse(r.status_value_json || '{}') : (r.status_value_json || {})
    }));
  }

  /**
   * Get Consolidated Device DDM Status Map
   */
  static getDeviceAggregatedStatus(db, deviceId) {
    if (!db || !deviceId) return {};

    const rows = db.prepare(`
      SELECT status_key, status_value_json, received_at
      FROM ddm_status_reports
      WHERE device_id = ?
      ORDER BY received_at ASC
    `).all(deviceId);

    const aggregated = {};
    for (const r of rows) {
      try {
        aggregated[r.status_key] = {
          value: JSON.parse(r.status_value_json || '{}'),
          received_at: r.received_at
        };
      } catch (e) {
        aggregated[r.status_key] = {
          value: r.status_value_json,
          received_at: r.received_at
        };
      }
    }

    return aggregated;
  }
}
