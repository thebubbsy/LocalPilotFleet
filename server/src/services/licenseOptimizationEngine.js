/**
 * LocalPilot Fleet — Autonomous Software License Optimization & Enterprise Metering Engine
 * server/src/services/licenseOptimizationEngine.js
 *
 * Implements full Software Asset Management (SAM), SaaS/Desktop FinOps, process foreground
 * usage metering, seat allocation lifecycle, shelfware detection, and automated license reclamation.
 */

import crypto from 'node:crypto';

export class LicenseOptimizationEngine {
  /**
   * Aggregate fleet SAM metrics and FinOps savings KPIs
   */
  static getLicenseStats(db) {
    const totalLicRow = db.prepare('SELECT COUNT(*) as count FROM software_licenses').get();
    const seatsRow = db.prepare('SELECT SUM(total_seats) as total, SUM(allocated_seats) as allocated FROM software_licenses').get();

    const totalLicenses = totalLicRow?.count || 0;
    const totalSeats = seatsRow?.total || 0;
    const allocatedSeats = seatsRow?.allocated || 0;
    const seatUtilizationPct = totalSeats > 0 ? parseFloat(((allocatedSeats / totalSeats) * 100).toFixed(1)) : 0;

    // Annual spend calculation
    const spendRow = db.prepare(`
      SELECT SUM(
        CASE
          WHEN billing_cycle = 'MONTHLY' THEN (total_seats * cost_per_seat_usd * 12)
          ELSE (total_seats * cost_per_seat_usd)
        END
      ) as annual_spend
      FROM software_licenses
    `).get();
    const totalAnnualSpendUsd = parseFloat((spendRow?.annual_spend || 0).toFixed(2));

    // Potential shelfware savings
    const shelfwareSavingsRow = db.prepare(`
      SELECT SUM(
        CASE
          WHEN sl.billing_cycle = 'MONTHLY' THEN (sl.cost_per_seat_usd * 12)
          ELSE sl.cost_per_seat_usd
        END
      ) as savings
      FROM software_license_allocations sla
      JOIN software_licenses sl ON sla.license_id = sl.id
      WHERE sla.status = 'FLAGGED_SHELFWARE'
    `).get();
    const potentialShelfwareSavingsUsd = parseFloat((shelfwareSavingsRow?.savings || 0).toFixed(2));

    const shelfwareCountRow = db.prepare("SELECT COUNT(*) as count FROM software_license_allocations WHERE status = 'FLAGGED_SHELFWARE'").get();
    const activeAllocRow = db.prepare("SELECT COUNT(*) as count FROM software_license_allocations WHERE status = 'ACTIVE'").get();

    return {
      totalLicenses,
      totalSeats,
      allocatedSeats,
      seatUtilizationPct,
      totalAnnualSpendUsd,
      potentialShelfwareSavingsUsd,
      shelfwareCount: shelfwareCountRow?.count || 0,
      activeAllocations: activeAllocRow?.count || 0,
      samOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * List software license entitlements with optional filtering
   */
  static getLicenses(db, query = {}) {
    let sql = 'SELECT * FROM software_licenses WHERE 1=1';
    const params = [];

    if (query.vendor) {
      sql += ' AND vendor LIKE ?';
      params.push(`%${query.vendor}%`);
    }
    if (query.license_type) {
      sql += ' AND license_type = ?';
      params.push(query.license_type);
    }
    if (query.expiring_soon) {
      sql += " AND expiration_date IS NOT NULL AND expiration_date <= DATETIME('now', '+30 days')";
    }

    sql += ' ORDER BY product_name ASC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => {
      const utilPct = r.total_seats > 0 ? parseFloat(((r.allocated_seats / r.total_seats) * 100).toFixed(1)) : 0;
      return { ...r, utilization_pct: utilPct };
    });
  }

  /**
   * Retrieve single license entitlement by ID with joined seat allocations
   */
  static getLicenseById(db, id) {
    const license = db.prepare('SELECT * FROM software_licenses WHERE id = ?').get(id);
    if (!license) return null;

    const allocations = db.prepare(`
      SELECT * FROM software_license_allocations
      WHERE license_id = ?
      ORDER BY assigned_at DESC
    `).all(id);

    const utilPct = license.total_seats > 0 ? parseFloat(((license.allocated_seats / license.total_seats) * 100).toFixed(1)) : 0;
    return {
      ...license,
      utilization_pct: utilPct,
      allocations
    };
  }

  /**
   * Create new software license entitlement
   */
  static createLicense(db, data) {
    const id = data.id || ('lic-' + crypto.randomBytes(4).toString('hex'));

    const stmt = db.prepare(`
      INSERT INTO software_licenses (
        id, product_name, vendor, license_type, license_key,
        total_seats, allocated_seats, cost_per_seat_usd, billing_cycle, expiration_date
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.product_name,
      data.vendor,
      data.license_type || 'PER_SEAT',
      data.license_key || null,
      data.total_seats !== undefined ? parseInt(data.total_seats, 10) : 1,
      data.allocated_seats !== undefined ? parseInt(data.allocated_seats, 10) : 0,
      data.cost_per_seat_usd !== undefined ? parseFloat(data.cost_per_seat_usd) : 0.0,
      data.billing_cycle || 'ANNUAL',
      data.expiration_date || null
    );

    return this.getLicenseById(db, id);
  }

  /**
   * Update license entitlement details
   */
  static updateLicense(db, id, data) {
    const existing = db.prepare('SELECT * FROM software_licenses WHERE id = ?').get(id);
    if (!existing) return null;

    const stmt = db.prepare(`
      UPDATE software_licenses SET
        product_name = COALESCE(?, product_name),
        vendor = COALESCE(?, vendor),
        license_type = COALESCE(?, license_type),
        license_key = COALESCE(?, license_key),
        total_seats = COALESCE(?, total_seats),
        allocated_seats = COALESCE(?, allocated_seats),
        cost_per_seat_usd = COALESCE(?, cost_per_seat_usd),
        billing_cycle = COALESCE(?, billing_cycle),
        expiration_date = COALESCE(?, expiration_date),
        updated_at = DATETIME('now')
      WHERE id = ?
    `);

    stmt.run(
      data.product_name !== undefined ? data.product_name : null,
      data.vendor !== undefined ? data.vendor : null,
      data.license_type !== undefined ? data.license_type : null,
      data.license_key !== undefined ? data.license_key : null,
      data.total_seats !== undefined ? parseInt(data.total_seats, 10) : null,
      data.allocated_seats !== undefined ? parseInt(data.allocated_seats, 10) : null,
      data.cost_per_seat_usd !== undefined ? parseFloat(data.cost_per_seat_usd) : null,
      data.billing_cycle !== undefined ? data.billing_cycle : null,
      data.expiration_date !== undefined ? data.expiration_date : null,
      id
    );

    return this.getLicenseById(db, id);
  }

  /**
   * Delete license entitlement and cascading allocations
   */
  static deleteLicense(db, id) {
    const existing = db.prepare('SELECT id FROM software_licenses WHERE id = ?').get(id);
    if (!existing) return false;

    db.prepare('DELETE FROM software_license_allocations WHERE license_id = ?').run(id);
    db.prepare('DELETE FROM software_licenses WHERE id = ?').run(id);
    return true;
  }

  /**
   * Retrieve seat allocations
   */
  static getAllocations(db, query = {}) {
    let sql = `
      SELECT sla.*, sl.product_name, sl.vendor, sl.cost_per_seat_usd
      FROM software_license_allocations sla
      JOIN software_licenses sl ON sla.license_id = sl.id
      WHERE 1=1
    `;
    const params = [];

    if (query.license_id) {
      sql += ' AND sla.license_id = ?';
      params.push(query.license_id);
    }
    if (query.device_id) {
      sql += ' AND sla.device_id = ?';
      params.push(query.device_id);
    }
    if (query.status) {
      sql += ' AND sla.status = ?';
      params.push(query.status);
    }

    sql += ' ORDER BY sla.assigned_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Allocate license seat to an endpoint device
   */
  static allocateLicense(db, data) {
    const license = db.prepare('SELECT * FROM software_licenses WHERE id = ?').get(data.license_id);
    if (!license) throw new Error('Target software license entitlement not found');

    const id = data.id || ('sla-' + crypto.randomBytes(4).toString('hex'));

    const stmt = db.prepare(`
      INSERT INTO software_license_allocations (
        id, license_id, device_id, hostname, assigned_user, status, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.license_id,
      data.device_id,
      data.hostname || 'UNKNOWN-HOST',
      data.assigned_user || null,
      data.status || 'ACTIVE',
      data.last_used_at || new Date().toISOString()
    );

    // Increment allocated seats count
    db.prepare('UPDATE software_licenses SET allocated_seats = allocated_seats + 1 WHERE id = ?').run(data.license_id);

    return db.prepare('SELECT * FROM software_license_allocations WHERE id = ?').get(id);
  }

  /**
   * Reclaim a license seat (FinOps recovery from unassigned or shelfware node)
   */
  static reclaimLicense(db, allocationId, reason = 'Administrative Reclamation') {
    const allocation = db.prepare('SELECT * FROM software_license_allocations WHERE id = ?').get(allocationId);
    if (!allocation) return null;

    if (allocation.status !== 'RECLAIMED') {
      db.prepare(`
        UPDATE software_license_allocations SET
          status = 'RECLAIMED',
          reclamation_reason = ?
        WHERE id = ?
      `).run(reason, allocationId);

      // Decrement allocated seats count
      db.prepare('UPDATE software_licenses SET allocated_seats = MAX(0, allocated_seats - 1) WHERE id = ?').run(allocation.license_id);
    }

    return db.prepare('SELECT * FROM software_license_allocations WHERE id = ?').get(allocationId);
  }

  /**
   * Ingest endpoint process usage metering telemetry
   */
  static ingestMeteringTelemetry(db, data) {
    const existing = db.prepare('SELECT * FROM software_usage_metering WHERE device_id = ? AND process_name = ?').get(
      data.device_id,
      data.process_name
    );

    if (existing) {
      const stmt = db.prepare(`
        UPDATE software_usage_metering SET
          product_name = COALESCE(?, product_name),
          total_runtime_seconds = total_runtime_seconds + ?,
          foreground_seconds = foreground_seconds + ?,
          launch_count = launch_count + ?,
          last_launched_at = DATETIME('now')
        WHERE id = ?
      `);

      stmt.run(
        data.product_name || null,
        data.runtime_seconds || 0,
        data.foreground_seconds || 0,
        data.launch_increment || 1,
        existing.id
      );

      return db.prepare('SELECT * FROM software_usage_metering WHERE id = ?').get(existing.id);
    } else {
      const id = data.id || ('sum-' + crypto.randomBytes(4).toString('hex'));

      const stmt = db.prepare(`
        INSERT INTO software_usage_metering (
          id, device_id, hostname, process_name, product_name,
          total_runtime_seconds, foreground_seconds, launch_count, last_launched_at, is_shelfware
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), ?)
      `);

      stmt.run(
        id,
        data.device_id,
        data.hostname || 'UNKNOWN-HOST',
        data.process_name,
        data.product_name || null,
        data.runtime_seconds || 0,
        data.foreground_seconds || 0,
        data.launch_increment || 1,
        data.is_shelfware ? 1 : 0
      );

      return db.prepare('SELECT * FROM software_usage_metering WHERE id = ?').get(id);
    }
  }

  /**
   * Query process usage metering summary
   */
  static getMeteringSummary(db, query = {}) {
    let sql = 'SELECT * FROM software_usage_metering WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.process_name) {
      sql += ' AND process_name LIKE ?';
      params.push(`%${query.process_name}%`);
    }
    if (query.is_shelfware !== undefined) {
      sql += ' AND is_shelfware = ?';
      params.push(query.is_shelfware ? 1 : 0);
    }

    sql += ' ORDER BY foreground_seconds DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Autonomous shelfware identification scanner
   * Flags active allocations with no recorded usage in the specified days threshold
   */
  static identifyShelfware(db, inactiveDaysThreshold = 30) {
    const cutoffDate = new Date(Date.now() - (inactiveDaysThreshold * 86400 * 1000)).toISOString();

    const candidates = db.prepare(`
      SELECT sla.id, sla.license_id, sla.device_id, sl.cost_per_seat_usd
      FROM software_license_allocations sla
      JOIN software_licenses sl ON sla.license_id = sl.id
      WHERE sla.status = 'ACTIVE'
        AND (sla.last_used_at IS NULL OR sla.last_used_at < ?)
    `).all(cutoffDate);

    const updateStmt = db.prepare(`
      UPDATE software_license_allocations SET
        status = 'FLAGGED_SHELFWARE',
        reclamation_reason = ?
      WHERE id = ?
    `);

    let flaggedCount = 0;
    let potentialSavings = 0;

    for (const cand of candidates) {
      updateStmt.run(`Inactive for >${inactiveDaysThreshold} days`, cand.id);
      flaggedCount++;
      potentialSavings += (cand.cost_per_seat_usd || 0);

      // Flag corresponding metering rows as shelfware
      db.prepare('UPDATE software_usage_metering SET is_shelfware = 1 WHERE device_id = ?').run(cand.device_id);
    }

    return {
      flaggedCount,
      potentialSavingsUsd: parseFloat(potentialSavings.toFixed(2)),
      thresholdDays: inactiveDaysThreshold,
      scannedAt: new Date().toISOString()
    };
  }
}
