import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { LicenseOptimizationEngine } from '../src/services/licenseOptimizationEngine.js';

describe('Software License Optimization & Enterprise Metering Engine (Iteration 63)', () => {
  let db;
  let testDev;

  before(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });

    testDev = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get();
    if (!testDev) {
      db.prepare(`
        INSERT INTO devices (id, hostname, os_name, os_version, total_ram_bytes)
        VALUES ('dev-test-01', 'TEST-HOST-01', 'Windows 11', '23H2', 17179869184)
      `).run();
      testDev = { id: 'dev-test-01', hostname: 'TEST-HOST-01' };
    }
  });

  after(() => {
    db.close();
  });

  it('1. getLicenseStats returns correct aggregate metrics with default seeds', () => {
    const stats = LicenseOptimizationEngine.getLicenseStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalLicenses, 'number');
    assert.ok(stats.totalLicenses >= 3);
    assert.ok(stats.totalSeats >= 80);
    assert.ok(stats.allocatedSeats >= 75);
    assert.ok(stats.seatUtilizationPct > 80);
    assert.ok(stats.totalAnnualSpendUsd > 10000);
    assert.ok(stats.potentialShelfwareSavingsUsd > 500);
    assert.ok(stats.shelfwareCount >= 1);
    assert.equal(stats.samOperational, true);
  });

  it('2. getLicenseStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = LicenseOptimizationEngine.getLicenseStats(emptyDb);
    assert.equal(stats.totalLicenses, 0);
    assert.equal(stats.totalSeats, 0);
    assert.equal(stats.allocatedSeats, 0);
    assert.equal(stats.seatUtilizationPct, 0);
    assert.equal(stats.totalAnnualSpendUsd, 0);
    assert.equal(stats.shelfwareCount, 0);
    emptyDb.close();
  });

  it('3. getLicenses retrieves entitlements with utilization percentages', () => {
    const licenses = LicenseOptimizationEngine.getLicenses(db);
    assert.ok(Array.isArray(licenses));
    assert.ok(licenses.length >= 3);
    assert.ok(licenses.every(l => typeof l.utilization_pct === 'number'));
  });

  it('4. getLicenses filters correctly by vendor', () => {
    const adobe = LicenseOptimizationEngine.getLicenses(db, { vendor: 'Adobe' });
    assert.ok(adobe.length >= 1);
    assert.ok(adobe[0].vendor.includes('Adobe'));
  });

  it('5. getLicenses filters correctly by license_type', () => {
    const subs = LicenseOptimizationEngine.getLicenses(db, { license_type: 'SUBSCRIPTION' });
    assert.ok(subs.length >= 2);
    assert.ok(subs.every(s => s.license_type === 'SUBSCRIPTION'));
  });

  it('6. getLicenses filters expiring soon licenses', () => {
    // Insert a test license expiring in 5 days
    const expDate = new Date(Date.now() + (5 * 86400 * 1000)).toISOString();
    LicenseOptimizationEngine.createLicense(db, {
      id: 'lic-exp-test',
      product_name: 'Expiring Tool Pro',
      vendor: 'Expiring Vendor',
      license_type: 'SUBSCRIPTION',
      expiration_date: expDate
    });

    const expiring = LicenseOptimizationEngine.getLicenses(db, { expiring_soon: true });
    assert.ok(expiring.length >= 1);
    assert.ok(expiring.some(e => e.id === 'lic-exp-test'));
  });

  it('7. getLicenseById retrieves single license entitlement with joined seat allocations', () => {
    const license = LicenseOptimizationEngine.getLicenseById(db, 'lic-01');
    assert.ok(license);
    assert.equal(license.id, 'lic-01');
    assert.ok(Array.isArray(license.allocations));
    assert.ok(license.allocations.length >= 1);
  });

  it('8. getLicenseById returns null for unknown license ID', () => {
    const unknown = LicenseOptimizationEngine.getLicenseById(db, 'unknown-lic-xyz');
    assert.equal(unknown, null);
  });

  it('9. createLicense registers new software license entitlement', () => {
    const created = LicenseOptimizationEngine.createLicense(db, {
      id: 'lic-test-01',
      product_name: 'Slack Enterprise Grid',
      vendor: 'Salesforce / Slack',
      license_type: 'SUBSCRIPTION',
      total_seats: 100,
      allocated_seats: 85,
      cost_per_seat_usd: 150.00,
      billing_cycle: 'ANNUAL'
    });

    assert.ok(created);
    assert.equal(created.id, 'lic-test-01');
    assert.equal(created.product_name, 'Slack Enterprise Grid');
    assert.equal(created.total_seats, 100);
    assert.equal(created.allocated_seats, 85);
    assert.equal(created.utilization_pct, 85.0);
  });

  it('10. updateLicense modifies seats, pricing, and expiration date', () => {
    const updated = LicenseOptimizationEngine.updateLicense(db, 'lic-test-01', {
      total_seats: 120,
      cost_per_seat_usd: 140.00
    });

    assert.ok(updated);
    assert.equal(updated.total_seats, 120);
    assert.equal(updated.cost_per_seat_usd, 140.00);
  });

  it('11. deleteLicense removes license and cascading allocations', () => {
    LicenseOptimizationEngine.allocateLicense(db, {
      id: 'sla-test-delete',
      license_id: 'lic-test-01',
      device_id: testDev.id,
      hostname: testDev.hostname
    });

    const deleted = LicenseOptimizationEngine.deleteLicense(db, 'lic-test-01');
    assert.equal(deleted, true);

    const check = LicenseOptimizationEngine.getLicenseById(db, 'lic-test-01');
    assert.equal(check, null);

    const allocs = LicenseOptimizationEngine.getAllocations(db, { license_id: 'lic-test-01' });
    assert.equal(allocs.length, 0);
  });

  it('12. deleteLicense returns false for non-existent license ID', () => {
    const deleted = LicenseOptimizationEngine.deleteLicense(db, 'non-existent-lic-99');
    assert.equal(deleted, false);
  });

  it('13. getAllocations retrieves seat allocations joined with license metadata', () => {
    const allocs = LicenseOptimizationEngine.getAllocations(db);
    assert.ok(Array.isArray(allocs));
    assert.ok(allocs.length >= 2);
    assert.ok(allocs[0].product_name);
    assert.ok(allocs[0].vendor);
  });

  it('14. getAllocations filters by status (ACTIVE vs FLAGGED_SHELFWARE)', () => {
    const active = LicenseOptimizationEngine.getAllocations(db, { status: 'ACTIVE' });
    assert.ok(active.length >= 1);
    assert.ok(active.every(a => a.status === 'ACTIVE'));

    const shelfware = LicenseOptimizationEngine.getAllocations(db, { status: 'FLAGGED_SHELFWARE' });
    assert.ok(shelfware.length >= 1);
    assert.ok(shelfware.every(s => s.status === 'FLAGGED_SHELFWARE'));
  });

  it('15. allocateLicense assigns seat to device and increments allocated_seats', () => {
    const licBefore = LicenseOptimizationEngine.getLicenseById(db, 'lic-02');
    const prevAllocated = licBefore.allocated_seats;

    const allocation = LicenseOptimizationEngine.allocateLicense(db, {
      id: 'sla-alloc-test',
      license_id: 'lic-02',
      device_id: testDev.id,
      hostname: testDev.hostname,
      assigned_user: 'dev_lead@localpilot.corp'
    });

    assert.ok(allocation);
    assert.equal(allocation.id, 'sla-alloc-test');
    assert.equal(allocation.assigned_user, 'dev_lead@localpilot.corp');

    const licAfter = LicenseOptimizationEngine.getLicenseById(db, 'lic-02');
    assert.equal(licAfter.allocated_seats, prevAllocated + 1);
  });

  it('16. reclaimLicense transitions status to RECLAIMED, decrements allocated_seats, records reason', () => {
    const licBefore = LicenseOptimizationEngine.getLicenseById(db, 'lic-02');
    const prevAllocated = licBefore.allocated_seats;

    const reclaimed = LicenseOptimizationEngine.reclaimLicense(
      db,
      'sla-alloc-test',
      'Employee offboarded - license reclaimed'
    );

    assert.ok(reclaimed);
    assert.equal(reclaimed.status, 'RECLAIMED');
    assert.equal(reclaimed.reclamation_reason, 'Employee offboarded - license reclaimed');

    const licAfter = LicenseOptimizationEngine.getLicenseById(db, 'lic-02');
    assert.equal(licAfter.allocated_seats, prevAllocated - 1);
  });

  it('17. reclaimLicense returns null for non-existent allocation', () => {
    const reclaimed = LicenseOptimizationEngine.reclaimLicense(db, 'non-existent-sla-xyz');
    assert.equal(reclaimed, null);
  });

  it('18. ingestMeteringTelemetry inserts and updates process runtime and foreground usage', () => {
    const initial = LicenseOptimizationEngine.ingestMeteringTelemetry(db, {
      id: 'sum-test-01',
      device_id: testDev.id,
      hostname: testDev.hostname,
      process_name: 'code.exe',
      product_name: 'Visual Studio Code',
      runtime_seconds: 3600,
      foreground_seconds: 2400,
      launch_increment: 1
    });

    assert.ok(initial);
    assert.equal(initial.process_name, 'code.exe');
    assert.equal(initial.total_runtime_seconds, 3600);
    assert.equal(initial.foreground_seconds, 2400);

    const updated = LicenseOptimizationEngine.ingestMeteringTelemetry(db, {
      device_id: testDev.id,
      process_name: 'code.exe',
      runtime_seconds: 1800,
      foreground_seconds: 1200,
      launch_increment: 1
    });

    assert.equal(updated.total_runtime_seconds, 5400);
    assert.equal(updated.foreground_seconds, 3600);
    assert.equal(updated.launch_count, 2);
  });

  it('19. getMeteringSummary filters processes by name and shelfware flag', () => {
    const summary = LicenseOptimizationEngine.getMeteringSummary(db, { process_name: 'code' });
    assert.ok(summary.length >= 1);
    assert.ok(summary[0].process_name.includes('code'));
  });

  it('20. identifyShelfware scans inactive allocations, flags shelfware status, and calculates potential USD savings', () => {
    // Insert an active allocation with an old last_used_at date
    const oldDate = new Date(Date.now() - (60 * 86400 * 1000)).toISOString();
    LicenseOptimizationEngine.allocateLicense(db, {
      id: 'sla-shelfware-candidate',
      license_id: 'lic-01',
      device_id: testDev.id,
      hostname: testDev.hostname,
      assigned_user: 'inactive_contractor@localpilot.corp',
      last_used_at: oldDate
    });

    const result = LicenseOptimizationEngine.identifyShelfware(db, 30);
    assert.ok(result);
    assert.ok(result.flaggedCount >= 1);
    assert.ok(result.potentialSavingsUsd > 0);

    const alloc = db.prepare("SELECT * FROM software_license_allocations WHERE id = 'sla-shelfware-candidate'").get();
    assert.equal(alloc.status, 'FLAGGED_SHELFWARE');
  });
});
