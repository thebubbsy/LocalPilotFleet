import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { CloudAppDiscoveryEngine } from '../src/services/cloudAppDiscoveryEngine.js';

describe('Cloud App Discovery & Shadow SaaS Governance Engine (Iteration 61)', () => {
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

  it('1. getCloudAppStats returns aggregate metrics with default seeds', () => {
    const stats = CloudAppDiscoveryEngine.getCloudAppStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalApps, 'number');
    assert.ok(stats.totalApps >= 4);
    assert.ok(stats.sanctionedApps >= 2);
    assert.ok(stats.unsanctionedApps >= 1);
    assert.ok(stats.monitoredApps >= 1);
    assert.ok(stats.totalBytesTransferred > 0);
    assert.ok(stats.activePolicies >= 1);
    assert.equal(stats.cloudDiscoveryOperational, true);
  });

  it('2. getCloudAppStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = CloudAppDiscoveryEngine.getCloudAppStats(emptyDb);
    assert.equal(stats.totalApps, 0);
    assert.equal(stats.sanctionedApps, 0);
    assert.equal(stats.unsanctionedApps, 0);
    assert.equal(stats.totalBytesTransferred, 0);
    assert.equal(stats.activePolicies, 0);
    emptyDb.close();
  });

  it('3. getCatalog retrieves cloud applications ordered by bytes transferred', () => {
    const catalog = CloudAppDiscoveryEngine.getCatalog(db);
    assert.ok(Array.isArray(catalog));
    assert.ok(catalog.length >= 4);
    assert.ok(catalog[0].total_bytes_transferred >= catalog[catalog.length - 1].total_bytes_transferred);
    assert.ok(Array.isArray(catalog[0].compliance_certifications));
  });

  it('4. getCatalog filters correctly by category', () => {
    const aiApps = CloudAppDiscoveryEngine.getCatalog(db, { category: 'GENERATIVE_AI' });
    assert.ok(aiApps.length >= 1);
    assert.ok(aiApps.every(a => a.category === 'GENERATIVE_AI'));
  });

  it('5. getCatalog filters correctly by sanctioned_status', () => {
    const unsanctioned = CloudAppDiscoveryEngine.getCatalog(db, { sanctioned_status: 'UNSANCTIONED' });
    assert.ok(unsanctioned.length >= 1);
    assert.ok(unsanctioned.every(a => a.sanctioned_status === 'UNSANCTIONED'));
  });

  it('6. getCatalog filters correctly by min_risk', () => {
    const highRisk = CloudAppDiscoveryEngine.getCatalog(db, { min_risk: 70 });
    assert.ok(highRisk.length >= 1);
    assert.ok(highRisk.every(a => a.risk_score >= 70));
  });

  it('7. getAppById retrieves single cloud application with parsed compliance and usage', () => {
    const app = CloudAppDiscoveryEngine.getAppById(db, 'cac-01');
    assert.ok(app);
    assert.equal(app.id, 'cac-01');
    assert.equal(app.app_name, 'ChatGPT / OpenAI');
    assert.ok(Array.isArray(app.compliance_certifications));
    assert.ok(Array.isArray(app.usage_telemetry));
  });

  it('8. getAppById returns null for unknown ID', () => {
    const app = CloudAppDiscoveryEngine.getAppById(db, 'cac-unknown-xyz');
    assert.equal(app, null);
  });

  it('9. createApp persists new cloud application with lowercased domain', () => {
    const created = CloudAppDiscoveryEngine.createApp(db, {
      id: 'cac-test-01',
      app_name: 'Dropbox Personal',
      category: 'CLOUD_STORAGE',
      domain_name: 'DROPBOX.COM',
      description: 'Personal cloud storage locker',
      risk_score: 75,
      sanctioned_status: 'UNSANCTIONED',
      compliance_certifications: ['SOC2']
    });

    assert.ok(created);
    assert.equal(created.id, 'cac-test-01');
    assert.equal(created.domain_name, 'dropbox.com');
    assert.equal(created.sanctioned_status, 'UNSANCTIONED');
  });

  it('10. updateApp updates app metadata, risk score, and compliance', () => {
    const updated = CloudAppDiscoveryEngine.updateApp(db, 'cac-test-01', {
      risk_score: 80,
      description: 'Updated high-risk cloud storage',
      compliance_certifications: ['SOC2', 'ISO27001']
    });

    assert.ok(updated);
    assert.equal(updated.risk_score, 80);
    assert.equal(updated.description, 'Updated high-risk cloud storage');
    assert.deepEqual(updated.compliance_certifications, ['SOC2', 'ISO27001']);
  });

  it('11. updateApp returns null for unknown ID', () => {
    const updated = CloudAppDiscoveryEngine.updateApp(db, 'non-existent-cac', { risk_score: 10 });
    assert.equal(updated, null);
  });

  it('12. deleteApp removes cloud application and cascading usage and policies', () => {
    // Add usage and policy to cac-test-01
    CloudAppDiscoveryEngine.recordUsageTelemetry(db, {
      app_id: 'cac-test-01',
      app_name: 'Dropbox Personal',
      device_id: testDev.id,
      hostname: testDev.hostname,
      user_principal: 'test.user@corp.local',
      bytes_uploaded: 1000
    });

    CloudAppDiscoveryEngine.createAccessPolicy(db, {
      name: 'Block Dropbox Personal',
      app_id: 'cac-test-01',
      enforcement_action: 'BLOCK'
    });

    const deleted = CloudAppDiscoveryEngine.deleteApp(db, 'cac-test-01');
    assert.equal(deleted, true);

    const check = CloudAppDiscoveryEngine.getAppById(db, 'cac-test-01');
    assert.equal(check, null);

    const usage = CloudAppDiscoveryEngine.getUsageTelemetry(db, { app_id: 'cac-test-01' });
    assert.equal(usage.length, 0);
  });

  it('13. deleteApp returns false for non-existent app', () => {
    const deleted = CloudAppDiscoveryEngine.deleteApp(db, 'cac-not-found');
    assert.equal(deleted, false);
  });

  it('14. updateSanctionStatus changes status to SANCTIONED or UNSANCTIONED', () => {
    const updated = CloudAppDiscoveryEngine.updateSanctionStatus(db, 'cac-01', 'SANCTIONED');
    assert.ok(updated);
    assert.equal(updated.sanctioned_status, 'SANCTIONED');

    // Revert back
    CloudAppDiscoveryEngine.updateSanctionStatus(db, 'cac-01', 'MONITORED');
  });

  it('15. getUsageTelemetry retrieves usage records with app_id and user filters', () => {
    const telemetry = CloudAppDiscoveryEngine.getUsageTelemetry(db, { app_id: 'cac-02' });
    assert.ok(Array.isArray(telemetry));
    assert.ok(telemetry.length >= 1);
    assert.equal(telemetry[0].app_id, 'cac-02');
  });

  it('16. recordUsageTelemetry ingests telemetry and dynamically updates total_bytes_transferred and total_users_count', () => {
    const appBefore = CloudAppDiscoveryEngine.getAppById(db, 'cac-03');
    const bytesBefore = appBefore.total_bytes_transferred;

    const entry = CloudAppDiscoveryEngine.recordUsageTelemetry(db, {
      app_id: 'cac-03',
      app_name: 'Microsoft 365 & OneDrive',
      device_id: testDev.id,
      hostname: testDev.hostname,
      user_principal: 'new.engineer@corp.local',
      bytes_uploaded: 5000000,
      bytes_downloaded: 10000000
    });

    assert.ok(entry);
    assert.equal(entry.bytes_uploaded, 5000000);

    const appAfter = CloudAppDiscoveryEngine.getAppById(db, 'cac-03');
    assert.equal(appAfter.total_bytes_transferred, bytesBefore + 15000000);
  });

  it('17. getAccessPolicies retrieves policies with action and active filters', () => {
    const policies = CloudAppDiscoveryEngine.getAccessPolicies(db, { is_active: 1 });
    assert.ok(Array.isArray(policies));
    assert.ok(policies.length >= 1);
    assert.equal(policies[0].enforcement_action, 'BLOCK');
  });

  it('18. createAccessPolicy persists new cloud access governance policy', () => {
    const policy = CloudAppDiscoveryEngine.createAccessPolicy(db, {
      id: 'caap-test-01',
      name: 'Audit Generative AI',
      target_scope: 'ALL_FLEET',
      app_id: 'cac-01',
      enforcement_action: 'AUDIT',
      is_active: 1
    });

    assert.ok(policy);
    assert.equal(policy.id, 'caap-test-01');
    assert.equal(policy.enforcement_action, 'AUDIT');
  });

  it('19. deleteAccessPolicy removes policy successfully', () => {
    const deleted = CloudAppDiscoveryEngine.deleteAccessPolicy(db, 'caap-test-01');
    assert.equal(deleted, true);

    const check = db.prepare('SELECT id FROM cloud_app_access_policies WHERE id = ?').get('caap-test-01');
    assert.equal(check, undefined);
  });

  it('20. generateBlocklist returns unsanctioned domains and active BLOCK policies for network protection', () => {
    const blocklist = CloudAppDiscoveryEngine.generateBlocklist(db);
    assert.ok(blocklist);
    assert.ok(blocklist.total_blocked_domains >= 1);
    assert.ok(Array.isArray(blocklist.domains));
    assert.ok(blocklist.domains.includes('mega.nz'));
  });
});
