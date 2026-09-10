import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { initDb, closeDb } from '../src/db.js';
import { multiTenancyEngine } from '../src/services/multiTenancyEngine.js';

describe('Multi-Tenancy (MSP Organizations, Sites & Collections) & Database HA QA (Dimension 6 & P4)', () => {
  let db;
  let createdOrgId;
  let createdSiteId;
  let createdColId;

  before(() => {
    db = initDb(':memory:', { seed: true });
    multiTenancyEngine._db = db;
  });

  after(() => {
    closeDb();
  });

  // 1. STATS
  it('TENANT-01: should return baseline multi-tenancy statistics and database HA posture', () => {
    const stats = multiTenancyEngine.getMultiTenancyStats();
    assert.ok(stats.totalOrganizations >= 2, 'Should have seed organizations');
    assert.ok(stats.activeOrganizations >= 2);
    assert.ok(stats.totalAllocatedSeats >= 1000);
    assert.ok(stats.totalSites >= 2);
    assert.ok(stats.totalScopedCollections >= 2);
    assert.strictEqual(stats.databaseHaReady, true);
    assert.strictEqual(stats.concurrencySupport, '100,000+ Nodes');
  });

  // 2. LIST ORGANIZATIONS
  it('TENANT-02: should list all organizations including default system tenant', () => {
    const orgs = multiTenancyEngine.getOrganizations();
    assert.ok(orgs.length >= 2);
    const defaultOrg = orgs.find(o => o.slug === 'default');
    assert.ok(defaultOrg);
    assert.strictEqual(defaultOrg.name, 'LocalPilot Primary Enterprise');
    assert.strictEqual(defaultOrg.license_tier, 'ENTERPRISE');
  });

  // 3. GET SINGLE ORGANIZATION
  it('TENANT-03: should retrieve an organization by ID or slug', () => {
    const org = multiTenancyEngine.getOrganizationById('contoso-corp');
    assert.ok(org);
    assert.strictEqual(org.name, 'Contoso Global Managed Client');
    assert.strictEqual(org.domain, 'contoso.com');
  });

  // 4. CREATE ORGANIZATION
  it('TENANT-04: should create a new MSP client organization', () => {
    const created = multiTenancyEngine.createOrganization({
      name: 'Fabrikam Aerospace MSP Client',
      slug: 'fabrikam-aero',
      domain: 'fabrikam.com',
      license_tier: 'ENTERPRISE',
      max_devices: 250
    });

    assert.ok(created);
    assert.strictEqual(created.name, 'Fabrikam Aerospace MSP Client');
    assert.strictEqual(created.slug, 'fabrikam-aero');
    assert.strictEqual(created.max_devices, 250);
    createdOrgId = created.id;
  });

  // 5. VALIDATION ON CREATE
  it('TENANT-05: should reject creating organization with missing name or slug', () => {
    assert.throws(() => {
      multiTenancyEngine.createOrganization({
        name: 'Missing Slug Corp'
      });
    }, /required/);
  });

  // 6. UPDATE ORGANIZATION
  it('TENANT-06: should update organization max devices allocation and tier', () => {
    const updated = multiTenancyEngine.updateOrganization(createdOrgId, {
      max_devices: 500,
      license_tier: 'PROFESSIONAL'
    });

    assert.ok(updated);
    assert.strictEqual(updated.max_devices, 500);
    assert.strictEqual(updated.license_tier, 'PROFESSIONAL');
  });

  // 7. DELETE ORGANIZATION
  it('TENANT-07: should delete created organization', () => {
    const result = multiTenancyEngine.deleteOrganization(createdOrgId);
    assert.strictEqual(result.success, true);
    const check = multiTenancyEngine.getOrganizationById(createdOrgId);
    assert.strictEqual(check, null);
  });

  // 8. PROTECT DEFAULT ORGANIZATION
  it('TENANT-08: should prevent deleting default system organization', () => {
    assert.throws(() => {
      multiTenancyEngine.deleteOrganization('org-default');
    }, /Cannot delete default system organization/);
  });

  // 9. LIST SITES
  it('TENANT-09: should list branch sites with parsed subnet CIDRs array', () => {
    const sites = multiTenancyEngine.getSites();
    assert.ok(sites.length >= 2);
    const hq = sites.find(s => s.id === 'site-hq');
    assert.ok(hq);
    assert.strictEqual(hq.city, 'Sydney');
    assert.ok(Array.isArray(hq.subnet_cidrs));
    assert.ok(hq.subnet_cidrs.includes('192.168.1.0/24'));
  });

  // 10. FILTER SITES BY ORG
  it('TENANT-10: should filter sites by target organization slug or ID', () => {
    const sites = multiTenancyEngine.getSites('org-default');
    assert.ok(sites.length >= 2);
    sites.forEach(s => assert.strictEqual(s.org_id, 'org-default'));
  });

  // 11. CREATE SITE
  it('TENANT-11: should create a new physical or logical branch site', () => {
    const site = multiTenancyEngine.createSite({
      org_id: 'org-default',
      name: 'Brisbane Data Center Hub',
      city: 'Brisbane',
      country: 'AU',
      subnet_cidrs: ['10.50.0.0/16'],
      bandwidth_cap_mbps: 2000
    });

    assert.ok(site);
    assert.strictEqual(site.name, 'Brisbane Data Center Hub');
    assert.strictEqual(site.city, 'Brisbane');
    assert.strictEqual(site.bandwidth_cap_mbps, 2000);
    assert.deepStrictEqual(site.subnet_cidrs, ['10.50.0.0/16']);
    createdSiteId = site.id;
  });

  // 12. UPDATE SITE
  it('TENANT-12: should update site bandwidth cap and city', () => {
    const updated = multiTenancyEngine.updateSite(createdSiteId, {
      bandwidth_cap_mbps: 2500,
      city: 'Greater Brisbane'
    });

    assert.ok(updated);
    assert.strictEqual(updated.bandwidth_cap_mbps, 2500);
    assert.strictEqual(updated.city, 'Greater Brisbane');
  });

  // 13. DELETE SITE
  it('TENANT-13: should delete created site', () => {
    const result = multiTenancyEngine.deleteSite(createdSiteId);
    assert.strictEqual(result.success, true);
    const check = multiTenancyEngine.getSiteById(createdSiteId);
    assert.strictEqual(check, null);
  });

  // 14. LIST SCOPED COLLECTIONS
  it('TENANT-14: should list scoped device collections with org and site metadata', () => {
    const collections = multiTenancyEngine.getScopedCollections();
    assert.ok(collections.length >= 2);
    const hqCol = collections.find(c => c.id === 'col-hq-workstations');
    assert.ok(hqCol);
    assert.strictEqual(hqCol.name, 'HQ Executive & Dev Workstations');
    assert.strictEqual(hqCol.is_dynamic, 0);
  });

  // 15. CREATE SCOPED COLLECTION
  it('TENANT-15: should create dynamic scoped collection with membership rule', () => {
    const col = multiTenancyEngine.createScopedCollection({
      org_id: 'org-default',
      name: 'VIP Developer Desktops',
      description: 'High-memory workstations assigned to core developers',
      is_dynamic: true,
      membership_rule: 'device.ram_gb >= 64'
    });

    assert.ok(col);
    assert.strictEqual(col.name, 'VIP Developer Desktops');
    assert.strictEqual(col.is_dynamic, 1);
    assert.strictEqual(col.membership_rule, 'device.ram_gb >= 64');
    createdColId = col.id;
  });

  // 16. DELETE SCOPED COLLECTION
  it('TENANT-16: should delete scoped device collection', () => {
    const result = multiTenancyEngine.deleteScopedCollection(createdColId);
    assert.strictEqual(result.success, true);
    const check = multiTenancyEngine.getScopedCollectionById(createdColId);
    assert.strictEqual(check, null);
  });

  // 17. SQLITE TO POSTGRESQL TRANSLATION - NOW()
  it('TENANT-17: should translate SQLite DATETIME(\'now\') to ANSI PostgreSQL NOW()', () => {
    const sqliteSql = "INSERT INTO events (id, created_at) VALUES ('ev-1', DATETIME('now'))";
    const pgSql = multiTenancyEngine.translateSqlToPostgres(sqliteSql);
    assert.ok(pgSql.includes('NOW()'));
    assert.ok(!pgSql.includes("DATETIME('now')"));
  });

  // 18. SQLITE TO POSTGRESQL TRANSLATION - INTERVALS
  it('TENANT-18: should translate SQLite day intervals to PostgreSQL INTERVAL', () => {
    const sqliteSql = "SELECT * FROM tokens WHERE expires_at > DATETIME('now', '+3 day')";
    const pgSql = multiTenancyEngine.translateSqlToPostgres(sqliteSql);
    assert.ok(pgSql.includes("INTERVAL '3 days'"));
  });

  // 19. DATABASE HEALTH CHECK
  it('TENANT-19: should perform synthetic database ping and return pool telemetry', () => {
    const health = multiTenancyEngine.getDatabaseHealth();
    assert.strictEqual(health.status, 'HEALTHY');
    assert.ok(typeof health.latencyMs === 'number');
    assert.ok(health.pool);
    assert.strictEqual(health.haCapabilities.readReplicasSupported, true);
  });

  // 20. NOT FOUND SAFETY
  it('TENANT-20: should safely return null for non-existent organization', () => {
    const org = multiTenancyEngine.getOrganizationById('org-non-existent-999');
    assert.strictEqual(org, null);
  });
});
