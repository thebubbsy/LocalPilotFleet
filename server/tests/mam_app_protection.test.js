/**
 * LocalPilot Fleet — Mobile Application Management (MAM) Engine Unit Tests (Iteration 66)
 * server/tests/mam_app_protection.test.js
 *
 * Validates corporate data containerization, clipboard sandboxing, app-level biometric/PIN locks,
 * offline grace period governance, selective corporate wipes, and compliance audits.
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { MamAppProtectionEngine } from '../src/services/mamAppProtectionEngine.js';

describe('Mobile Application Management (MAM) & App Protection Engine (Iteration 66)', () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });
  });

  afterEach(() => {
    if (db) db.close();
  });

  it('1. getMamStats aggregates total policies, managed apps, and selective wipes', () => {
    const stats = MamAppProtectionEngine.getMamStats(db);
    assert.ok(stats.total_policies >= 1);
    assert.ok(stats.active_policies >= 1);
    assert.ok(stats.total_managed_apps >= 3);
    assert.ok(stats.enlightened_apps >= 3);
    assert.ok(stats.total_selective_wipes >= 1);
  });

  it('2. getMamStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    emptyDb.exec(`
      CREATE TABLE mam_app_protection_policies (id TEXT, is_active INT);
      CREATE TABLE mam_managed_apps_catalog (id TEXT, is_enlightened INT);
      CREATE TABLE mam_selective_wipe_requests (id TEXT, status TEXT);
    `);
    const stats = MamAppProtectionEngine.getMamStats(emptyDb);
    assert.equal(stats.total_policies, 0);
    assert.equal(stats.total_managed_apps, 0);
    emptyDb.close();
  });

  it('3. getPolicies retrieves active MAM policies', () => {
    const policies = MamAppProtectionEngine.getPolicies(db);
    assert.ok(policies.length >= 1);
    assert.equal(policies[0].id, 'mam-pol-01');
    assert.ok(policies[0].assigned_apps_count >= 1);
    assert.equal(policies[0].require_pin_or_biometrics, true);
  });

  it('4. getPolicies filters by platform', () => {
    MamAppProtectionEngine.createPolicy(db, {
      id: 'pol-and-test',
      name: 'Android Work Profile Policy',
      platform: 'ANDROID'
    });

    const andOnly = MamAppProtectionEngine.getPolicies(db, { platform: 'ANDROID' });
    assert.ok(andOnly.some(p => p.id === 'pol-and-test'));
  });

  it('5. createPolicy inserts new policy with default parameters', () => {
    const policy = MamAppProtectionEngine.createPolicy(db, {
      name: 'Windows Information Protection MAM',
      platform: 'WINDOWS',
      clipboard_sharing_mode: 'BLOCKED'
    });

    assert.ok(policy.id);
    assert.equal(policy.name, 'Windows Information Protection MAM');
    assert.equal(policy.clipboard_sharing_mode, 'BLOCKED');
    assert.equal(policy.min_pin_length, 6);
    assert.equal(policy.prevent_save_as, true);
  });

  it('6. createPolicy throws error when name is missing', () => {
    assert.throws(() => {
      MamAppProtectionEngine.createPolicy(db, { platform: 'IOS' });
    }, /Policy name is required/);
  });

  it('7. getPolicy returns single policy with its assigned apps list', () => {
    const policy = MamAppProtectionEngine.getPolicy(db, 'mam-pol-01');
    assert.ok(policy);
    assert.equal(policy.id, 'mam-pol-01');
    assert.ok(policy.apps.length >= 3);
    assert.ok(policy.apps.some(a => a.bundle_id === 'com.microsoft.Office.Outlook'));
  });

  it('8. getPolicy returns null for non-existent policy ID', () => {
    const policy = MamAppProtectionEngine.getPolicy(db, 'pol-nonexistent');
    assert.equal(policy, null);
  });

  it('9. updatePolicy modifies clipboard sharing mode and offline grace minutes', () => {
    const updated = MamAppProtectionEngine.updatePolicy(db, 'mam-pol-01', {
      clipboard_sharing_mode: 'POLICY_MANAGED_WITH_PASTE_IN',
      max_offline_grace_minutes: 1440
    });

    assert.equal(updated.clipboard_sharing_mode, 'POLICY_MANAGED_WITH_PASTE_IN');
    assert.equal(updated.max_offline_grace_minutes, 1440);
  });

  it('10. deletePolicy removes policy and cascades deletion', () => {
    const policy = MamAppProtectionEngine.createPolicy(db, { name: 'Temp Policy', platform: 'IOS' });
    const deleted = MamAppProtectionEngine.deletePolicy(db, policy.id);
    assert.equal(deleted, true);
    assert.equal(MamAppProtectionEngine.getPolicy(db, policy.id), null);
  });

  it('11. getManagedApps lists apps in catalog with policy details', () => {
    const apps = MamAppProtectionEngine.getManagedApps(db);
    assert.ok(apps.length >= 3);
    assert.ok(apps.some(a => a.app_name === 'Microsoft Outlook'));
  });

  it('12. registerManagedApp inserts new managed application', () => {
    const app = MamAppProtectionEngine.registerManagedApp(db, {
      policy_id: 'mam-pol-01',
      app_name: 'Slack Enterprise MAM',
      bundle_id: 'com.tinyspeck.chatlyenterprise',
      platform: 'IOS',
      min_app_version: '23.01.0'
    });

    assert.ok(app.id);
    assert.equal(app.app_name, 'Slack Enterprise MAM');
    assert.equal(app.bundle_id, 'com.tinyspeck.chatlyenterprise');
  });

  it('13. deleteManagedApp removes app from catalog', () => {
    const app = MamAppProtectionEngine.registerManagedApp(db, {
      policy_id: 'mam-pol-01',
      app_name: 'Ephemeral App',
      bundle_id: 'com.test.ephemeral',
      platform: 'IOS'
    });

    const deleted = MamAppProtectionEngine.deleteManagedApp(db, app.id);
    assert.equal(deleted, true);
  });

  it('14. requestSelectiveWipe queues corporate account wipe in PENDING status', () => {
    const wipe = MamAppProtectionEngine.requestSelectiveWipe(db, {
      target_user_email: 'departing.employee@localpilot.corp',
      wipe_reason: 'USER_OFFBOARDED',
      issued_by: 'HR Admin'
    });

    assert.ok(wipe.id);
    assert.equal(wipe.target_user_email, 'departing.employee@localpilot.corp');
    assert.equal(wipe.status, 'PENDING');
  });

  it('15. cancelSelectiveWipe cancels pending wipe order', () => {
    const wipe = MamAppProtectionEngine.requestSelectiveWipe(db, {
      target_user_email: 'test.cancel@localpilot.corp'
    });

    const cancelled = MamAppProtectionEngine.cancelSelectiveWipe(db, wipe.id);
    assert.equal(cancelled, true);

    const wipes = MamAppProtectionEngine.getSelectiveWipes(db, { status: 'CANCELLED' });
    assert.ok(wipes.some(w => w.id === wipe.id));
  });

  it('16. completeSelectiveWipe marks wipe COMPLETED with audit payload', () => {
    const wipe = MamAppProtectionEngine.requestSelectiveWipe(db, {
      target_user_email: 'wiped.user@localpilot.corp'
    });

    const completed = MamAppProtectionEngine.completeSelectiveWipe(db, wipe.id, {
      wiped_containers: ['com.microsoft.Office.Outlook', 'corp.localpilot.vault'],
      bytes_purged: 4520110
    });
    assert.equal(completed, true);

    const wipes = MamAppProtectionEngine.getSelectiveWipes(db, { status: 'COMPLETED' });
    const match = wipes.find(w => w.id === wipe.id);
    assert.ok(match);
    assert.ok(match.completed_at);
  });

  it('17. getPendingWipesForNodeOrUser matches user email and device ID', () => {
    MamAppProtectionEngine.requestSelectiveWipe(db, {
      target_user_email: 'target.alice@localpilot.corp',
      target_device_id: 'dev-alice-phone'
    });

    const wipes = MamAppProtectionEngine.getPendingWipesForNodeOrUser(db, {
      userEmail: 'target.alice@localpilot.corp',
      deviceId: 'dev-alice-phone'
    });

    assert.ok(wipes.length >= 1);
    assert.ok(wipes.some(w => w.target_user_email === 'target.alice@localpilot.corp'));
  });

  it('18. evaluateAppCompliance authorizes compliant app with PIN required', () => {
    const res = MamAppProtectionEngine.evaluateAppCompliance(db, {
      bundle_id: 'com.microsoft.Office.Outlook',
      platform: 'IOS',
      app_version: '4.2450.0',
      offline_minutes: 30,
      is_jailbroken: false
    });

    assert.equal(res.compliant, true);
    assert.equal(res.action, 'PIN_REQUIRED');
    assert.equal(res.clipboard_sharing_mode, 'POLICY_MANAGED_APPS_ONLY');
    assert.equal(res.prevent_save_as, true);
  });

  it('19. evaluateAppCompliance blocks unmanaged apps not in catalog', () => {
    const res = MamAppProtectionEngine.evaluateAppCompliance(db, {
      bundle_id: 'com.rogue.unmanaged.app',
      platform: 'IOS'
    });

    assert.equal(res.compliant, false);
    assert.equal(res.action, 'BLOCK');
    assert.equal(res.reason, 'UNMANAGED_APPLICATION');
  });

  it('20. evaluateAppCompliance triggers WIPE action on jailbroken device and detects pending wipe orders', () => {
    // Jailbroken test
    const jbRes = MamAppProtectionEngine.evaluateAppCompliance(db, {
      bundle_id: 'com.microsoft.Office.Outlook',
      is_jailbroken: true
    });
    assert.equal(jbRes.compliant, false);
    assert.equal(jbRes.action, 'WIPE');

    // Pending selective wipe test
    MamAppProtectionEngine.requestSelectiveWipe(db, {
      target_user_email: 'compromised.user@localpilot.corp'
    });

    const wipeRes = MamAppProtectionEngine.evaluateAppCompliance(db, {
      bundle_id: 'com.microsoft.Office.Outlook',
      user_email: 'compromised.user@localpilot.corp'
    });
    assert.equal(wipeRes.compliant, false);
    assert.equal(wipeRes.action, 'WIPE');
    assert.equal(wipeRes.reason, 'PENDING_SELECTIVE_WIPE');
  });
});
