import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb } from '../src/db.js';
import { DeclarativeDeviceManagementEngine } from '../src/services/declarativeDeviceManagementEngine.js';

describe('Apple Declarative Device Management (DDM) Engine (Iteration 70)', () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    initDb(db, { seed: true });
  });

  test('1. getDdmStats aggregates total declarations, manifests, devices, and type distribution', () => {
    const stats = DeclarativeDeviceManagementEngine.getDdmStats(db);
    assert.ok(stats);
    assert.strictEqual(stats.total_declarations >= 1, true);
    assert.strictEqual(stats.total_manifests >= 1, true);
    assert.strictEqual(stats.by_type.configuration >= 1, true);
  });

  test('2. getDdmStats handles empty database tables gracefully', () => {
    const emptyDb = new DatabaseSync(':memory:');
    initDb(emptyDb, { seed: false });
    const stats = DeclarativeDeviceManagementEngine.getDdmStats(emptyDb);
    assert.strictEqual(stats.total_declarations, 0);
    assert.strictEqual(stats.total_manifests, 0);
    assert.strictEqual(stats.total_status_reports, 0);
  });

  test('3. getDeclarations retrieves declarations and filters by declaration_type', () => {
    const configs = DeclarativeDeviceManagementEngine.getDeclarations(db, { declaration_type: 'configuration' });
    assert.ok(configs.length >= 1);
    assert.strictEqual(configs[0].declaration_type, 'configuration');

    const assets = DeclarativeDeviceManagementEngine.getDeclarations(db, { declaration_type: 'asset' });
    assert.strictEqual(assets.length, 0);
  });

  test('4. getDeclarations filters by is_active status', () => {
    const active = DeclarativeDeviceManagementEngine.getDeclarations(db, { is_active: true });
    assert.ok(active.length >= 1);
    const inactive = DeclarativeDeviceManagementEngine.getDeclarations(db, { is_active: false });
    assert.strictEqual(inactive.length, 0);
  });

  test('5. getDeclaration retrieves single declaration by ID and parses payload JSON', () => {
    const dec = DeclarativeDeviceManagementEngine.getDeclaration(db, 'ddm-dec-01');
    assert.ok(dec);
    assert.strictEqual(dec.id, 'ddm-dec-01');
    assert.strictEqual(typeof dec.payload, 'object');
    assert.strictEqual(dec.payload.minimum_length, 8);
  });

  test('6. getDeclaration retrieves declaration by reverse-DNS identifier', () => {
    const dec = DeclarativeDeviceManagementEngine.getDeclaration(db, 'com.localpilot.declaration.security.passcode');
    assert.ok(dec);
    assert.strictEqual(dec.id, 'ddm-dec-01');
    assert.strictEqual(dec.identifier, 'com.localpilot.declaration.security.passcode');
  });

  test('7. getDeclaration returns null for non-existent identifier', () => {
    const dec = DeclarativeDeviceManagementEngine.getDeclaration(db, 'non-existent-ident');
    assert.strictEqual(dec, null);
  });

  test('8. createDeclaration inserts new configuration declaration and generates server_token', () => {
    const newDec = DeclarativeDeviceManagementEngine.createDeclaration(db, {
      declaration_type: 'configuration',
      identifier: 'com.localpilot.declaration.network.wifi',
      payload: { ssid: 'Corporate-Secure-5G', encryption: 'WPA3-Enterprise' }
    });

    assert.ok(newDec);
    assert.strictEqual(newDec.identifier, 'com.localpilot.declaration.network.wifi');
    assert.ok(newDec.server_token.length > 0);
    assert.strictEqual(newDec.payload.ssid, 'Corporate-Secure-5G');
  });

  test('9. createDeclaration updates existing declaration on identifier conflict (idempotency)', () => {
    const updated = DeclarativeDeviceManagementEngine.createDeclaration(db, {
      declaration_type: 'configuration',
      identifier: 'com.localpilot.declaration.security.passcode',
      payload: { minimum_length: 12, require_alphanumeric: true }
    });

    assert.ok(updated);
    assert.strictEqual(updated.payload.minimum_length, 12);
  });

  test('10. createDeclaration throws on invalid declaration_type', () => {
    assert.throws(() => {
      DeclarativeDeviceManagementEngine.createDeclaration(db, {
        declaration_type: 'invalid_type',
        identifier: 'com.test.invalid'
      });
    }, /Invalid declaration_type/);
  });

  test('11. createDeclaration throws on missing identifier', () => {
    assert.throws(() => {
      DeclarativeDeviceManagementEngine.createDeclaration(db, {
        declaration_type: 'configuration'
      });
    }, /declaration_type and identifier are required/);
  });

  test('12. deleteDeclaration removes declaration and returns true', () => {
    const created = DeclarativeDeviceManagementEngine.createDeclaration(db, {
      declaration_type: 'activation',
      identifier: 'com.localpilot.activation.test',
      payload: { predicate: 'device.os.version >= 15' }
    });
    assert.ok(created);

    const deleted = DeclarativeDeviceManagementEngine.deleteDeclaration(db, created.id);
    assert.strictEqual(deleted, true);

    const check = DeclarativeDeviceManagementEngine.getDeclaration(db, created.id);
    assert.strictEqual(check, null);
  });

  test('13. deleteDeclaration returns false for invalid declaration ID', () => {
    const result = DeclarativeDeviceManagementEngine.deleteDeclaration(db, 'non-existent-id');
    assert.strictEqual(result, false);
  });

  test('14. assignDeclarationToDevice creates manifest record with PENDING status', () => {
    const manifest = DeclarativeDeviceManagementEngine.assignDeclarationToDevice(db, 'dev-daddy-pc', 'ddm-dec-01');
    assert.ok(manifest);
    assert.strictEqual(manifest.device_id, 'dev-daddy-pc');
    assert.strictEqual(manifest.declaration_id, 'ddm-dec-01');
    assert.strictEqual(manifest.sync_status, 'PENDING');
  });

  test('15. assignDeclarationToDevice throws when target declaration does not exist', () => {
    assert.throws(() => {
      DeclarativeDeviceManagementEngine.assignDeclarationToDevice(db, 'dev-daddy-pc', 'non-existent-dec');
    }, /not found/);
  });

  test('16. unassignDeclaration removes manifest entry', () => {
    const manifests = DeclarativeDeviceManagementEngine.getManifests(db, { device_id: 'dev-daddy-pc' });
    assert.ok(manifests.length >= 1);
    const targetId = manifests[0].id;

    const removed = DeclarativeDeviceManagementEngine.unassignDeclaration(db, targetId);
    assert.strictEqual(removed, true);
  });

  test('17. getDeviceTokens generates RFC DDM SyncTokens composite hash', () => {
    const tokens = DeclarativeDeviceManagementEngine.getDeviceTokens(db, 'dev-daddy-pc');
    assert.ok(tokens);
    assert.ok(tokens.SyncTokens);
    assert.ok(tokens.SyncTokens.DeclarationsToken);
    assert.strictEqual(typeof tokens.SyncTokens.DeclarationsToken, 'string');
    assert.ok(tokens.SyncTokens.Timestamp);
  });

  test('18. getDeviceDeclarationItemsManifest generates grouped declarations manifest for /declaration-items', () => {
    const manifest = DeclarativeDeviceManagementEngine.getDeviceDeclarationItemsManifest(db, 'dev-daddy-pc');
    assert.ok(manifest);
    assert.ok(manifest.Declarations);
    assert.ok(Array.isArray(manifest.Declarations.Configurations));
    assert.strictEqual(manifest.Declarations.Configurations.length >= 1, true);
    assert.strictEqual(manifest.Declarations.Configurations[0].Identifier, 'com.localpilot.declaration.security.passcode');
    assert.ok(Array.isArray(manifest.DeclarationIdentifiers));
    assert.ok(manifest.SyncTokens);
  });

  test('19. ingestStatusReport ingests status items and updates manifest status to SYNCHRONIZED', () => {
    const reportPayload = {
      StatusItems: {
        'device.battery.level': 0.88,
        'management.declarations.active': [
          'com.localpilot.declaration.security.passcode'
        ]
      }
    };

    const res = DeclarativeDeviceManagementEngine.ingestStatusReport(db, 'dev-daddy-pc', reportPayload);
    assert.ok(res);
    assert.strictEqual(res.ingested_count, 2);

    const manifests = DeclarativeDeviceManagementEngine.getManifests(db, { device_id: 'dev-daddy-pc' });
    const decManifest = manifests.find(m => m.identifier === 'com.localpilot.declaration.security.passcode');
    assert.ok(decManifest);
    assert.strictEqual(decManifest.sync_status, 'SYNCHRONIZED');
  });

  test('20. getDeviceAggregatedStatus consolidates latest status key-value pairs for device', () => {
    const statusMap = DeclarativeDeviceManagementEngine.getDeviceAggregatedStatus(db, 'dev-daddy-pc');
    assert.ok(statusMap);
    assert.ok(statusMap['device.operating-system.version']);
    assert.strictEqual(statusMap['device.operating-system.version'].value.version, '15.0');
  });
});
