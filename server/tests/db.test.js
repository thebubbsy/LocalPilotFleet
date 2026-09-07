/**
 * LocalPilot Fleet — Database Engine & Concurrency QA Tests
 * server/tests/db.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createTestDb } from './helpers/testServer.js';

describe('Database Engine & Concurrency QA (db.test.js)', () => {
  let harness;
  let db;

  before(() => {
    harness = createTestDb({ seed: true });
    db = harness.db;
  });

  after(() => {
    harness.cleanup();
  });

  describe('1. WAL Pragmas & Configuration', () => {
    it('enforces journal_mode = wal', () => {
      const row = db.prepare('PRAGMA journal_mode;').get();
      assert.equal(row.journal_mode, 'wal');
    });

    it('enforces synchronous = NORMAL (1)', () => {
      const row = db.prepare('PRAGMA synchronous;').get();
      assert.equal(row.synchronous, 1);
    });

    it('enforces foreign_keys = ON (1)', () => {
      const row = db.prepare('PRAGMA foreign_keys;').get();
      assert.equal(row.foreign_keys, 1);
    });

    it('enforces busy_timeout = 5000ms', () => {
      const row = db.prepare('PRAGMA busy_timeout;').get();
      assert.equal(row.timeout, 5000);
    });
  });

  describe('2. Schema Tables & Generated Columns', () => {
    const expectedTables = [
      'devices',
      'telemetry_snapshots',
      'dynamic_groups',
      'group_memberships',
      'software_catalog',
      'policy_assignments',
      'security_events',
      'fleet_settings',
      'device_commands'
    ];

    it('creates all 9 required tables', () => {
      const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';").all();
      const tableNames = rows.map(r => r.name);
      for (const table of expectedTables) {
        assert.ok(tableNames.includes(table), `Table ${table} should exist in database`);
      }
    });

    it('computes generated stored column total_ram_gb accurately', () => {
      const testDeviceId = 'ram-calc-test-node';
      const ram32GbBytes = 34359738368; // 32 * 1024^3
      db.prepare(`
        INSERT INTO devices (
          id, hostname, serial_number, os_name, os_version, total_ram_bytes, node_token_hash, agent_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(testDeviceId, 'RAM-TEST-PC', 'SN-RAM-001', 'Windows 11', '10.0.22631', ram32GbBytes, 'hash123', '1.0.0');

      const dev = db.prepare('SELECT total_ram_bytes, total_ram_gb FROM devices WHERE id = ?').get(testDeviceId);
      assert.equal(dev.total_ram_bytes, ram32GbBytes);
      assert.equal(dev.total_ram_gb, 32.0);

      // Clean up
      db.prepare('DELETE FROM devices WHERE id = ?').run(testDeviceId);
    });
  });

  describe('3. Database Indexes Verification', () => {
    const requiredIndexes = [
      'idx_devices_status',
      'idx_devices_last_seen',
      'idx_devices_hostname',
      'idx_devices_serial',
      'idx_devices_token_hash',
      'idx_telemetry_dev_time',
      'idx_telemetry_timestamp',
      'idx_dynamic_groups_priority',
      'idx_memberships_device',
      'idx_memberships_group',
      'idx_software_winget',
      'idx_policy_group',
      'idx_policy_software',
      'idx_events_device',
      'idx_events_sev_ack',
      'idx_events_created'
    ];

    it('contains all 16 required performance and constraint indexes', () => {
      const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%';").all();
      const indexNames = rows.map(r => r.name);
      for (const idx of requiredIndexes) {
        assert.ok(indexNames.includes(idx), `Index ${idx} should exist in schema`);
      }
    });
  });

  describe('4. Foreign Key Constraints & Cascading Deletions', () => {
    it('throws foreign key error when inserting child with non-existent parent', () => {
      assert.throws(() => {
        db.prepare(`
          INSERT INTO telemetry_snapshots (
            device_id, cpu_usage_percent, ram_used_bytes, ram_free_bytes, ram_usage_percent, disks_json
          ) VALUES (?, ?, ?, ?, ?, ?)
        `).run('non-existent-device-id', 12.5, 4000000000, 4000000000, 50.0, '[]');
      }, /FOREIGN KEY constraint failed/);
    });

    it('cascades deletion of device to telemetry, group memberships, and security events', () => {
      const devId = 'cascade-test-dev-01';
      // 1. Insert device
      db.prepare(`
        INSERT INTO devices (
          id, hostname, serial_number, os_name, os_version, total_ram_bytes, node_token_hash, agent_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(devId, 'CASCADE-PC', 'SN-CASCADE-001', 'Win 11', '10.0', 17179869184, 'hash_casc', '1.0.0');

      // 2. Insert telemetry snapshot
      db.prepare(`
        INSERT INTO telemetry_snapshots (
          device_id, cpu_usage_percent, ram_used_bytes, ram_free_bytes, ram_usage_percent, disks_json
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(devId, 25.0, 8000000000, 8000000000, 50.0, '[]');

      // 3. Insert group membership
      db.prepare(`
        INSERT INTO group_memberships (group_id, device_id) VALUES (?, ?)
      `).run('grp-all', devId);

      // 4. Insert security event
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_source, severity, summary, raw_payload_json
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(devId, 'USER_CREATED', 'Security', 'CRITICAL', 'User alert', '{}');

      // Verify records exist
      assert.equal(db.prepare('SELECT count(*) as c FROM telemetry_snapshots WHERE device_id = ?').get(devId).c, 1);
      assert.equal(db.prepare('SELECT count(*) as c FROM group_memberships WHERE device_id = ?').get(devId).c, 1);
      assert.equal(db.prepare('SELECT count(*) as c FROM security_events WHERE device_id = ?').get(devId).c, 1);

      // 5. Delete device
      db.prepare('DELETE FROM devices WHERE id = ?').run(devId);

      // Verify cascaded deletion
      assert.equal(db.prepare('SELECT count(*) as c FROM telemetry_snapshots WHERE device_id = ?').get(devId).c, 0);
      assert.equal(db.prepare('SELECT count(*) as c FROM group_memberships WHERE device_id = ?').get(devId).c, 0);
      assert.equal(db.prepare('SELECT count(*) as c FROM security_events WHERE device_id = ?').get(devId).c, 0);
    });
  });

  describe('5. Migration & DDL Idempotency', () => {
    it('executing schema creation repeatedly does not fail or erase existing records', () => {
      const devCountBefore = db.prepare('SELECT count(*) as c FROM devices;').get().c;
      assert.ok(devCountBefore >= 0);

      // Re-run DDL statements
      const ddl = `
        CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY NOT NULL);
        CREATE TABLE IF NOT EXISTS dynamic_groups (id TEXT PRIMARY KEY NOT NULL);
      `;
      assert.doesNotThrow(() => {
        db.exec(ddl);
      });

      const devCountAfter = db.prepare('SELECT count(*) as c FROM devices;').get().c;
      assert.equal(devCountAfter, devCountBefore);
    });
  });

  describe('6. WAL Concurrency & Snapshot Isolation QA', () => {
    it('concurrent connection reads uncommitted write snapshot without blocking', () => {
      const dbPath = harness.dbPath;
      const connA = new DatabaseSync(dbPath);
      const connB = new DatabaseSync(dbPath);
      connA.exec('PRAGMA busy_timeout = 5000;');
      connB.exec('PRAGMA busy_timeout = 5000;');

      const testDevId = 'wal-concur-dev';
      connA.prepare(`
        INSERT INTO devices (
          id, hostname, serial_number, os_name, os_version, total_ram_bytes, status, node_token_hash, agent_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(testDevId, 'CONCUR-PC', 'SN-CONCUR-001', 'Win 11', '10.0', 16000000000, 'online', 'h1', '1.0.0');

      // Verify connB sees 'online'
      assert.equal(connB.prepare('SELECT status FROM devices WHERE id = ?').get(testDevId).status, 'online');

      // ConnA begins immediate transaction and updates status to 'drifted'
      connA.exec('BEGIN IMMEDIATE;');
      connA.prepare('UPDATE devices SET status = ? WHERE id = ?').run('drifted', testDevId);

      // ConnB reads while ConnA transaction is still UNCOMMITTED (Snapshot isolation)
      const connBView = connB.prepare('SELECT status FROM devices WHERE id = ?').get(testDevId);
      assert.equal(connBView.status, 'online', 'ConnB must see committed snapshot (online) while ConnA writes');

      // ConnA commits
      connA.exec('COMMIT;');

      // ConnB now sees 'drifted'
      assert.equal(connB.prepare('SELECT status FROM devices WHERE id = ?').get(testDevId).status, 'drifted');

      // Cleanup
      connA.prepare('DELETE FROM devices WHERE id = ?').run(testDevId);
      connA.close();
      connB.close();
    });
  });

  describe('7. O(1) Telemetry Ingestion Benchmark', () => {
    it('maintains sub-5ms average latency for snapshot insert and device update in WAL mode', () => {
      const benchDevId = 'bench-target-node';
      db.prepare(`
        INSERT INTO devices (
          id, hostname, serial_number, os_name, os_version, total_ram_bytes, status, node_token_hash, agent_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(benchDevId, 'BENCH-PC', 'SN-BENCH-001', 'Win 11', '10.0', 32000000000, 'online', 'h_bench', '1.0.0');

      const insertStmt = db.prepare(`
        INSERT INTO telemetry_snapshots (
          device_id, cpu_usage_percent, ram_used_bytes, ram_free_bytes, ram_usage_percent, disks_json, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const updateStmt = db.prepare(`
        UPDATE devices SET status = ?, last_seen_at = ? WHERE id = ?
      `);

      const iterations = 100;
      const latencies = [];

      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        db.exec('BEGIN IMMEDIATE;');
        insertStmt.run(benchDevId, 15.2, 16000000000, 16000000000, 50.0, '[]', new Date().toISOString());
        updateStmt.run('online', new Date().toISOString(), benchDevId);
        db.exec('COMMIT;');
        const duration = performance.now() - start;
        latencies.push(duration);
      }

      const avgLatency = latencies.reduce((sum, val) => sum + val, 0) / latencies.length;
      const maxLatency = Math.max(...latencies);

      // Assert SLA: Average ingest latency strictly under 5ms
      assert.ok(avgLatency < 5.0, `Average ingest latency (${avgLatency.toFixed(3)}ms) must be < 5.0ms`);
      assert.ok(maxLatency < 25.0, `Max ingest latency (${maxLatency.toFixed(3)}ms) must be < 25.0ms`);

      // Clean up
      db.prepare('DELETE FROM devices WHERE id = ?').run(benchDevId);
    });
  });
});
