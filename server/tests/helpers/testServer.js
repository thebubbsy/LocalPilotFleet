/**
 * LocalPilot Fleet — Test Server Harness
 * server/tests/helpers/testServer.js
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createServer } from '../../src/index.js';
import { initDb, applyPragmas } from '../../src/db.js';

export function createTestDb(options = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lpfleet-test-db-'));
  const dbPath = path.join(tmpDir, 'test_fleet.db');
  const db = new DatabaseSync(dbPath);

  applyPragmas(db);
  initDb(db, { seed: options.seed ?? true });

  return {
    db,
    dbPath,
    tmpDir,
    cleanup() {
      try {
        db.close();
      } catch (err) {}
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch (err) {}
    }
  };
}

export async function createTestApp(options = {}) {
  const testDb = createTestDb(options);
  const fleetKey = options.fleetKey || 'test-master-fleet-key-2026';

  // Instantiate server on port 0
  const server = createServer({
    db: testDb.db,
    fleetKey,
    port: 0,
    host: '127.0.0.1'
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    server,
    port,
    baseUrl,
    db: testDb.db,
    fleetKey,
    async cleanup() {
      await new Promise((resolve) => server.close(resolve));
      testDb.cleanup();
    }
  };
}
