import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { RansomwareCanaryEngine } from '../src/services/ransomwareCanaryEngine.js';

describe('Automated Ransomware Canary & File Integrity Trap Engine (Iteration 62)', () => {
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

  it('1. getCanaryStats returns correct aggregate metrics with default seeds', () => {
    const stats = RansomwareCanaryEngine.getCanaryStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalTraps, 'number');
    assert.ok(stats.totalTraps >= 3);
    assert.ok(stats.healthyTraps >= 3);
    assert.ok(stats.totalDetections >= 1);
    assert.ok(stats.containedIncidents >= 1);
    assert.ok(stats.activePolicies >= 1);
    assert.equal(stats.ransomwareOperational, true);
  });

  it('2. getCanaryStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = RansomwareCanaryEngine.getCanaryStats(emptyDb);
    assert.equal(stats.totalTraps, 0);
    assert.equal(stats.healthyTraps, 0);
    assert.equal(stats.totalDetections, 0);
    assert.equal(stats.activePolicies, 0);
    emptyDb.close();
  });

  it('3. getTraps retrieves traps with default ordering', () => {
    const traps = RansomwareCanaryEngine.getTraps(db);
    assert.ok(Array.isArray(traps));
    assert.ok(traps.length >= 3);
  });

  it('4. getTraps filters correctly by status', () => {
    const healthy = RansomwareCanaryEngine.getTraps(db, { status: 'HEALTHY' });
    assert.ok(healthy.length >= 3);
    assert.ok(healthy.every(t => t.status === 'HEALTHY'));
  });

  it('5. getTraps filters correctly by directory_path', () => {
    const docs = RansomwareCanaryEngine.getTraps(db, { directory_path: 'Documents' });
    assert.ok(docs.length >= 1);
    assert.ok(docs[0].directory_path.includes('Documents'));
  });

  it('6. getTrapById retrieves single trap with joined detections', () => {
    const trap = RansomwareCanaryEngine.getTrapById(db, 'rct-01');
    assert.ok(trap);
    assert.equal(trap.id, 'rct-01');
    assert.ok(Array.isArray(trap.detections));
    assert.ok(trap.detections.length >= 1);
  });

  it('7. getTrapById returns null for unknown ID', () => {
    const trap = RansomwareCanaryEngine.getTrapById(db, 'unknown-trap-xyz');
    assert.equal(trap, null);
  });

  it('8. deployTrap creates new canary file record with sha256 generation', () => {
    const created = RansomwareCanaryEngine.deployTrap(db, {
      id: 'rct-test-01',
      filename: 'Payroll_Salary_Archive_2026.xlsx',
      directory_path: 'C:\\Finance\\Payroll',
      baseline_entropy: 4.1
    });

    assert.ok(created);
    assert.equal(created.id, 'rct-test-01');
    assert.equal(created.filename, 'Payroll_Salary_Archive_2026.xlsx');
    assert.ok(created.original_sha256);
    assert.equal(created.status, 'HEALTHY');
  });

  it('9. deleteTrap removes trap and cascading detections', () => {
    RansomwareCanaryEngine.recordTamperDetection(db, {
      trap_id: 'rct-test-01',
      device_id: testDev.id,
      hostname: testDev.hostname,
      tamper_type: 'FILE_RENAME'
    });

    const deleted = RansomwareCanaryEngine.deleteTrap(db, 'rct-test-01');
    assert.equal(deleted, true);

    const check = RansomwareCanaryEngine.getTrapById(db, 'rct-test-01');
    assert.equal(check, null);

    const detections = RansomwareCanaryEngine.getTamperDetections(db, { trap_id: 'rct-test-01' });
    assert.equal(detections.length, 0);
  });

  it('10. deleteTrap returns false for non-existent trap', () => {
    const deleted = RansomwareCanaryEngine.deleteTrap(db, 'non-existent-rct');
    assert.equal(deleted, false);
  });

  it('11. verifyTrapHealth confirms healthy when sha256 and entropy match baseline', () => {
    const trap = RansomwareCanaryEngine.getTrapById(db, 'rct-02');
    const verified = RansomwareCanaryEngine.verifyTrapHealth(db, 'rct-02', trap.original_sha256, 4.3);
    assert.ok(verified);
    assert.equal(verified.status, 'HEALTHY');
  });

  it('12. verifyTrapHealth transitions status to TAMPERED when sha256 differs with low entropy', () => {
    const verified = RansomwareCanaryEngine.verifyTrapHealth(db, 'rct-02', 'altered_hash_123', 4.5);
    assert.ok(verified);
    assert.equal(verified.status, 'TAMPERED');
  });

  it('13. verifyTrapHealth transitions status to ENCRYPTED when entropy exceeds 7.5', () => {
    const verified = RansomwareCanaryEngine.verifyTrapHealth(db, 'rct-02', 'ransomware_encrypted_hash', 7.95);
    assert.ok(verified);
    assert.equal(verified.status, 'ENCRYPTED');

    // Revert status for clean state
    db.prepare("UPDATE ransomware_canary_traps SET status = 'HEALTHY' WHERE id = 'rct-02'").run();
  });

  it('14. verifyTrapHealth returns null for unknown trap ID', () => {
    const verified = RansomwareCanaryEngine.verifyTrapHealth(db, 'unknown-id-xyz');
    assert.equal(verified, null);
  });

  it('15. getTamperDetections retrieves detections with forensic details', () => {
    const detections = RansomwareCanaryEngine.getTamperDetections(db);
    assert.ok(Array.isArray(detections));
    assert.ok(detections.length >= 1);
    assert.equal(typeof detections[0].forensic_details, 'object');
  });

  it('16. getTamperDetections filters by device_id', () => {
    const detections = RansomwareCanaryEngine.getTamperDetections(db, { device_id: testDev.id });
    assert.ok(Array.isArray(detections));
    assert.ok(detections.every(d => d.device_id === testDev.id));
  });

  it('17. recordTamperDetection executes automated containment action from active policy', () => {
    const detection = RansomwareCanaryEngine.recordTamperDetection(db, {
      trap_id: 'rct-03',
      device_id: testDev.id,
      hostname: testDev.hostname,
      tamper_type: 'EXTENSION_CHANGE',
      detected_extension: '.blackcat',
      process_id: 6120,
      process_name: 'encrypter.exe',
      forensic_details: { entropy: 7.98 }
    });

    assert.ok(detection);
    assert.equal(detection.containment_action, 'ISOLATE_HOST');
  });

  it('18. recordTamperDetection marks target canary trap as ENCRYPTED', () => {
    const trap = RansomwareCanaryEngine.getTrapById(db, 'rct-03');
    assert.equal(trap.status, 'ENCRYPTED');
  });

  it('19. getPolicies and createPolicy manage ransomware response rules', () => {
    const policy = RansomwareCanaryEngine.createPolicy(db, {
      id: 'rcp-test-01',
      name: 'Custom Air-Gap Isolation Policy',
      auto_kill_process: 1,
      auto_isolate_network: 1,
      entropy_threshold: 7.5
    });

    assert.ok(policy);
    assert.equal(policy.id, 'rcp-test-01');

    const policies = RansomwareCanaryEngine.getPolicies(db);
    assert.ok(policies.length >= 2);

    const deleted = RansomwareCanaryEngine.deletePolicy(db, 'rcp-test-01');
    assert.equal(deleted, true);
  });

  it('20. generateDeployScript outputs valid PowerShell commands with trap paths and hashes', () => {
    const script = RansomwareCanaryEngine.generateDeployScript(db);
    assert.ok(script);
    assert.equal(script.script_type, 'POWERSHELL');
    assert.ok(script.script_content.includes('LocalPilot Fleet — Automated Ransomware Canary Deployment Script'));
    assert.ok(script.script_content.includes('Set-Content -Path $fullPath'));
  });
});
