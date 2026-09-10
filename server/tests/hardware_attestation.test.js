import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { HardwareAttestationEngine } from '../src/services/hardwareAttestationEngine.js';

describe('Hardware Supply Chain & TPM 2.0 / UEFI Measured Boot Attestation Engine (Iteration 64)', () => {
  let db;
  let testDev;

  before(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });

    testDev = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get();
    if (!testDev) {
      db.prepare(`
        INSERT INTO devices (id, hostname, os_name, os_version, total_ram_bytes, node_token_hash, agent_version)
        VALUES ('dev-test-01', 'TEST-HOST-01', 'Windows 11', '23H2', 17179869184, 'dummy_hash', '1.0.0')
      `).run();
      testDev = { id: 'dev-test-01', hostname: 'TEST-HOST-01' };
    }
  });

  after(() => {
    db.close();
  });

  it('1. getAttestationStats returns correct aggregate metrics with default seeds', () => {
    const stats = HardwareAttestationEngine.getAttestationStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalAttestedDevices, 'number');
    assert.ok(stats.totalAttestedDevices >= 1);
    assert.ok(stats.verifiedDevices >= 1);
    assert.equal(stats.componentMismatches, 0);
    assert.equal(stats.secureBootCompliancePct, 100);
    assert.equal(stats.dmaGuardCompliancePct, 100);
    assert.equal(stats.hvciCompliancePct, 100);
    assert.ok(stats.totalBootLogs >= 1);
    assert.equal(stats.pcrDriftsDetected, 0);
    assert.ok(stats.activePolicies >= 1);
    assert.equal(stats.attestationOperational, true);
  });

  it('2. getAttestationStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = HardwareAttestationEngine.getAttestationStats(emptyDb);
    assert.equal(stats.totalAttestedDevices, 0);
    assert.equal(stats.verifiedDevices, 0);
    assert.equal(stats.componentMismatches, 0);
    assert.equal(stats.totalBootLogs, 0);
    assert.equal(stats.activePolicies, 0);
    emptyDb.close();
  });

  it('3. getSupplyChainBaselines retrieves baselines with parsed DIMM and NVMe arrays', () => {
    const baselines = HardwareAttestationEngine.getSupplyChainBaselines(db);
    assert.ok(Array.isArray(baselines));
    assert.ok(baselines.length >= 1);
    assert.ok(Array.isArray(baselines[0].dimm_serials));
    assert.ok(Array.isArray(baselines[0].nvme_serials));
  });

  it('4. getSupplyChainBaselines filters by verified_status', () => {
    const verified = HardwareAttestationEngine.getSupplyChainBaselines(db, { verified_status: 'VERIFIED' });
    assert.ok(verified.length >= 1);
    assert.ok(verified.every(b => b.verified_status === 'VERIFIED'));
  });

  it('5. getSupplyChainBaselines filters by tpm_manufacturer', () => {
    const infineon = HardwareAttestationEngine.getSupplyChainBaselines(db, { tpm_manufacturer: 'Infineon' });
    assert.ok(infineon.length >= 1);
    assert.ok(infineon[0].tpm_manufacturer.includes('Infineon'));
  });

  it('6. getBaselineByDeviceId retrieves single baseline with joined latest measured boot log', () => {
    const baseline = HardwareAttestationEngine.getBaselineByDeviceId(db, testDev.id);
    assert.ok(baseline);
    assert.equal(baseline.device_id, testDev.id);
    assert.ok(baseline.latest_measured_boot);
    assert.equal(baseline.latest_measured_boot.attestation_result, 'PASSED');
  });

  it('7. getBaselineByDeviceId returns null for non-existent device', () => {
    const baseline = HardwareAttestationEngine.getBaselineByDeviceId(db, 'non-existent-device-xyz');
    assert.equal(baseline, null);
  });

  it('8. registerBaseline creates new hardware supply chain baseline', () => {
    // Insert a dummy second device
    db.prepare(`
      INSERT OR IGNORE INTO devices (id, hostname, os_name, os_version, total_ram_bytes, node_token_hash, agent_version)
      VALUES ('dev-test-02', 'TEST-HOST-02', 'Windows 11', '23H2', 17179869184, 'dummy_hash_2', '1.0.0')
    `).run();

    const created = HardwareAttestationEngine.registerBaseline(db, {
      device_id: 'dev-test-02',
      hostname: 'TEST-HOST-02',
      tpm_manufacturer: 'STMicroelectronics (STM)',
      tpm_spec_version: '2.0',
      motherboard_serial: 'MB-STM-77123',
      chassis_serial: 'CHS-SEC-02',
      dimm_serials: ['DIMM-CRUCIAL-101', 'DIMM-CRUCIAL-102'],
      nvme_serials: ['SAMSUNG-980PRO-5541'],
      secure_boot_enabled: 1,
      dma_guard_enabled: 1,
      hvci_code_integrity: 1
    });

    assert.ok(created);
    assert.equal(created.device_id, 'dev-test-02');
    assert.equal(created.tpm_manufacturer, 'STMicroelectronics (STM)');
    assert.equal(created.dimm_serials.length, 2);
  });

  it('9. registerBaseline updates existing baseline with new component serials', () => {
    const updated = HardwareAttestationEngine.registerBaseline(db, {
      device_id: 'dev-test-02',
      chassis_serial: 'CHS-SEC-02-UPGRADED'
    });

    assert.ok(updated);
    assert.equal(updated.chassis_serial, 'CHS-SEC-02-UPGRADED');
  });

  it('10. deleteBaseline removes baseline record', () => {
    const target = HardwareAttestationEngine.getBaselineByDeviceId(db, 'dev-test-02');
    assert.ok(target);

    const deleted = HardwareAttestationEngine.deleteBaseline(db, target.id);
    assert.equal(deleted, true);

    const check = HardwareAttestationEngine.getBaselineByDeviceId(db, 'dev-test-02');
    assert.equal(check, null);
  });

  it('11. deleteBaseline returns false for non-existent baseline ID', () => {
    const deleted = HardwareAttestationEngine.deleteBaseline(db, 'non-existent-hscb-id');
    assert.equal(deleted, false);
  });

  it('12. verifyHardwareComponents returns matches: true when all components match baseline', () => {
    const result = HardwareAttestationEngine.verifyHardwareComponents(db, testDev.id, {
      motherboard_serial: 'MB-LPT-998234-A',
      chassis_serial: 'CHS-CORP-SEC-01',
      dimm_serials: ['DIMM-SKH-8821092', 'DIMM-SKH-8821093'],
      nvme_serials: ['SNDK-NVME-991208']
    });

    assert.ok(result);
    assert.equal(result.matches, true);
    assert.equal(result.status, 'VERIFIED');
    assert.equal(result.mismatches.length, 0);
  });

  it('13. verifyHardwareComponents detects motherboard serial mismatch and updates status to COMPONENT_MISMATCH', () => {
    const result = HardwareAttestationEngine.verifyHardwareComponents(db, testDev.id, {
      motherboard_serial: 'ROGUE-MB-UNKNOWN-999',
      chassis_serial: 'CHS-CORP-SEC-01'
    });

    assert.ok(result);
    assert.equal(result.matches, false);
    assert.equal(result.status, 'COMPONENT_MISMATCH');
    assert.ok(result.mismatches.some(m => m.includes('Motherboard serial mismatch')));

    const baseline = HardwareAttestationEngine.getBaselineByDeviceId(db, testDev.id);
    assert.equal(baseline.verified_status, 'COMPONENT_MISMATCH');

    // Restore to VERIFIED for clean state
    db.prepare("UPDATE hardware_supply_chain_baselines SET verified_status = 'VERIFIED' WHERE device_id = ?").run(testDev.id);
  });

  it('14. verifyHardwareComponents detects swapped or missing RAM DIMMs', () => {
    const result = HardwareAttestationEngine.verifyHardwareComponents(db, testDev.id, {
      motherboard_serial: 'MB-LPT-998234-A',
      dimm_serials: ['DIMM-SKH-8821092', 'ROGUE-UNAPPROVED-RAM-99']
    });

    assert.ok(result);
    assert.equal(result.matches, false);
    assert.ok(result.mismatches.some(m => m.includes('RAM DIMM module swapped or missing')));

    db.prepare("UPDATE hardware_supply_chain_baselines SET verified_status = 'VERIFIED' WHERE device_id = ?").run(testDev.id);
  });

  it('15. verifyHardwareComponents detects unauthorized NVMe drive replacement', () => {
    const result = HardwareAttestationEngine.verifyHardwareComponents(db, testDev.id, {
      motherboard_serial: 'MB-LPT-998234-A',
      nvme_serials: ['UNAPPROVED-NVME-DRIVE']
    });

    assert.ok(result);
    assert.equal(result.matches, false);
    assert.ok(result.mismatches.some(m => m.includes('NVMe storage drive replaced or unauthorized')));

    db.prepare("UPDATE hardware_supply_chain_baselines SET verified_status = 'VERIFIED' WHERE device_id = ?").run(testDev.id);
  });

  it('16. verifyHardwareComponents returns error when device has no enrolled baseline', () => {
    const result = HardwareAttestationEngine.verifyHardwareComponents(db, 'non-enrolled-device', {
      motherboard_serial: 'ANY-MB'
    });

    assert.equal(result.matches, false);
    assert.equal(result.reason, 'NO_BASELINE');
  });

  it('17. getMeasuredBootLogs retrieves logs with parsed drift details', () => {
    const logs = HardwareAttestationEngine.getMeasuredBootLogs(db);
    assert.ok(Array.isArray(logs));
    assert.ok(logs.length >= 1);
    assert.equal(typeof logs[0].drift_details, 'object');
  });

  it('18. ingestMeasuredBootLog detects unauthorized PCR 0 (BIOS) hash drift and sets attestation_result to PCR_DRIFT_DETECTED', () => {
    const log = HardwareAttestationEngine.ingestMeasuredBootLog(db, {
      device_id: testDev.id,
      hostname: testDev.hostname,
      boot_session_id: 'boot-sess-unauth-tamper',
      pcr_0_bios_sha256: 'tampered_rogue_bios_code_sha256_hash_value_999999999999999999',
      pcr_7_secureboot_sha256: 'c8d7e6f5a4b3928170615243342516070123456789abcdef0123456789abcdef'
    });

    assert.ok(log);
    assert.equal(log.attestation_result, 'PCR_DRIFT_DETECTED');

    const logs = HardwareAttestationEngine.getMeasuredBootLogs(db, { attestation_result: 'PCR_DRIFT_DETECTED' });
    assert.ok(logs.length >= 1);
    assert.ok(logs[0].drift_details.pcr_0_drift);
  });

  it('19. getAttestationPolicies, createAttestationPolicy, deleteAttestationPolicy manage lifecycle', () => {
    const policy = HardwareAttestationEngine.createAttestationPolicy(db, {
      id: 'hap-test-01',
      name: 'Custom High-Security Attestation Guard',
      require_tpm_2_0: 1,
      require_secure_boot: 1,
      require_dma_protection: 1
    });

    assert.ok(policy);
    assert.equal(policy.id, 'hap-test-01');

    const list = HardwareAttestationEngine.getAttestationPolicies(db);
    assert.ok(list.length >= 2);

    const deleted = HardwareAttestationEngine.deleteAttestationPolicy(db, 'hap-test-01');
    assert.equal(deleted, true);
  });

  it('20. evaluateDeviceCompliance validates device against strict active policy and detects compliance violations', () => {
    const compliant = HardwareAttestationEngine.evaluateDeviceCompliance(db, testDev.id);
    assert.ok(compliant);
    assert.equal(compliant.compliant, true);

    // Simulate component mismatch violation
    db.prepare("UPDATE hardware_supply_chain_baselines SET verified_status = 'COMPONENT_MISMATCH' WHERE device_id = ?").run(testDev.id);
    const nonCompliant = HardwareAttestationEngine.evaluateDeviceCompliance(db, testDev.id);
    assert.equal(nonCompliant.compliant, false);
    assert.ok(nonCompliant.reasons.length >= 1);

    // Restore clean state
    db.prepare("UPDATE hardware_supply_chain_baselines SET verified_status = 'VERIFIED' WHERE device_id = ?").run(testDev.id);
  });
});
