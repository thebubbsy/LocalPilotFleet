import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { UebaEngine } from '../src/services/uebaEngine.js';

describe('User & Entity Behavior Analytics (UEBA) & Insider Risk Engine (Iteration 60)', () => {
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

  it('1. getUebaStats returns correct aggregate structure with default seeds', () => {
    const stats = UebaEngine.getUebaStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalIndicators, 'number');
    assert.ok(stats.totalIndicators >= 4);
    assert.ok(stats.activeIndicators >= 4);
    assert.ok(stats.totalAnomalies >= 1);
    assert.ok(stats.highRiskUsersCount >= 1);
    assert.ok(stats.flightRiskUsersCount >= 1);
    assert.equal(stats.uebaOperational, true);
    assert.equal(typeof stats.meanUserRiskScore, 'number');
  });

  it('2. getUebaStats handles empty database safely with 0 risk defaults', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = UebaEngine.getUebaStats(emptyDb);
    assert.equal(stats.totalIndicators, 0);
    assert.equal(stats.totalAnomalies, 0);
    assert.equal(stats.highRiskUsersCount, 0);
    assert.equal(stats.flightRiskUsersCount, 0);
    assert.equal(stats.meanUserRiskScore, 0.0);
    emptyDb.close();
  });

  it('3. getRiskIndicators retrieves catalog sorted by risk_weight', () => {
    const indicators = UebaEngine.getRiskIndicators(db);
    assert.ok(Array.isArray(indicators));
    assert.ok(indicators.length >= 4);
    assert.ok(indicators[0].risk_weight >= indicators[indicators.length - 1].risk_weight);
  });

  it('4. getRiskIndicators filters correctly by category', () => {
    const dataExfil = UebaEngine.getRiskIndicators(db, { category: 'DATA_EXFILTRATION' });
    assert.ok(dataExfil.length >= 1);
    assert.ok(dataExfil.every(i => i.category === 'DATA_EXFILTRATION'));
  });

  it('5. getRiskIndicators filters correctly by severity', () => {
    const high = UebaEngine.getRiskIndicators(db, { severity: 'HIGH' });
    assert.ok(high.length >= 1);
    assert.ok(high.every(i => i.severity === 'HIGH'));
  });

  it('6. getRiskIndicatorById retrieves single indicator', () => {
    const indicator = UebaEngine.getRiskIndicatorById(db, 'uri-01');
    assert.ok(indicator);
    assert.equal(indicator.indicator_name, 'MASS_FILE_EXFILTRATION_SPIKE');
  });

  it('7. getRiskIndicatorById returns null for unknown ID', () => {
    const indicator = UebaEngine.getRiskIndicatorById(db, 'unknown-uri-xyz');
    assert.equal(indicator, null);
  });

  it('8. createRiskIndicator persists new indicator with uppercase name', () => {
    const created = UebaEngine.createRiskIndicator(db, {
      id: 'uri-test-01',
      indicator_name: 'test_ransomware_mass_rename',
      category: 'RESOURCE_SNOOPING',
      description: 'Rapid mass file extensions rename',
      risk_weight: 40,
      threshold_value: 5.0,
      severity: 'CRITICAL'
    });

    assert.ok(created);
    assert.equal(created.id, 'uri-test-01');
    assert.equal(created.indicator_name, 'TEST_RANSOMWARE_MASS_RENAME');
    assert.equal(created.risk_weight, 40);
  });

  it('9. updateRiskIndicator updates weight and threshold', () => {
    const updated = UebaEngine.updateRiskIndicator(db, 'uri-test-01', {
      risk_weight: 45,
      threshold_value: 6.0
    });

    assert.ok(updated);
    assert.equal(updated.risk_weight, 45);
    assert.equal(updated.threshold_value, 6.0);
  });

  it('10. updateRiskIndicator returns null for unknown ID', () => {
    const updated = UebaEngine.updateRiskIndicator(db, 'non-existent-uri', { risk_weight: 20 });
    assert.equal(updated, null);
  });

  it('11. deleteRiskIndicator removes indicator successfully', () => {
    const deleted = UebaEngine.deleteRiskIndicator(db, 'uri-test-01');
    assert.equal(deleted, true);

    const check = UebaEngine.getRiskIndicatorById(db, 'uri-test-01');
    assert.equal(check, null);
  });

  it('12. deleteRiskIndicator returns false for non-existent indicator', () => {
    const deleted = UebaEngine.deleteRiskIndicator(db, 'unknown-uri-404');
    assert.equal(deleted, false);
  });

  it('13. getBehaviorAnomalies returns anomaly records and parses details_json', () => {
    const anomalies = UebaEngine.getBehaviorAnomalies(db);
    assert.ok(Array.isArray(anomalies));
    assert.ok(anomalies.length >= 1);
    assert.equal(typeof anomalies[0].details, 'object');
  });

  it('14. getBehaviorAnomalies filters by user_principal', () => {
    const anomalies = UebaEngine.getBehaviorAnomalies(db, { user_principal: 'alex.mercer@corp.local' });
    assert.ok(anomalies.length >= 1);
    assert.ok(anomalies.every(a => a.user_principal === 'alex.mercer@corp.local'));
  });

  it('15. recordBehaviorAnomaly calculates deviation score when baseline provided', () => {
    const anomaly = UebaEngine.recordBehaviorAnomaly(db, {
      user_principal: 'john.doe@corp.local',
      device_id: testDev.id,
      hostname: testDev.hostname,
      indicator_id: 'uri-02',
      anomaly_type: 'ANOMALOUS_AFTER_HOURS_LOGON',
      observed_value: 4.0,
      baseline_value: 1.0,
      details: { logon_time: '03:15:00 AM' }
    });

    assert.ok(anomaly);
    assert.equal(anomaly.deviation_score, 4.0);
    assert.equal(anomaly.user_principal, 'john.doe@corp.local');
  });

  it('16. recordBehaviorAnomaly recalculates user risk profile and elevates risk_level', () => {
    const profile = UebaEngine.getUserRiskProfile(db, 'john.doe@corp.local');
    assert.ok(profile);
    assert.ok(profile.composite_risk_score > 0);
    assert.equal(profile.anomalies_count, 1);
  });

  it('17. recalculateUserRisk caps composite risk score at 100', () => {
    // Add multiple high-weight critical anomalies for john.doe
    UebaEngine.recordBehaviorAnomaly(db, {
      user_principal: 'john.doe@corp.local',
      device_id: testDev.id,
      hostname: testDev.hostname,
      indicator_id: 'uri-01',
      anomaly_type: 'MASS_FILE_EXFILTRATION_SPIKE',
      observed_value: 5000.0,
      baseline_value: 50.0
    });

    UebaEngine.recordBehaviorAnomaly(db, {
      user_principal: 'john.doe@corp.local',
      device_id: testDev.id,
      hostname: testDev.hostname,
      indicator_id: 'uri-03',
      anomaly_type: 'PRIVILEGE_CREEP_ABUSE',
      observed_value: 10.0,
      baseline_value: 1.0
    });

    const profile = UebaEngine.getUserRiskProfile(db, 'john.doe@corp.local');
    assert.equal(profile.composite_risk_score, 100);
    assert.equal(profile.risk_level, 'CRITICAL');
  });

  it('18. updateAnomalyStatus transitions status and dynamically recalculates user risk', () => {
    const anomalies = UebaEngine.getBehaviorAnomalies(db, { user_principal: 'john.doe@corp.local' });
    assert.ok(anomalies.length >= 2);

    // Resolve all anomalies for john.doe
    for (const a of anomalies) {
      UebaEngine.updateAnomalyStatus(db, a.id, 'RESOLVED');
    }

    const profile = UebaEngine.getUserRiskProfile(db, 'john.doe@corp.local');
    assert.equal(profile.composite_risk_score, 0);
    assert.equal(profile.risk_level, 'LOW');
  });

  it('19. getUserRiskProfiles filters by risk_level', () => {
    const highProfiles = UebaEngine.getUserRiskProfiles(db, { risk_level: 'HIGH' });
    assert.ok(highProfiles.length >= 1);
    assert.ok(highProfiles.every(p => p.risk_level === 'HIGH'));
  });

  it('20. updateUserContainment changes containment status to RESTRICTED or CONTAINED', () => {
    const updated = UebaEngine.updateUserContainment(db, 'alex.mercer@corp.local', 'CONTAINED');
    assert.ok(updated);
    assert.equal(updated.containment_status, 'CONTAINED');

    const queried = UebaEngine.getUserRiskProfile(db, 'alex.mercer@corp.local');
    assert.equal(queried.containment_status, 'CONTAINED');
  });
});
