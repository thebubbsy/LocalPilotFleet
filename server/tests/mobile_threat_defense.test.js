/**
 * LocalPilot Fleet — Mobile Threat Defense (MTD) & Device Risk Posture Tests (Iteration 69)
 * server/tests/mobile_threat_defense.test.js
 *
 * Validates real-time OS-level threat signal ingestion (jailbreak / root detection,
 * SELinux permissive mode, SIP tampering, sideloaded app analysis), dynamic device
 * risk scoring, compliance policy evaluation, and automated remediation orchestration.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { MobileThreatDefenseEngine } from '../src/services/mobileThreatDefenseEngine.js';

describe('Mobile Threat Defense (MTD) & Risk Posture Engine (Iteration 69)', () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });
  });

  afterEach(() => {
    if (db) db.close();
  });

  it('1. getMtdStats aggregates total signals, active signals, critical signals, and policies', () => {
    const stats = MobileThreatDefenseEngine.getMtdStats(db);
    assert.ok(stats.total_threat_signals >= 1);
    assert.ok(stats.active_threat_signals >= 1);
    assert.ok(stats.critical_threat_signals >= 1);
    assert.ok(stats.total_policies >= 1);
    assert.ok(stats.active_policies >= 1);
    assert.ok(stats.total_remediations >= 1);
  });

  it('2. getMtdStats handles empty database tables gracefully', () => {
    const emptyDb = new DatabaseSync(':memory:');
    emptyDb.exec(`
      CREATE TABLE mtd_device_threat_signals (id TEXT, status TEXT, threat_level TEXT, device_id TEXT);
      CREATE TABLE mtd_risk_compliance_policies (id TEXT, is_active INT);
      CREATE TABLE mtd_remediation_actions (id TEXT);
    `);
    const stats = MobileThreatDefenseEngine.getMtdStats(emptyDb);
    assert.equal(stats.total_threat_signals, 0);
    assert.equal(stats.active_threat_signals, 0);
    assert.equal(stats.total_policies, 0);
    assert.equal(stats.total_remediations, 0);
    emptyDb.close();
  });

  it('3. getThreatSignals retrieves signals and filters by device_id and status', () => {
    const signals = MobileThreatDefenseEngine.getThreatSignals(db, { status: 'ACTIVE' });
    assert.ok(signals.length >= 1);
    assert.equal(signals[0].status, 'ACTIVE');
    assert.ok(signals[0].threat_details);
  });

  it('4. getThreatSignals filters by threat_level', () => {
    const critical = MobileThreatDefenseEngine.getThreatSignals(db, { threat_level: 'CRITICAL' });
    assert.ok(critical.length >= 1);
    assert.ok(critical.every(s => s.threat_level === 'CRITICAL'));

    const informational = MobileThreatDefenseEngine.getThreatSignals(db, { threat_level: 'INFORMATIONAL' });
    assert.equal(informational.length, 0);
  });

  it('5. getSignal retrieves single threat signal with parsed threat_details object', () => {
    const sig = MobileThreatDefenseEngine.getSignal(db, 'mtd-sig-01');
    assert.ok(sig);
    assert.equal(sig.id, 'mtd-sig-01');
    assert.equal(sig.signal_type, 'JAILBREAK_DETECTED');
    assert.equal(typeof sig.threat_details, 'object');
    assert.ok(sig.threat_details.indicator);
  });

  it('6. getSignal returns null for non-existent signal ID', () => {
    const notFound = MobileThreatDefenseEngine.getSignal(db, 'non-existent-signal');
    assert.equal(notFound, null);
  });

  it('7. ingestThreatSignal records new signal and calculates live risk evaluation', () => {
    const result = MobileThreatDefenseEngine.ingestThreatSignal(db, {
      device_id: 'dev-daddy-pc',
      signal_type: 'ROOT_DETECTED',
      threat_level: 'CRITICAL',
      threat_details: { binary: '/system/xbin/su', su_version: '2.82-SR5' }
    });

    assert.ok(result.signal.id);
    assert.equal(result.signal.signal_type, 'ROOT_DETECTED');
    assert.equal(result.signal.threat_level, 'CRITICAL');
    assert.equal(result.risk_evaluation.risk_level, 'CRITICAL');
  });

  it('8. ingestThreatSignal automatically triggers compliance remediation when policy violated', () => {
    const result = MobileThreatDefenseEngine.ingestThreatSignal(db, {
      device_id: 'dev-daddy-pc',
      signal_type: 'DEBUGGER_ATTACHED',
      threat_level: 'HIGH',
      threat_details: { process_id: 1337, debugger: 'lldb' }
    });

    assert.equal(result.remediation_triggered, true);
    assert.ok(result.remediation);
    assert.equal(result.remediation.action_type, 'TRIGGER_MAM_SELECTIVE_WIPE');
    assert.equal(result.remediation.device_id, 'dev-daddy-pc');
  });

  it('9. ingestThreatSignal throws when required parameters are missing', () => {
    assert.throws(() => {
      MobileThreatDefenseEngine.ingestThreatSignal(db, { signal_type: 'ROOT_DETECTED', threat_level: 'CRITICAL' });
    }, /device_id is required/);

    assert.throws(() => {
      MobileThreatDefenseEngine.ingestThreatSignal(db, { device_id: 'dev-daddy-pc', threat_level: 'CRITICAL' });
    }, /signal_type is required/);

    assert.throws(() => {
      MobileThreatDefenseEngine.ingestThreatSignal(db, { device_id: 'dev-daddy-pc', signal_type: 'ROOT_DETECTED' });
    }, /threat_level is required/);
  });

  it('10. resolveThreatSignal transitions signal to RESOLVED with notes and timestamp', () => {
    const resolved = MobileThreatDefenseEngine.resolveThreatSignal(db, 'mtd-sig-01', 'Device re-flashed with stock firmware');
    assert.ok(resolved);
    assert.equal(resolved.status, 'RESOLVED');
    assert.equal(resolved.threat_details.resolution_notes, 'Device re-flashed with stock firmware');
    assert.ok(resolved.resolved_at);

    // Verify persisted state
    const fetched = MobileThreatDefenseEngine.getSignal(db, 'mtd-sig-01');
    assert.equal(fetched.status, 'RESOLVED');
  });

  it('11. resolveThreatSignal returns null for invalid signal ID', () => {
    const res = MobileThreatDefenseEngine.resolveThreatSignal(db, 'non-existent-id');
    assert.equal(res, null);
  });

  it('12. calculateDeviceRiskScore returns CRITICAL when active critical threat exists', () => {
    const evaluation = MobileThreatDefenseEngine.calculateDeviceRiskScore(db, 'dev-daddy-pc');
    assert.equal(evaluation.risk_level, 'CRITICAL');
    assert.ok(evaluation.active_signals_count >= 1);
  });

  it('13. calculateDeviceRiskScore returns SECURE when device has zero active threats', () => {
    const evaluation = MobileThreatDefenseEngine.calculateDeviceRiskScore(db, 'clean-device-123');
    assert.equal(evaluation.risk_level, 'SECURE');
    assert.equal(evaluation.active_signals_count, 0);
  });

  it('14. getPolicies retrieves compliance policies and filters by target_platform', () => {
    const policies = MobileThreatDefenseEngine.getPolicies(db, { target_platform: 'COMBINED' });
    assert.ok(policies.length >= 1);
    assert.equal(policies[0].id, 'mtd-pol-01');
    assert.equal(policies[0].auto_remediation_action, 'TRIGGER_MAM_SELECTIVE_WIPE');
  });

  it('15. createPolicy inserts new compliance policy with auto_remediation_action', () => {
    const policy = MobileThreatDefenseEngine.createPolicy(db, {
      name: 'Strict Windows Isolation Policy',
      max_allowed_risk_level: 'SECURE',
      target_platform: 'WINDOWS',
      auto_remediation_action: 'QUARANTINE_DEVICE'
    });

    assert.ok(policy.id);
    assert.equal(policy.name, 'Strict Windows Isolation Policy');
    assert.equal(policy.max_allowed_risk_level, 'SECURE');
    assert.equal(policy.target_platform, 'WINDOWS');
    assert.equal(policy.auto_remediation_action, 'QUARANTINE_DEVICE');
  });

  it('16. createPolicy throws error when policy name is missing', () => {
    assert.throws(() => {
      MobileThreatDefenseEngine.createPolicy(db, { target_platform: 'IOS' });
    }, /Policy name is required/);
  });

  it('17. deletePolicy removes policy and returns true', () => {
    const created = MobileThreatDefenseEngine.createPolicy(db, {
      name: 'Temp Policy',
      target_platform: 'ANDROID'
    });

    const deleted = MobileThreatDefenseEngine.deletePolicy(db, created.id);
    assert.equal(deleted, true);

    const check = MobileThreatDefenseEngine.getPolicy(db, created.id);
    assert.equal(check, null);

    const falseRes = MobileThreatDefenseEngine.deletePolicy(db, 'non-existent-pol');
    assert.equal(falseRes, false);
  });

  it('18. getRemediations lists remediation actions and filters by device_id', () => {
    const remediations = MobileThreatDefenseEngine.getRemediations(db);
    assert.ok(remediations.length >= 1);
    assert.equal(remediations[0].id, 'mtd-rem-01');
    assert.equal(remediations[0].status, 'EXECUTED');
    assert.ok(remediations[0].action_details);
  });

  it('19. dispatchRemediation records manual remediation action', () => {
    const rem = MobileThreatDefenseEngine.dispatchRemediation(db, {
      device_id: 'dev-daddy-pc',
      action_type: 'BLOCK_ACCESS',
      action_details: { reason: 'Manual quarantine by SecOps administrator' }
    });

    assert.ok(rem.id);
    assert.equal(rem.device_id, 'dev-daddy-pc');
    assert.equal(rem.action_type, 'BLOCK_ACCESS');
    assert.equal(rem.status, 'EXECUTED');
  });

  it('20. evaluateDevicePosture evaluates agent telemetry and flags non-compliance', () => {
    const postureResult = MobileThreatDefenseEngine.evaluateDevicePosture(db, 'dev-daddy-pc', {
      is_jailbroken: true,
      detection_indicator: 'unc0ver jailbreak artifacts in /bin',
      selinux_mode: 'PERMISSIVE',
      sip_enabled: false,
      sideloaded_apps: ['com.malicious.payload']
    });

    assert.equal(postureResult.compliant, false);
    assert.equal(postureResult.risk_level, 'CRITICAL');
    assert.ok(postureResult.violations.length >= 3);
  });
});
