import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, seedDatabase } from '../src/db.js';
import * as supervisorEngine from '../src/services/supervisorEngine.js';

describe('Agent Architecture & Host Execution Model (Dimension 1)', () => {
  let db;

  beforeEach(() => {
    db = initDb(':memory:', { seed: false });
    seedDatabase(db);
  });

  test('SUP-01: should initialize supervisor tables and retrieve initial fleet supervisor stats', () => {
    const stats = supervisorEngine.getSupervisorStats(db);
    assert.ok(stats);
    assert.strictEqual(typeof stats.total_supervisors, 'number');
    assert.strictEqual(typeof stats.running_supervisors, 'number');
    assert.strictEqual(typeof stats.quota_compliance_percent, 'number');
    assert.strictEqual(stats.status, 'SUPERVISED_OPERATIONAL');
  });

  test('SUP-02: should register a native Windows Service supervisor for a device', () => {
    const sup = supervisorEngine.registerSupervisor(db, {
      deviceId: 'dev-livingroom-pc',
      serviceName: 'LocalPilotHostSvc',
      supervisorPid: 5012,
      workerPid: 5016,
      watchdogPid: 5020,
      cpuLimitPercent: 5,
      ramLimitMb: 150,
      jobObjectActive: 1
    });

    assert.ok(sup);
    assert.strictEqual(sup.device_id, 'dev-livingroom-pc');
    assert.strictEqual(sup.service_status, 'RUNNING');
    assert.strictEqual(sup.cpu_limit_percent, 5);
    assert.strictEqual(sup.ram_limit_mb, 150);
    assert.strictEqual(sup.job_object_active, 1);
  });

  test('SUP-03: should update supervisor heartbeat and worker PIDs', () => {
    const ok = supervisorEngine.heartbeatSupervisor(db, {
      deviceId: 'dev-daddy-pc',
      workerPid: 9912,
      status: 'RUNNING'
    });

    assert.strictEqual(ok, true);
    const updated = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(updated.worker_pid, 9912);
    assert.ok(updated.last_watchdog_ping);
  });

  test('SUP-04: should record crash dump and increment crash counter', () => {
    const initial = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    const initialCount = initial ? initial.crash_count : 0;

    const crash = supervisorEngine.recordCrashDump(db, {
      deviceId: 'dev-daddy-pc',
      crashType: 'UNHANDLED_EXCEPTION',
      exitCode: 1,
      exceptionMessage: 'NullReferenceException at Invoke-LocalPilotAgent line 124',
      recoveryAction: 'RESTARTED_WORKER',
      recoveryDurationMs: 850
    });

    assert.ok(crash);
    assert.strictEqual(crash.device_id, 'dev-daddy-pc');
    assert.strictEqual(crash.crash_type, 'UNHANDLED_EXCEPTION');
    assert.strictEqual(crash.recovery_duration_ms, 850);

    const updated = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(updated.crash_count, initialCount + 1);
  });

  test('SUP-05: should transition supervisor to CRASH_LOOP when crash count reaches threshold', () => {
    for (let i = 0; i < 5; i++) {
      supervisorEngine.recordCrashDump(db, {
        deviceId: 'dev-daddy-pc',
        crashType: 'WATCHDOG_TIMEOUT',
        exitCode: 1067
      });
    }

    const sup = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(sup.service_status, 'CRASH_LOOP');
  });

  test('SUP-06: should query supervisors filtered by service status', () => {
    const running = supervisorEngine.getSupervisors(db, { status: 'RUNNING' });
    assert.ok(running.length > 0);
    assert.strictEqual(running.every(s => s.service_status === 'RUNNING'), true);
  });

  test('SUP-07: should retrieve supervisor by specific device_id', () => {
    const sup = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.ok(sup);
    assert.strictEqual(sup.device_id, 'dev-daddy-pc');
    assert.strictEqual(sup.hostname, 'DADDY-RIG');
  });

  test('SUP-08: should update Job Object resource quotas', () => {
    const ok = supervisorEngine.updateResourceQuotas(db, {
      deviceId: 'dev-daddy-pc',
      cpuLimitPercent: 3,
      ramLimitMb: 120,
      jobObjectActive: 1
    });

    assert.strictEqual(ok, true);
    const updated = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(updated.cpu_limit_percent, 3);
    assert.strictEqual(updated.ram_limit_mb, 120);
  });

  test('SUP-09: should enforce 5% CPU and 150MB RAM defaults in supervisor registration', () => {
    const sup = supervisorEngine.registerSupervisor(db, {
      deviceId: 'dev-livingroom-pc'
    });

    assert.strictEqual(sup.cpu_limit_percent, 5);
    assert.strictEqual(sup.ram_limit_mb, 150);
  });

  test('SUP-10: should query crash dumps with device metadata join', () => {
    const dumps = supervisorEngine.getCrashDumps(db);
    assert.ok(dumps.length > 0);
    assert.ok(dumps[0].hostname);
  });

  test('SUP-11: should filter crash dumps by crash_type', () => {
    const dumps = supervisorEngine.getCrashDumps(db, { crashType: 'TERMINATED_BY_USER' });
    assert.ok(dumps.length > 0);
    assert.strictEqual(dumps[0].crash_type, 'TERMINATED_BY_USER');
  });

  test('SUP-12: should calculate mean, min, and max crash recovery durations', () => {
    const stats = supervisorEngine.getSupervisorStats(db);
    assert.strictEqual(typeof stats.mean_recovery_duration_ms, 'number');
    assert.ok(stats.max_recovery_duration_ms >= stats.min_recovery_duration_ms);
  });

  test('SUP-13: should calculate Job Object quota compliance percentage across active fleet', () => {
    const stats = supervisorEngine.getSupervisorStats(db);
    assert.strictEqual(typeof stats.quota_compliance_percent, 'number');
    assert.ok(stats.quota_compliance_percent >= 0 && stats.quota_compliance_percent <= 100);
  });

  test('SUP-14: should generate valid supervisor PowerShell startup script with Job Object interop', () => {
    const script = supervisorEngine.generateSupervisorScript({
      deviceId: 'test-device-id',
      cpuLimit: 5,
      ramLimitMb: 150
    });

    assert.ok(script);
    assert.ok(script.includes('JobObjectNative'));
    assert.ok(script.includes('CreateJobObject'));
    assert.ok(script.includes('AssignProcessToJobObject'));
    assert.ok(script.includes('5% CPU, 150MB RAM'));
  });

  test('SUP-15: should verify P/Invoke definitions for SetInformationJobObject and AssignProcessToJobObject', () => {
    const script = supervisorEngine.generateSupervisorScript();
    assert.ok(script.includes('SetInformationJobObject'));
    assert.ok(script.includes('JOBOBJECT_CPU_RATE_CONTROL_INFORMATION'));
    assert.ok(script.includes('JOBOBJECT_EXTENDED_LIMIT_INFORMATION'));
  });

  test('SUP-16: should track tamper protection status on supervisor registration', () => {
    const sup = supervisorEngine.registerSupervisor(db, {
      deviceId: 'dev-daddy-pc',
      tamperProtectionEnabled: 1
    });

    assert.strictEqual(sup.tamper_protection_enabled, 1);
  });

  test('SUP-17: should update supervisor PIDs on worker process restart', () => {
    supervisorEngine.heartbeatSupervisor(db, {
      deviceId: 'dev-daddy-pc',
      supervisorPid: 4112,
      workerPid: 8844,
      watchdogPid: 4120
    });

    const sup = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(sup.worker_pid, 8844);
  });

  test('SUP-18: should record recovery actions (RESTARTED_WORKER, REINSTALLED_SERVICE)', () => {
    const dump = supervisorEngine.recordCrashDump(db, {
      deviceId: 'dev-daddy-pc',
      recoveryAction: 'REINSTALLED_SERVICE'
    });

    assert.strictEqual(dump.recovery_action, 'REINSTALLED_SERVICE');
  });

  test('SUP-19: should cascade delete supervisor records when host device is deleted', () => {
    db.prepare("DELETE FROM devices WHERE id = 'dev-sarah-laptop'").run();
    const sup = supervisorEngine.getSupervisorByDeviceId(db, 'dev-sarah-laptop');
    assert.strictEqual(sup, null);
  });

  test('SUP-20: should handle concurrent supervisor heartbeats without database locks', () => {
    for (let i = 0; i < 20; i++) {
      supervisorEngine.heartbeatSupervisor(db, {
        deviceId: 'dev-daddy-pc',
        workerPid: 1000 + i
      });
    }

    const sup = supervisorEngine.getSupervisorByDeviceId(db, 'dev-daddy-pc');
    assert.strictEqual(sup.worker_pid, 1019);
  });
});
