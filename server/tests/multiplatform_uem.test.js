import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { MultiPlatformUemEngine } from '../src/services/multiPlatformUemEngine.js';

describe('Unified Endpoint Management (UEM) Multi-Platform Engine (Iteration 65)', () => {
  let db;

  before(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });
  });

  after(() => {
    db.close();
  });

  it('1. detectPlatform categorizes OS strings accurately across Windows, macOS, iOS, Android, and Linux', () => {
    assert.equal(MultiPlatformUemEngine.detectPlatform('Windows 11 Pro'), 'WINDOWS');
    assert.equal(MultiPlatformUemEngine.detectPlatform('macOS Sonoma 14.5'), 'MACOS');
    assert.equal(MultiPlatformUemEngine.detectPlatform('Darwin 23.5.0'), 'MACOS');
    assert.equal(MultiPlatformUemEngine.detectPlatform('iOS 17.4.1'), 'IOS');
    assert.equal(MultiPlatformUemEngine.detectPlatform('iPadOS 17.4'), 'IOS');
    assert.equal(MultiPlatformUemEngine.detectPlatform('Android 14'), 'ANDROID');
    assert.equal(MultiPlatformUemEngine.detectPlatform('Ubuntu Linux 22.04 LTS'), 'LINUX');
  });

  it('2. getPlatformStats aggregates multi-platform breakdown and non-Windows totals', () => {
    const stats = MultiPlatformUemEngine.getPlatformStats(db);
    assert.ok(stats);
    assert.equal(typeof stats.totalDevices, 'number');
    assert.ok(stats.totalDevices >= 1);
    assert.ok(stats.activeAppleProfiles >= 1);
    assert.ok(stats.activeAndroidProfiles >= 1);
    assert.ok(stats.pendingCommands >= 1);
    assert.equal(stats.uemOperational, true);
  });

  it('3. getPlatformStats handles empty database safely', () => {
    const emptyDb = new DatabaseSync(':memory:');
    applyPragmas(emptyDb);
    initDb(emptyDb, { seed: false });

    const stats = MultiPlatformUemEngine.getPlatformStats(emptyDb);
    assert.equal(stats.totalDevices, 0);
    assert.equal(stats.windowsDevices, 0);
    assert.equal(stats.macosDevices, 0);
    assert.equal(stats.activeAppleProfiles, 0);
    assert.equal(stats.pendingCommands, 0);
    emptyDb.close();
  });

  it('4. getMultiplatformDevices retrieves all devices with normalized platform badge', () => {
    const devices = MultiPlatformUemEngine.getMultiplatformDevices(db);
    assert.ok(Array.isArray(devices));
    assert.ok(devices.length >= 1);
    assert.ok(devices.every(d => typeof d.platform === 'string'));
  });

  it('5. getMultiplatformDevices filters by platform', () => {
    const winDevices = MultiPlatformUemEngine.getMultiplatformDevices(db, { platform: 'windows' });
    assert.ok(winDevices.length >= 1);
    assert.ok(winDevices.every(d => d.platform === 'WINDOWS'));
  });

  it('6. enrollMobileDevice registers new macOS endpoint with hardware attributes', () => {
    const mac = MultiPlatformUemEngine.enrollMobileDevice(db, {
      device_id: 'mac-test-node',
      hostname: 'MacBook-Pro-M2',
      os_name: 'macOS Sonoma',
      os_version: '14.5',
      serial_number: 'C02TESTMAC01',
      cpu_model: 'Apple M2 Pro',
      total_ram_bytes: 17179869184,
      primary_user: 'developer@localpilot.corp'
    });

    assert.ok(mac);
    assert.equal(mac.device_id, 'mac-test-node');
    assert.equal(mac.platform, 'MACOS');
    assert.ok(mac.token);
    assert.equal(mac.is_new, true);

    const check = db.prepare('SELECT * FROM devices WHERE id = ?').get('mac-test-node');
    assert.equal(check.os_name, 'macOS Sonoma');
  });

  it('7. enrollMobileDevice registers new iOS / iPhone endpoint with serial and UDID', () => {
    const ios = MultiPlatformUemEngine.enrollMobileDevice(db, {
      device_id: 'ios-test-node',
      hostname: 'CEO-iPhone-15-Pro',
      os_name: 'iOS',
      os_version: '17.4',
      serial_number: 'DNQTESTIOS01',
      uuid: '00008101-001234567890ABCD',
      primary_user: 'ceo@localpilot.corp'
    });

    assert.ok(ios);
    assert.equal(ios.device_id, 'ios-test-node');
    assert.equal(ios.platform, 'IOS');
    assert.equal(ios.is_new, true);
  });

  it('8. enrollMobileDevice registers new Android endpoint with hardware specs', () => {
    const droid = MultiPlatformUemEngine.enrollMobileDevice(db, {
      device_id: 'and-test-node',
      hostname: 'Pixel-8-Enterprise',
      os_name: 'Android',
      os_version: '14.0',
      serial_number: 'G011ATEST01',
      primary_user: 'field_ops@localpilot.corp'
    });

    assert.ok(droid);
    assert.equal(droid.device_id, 'and-test-node');
    assert.equal(droid.platform, 'ANDROID');
    assert.equal(droid.is_new, true);
  });

  it('9. enrollMobileDevice updates existing mobile node without creating duplicate records', () => {
    const updated = MultiPlatformUemEngine.enrollMobileDevice(db, {
      device_id: 'mac-test-node',
      hostname: 'MacBook-Pro-M2-Renamed',
      os_name: 'macOS Sequoia',
      os_version: '15.0',
      serial_number: 'C02TESTMAC01'
    });

    assert.ok(updated);
    assert.equal(updated.device_id, 'mac-test-node');
    assert.equal(updated.hostname, 'MacBook-Pro-M2-Renamed');
    assert.equal(updated.is_new, false);

    const count = db.prepare("SELECT COUNT(*) as c FROM devices WHERE serial_number = 'C02TESTMAC01'").get().c;
    assert.equal(count, 1);
  });

  it('10. getAppleProfiles retrieves active Apple configuration profiles', () => {
    const profiles = MultiPlatformUemEngine.getAppleProfiles(db);
    assert.ok(Array.isArray(profiles));
    assert.ok(profiles.length >= 1);
    assert.equal(profiles[0].id, 'amp-01');
  });

  it('11. createAppleProfile stores new Apple profile with passcode policy JSON', () => {
    const created = MultiPlatformUemEngine.createAppleProfile(db, {
      id: 'amp-test-02',
      name: 'Executive High-Security iOS Profile',
      target_platform: 'IOS',
      passcode_policy: { minLength: 12, requireAlphanumeric: true },
      filevault_enabled: 0,
      wifi_ssid: 'EXEC-5G'
    });

    assert.ok(created);
    assert.equal(created.id, 'amp-test-02');
    assert.equal(created.target_platform, 'IOS');
    assert.equal(created.wifi_ssid, 'EXEC-5G');
  });

  it('12. generateAppleMdmProfile generates valid standard Apple .mobileconfig XML Property List', () => {
    const payload = MultiPlatformUemEngine.generateAppleMdmProfile(db, 'amp-01');
    assert.ok(payload);
    assert.equal(payload.filename, 'corp.localpilot.mdm.baseline.mobileconfig');
    assert.ok(payload.plist_xml.includes('<?xml version="1.0" encoding="UTF-8"?>'));
    assert.ok(payload.plist_xml.includes('<!DOCTYPE plist'));
    assert.ok(payload.plist_xml.includes('com.apple.mobiledevice.passwordpolicy'));
    assert.ok(payload.plist_xml.includes('com.apple.MCX.FileVault2'));
  });

  it('13. generateAppleMdmProfile returns null for non-existent profile ID', () => {
    const payload = MultiPlatformUemEngine.generateAppleMdmProfile(db, 'non-existent-amp');
    assert.equal(payload, null);
  });

  it('14. getAndroidProfiles and createAndroidProfile manage Android Enterprise profiles', () => {
    const created = MultiPlatformUemEngine.createAndroidProfile(db, {
      id: 'aep-test-02',
      name: 'Warehouse Rugged Scanner Kiosk Profile',
      enrollment_mode: 'DEDICATED_KIOSK',
      camera_disabled: 0,
      screen_capture_disabled: 1
    });

    assert.ok(created);
    assert.equal(created.id, 'aep-test-02');
    assert.equal(created.enrollment_mode, 'DEDICATED_KIOSK');

    const profiles = MultiPlatformUemEngine.getAndroidProfiles(db);
    assert.ok(profiles.length >= 2);
  });

  it('15. generateAndroidQrPayload returns parsed JSON provisioning dictionary', () => {
    const qr = MultiPlatformUemEngine.generateAndroidQrPayload(db, 'aep-01');
    assert.ok(qr);
    assert.equal(qr.profile_id, 'aep-01');
    assert.equal(qr.enrollment_token, 'LP-AND-CORP-2026-TOKEN');
    assert.ok(qr.qr_payload['android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME']);
  });

  it('16. dispatchDeviceCommand enqueues remote command in PENDING status', () => {
    const cmd = MultiPlatformUemEngine.dispatchDeviceCommand(db, {
      id: 'mdc-test-01',
      device_id: 'mac-test-node',
      command_type: 'DEVICE_LOCK',
      command_params: { lock_code: '123456' },
      issued_by: 'Test Security Officer'
    });

    assert.ok(cmd);
    assert.equal(cmd.id, 'mdc-test-01');
    assert.equal(cmd.command_type, 'DEVICE_LOCK');
    assert.equal(cmd.status, 'PENDING');
  });

  it('17. getPendingCommands returns queued commands for target mobile device', () => {
    const pending = MultiPlatformUemEngine.getPendingCommands(db, 'mac-test-node');
    assert.ok(Array.isArray(pending));
    assert.ok(pending.length >= 1);
    assert.equal(pending[0].command_type, 'DEVICE_LOCK');
    assert.equal(typeof pending[0].command_params, 'object');
  });

  it('18. acknowledgeCommand marks command ACKNOWLEDGED and records execution details', () => {
    const ack = MultiPlatformUemEngine.acknowledgeCommand(db, 'mdc-test-01', {
      success: true,
      message: 'Lock screen invoked via pmset'
    });

    assert.ok(ack);
    assert.equal(ack.status, 'ACKNOWLEDGED');
    assert.ok(ack.executed_at);

    const pendingNow = MultiPlatformUemEngine.getPendingCommands(db, 'mac-test-node');
    assert.equal(pendingNow.length, 0);
  });

  it('19. evaluatePlatformCompliance checks macOS SIP, FileVault, and Gatekeeper compliance', () => {
    const passing = MultiPlatformUemEngine.evaluatePlatformCompliance(db, 'mac-test-node', {
      sip_enabled: true,
      filevault_enabled: true,
      gatekeeper_enabled: true
    });
    assert.equal(passing.compliant, true);
    assert.equal(passing.platform, 'MACOS');

    const failing = MultiPlatformUemEngine.evaluatePlatformCompliance(db, 'mac-test-node', {
      sip_enabled: false,
      filevault_enabled: false,
      gatekeeper_enabled: true
    });
    assert.equal(failing.compliant, false);
    assert.ok(failing.violations.some(v => v.includes('SIP')));
    assert.ok(failing.violations.some(v => v.includes('FileVault')));
  });

  it('20. evaluatePlatformCompliance checks iOS jailbreak status and Android root status', () => {
    const jailbrokenIos = MultiPlatformUemEngine.evaluatePlatformCompliance(db, 'ios-test-node', {
      is_jailbroken: true,
      passcode_set: true
    });
    assert.equal(jailbrokenIos.compliant, false);
    assert.ok(jailbrokenIos.violations.some(v => v.includes('jailbreak')));

    const rootedAndroid = MultiPlatformUemEngine.evaluatePlatformCompliance(db, 'and-test-node', {
      is_rooted: true,
      storage_encrypted: true,
      play_integrity_valid: false
    });
    assert.equal(rootedAndroid.compliant, false);
    assert.ok(rootedAndroid.violations.some(v => v.includes('root')));
    assert.ok(rootedAndroid.violations.some(v => v.includes('Play Integrity')));
  });
});
