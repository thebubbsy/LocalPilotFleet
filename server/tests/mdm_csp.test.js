import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { initDb, closeDb } from '../src/db.js';
import { mdmCspEngine } from '../src/services/mdmCspEngine.js';

describe('Native Windows MDM Protocol & CSP Integration QA (Dimension 5)', () => {
  let db;
  let testDeviceId;

  before(() => {
    db = initDb(':memory:', { seed: true });
    mdmCspEngine._db = db;
    const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    testDeviceId = dev.id;
  });

  after(() => {
    closeDb();
  });

  // 1. STATS
  it('MDM-01: should return baseline OMA-DM stats and operational status', () => {
    const stats = mdmCspEngine.getMdmStats();
    assert.ok(stats.total_csp_configurations >= 3, 'Should have seed CSPs');
    assert.ok(stats.enforced_csp_configurations >= 3);
    assert.strictEqual(stats.status, 'OMA_DM_OPERATIONAL');
    assert.strictEqual(stats.protocol.includes('root\cimv2\mdm\dmmap'), true);
  });

  // 2. LIST CSPS
  it('MDM-02: should list seeded CSP configurations', () => {
    const csps = mdmCspEngine.getCspConfigurations();
    assert.ok(csps.length >= 3);
    const bitlockerCsp = csps.find(c => c.csp_uri === './Vendor/MSFT/BitLocker/RequireDeviceEncryption');
    assert.ok(bitlockerCsp);
    assert.strictEqual(bitlockerCsp.wmi_class, 'MDM_BitLocker');
    assert.strictEqual(bitlockerCsp.data_type, 'int');
  });

  // 3. GET SINGLE CSP
  it('MDM-03: should retrieve single CSP configuration by ID', () => {
    const csp = mdmCspEngine.getCspConfigurationById('csp-devicelock-history');
    assert.ok(csp);
    assert.strictEqual(csp.csp_uri, './Vendor/MSFT/DeviceLock/DevicePasswordHistory');
    assert.strictEqual(csp.target_value, '5');
  });

  // 4. CREATE CUSTOM CSP
  it('MDM-04: should create a new custom OMA-DM CSP configuration', () => {
    const created = mdmCspEngine.createCspConfiguration({
      name: 'Disable Camera Hardware CSP',
      csp_uri: './Vendor/MSFT/Policy/Config/Camera/AllowCamera',
      csp_type: 'SET',
      wmi_class: 'MDM_Policy_Config01_Camera02',
      data_type: 'int',
      target_value: '0',
      target_group_id: 'grp-workstations',
      is_enforced: 1
    });

    assert.ok(created);
    assert.strictEqual(created.name, 'Disable Camera Hardware CSP');
    assert.strictEqual(created.csp_uri, './Vendor/MSFT/Policy/Config/Camera/AllowCamera');
    assert.strictEqual(created.target_group_id, 'grp-workstations');
  });

  // 5. REJECT INVALID CSP URI
  it('MDM-05: should reject creating CSP with invalid URI not starting with ./Vendor/MSFT/', () => {
    assert.throws(() => {
      mdmCspEngine.createCspConfiguration({
        name: 'Invalid Custom Path',
        csp_uri: 'HKLM:\Software\Policies\Windows'
      });
    }, /INVALID_CSP_URI/);
  });

  // 6. REJECT MISSING NAME
  it('MDM-06: should reject creating CSP with missing name', () => {
    assert.throws(() => {
      mdmCspEngine.createCspConfiguration({
        name: '',
        csp_uri: './Vendor/MSFT/Policy/Config/System/AllowStorageCard'
      });
    }, /MISSING_CSP_NAME/);
  });

  // 7. UPDATE CSP
  it('MDM-07: should update CSP target value, data type, and enforcement status', () => {
    const csps = mdmCspEngine.getCspConfigurations();
    const target = csps.find(c => c.name === 'Disable Camera Hardware CSP');
    assert.ok(target);

    const updated = mdmCspEngine.updateCspConfiguration(target.id, {
      target_value: '1',
      is_enforced: 0
    });

    assert.strictEqual(updated.target_value, '1');
    assert.strictEqual(updated.is_enforced, 0);
  });

  // 8. DELETE CSP
  it('MDM-08: should delete custom CSP configuration', () => {
    const temp = mdmCspEngine.createCspConfiguration({
      name: 'Temp Bluetooth CSP',
      csp_uri: './Vendor/MSFT/Policy/Config/Bluetooth/AllowBluetooth',
      csp_type: 'SET'
    });

    const res = mdmCspEngine.deleteCspConfiguration(temp.id);
    assert.strictEqual(res.success, true);
    assert.strictEqual(mdmCspEngine.getCspConfigurationById(temp.id), null);
  });

  // 9. RESOLVE EFFECTIVE CSPS FOR DEVICE
  it('MDM-09: should resolve effective CSP policies for a device via dynamic groups', () => {
    const effective = mdmCspEngine.getEffectiveCspPoliciesForDevice(testDeviceId);
    assert.ok(Array.isArray(effective));
    assert.ok(effective.length >= 2);
    assert.ok(effective.some(c => c.csp_uri.includes('BitLocker')));
  });

  // 10. GENERATE WMI BRIDGE SCRIPT
  it('MDM-10: should generate native PowerShell script for WMI Bridge (root\cimv2\mdm\dmmap)', () => {
    const csp = mdmCspEngine.getCspConfigurationById('csp-bitlocker-req');
    const script = mdmCspEngine.generateCspWmiBridgePowerShellScript(csp);
    assert.ok(script.includes('root\\cimv2\\mdm\\dmmap'));
    assert.ok(script.includes('MDM_BitLocker'));
  });

  // 11. VERIFY EXEC METHOD IN WMI SCRIPT
  it('MDM-11: should verify WMI class and method in generated EXEC PowerShell script', () => {
    const wipeCsp = mdmCspEngine.getCspConfigurationById('csp-remotewipe-dowipe');
    const script = mdmCspEngine.generateCspWmiBridgePowerShellScript(wipeCsp);
    assert.ok(script.includes('Invoke-CimMethod'));
    assert.ok(script.includes('doWipeMethod'));
  });

  // 12. HARVEST AUTOPILOT 4K HARDWARE HASH
  it('MDM-12: should harvest an authentic 4K Autopilot Hardware Hash for a workstation', () => {
    const synthetic4k = Buffer.alloc(2500, 0x41).toString('base64'); // > 3000 chars
    const harvested = mdmCspEngine.harvestAutopilotHardwareHash({
      device_id: testDeviceId,
      hardware_hash_4k: synthetic4k,
      smbios_uuid: '12345678-1234-1234-1234-123456789abc',
      serial_number: 'SN-DESKTOP-9901',
      oem_manufacturer: 'Microsoft Corporation',
      oem_model: 'Surface Laptop Studio 2'
    });

    assert.ok(harvested);
    assert.strictEqual(harvested.device_id, testDeviceId);
    assert.strictEqual(harvested.oem_manufacturer, 'Microsoft Corporation');
    assert.ok(harvested.hash_length >= 2000);
  });

  // 13. REJECT SHORT HASH
  it('MDM-13: should reject invalid/truncated Autopilot hardware hash (< 1000 chars)', () => {
    assert.throws(() => {
      mdmCspEngine.harvestAutopilotHardwareHash({
        device_id: testDeviceId,
        hardware_hash_4k: 'short_hash_123'
      });
    }, /INVALID_HASH_LENGTH/);
  });

  // 14. LIST HARVESTED 4K HASHES
  it('MDM-14: should query all harvested Autopilot 4K hardware hashes with device join', () => {
    const hashes = mdmCspEngine.getAutopilotHardwareHashes();
    assert.ok(hashes.length >= 1);
    assert.ok(hashes[0].hostname);
    assert.strictEqual(hashes[0].hash_length >= 2000, true);
  });

  // 15. GET HASH BY DEVICE ID
  it('MDM-15: should retrieve single device Autopilot 4K hardware hash', () => {
    const hash = mdmCspEngine.getAutopilotHardwareHashByDeviceId(testDeviceId);
    assert.ok(hash);
    assert.strictEqual(hash.device_id, testDeviceId);
    assert.strictEqual(hash.enrollment_state, 'ENROLLED');
  });

  // 16. ENROLLMENT STATE TRACKING
  it('MDM-16: should update Autopilot device enrollment state (READY, ENROLLED, PENDING_RESET)', () => {
    const synthetic4k = Buffer.alloc(2000, 0x42).toString('base64');
    const updated = mdmCspEngine.harvestAutopilotHardwareHash({
      device_id: testDeviceId,
      hardware_hash_4k: synthetic4k,
      enrollment_state: 'READY'
    });

    assert.strictEqual(updated.enrollment_state, 'READY');
  });

  // 17. DISPATCH NATIVE REMOTE WIPE CSP
  it('MDM-17: should dispatch native RemoteWipe CSP with WinRE recovery script generation', () => {
    const wipe = mdmCspEngine.dispatchNativeRemoteWipe({
      device_id: testDeviceId,
      wipe_method: 'REMOTE_WIPE_CSP',
      initiated_by: 'lead.secops@localpilot.corp'
    });

    assert.ok(wipe);
    assert.strictEqual(wipe.status, 'QUEUED');
    assert.ok(wipe.wipe_id);
    assert.ok(wipe.native_powershell_script.includes('MDM_RemoteWipe'));
    assert.ok(wipe.native_powershell_script.includes('reagentc.exe /boottore'));
  });

  // 18. UPDATE WIPE STATUS
  it('MDM-18: should update native RemoteWipe status to EXECUTING_IN_WINRE and CRYPTO_ERASED_COMPLETED', () => {
    const wipes = db.prepare('SELECT id FROM native_remote_wipes WHERE device_id = ?').all(testDeviceId);
    assert.ok(wipes.length >= 1);
    const wipeId = wipes[0].id;

    const inProgress = mdmCspEngine.updateRemoteWipeStatus(wipeId, {
      status: 'EXECUTING_IN_WINRE'
    });
    assert.strictEqual(inProgress.status, 'EXECUTING_IN_WINRE');

    const completed = mdmCspEngine.updateRemoteWipeStatus(wipeId, {
      status: 'CRYPTO_ERASED_COMPLETED'
    });
    assert.strictEqual(completed.status, 'CRYPTO_ERASED_COMPLETED');
    assert.ok(completed.completed_at);
  });

  // 19. REJECT WIPE FOR UNKNOWN DEVICE
  it('MDM-19: should reject remote wipe for non-existent device', () => {
    assert.throws(() => {
      mdmCspEngine.dispatchNativeRemoteWipe({
        device_id: 'non-existent-device-id'
      });
    }, /DEVICE_NOT_FOUND/);
  });

  // 20. STATS REFLECTION
  it('MDM-20: should accurately reflect updated stats including native remote wipes', () => {
    const stats = mdmCspEngine.getMdmStats();
    assert.ok(stats.native_remote_wipes >= 1);
    assert.ok(stats.autopilot_4k_hashes.total >= 1);
  });
});
