/**
 * LocalPilot Fleet — Windows Autopilot & Hardware Provisioning QA Tests
 * server/tests/autopilot.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as autopilotEngine from '../src/services/autopilotEngine.js';

describe('Windows Autopilot & Provisioning QA (autopilot.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-autopilot-qa';
  const authHeader = { 'X-Fleet-Key': FLEET_KEY };
  const jsonHeader = { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY };

  before(async () => {
    app = await createTestApp({
      fleetKey: FLEET_KEY,
      seed: true
    });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. Autopilot KPI & Statistics', () => {
    it('GET /api/v1/fleet/autopilot/stats returns accurate fleet provisioning summary', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(data.total_devices >= 3, 'Should have at least 3 seed devices');
      assert.ok(data.total_profiles >= 2, 'Should have at least 2 seed profiles');
      assert.ok(data.total_esp_policies >= 1, 'Should have at least 1 seed ESP policy');
      assert.equal(typeof data.unassigned_devices, 'number');
      assert.equal(typeof data.assigned_devices, 'number');
      assert.equal(typeof data.enrolled_devices, 'number');
    });
  });

  describe('2. Autopilot Deployment Profiles CRUD', () => {
    let createdProfileId;

    it('GET /api/v1/fleet/autopilot/profiles returns seeded profiles with device counts', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(Array.isArray(data.profiles));
      assert.ok(data.profiles.length >= 2);

      const standardProf = data.profiles.find(p => p.id === 'ap-prof-standard');
      assert.ok(standardProf);
      assert.equal(standardProf.deployment_mode, 'USER_DRIVEN');
      assert.equal(standardProf.account_type, 'STANDARD');
      assert.equal(standardProf.is_default, 1);
    });

    it('GET /api/v1/fleet/autopilot/profiles/:id returns single profile with assigned devices', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles/ap-prof-standard`, { headers: authHeader });
      assert.equal(res.status, 200);
      const profile = await res.json();

      assert.equal(profile.id, 'ap-prof-standard');
      assert.ok(Array.isArray(profile.devices));
    });

    it('POST /api/v1/fleet/autopilot/profiles creates a new custom OOBE profile', async () => {
      const newProfile = {
        name: 'Executive Ultra-Secure Laptop Profile',
        description: 'Self-deploying profile with domain join and restricted standard account',
        deployment_mode: 'SELF_DEPLOYING',
        join_type: 'WORKGROUP_LOCAL',
        account_type: 'STANDARD',
        device_name_template: 'EXEC-%RAND:5%',
        skip_eula: true,
        skip_privacy_settings: true,
        skip_user_licensing: true,
        target_group_id: 'grp-workstations',
        is_default: false
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newProfile)
      });
      assert.equal(res.status, 201);
      const created = await res.json();

      assert.ok(created.id);
      assert.equal(created.name, 'Executive Ultra-Secure Laptop Profile');
      assert.equal(created.deployment_mode, 'SELF_DEPLOYING');
      assert.equal(created.device_name_template, 'EXEC-%RAND:5%');
      createdProfileId = created.id;
    });

    it('POST /api/v1/fleet/autopilot/profiles rejects invalid deployment mode', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Invalid Profile',
          deployment_mode: 'NON_EXISTENT_MODE'
        })
      });
      assert.equal(res.status, 400);
    });

    it('PATCH /api/v1/fleet/autopilot/profiles/:id updates profile parameters', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles/${createdProfileId}`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Executive Ultra-Secure Laptop Profile (Updated)',
          device_name_template: 'EXEC-SEC-%RAND:4%'
        })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.name, 'Executive Ultra-Secure Laptop Profile (Updated)');
      assert.equal(updated.device_name_template, 'EXEC-SEC-%RAND:4%');
    });

    it('DELETE /api/v1/fleet/autopilot/profiles/:id removes profile safely', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles/${createdProfileId}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);

      const verifyRes = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/profiles/${createdProfileId}`, { headers: authHeader });
      assert.equal(verifyRes.status, 404);
    });
  });

  describe('3. Autopilot Device Registry & Hardware Hash Management', () => {
    let testDeviceId;

    it('GET /api/v1/fleet/autopilot/devices returns registered fleet devices with live node status', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(Array.isArray(data.devices));
      assert.ok(data.devices.length >= 3);

      const vmDevice = data.devices.find(d => d.serial_number === 'VMW-99210-LAB');
      assert.ok(vmDevice);
      assert.equal(vmDevice.model, 'VMware Virtual Platform');
      assert.equal(vmDevice.deployment_status, 'ASSIGNED');
    });

    it('POST /api/v1/fleet/autopilot/devices registers new physical hardware hash', async () => {
      const devPayload = {
        serial_number: 'TEST-SN-998877',
        hardware_hash: 'T1BSR1VJRDAwMDFBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjEyMzQ1Njc4OTAqKipXRUJfSEFTSA==',
        windows_product_id: '00330-80000-00000-AAOEM',
        model: 'ThinkPad X1 Carbon Gen 11',
        manufacturer: 'Lenovo',
        group_tag: 'Engineering',
        assigned_user: 'developer@localpilot.fleet'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(devPayload)
      });
      assert.equal(res.status, 201);
      const created = await res.json();

      assert.ok(created.id);
      assert.equal(created.serial_number, 'TEST-SN-998877');
      assert.equal(created.model, 'ThinkPad X1 Carbon Gen 11');
      assert.equal(created.group_tag, 'Engineering');
      // Default profile should automatically be assigned
      assert.equal(created.deployment_status, 'ASSIGNED');
      testDeviceId = created.id;
    });

    it('POST /api/v1/fleet/autopilot/devices rejects duplicate serial number with 400', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          serial_number: 'TEST-SN-998877',
          hardware_hash: 'DUPLICATE_HASH'
        })
      });
      assert.equal(res.status, 400);
      const err = await res.json();
      assert.ok(err.message.includes('already registered'));
    });

    it('POST /api/v1/fleet/autopilot/devices/:id/assign-profile changes assigned profile', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/${testDeviceId}/assign-profile`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ profile_id: 'ap-prof-kiosk' })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();

      assert.equal(updated.profile_id, 'ap-prof-kiosk');
      assert.equal(updated.profile_name, 'Self-Deploying Lab & Kiosk Rig');
    });

    it('PATCH /api/v1/fleet/autopilot/devices/:id updates group tag and user metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/${testDeviceId}`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          group_tag: 'DevOps-Lead',
          assigned_user: 'lead@localpilot.fleet'
        })
      });
      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.group_tag, 'DevOps-Lead');
      assert.equal(updated.assigned_user, 'lead@localpilot.fleet');
    });

    it('DELETE /api/v1/fleet/autopilot/devices/:id removes registered device', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/${testDeviceId}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);

      const check = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/${testDeviceId}`, { headers: authHeader });
      assert.equal(check.status, 404);
    });
  });

  describe('4. Microsoft Intune CSV Bulk Import & Export', () => {
    it('POST /api/v1/fleet/autopilot/devices/import-csv imports devices using standard Intune headers', async () => {
      const sampleCsv = `Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
CSV-SN-001,00330-10000-00000-AAOEM,T0FSMDAxX0hBU0hfREFUQV9TQU1QTEVfMDEwMTAxMDEwMTAxMDEwMTA=,Finance,alice@localpilot.fleet
CSV-SN-002,00330-20000-00000-AAOEM,T0FSMDAyX0hBU0hfREFUQV9TQU1QTEVfMDEwMTAxMDEwMTAxMDEwMTA=,Marketing,bob@localpilot.fleet
CSV-SN-003,00330-30000-00000-AAOEM,T0FSMDAzX0hBU0hfREFUQV9TQU1QTEVfMDEwMTAxMDEwMTAxMDEwMTA=,Engineering,charlie@localpilot.fleet`;

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/import-csv`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ csv_content: sampleCsv })
      });
      assert.equal(res.status, 200);
      const result = await res.json();

      assert.equal(result.total_parsed, 3);
      assert.equal(result.imported_count, 3);
      assert.equal(result.errors.length, 0);

      // Verify devices appear in list
      const listRes = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices?search=CSV-SN-001`, { headers: authHeader });
      const listData = await listRes.json();
      assert.equal(listData.total, 1);
      assert.equal(listData.devices[0].serial_number, 'CSV-SN-001');
      assert.equal(listData.devices[0].group_tag, 'Finance');
    });

    it('POST /api/v1/fleet/autopilot/devices/import-csv handles updates for existing serials', async () => {
      const updateCsv = `Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
CSV-SN-001,00330-10000-00000-AAOEM,T0FSMDAxX05FV19IQVNIX0RBVEFfMDAwMDAwMDAwMDAwMDAwMDAwMA==,Executive-Finance,alice.vp@localpilot.fleet`;

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/import-csv`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ csv_content: updateCsv })
      });
      assert.equal(res.status, 200);
      const result = await res.json();

      assert.equal(result.updated_count, 1);

      const checkRes = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices?search=CSV-SN-001`, { headers: authHeader });
      const checkData = await checkRes.json();
      assert.equal(checkData.devices[0].group_tag, 'Executive-Finance');
      assert.equal(checkData.devices[0].assigned_user, 'alice.vp@localpilot.fleet');
    });

    it('GET /api/v1/fleet/autopilot/devices/export-csv outputs RFC 4180 standard Intune CSV', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/devices/export-csv`, { headers: authHeader });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'text/csv; charset=utf-8');
      assert.ok(res.headers.get('content-disposition').includes('AutopilotDevices.csv'));

      const csvText = await res.text();
      assert.ok(csvText.startsWith('Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User'));
      assert.ok(csvText.includes('CSV-SN-001'));
      assert.ok(csvText.includes('VMW-99210-LAB'));
    });
  });

  describe('5. Enrollment Status Page (ESP) Governance', () => {
    let createdEspId;

    it('GET /api/v1/fleet/autopilot/esp-policies returns default ESP policy', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/esp-policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(Array.isArray(data.esp_policies));
      assert.ok(data.esp_policies.length >= 1);

      const defaultEsp = data.esp_policies.find(e => e.id === 'esp-default');
      assert.ok(defaultEsp);
      assert.equal(defaultEsp.show_progress, 1);
      assert.equal(defaultEsp.block_until_completed, 1);
      assert.equal(defaultEsp.timeout_minutes, 60);
    });

    it('POST /api/v1/fleet/autopilot/esp-policies creates customized ESP policy', async () => {
      const newEsp = {
        name: 'Fast Lab Provisioning ESP (30 min)',
        description: 'Lightweight ESP for test benches allowing fast user reset',
        show_progress: true,
        block_until_completed: false,
        allow_user_reset_on_failure: true,
        timeout_minutes: 30,
        required_app_ids: ['app-edge', 'app-terminal'],
        required_script_ids: [],
        target_group_id: 'grp-workstations'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/esp-policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newEsp)
      });
      assert.equal(res.status, 201);
      const created = await res.json();

      assert.ok(created.id);
      assert.equal(created.name, 'Fast Lab Provisioning ESP (30 min)');
      assert.equal(created.timeout_minutes, 30);
      createdEspId = created.id;
    });

    it('POST /api/v1/fleet/autopilot/esp-policies rejects invalid timeout boundary', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/esp-policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Invalid Timeout ESP',
          timeout_minutes: 5 // Minimum is 10 min
        })
      });
      assert.equal(res.status, 400);
    });

    it('DELETE /api/v1/fleet/autopilot/esp-policies/:id removes custom ESP policy', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/esp-policies/${createdEspId}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(res.status, 200);

      const check = await fetch(`${app.baseUrl}/api/v1/fleet/autopilot/esp-policies/${createdEspId}`, { headers: authHeader });
      assert.equal(check.status, 404);
    });
  });

  describe('6. Provisioning Events & Lifecycle Progression', () => {
    it('POST /api/v1/nodes/:id/provisioning-event tracks progress during OOBE phases', async () => {
      // Find a device to track
      const db = app.db;
      const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
      assert.ok(dev, 'Test fleet must contain a device');

      // Register device in Autopilot first
      const apDev = autopilotEngine.registerAutopilotDevice(db, {
        serial_number: `PROV-SN-${Date.now()}`,
        hardware_hash: 'U0FNTExFX0hBU0hfUFJPVklTSU9OSU5HX1RFU1Q=',
        model: 'Test Rig'
      });

      // Link device ID
      db.prepare('UPDATE autopilot_devices SET device_id = ? WHERE id = ?').run(dev.id, apDev.id);

      // Node token header
      const nodeToken = 'valid-token'; // We can test endpoint with fleet key
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${dev.id}/provisioning-event`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          phase: 'DEVICE_PREPARATION',
          step_name: 'TPM Attestation Verification',
          status: 'IN_PROGRESS',
          details: 'Communicating with fleet master CA'
        })
      });
      assert.equal(res.status, 201);
      const ev = await res.json();
      assert.equal(ev.phase, 'DEVICE_PREPARATION');
      assert.equal(ev.deployment_status, 'PROVISIONING');

      // Now complete account setup step
      const completeRes = await fetch(`${app.baseUrl}/api/v1/nodes/${dev.id}/provisioning-event`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          phase: 'ACCOUNT_SETUP',
          step_name: 'Primary User Account Setup',
          status: 'COMPLETED',
          details: 'Standard user profile provisioned'
        })
      });
      assert.equal(completeRes.status, 201);
      const completeEv = await completeRes.json();
      assert.equal(completeEv.deployment_status, 'ENROLLED');
    });

    it('GET /api/v1/nodes/:id/autopilot-profile returns assigned profile and ESP', async () => {
      const db = app.db;
      const enrolledAp = db.prepare('SELECT device_id FROM autopilot_devices WHERE device_id IS NOT NULL LIMIT 1').get();
      assert.ok(enrolledAp, 'Should have an enrolled device');

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${enrolledAp.device_id}/autopilot-profile`, { headers: authHeader });
      assert.equal(res.status, 200);
      const posture = await res.json();

      assert.equal(posture.is_registered, true);
      assert.ok(posture.autopilot_device);
      assert.ok(posture.effective_esp);
      assert.ok(Array.isArray(posture.provisioning_events));
    });

    it('GET /api/v1/fleet/devices/:id/autopilot returns full device posture in fleet management blade', async () => {
      const db = app.db;
      const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/${dev.id}/autopilot`, { headers: authHeader });
      assert.equal(res.status, 200);
      const posture = await res.json();

      assert.equal(typeof posture.is_registered, 'boolean');
      assert.ok(posture.effective_esp);
    });
  });
});
