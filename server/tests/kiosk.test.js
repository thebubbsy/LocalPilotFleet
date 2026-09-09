/**
 * LocalPilot Fleet — Kiosk Mode & Multi-App Assigned Access QA
 * server/tests/kiosk.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateAssignedAccessXml, generateShellLauncherScript } from '../src/services/kioskEngine.js';

describe('Kiosk Mode & Multi-App Assigned Access QA (kiosk.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-kiosk-qa';
  let testDeviceId;
  let testNodeToken;
  let createdSingleAppId;
  let createdMultiAppId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'KIOSK-TEST-WORKSTATION',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26100',
        total_ram_bytes: 34359738368,
        mac_address: '00:15:5D:DD:EE:FF',
        serial_number: 'VMware-DD-EE-FF'
      })
    });
    assert.equal(enrollRes.status, 201);
    const enrollData = await enrollRes.json();
    testDeviceId = enrollData.device_id;
    testNodeToken = enrollData.node_token;
  });

  after(async () => {
    if (app) await app.cleanup();
  });

  async function api(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Fleet-Key': FLEET_KEY,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  async function nodeApi(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  it('KSK-01: GET /api/v1/fleet/kiosks/stats should return baseline kiosk statistics', async () => {
    const res = await api('/api/v1/fleet/kiosks/stats');
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.total_profiles === 'number');
    assert.ok(res.body.total_profiles >= 3);
    assert.ok(res.body.active_profiles >= 3);
    assert.ok(typeof res.body.single_app_count === 'number');
    assert.ok(typeof res.body.multi_app_count === 'number');
  });

  it('KSK-02: GET /api/v1/fleet/kiosks/profiles should return seed profiles with assigned device count', async () => {
    const res = await api('/api/v1/fleet/kiosks/profiles');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.profiles));
    assert.ok(res.body.profiles.length >= 3);
    const signage = res.body.profiles.find(p => p.id === 'kiosk-edge-digital-signage');
    assert.ok(signage);
    assert.equal(signage.kiosk_mode, 'DIGITAL_SIGNAGE');
    assert.equal(signage.app_type, 'EDGE_BROWSER');
    assert.ok(signage.assigned_devices_count >= 1);
  });

  it('KSK-03: POST /api/v1/fleet/kiosks/profiles should create a Single-App Edge Kiosk profile', async () => {
    const payload = {
      name: 'Showroom Interactive Display',
      description: 'Customer showroom interactive Edge kiosk with 10-minute inactivity reset',
      kiosk_mode: 'SINGLE_APP',
      target_group_id: 'grp-all',
      logon_type: 'AUTO_LOGON',
      user_account: 'ShowroomKiosk',
      app_type: 'EDGE_BROWSER',
      edge_kiosk_type: 'FULL_SCREEN_INTERACTIVE',
      edge_kiosk_url: 'https://showroom.localpilot.internal',
      edge_idle_timeout_min: 10,
      disable_taskbar: true,
      disable_cad_keys: true
    };
    const res = await api('/api/v1/fleet/kiosks/profiles', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.edge_idle_timeout_min, 10);
    assert.ok(res.body.generated_xml.includes('https://showroom.localpilot.internal'));
    createdSingleAppId = res.body.id;
  });

  it('KSK-04: POST /api/v1/fleet/kiosks/profiles should reject missing name with 400', async () => {
    const res = await api('/api/v1/fleet/kiosks/profiles', {
      method: 'POST',
      body: JSON.stringify({ description: 'Nameless profile' })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  it('KSK-05: POST /api/v1/fleet/kiosks/profiles should create a Multi-App profile with allowed apps array', async () => {
    const payload = {
      name: 'Warehouse Logistics Terminal',
      description: 'Restricted warehouse workstation running barcode scanning app and Edge ERP',
      kiosk_mode: 'MULTI_APP',
      target_group_id: 'grp-all',
      logon_type: 'LOCAL_USER',
      user_account: 'WarehouseWorker',
      app_type: 'MULTI_APP_XML',
      allowed_apps: [
        { name: 'Logistics Scanner', path: 'C:\\Warehouse\\Scan.exe' },
        { name: 'Edge ERP', aumid: 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App' }
      ],
      disable_taskbar: false
    };
    const res = await api('/api/v1/fleet/kiosks/profiles', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.kiosk_mode, 'MULTI_APP');
    assert.equal(res.body.allowed_apps.length, 2);
    assert.ok(res.body.generated_xml.includes('C:\\Warehouse\\Scan.exe'));
    createdMultiAppId = res.body.id;
  });

  it('KSK-06: GET /api/v1/fleet/kiosks/profiles/:id should return profile with generated XML and shell script', async () => {
    const res = await api(`/api/v1/fleet/kiosks/profiles/${createdSingleAppId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdSingleAppId);
    assert.ok(res.body.generated_xml.includes('AssignedAccessConfiguration'));
    assert.ok(res.body.shell_launcher_script.includes('WESL_UserSetting'));
  });

  it('KSK-07: GET /api/v1/fleet/kiosks/profiles/:id should 404 for unknown profile', async () => {
    const res = await api('/api/v1/fleet/kiosks/profiles/kiosk-non-existent-999');
    assert.equal(res.status, 404);
  });

  it('KSK-08: generateAssignedAccessXml should format valid XML for single-app and multi-app modes', () => {
    const singleAppXml = generateAssignedAccessXml({
      id: 'test-single',
      kiosk_mode: 'SINGLE_APP',
      logon_type: 'AUTO_LOGON',
      app_type: 'EDGE_BROWSER',
      edge_kiosk_type: 'DIGITAL_SIGNAGE',
      edge_kiosk_url: 'https://display.internal',
      disable_taskbar: true
    });
    assert.ok(singleAppXml.includes('<AutoLogonAccount />'));
    assert.ok(singleAppXml.includes('https://display.internal'));
    assert.ok(singleAppXml.includes('ShowTaskbar="false"'));

    const multiAppXml = generateAssignedAccessXml({
      id: 'test-multi',
      kiosk_mode: 'MULTI_APP',
      logon_type: 'LOCAL_USER',
      user_account: 'Operator',
      allowed_apps_json: JSON.stringify([{ name: 'Test', aumid: 'TestAumid' }]),
      disable_taskbar: false
    });
    assert.ok(multiAppXml.includes('<Account>Operator</Account>'));
    assert.ok(multiAppXml.includes('<App AUMID="TestAumid" />'));
    assert.ok(multiAppXml.includes('ShowTaskbar="true"'));
  });

  it('KSK-09: generateShellLauncherScript should generate valid PowerShell syntax with SID resolution', () => {
    const script = generateShellLauncherScript({
      id: 'test-shell',
      name: 'Custom Shell Launcher',
      kiosk_mode: 'SHELL_LAUNCHER',
      user_account: 'KioskUser',
      app_path_or_aumid: 'C:\\Apps\\CustomShell.exe',
      restart_on_exit: 1
    });
    assert.ok(script.includes('Client-EmbeddedShellLauncher'));
    assert.ok(script.includes('WESL_UserSetting'));
    assert.ok(script.includes('C:\\Apps\\CustomShell.exe'));
    assert.ok(script.includes('DefaultReturnCodeAction = 0'));
  });

  it('KSK-10: PATCH /api/v1/fleet/kiosks/profiles/:id should update profile properties', async () => {
    const res = await api(`/api/v1/fleet/kiosks/profiles/${createdSingleAppId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        name: 'Showroom Interactive Display v2',
        edge_idle_timeout_min: 15,
        enabled: false
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'Showroom Interactive Display v2');
    assert.equal(res.body.edge_idle_timeout_min, 15);
    assert.equal(res.body.enabled, false);
  });

  it('KSK-11: PATCH /api/v1/fleet/kiosks/profiles/:id should reject empty name with 400', async () => {
    const res = await api(`/api/v1/fleet/kiosks/profiles/${createdSingleAppId}`, {
      method: 'PATCH',
      body: JSON.stringify({ name: '   ' })
    });
    assert.equal(res.status, 400);
  });

  it('KSK-12: POST /api/v1/nodes/heartbeat should deliver kiosk_profile in response', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 12.5,
        ram_usage_percent: 45.0
      })
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.kiosk_profile !== undefined);
  });

  it('KSK-13: POST /api/v1/nodes/:id/kiosk-status should ingest live kiosk posture', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/kiosk-status`, {
      method: 'POST',
      body: JSON.stringify({
        assigned_access_supported: true,
        shell_launcher_supported: true,
        current_shell: 'explorer.exe',
        kiosk_active: false,
        active_kiosk_user: ''
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.current_shell, 'explorer.exe');
    assert.equal(res.body.kiosk_active, false);
    assert.ok(['STANDARD_SHELL', 'KIOSK_CONFIGURED'].includes(res.body.lockdown_status));
  });

  it('KSK-14: POST /api/v1/nodes/:id/kiosk-status should reject unauthenticated request', async () => {
    const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/kiosk-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kiosk_active: true })
    });
    assert.equal(res.status, 401);
  });

  it('KSK-15: GET /api/v1/nodes/:id/kiosk-profile should allow node to fetch assigned kiosk profile', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/kiosk-profile`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.profile !== undefined);
  });

  it('KSK-16: GET /api/v1/fleet/kiosks/inventory should list audited workstations', async () => {
    const res = await api('/api/v1/fleet/kiosks/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.inventory));
    const deviceEntry = res.body.inventory.find(i => i.device_id === testDeviceId);
    assert.ok(deviceEntry);
    assert.equal(deviceEntry.hostname, 'KIOSK-TEST-WORKSTATION');
  });

  it('KSK-17: GET /api/v1/fleet/devices/:id/kiosk should return workstation kiosk posture', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/kiosk`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.assigned_access_supported);
    assert.ok(res.body.shell_launcher_supported);
  });

  it('KSK-18: DELETE /api/v1/fleet/kiosks/profiles/:id should delete custom profile', async () => {
    const res = await api(`/api/v1/fleet/kiosks/profiles/${createdMultiAppId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);

    const getRes = await api(`/api/v1/fleet/kiosks/profiles/${createdMultiAppId}`);
    assert.equal(getRes.status, 404);
  });

  it('KSK-19: DELETE /api/v1/fleet/kiosks/profiles/:id should 404 for already deleted profile', async () => {
    const res = await api(`/api/v1/fleet/kiosks/profiles/${createdMultiAppId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 404);
  });

  it('KSK-20: GET /api/v1/fleet/kiosks/stats should reflect updated audit totals', async () => {
    const res = await api('/api/v1/fleet/kiosks/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_audited_workstations >= 1);
  });
});
