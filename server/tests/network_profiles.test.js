/**
 * LocalPilot Fleet — Wi-Fi & VPN Configuration Profiles QA
 * server/tests/network_profiles.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { generateWlanXml } from '../src/services/networkEngine.js';

describe('Wi-Fi & VPN Configuration Profiles QA (network_profiles.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-net-qa';
  let testDeviceId;
  let testNodeToken;
  let createdWifiId;
  let createdVpnId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'NET-TEST-WORKSTATION',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26100',
        total_ram_bytes: 34359738368,
        mac_address: '00:15:5D:AA:BB:CC',
        serial_number: 'VMware-AA-BB-CC'
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

  it('NET-01: GET /api/v1/fleet/networks/stats returns aggregated network metrics', async () => {
    const res = await api('/api/v1/fleet/networks/stats');
    assert.equal(res.status, 200);
    assert.equal(typeof res.body.total_profiles, 'number');
    assert.ok(res.body.total_profiles >= 3, 'Should include at least 3 seed profiles');
    assert.ok(res.body.wifi_profiles_count >= 1);
    assert.ok(res.body.vpn_profiles_count >= 2);
    assert.equal(typeof res.body.total_audited_workstations, 'number');
  });

  it('NET-02: GET /api/v1/fleet/networks/profiles returns seed profiles with assigned device counts', async () => {
    const res = await api('/api/v1/fleet/networks/profiles');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.profiles));
    assert.ok(res.body.profiles.length >= 3);
    const corpWifi = res.body.profiles.find(p => p.id === 'net-corp-wifi-8021x');
    assert.ok(corpWifi);
    assert.equal(corpWifi.network_type, 'WIFI');
    assert.equal(corpWifi.security_type, 'WPA3_ENTERPRISE');
    assert.ok(corpWifi.assigned_devices_count >= 1);
  });

  it('NET-03: POST /api/v1/fleet/networks/profiles creates a new corporate Wi-Fi profile', async () => {
    const res = await api('/api/v1/fleet/networks/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Executive Guest Wi-Fi',
        description: 'Isolated high-speed guest network for executive visitors',
        network_type: 'WIFI',
        connection_name: 'ExecGuest',
        ssid: 'ExecGuest',
        security_type: 'WPA2_PERSONAL',
        eap_type: 'PSK',
        auto_connect: true,
        target_group_id: 'grp-all'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, 'Executive Guest Wi-Fi');
    assert.equal(res.body.network_type, 'WIFI');
    assert.ok(res.body.wlan_xml_preview.includes('ExecGuest'));
    createdWifiId = res.body.id;
  });

  it('NET-04: POST /api/v1/fleet/networks/profiles creates a new VPN tunnel profile', async () => {
    const res = await api('/api/v1/fleet/networks/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Homelab Admin WireGuard VPN',
        description: 'Direct site-to-site administration tunnel to homelab hypervisors',
        network_type: 'VPN',
        connection_name: 'Homelab-Tunnel',
        security_type: 'WIREGUARD',
        eap_type: 'CERTIFICATE',
        server_address: 'lab-gw.localpilot.io:51820',
        split_tunneling: true,
        always_on: true,
        target_group_id: 'grp-all'
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id);
    assert.equal(res.body.name, 'Homelab Admin WireGuard VPN');
    assert.equal(res.body.network_type, 'VPN');
    assert.equal(res.body.server_address, 'lab-gw.localpilot.io:51820');
    createdVpnId = res.body.id;
  });

  it('NET-05: POST /api/v1/fleet/networks/profiles rejects missing name', async () => {
    const res = await api('/api/v1/fleet/networks/profiles', {
      method: 'POST',
      body: JSON.stringify({
        network_type: 'WIFI',
        connection_name: 'MissingName'
      })
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  it('NET-06: POST /api/v1/fleet/networks/profiles rejects invalid network_type', async () => {
    const res = await api('/api/v1/fleet/networks/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Invalid Type Network',
        network_type: 'BLUETOOTH',
        connection_name: 'BT-Network'
      })
    });
    assert.equal(res.status, 400);
  });

  it('NET-07: POST /api/v1/fleet/networks/profiles rejects missing connection_name', async () => {
    const res = await api('/api/v1/fleet/networks/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Missing Conn Name',
        network_type: 'WIFI'
      })
    });
    assert.equal(res.status, 400);
  });

  it('NET-08: GET /api/v1/fleet/networks/profiles/:id returns profile details and XML preview', async () => {
    const res = await api(`/api/v1/fleet/networks/profiles/${createdWifiId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdWifiId);
    assert.equal(res.body.name, 'Executive Guest Wi-Fi');
    assert.ok(res.body.wlan_xml_preview);
    assert.ok(res.body.wlan_xml_preview.includes('<WLANProfile'));
  });

  it('NET-09: GET /api/v1/fleet/networks/profiles/:id returns 404 for unknown profile', async () => {
    const res = await api('/api/v1/fleet/networks/profiles/net-nonexistent-999');
    assert.equal(res.status, 404);
  });

  it('NET-10: PATCH /api/v1/fleet/networks/profiles/:id updates profile fields', async () => {
    const res = await api(`/api/v1/fleet/networks/profiles/${createdWifiId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated description for executive guest Wi-Fi',
        auto_connect: false
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.description, 'Updated description for executive guest Wi-Fi');
    assert.equal(res.body.auto_connect, false);
  });

  it('NET-11: PATCH /api/v1/fleet/networks/profiles/:id returns 404 for unknown profile', async () => {
    const res = await api('/api/v1/fleet/networks/profiles/net-unknown-xyz', {
      method: 'PATCH',
      body: JSON.stringify({ name: 'Should Fail' })
    });
    assert.equal(res.status, 404);
  });

  it('NET-12: DELETE /api/v1/fleet/networks/profiles/:id deletes the profile', async () => {
    const res = await api(`/api/v1/fleet/networks/profiles/${createdVpnId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.id, createdVpnId);

    const check = await api(`/api/v1/fleet/networks/profiles/${createdVpnId}`);
    assert.equal(check.status, 404);
  });

  it('NET-13: DELETE /api/v1/fleet/networks/profiles/:id returns 404 for already deleted profile', async () => {
    const res = await api(`/api/v1/fleet/networks/profiles/${createdVpnId}`, {
      method: 'DELETE'
    });
    assert.equal(res.status, 404);
  });

  it('NET-14: POST /api/v1/nodes/:id/network-posture records workstation Wi-Fi and adapter telemetry', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/network-posture`, {
      method: 'POST',
      body: JSON.stringify({
        connected_ssid: 'CorpNet-Secure',
        bssid: '00:11:22:33:44:55',
        signal_quality_pct: 94,
        radio_type: '802.11ax',
        channel: 36,
        security_type: 'WPA3_ENTERPRISE',
        active_adapters: [
          { name: 'Wi-Fi 6E', description: 'Intel(R) Wi-Fi 6E AX210', mac: '00:15:5D:AA:BB:CC', status: 'Up' },
          { name: 'Ethernet', description: 'Intel Ethernet Connection', mac: '00:15:5D:AA:BB:CD', status: 'Disconnected' }
        ],
        configured_profiles: ['CorpNet-Secure', 'Home-5G'],
        active_vpns: ['LocalPilot-Mesh'],
        ipv4_address: '192.168.1.145',
        ipv4_gateway: '192.168.1.1',
        dns_servers: ['192.168.1.1', '1.1.1.1']
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.connected_ssid, 'CorpNet-Secure');
    assert.equal(res.body.signal_quality_pct, 94);
    assert.equal(res.body.compliance_status, 'COMPLIANT');
    assert.equal(res.body.active_adapters.length, 2);
  });

  it('NET-15: POST /api/v1/nodes/:id/network-posture flags WARNING for unencrypted OPEN Wi-Fi', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/network-posture`, {
      method: 'POST',
      body: JSON.stringify({
        connected_ssid: 'Free-Airport-WiFi',
        security_type: 'OPEN',
        is_open_network: true,
        signal_quality_pct: 80,
        ipv4_address: '10.0.0.55'
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.connected_ssid, 'Free-Airport-WiFi');
    assert.equal(res.body.compliance_status, 'WARNING');
  });

  it('NET-16: GET /api/v1/fleet/devices/:id/network returns workstation posture and assigned profiles', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/network`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.posture);
    assert.equal(res.body.posture.connected_ssid, 'Free-Airport-WiFi');
    assert.ok(Array.isArray(res.body.assigned_profiles));
    assert.ok(res.body.assigned_profiles.length >= 2);
  });

  it('NET-17: GET /api/v1/fleet/networks/inventory filters devices by SSID and compliance', async () => {
    const resAll = await api('/api/v1/fleet/networks/inventory');
    assert.equal(resAll.status, 200);
    assert.ok(Array.isArray(resAll.body.inventory));
    assert.ok(resAll.body.inventory.length >= 1);

    const resFilter = await api('/api/v1/fleet/networks/inventory?compliance=WARNING');
    assert.equal(resFilter.status, 200);
    assert.ok(resFilter.body.inventory.some(d => d.device_id === testDeviceId));
  });

  it('NET-18: POST /api/v1/nodes/heartbeat delivers network_profiles to agent', async () => {
    const hbRes = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 12,
        ram_used_bytes: 8589934592,
        ram_free_bytes: 25769803776
      })
    });
    assert.equal(hbRes.status, 200);
    assert.ok(Array.isArray(hbRes.body.network_profiles));
    assert.ok(hbRes.body.network_profiles.length >= 2);
    const corpWifi = hbRes.body.network_profiles.find(p => p.connection_name === 'CorpNet-Secure');
    assert.ok(corpWifi);
    assert.equal(corpWifi.network_type, 'WIFI');
    assert.ok(corpWifi.wlan_xml.includes('CorpNet-Secure'));
  });

  it('NET-19: GET /api/v1/nodes/:id/network-profiles returns effective profiles for device', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/network-profiles`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(Array.isArray(res.body.profiles));
    assert.ok(res.body.profiles.length >= 2);
  });

  it('NET-20: Rejects unauthorized requests without valid credentials', async () => {
    const unauthorizedFleet = await fetch(`${app.baseUrl}/api/v1/fleet/networks/stats`, {
      headers: { 'Content-Type': 'application/json' }
    });
    assert.equal(unauthorizedFleet.status, 401);

    const unauthorizedNode = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/network-posture`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connected_ssid: 'Test' })
    });
    assert.equal(unauthorizedNode.status, 401);
  });
});
