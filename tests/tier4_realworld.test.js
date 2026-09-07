import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  setupTestEnvironment,
  teardownTestEnvironment,
  apiRequest,
  enrollTestDevice,
  getFleetKey,
  createEnrollPayload,
  createHeartbeatPayload,
  createTelemetryPayload,
  createEventPayload,
  getDispatchedAlerts,
  clearDispatchedAlerts
} from './harness/test_helper.js';

describe('Tier 4: Real-World Scenarios (End-to-End User & Admin Journeys)', () => {
  before(async () => {
    await setupTestEnvironment();
  });

  after(async () => {
    await teardownTestEnvironment();
  });

  // --------------------------------------------------------------------------
  // Scenario 1: The "Family Laptop on Roaming Wi-Fi" Journey
  // --------------------------------------------------------------------------
  it('Scenario 1: Daughter takes laptop from Home LAN to University Wi-Fi via Cloudflare Tunnel', async () => {
    // 1. Enrollment at Home on LAN
    const laptop = await enrollTestDevice({
      hostname: 'DAUGHTER-XPS15',
      friendly_name: "Emma's Dell XPS 15",
      has_battery: true,
      battery_percent: 100.0,
      tags: ['family', 'laptop', 'student']
    });

    // Verify initial state: LAN, 100% battery
    const initialCheck = await apiRequest(`/api/v1/fleet/devices/${laptop.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(initialCheck.data.device.connection_route, 'LAN');
    assert.equal(initialCheck.data.device.battery_percent, 100.0);
    assert.ok(initialCheck.data.groups.some(g => g.id === 'grp-family-laptops'));

    // 2. Daughter closes lid, travels to campus, opens laptop on university Wi-Fi.
    // LAN probe times out at 1500ms; dual-mode resolver switches to Cloudflare Tunnel.
    const roamingHb = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: laptop.node_token,
      headers: {
        'CF-Connecting-IP': '139.130.4.5',
        'CF-Ray': '85f392819a0-SYD'
      },
      body: createHeartbeatPayload({
        ip_address: '10.140.22.84',
        battery_percent: 68.0,
        battery_charging: false,
        uptime_seconds: 7200
      })
    });
    assert.equal(roamingHb.status, 200);
    assert.equal(roamingHb.data.acknowledged, true);

    // 3. Daddy checks Fleet Console: device shows Online, Cloudflare badge, 68% battery
    const roamingCheck = await apiRequest(`/api/v1/fleet/devices/${laptop.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(roamingCheck.data.device.status, 'online');
    assert.equal(roamingCheck.data.device.connection_route, 'Cloudflare');
    assert.equal(roamingCheck.data.device.battery_percent, 68.0);
    assert.equal(roamingCheck.data.device.ip_address, '10.140.22.84');
  });

  // --------------------------------------------------------------------------
  // Scenario 2: The "Rogue Local User Creation" Watchdog Alert (< 2.0s Latency)
  // --------------------------------------------------------------------------
  it('Scenario 2: Rogue account creation triggers Event 4720 watchdog, desktop toast, and sub-2s alert', async () => {
    clearDispatchedAlerts();
    const livingRoom = await enrollTestDevice({
      hostname: 'LIVINGROOM-PC',
      friendly_name: 'Living Room Family PC'
    });

    const startTimestamp = performance.now();

    // 1. Simulated Event 4720 fired on client
    const evtPayload = createEventPayload({
      event_type: 'USER_CREATED',
      event_id: 4720,
      severity: 'CRITICAL',
      summary: "CRITICAL: New local Windows user account 'gamer123' created on LIVINGROOM-PC",
      details: {
        TargetUserName: 'gamer123',
        TargetDomainName: 'LIVINGROOM-PC',
        SubjectUserName: 'Dad',
        SubjectUserSid: 'S-1-5-21-239482938-239482-1001'
      }
    });

    const dispatchRes = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: livingRoom.node_token,
      body: evtPayload
    });

    const totalElapsedMs = performance.now() - startTimestamp;

    // 2. Verify sub-2-second latency requirement (NFR-02)
    assert.equal(dispatchRes.status, 202);
    assert.ok(totalElapsedMs < 2000, `Alert pipeline must complete in < 2000ms (took ${totalElapsedMs.toFixed(1)}ms)`);

    // 3. Verify notifications dispatched to Daddy PC toast and Discord webhook
    const alerts = getDispatchedAlerts();
    assert.ok(alerts.toasts.some(t => t.body.includes('gamer123')));
    assert.ok(alerts.discord.some(d => d.summary.includes('gamer123')));

    // 4. Daddy reviews event in Live Activity Feed and acknowledges it
    const eventId = dispatchRes.data.event_record_id;
    const ackRes = await apiRequest(`/api/v1/fleet/events/${eventId}/ack`, {
      method: 'POST',
      fleetKey: getFleetKey()
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.data.acknowledged, true);
  });

  // --------------------------------------------------------------------------
  // Scenario 3: The "Unapproved P2P Torrent App" Detection & Drift Remediation
  // --------------------------------------------------------------------------
  it('Scenario 3: Homelab VM installs prohibited app uTorrent; system flags drift and alert', async () => {
    const vmNode = await enrollTestDevice({
      hostname: 'HOMELAB-WIN-01',
      friendly_name: 'Windows Homelab VM',
      tags: ['homelab', 'vm']
    });

    // 1. VM checks policy: uTorrent is prohibited
    const policyRes = await apiRequest(`/api/v1/nodes/${vmNode.device_id}/policy`, {
      nodeToken: vmNode.node_token
    });
    assert.equal(policyRes.status, 200);
    const prohibited = policyRes.data.policies.prohibited;
    assert.ok(prohibited.some(p => p.software_id === 'pkg-utorrent'));

    // 2. VM reports telemetry with uTorrent installed
    const teleRes = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: vmNode.node_token,
      body: createTelemetryPayload(vmNode.device_id, {
        installed_software: [
          { name: 'Google Chrome', winget_id: 'Google.Chrome', version: '122.0' },
          { name: 'uTorrent', publisher: 'BitTorrent Inc.', winget_id: 'BitTorrent.uTorrent', version: '3.5.5' }
        ]
      })
    });

    assert.equal(teleRes.status, 200);
    assert.equal(teleRes.data.drift_detected, true);
    assert.ok(teleRes.data.drift_reasons.some(r => r.includes('uTorrent')));

    // 3. Verify device status is now 'drifted'
    const devCheck = await apiRequest(`/api/v1/fleet/devices/${vmNode.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(devCheck.data.device.status, 'drifted');

    // 4. Verify security event created for the prohibited app
    const eventCheck = await apiRequest('/api/v1/fleet/events?severity=CRITICAL', {
      fleetKey: getFleetKey()
    });
    assert.ok(eventCheck.data.some(e => e.device_id === vmNode.device_id && e.event_type === 'APP_PROHIBITED_DETECTED'));
  });

  // --------------------------------------------------------------------------
  // Scenario 4: The "High-Performance Workstation Zero-Touch Setup"
  // --------------------------------------------------------------------------
  it('Scenario 4: High-performance gaming rig enrolls, matches workstation group, receives policies', async () => {
    // 1. Enroll high-spec desktop rig
    const gamingRig = await enrollTestDevice({
      hostname: 'DADDY-BEEF-RIG',
      friendly_name: "Daddy's Ultimate Gaming Workstation",
      os_name: 'Microsoft Windows 11 Pro',
      os_version: '10.0.22631',
      cpu_model: 'AMD Ryzen 9 7950X 16-Core Processor',
      cpu_cores: 16,
      cpu_logical: 32,
      total_ram_bytes: 68719476736, // 64GB
      gpu_name: 'NVIDIA GeForce RTX 4090 24GB',
      has_battery: false,
      tpm_present: true,
      tpm_enabled: true,
      secure_boot_enabled: true,
      tags: ['gaming', 'workstation', 'daddy']
    });

    // 2. Verify dynamic groups automatically assigned:
    // Should match 'grp-workstations' (>=32GB RAM + NVIDIA GPU + No Battery)
    // Should match 'grp-win11-modern' (Win 11 + TPM enabled + SecureBoot)
    const devCheck = await apiRequest(`/api/v1/fleet/devices/${gamingRig.device_id}`, {
      fleetKey: getFleetKey()
    });
    const groupIds = devCheck.data.groups.map(g => g.id);
    assert.ok(groupIds.includes('grp-workstations'), 'Must qualify for High-Performance Workstations');
    assert.ok(groupIds.includes('grp-win11-modern'), 'Must qualify for Windows 11 Modern Core');

    // 3. Query policy assignments
    const policyRes = await apiRequest(`/api/v1/nodes/${gamingRig.device_id}/policy`, {
      nodeToken: gamingRig.node_token
    });
    assert.equal(policyRes.status, 200);
    // Workstation policy grants Steam and VS Code in available packages
    const available = policyRes.data.policies.available;
    assert.ok(available.some(a => a.software_id === 'pkg-steam'));
    assert.ok(available.some(a => a.software_id === 'pkg-vscode'));
  });

  // --------------------------------------------------------------------------
  // Scenario 5: The "Low Storage Capacity Watchlist" Incident
  // --------------------------------------------------------------------------
  it('Scenario 5: Media server storage drops below 50GB; node automatically joins warning group', async () => {
    const serverNode = await enrollTestDevice({
      hostname: 'PLEX-MEDIA-01',
      friendly_name: 'Plex & Storage Server'
    });

    // 1. Initial snapshot with plenty of space (450GB free)
    await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: serverNode.node_token,
      body: createTelemetryPayload(serverNode.device_id, {
        hardware: {
          cpu_usage_percent: 5,
          ram_usage_percent: 30,
          disks: [{ drive_letter: 'C:', total_gb: 1000, free_gb: 450, smart_status: 'Healthy' }]
        }
      })
    });

    const check1 = await apiRequest(`/api/v1/fleet/devices/${serverNode.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(!check1.data.groups.some(g => g.id === 'grp-low-storage'), 'Should not be in low storage group yet');

    // 2. Large media downloads consume disk; free space drops to 32GB (<50GB threshold)
    await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: serverNode.node_token,
      body: createTelemetryPayload(serverNode.device_id, {
        hardware: {
          cpu_usage_percent: 15,
          ram_usage_percent: 45,
          disks: [{ drive_letter: 'C:', total_gb: 1000, free_gb: 32.5, smart_status: 'Healthy' }]
        }
      })
    });

    // 3. Verify server automatically joined 'grp-low-storage'
    const check2 = await apiRequest(`/api/v1/fleet/devices/${serverNode.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(check2.data.groups.some(g => g.id === 'grp-low-storage'), 'Must join Storage Warning Watchlist');
  });

  // --------------------------------------------------------------------------
  // Scenario 6: The "Privilege Escalation Watchdog Alert" (Event 4732)
  // --------------------------------------------------------------------------
  it('Scenario 6: User added to local Administrators group triggers Event 4732 watchdog alert', async () => {
    clearDispatchedAlerts();
    const kidPc = await enrollTestDevice({
      hostname: 'KIDS-MINECRAFT-PC',
      friendly_name: "Kid's Gaming PC"
    });

    // Watchdog fires Event 4732
    const evtRes = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: kidPc.node_token,
      body: createEventPayload({
        event_type: 'ADMIN_ADDED',
        event_id: 4732,
        event_source: 'Security',
        severity: 'CRITICAL',
        summary: "SECURITY ALERT: Account 'junior' added to local Administrators group on KIDS-MINECRAFT-PC",
        details: {
          TargetUserName: 'junior',
          TargetSid: 'S-1-5-32-544',
          SubjectUserName: 'Dad'
        }
      })
    });

    assert.equal(evtRes.status, 202);
    assert.equal(evtRes.data.toast_fired, true);

    const alerts = getDispatchedAlerts();
    assert.ok(alerts.slack.some(s => s.summary.includes('junior')));
    assert.ok(alerts.telegram.some(t => t.summary.includes('junior')));
  });

  // --------------------------------------------------------------------------
  // Scenario 7: The "Off-Grid Spool & Chronological Drain"
  // --------------------------------------------------------------------------
  it('Scenario 7: Client buffers events while off-grid and drains successfully on reconnection', async () => {
    const travelLaptop = await enrollTestDevice({
      hostname: 'TRAVEL-SURFACE-PRO',
      friendly_name: 'Travel Surface Pro'
    });

    // Simulated offline spool queue on local client disk
    const offlineSpoolQueue = [
      {
        endpoint: '/api/v1/nodes/heartbeat',
        body: createHeartbeatPayload({ battery_percent: 92.0, uptime_seconds: 1000 })
      },
      {
        endpoint: '/api/v1/nodes/events',
        body: createEventPayload({
          event_type: 'USER_DELETED',
          event_id: 4726,
          severity: 'WARNING',
          summary: 'Temporary user removed while off-grid'
        })
      },
      {
        endpoint: '/api/v1/nodes/heartbeat',
        body: createHeartbeatPayload({ battery_percent: 85.0, uptime_seconds: 2000 })
      }
    ];

    // Node reconnects to Wi-Fi; drain spool in sequential FIFO order
    for (const item of offlineSpoolQueue) {
      const drainRes = await apiRequest(item.endpoint, {
        method: 'POST',
        nodeToken: travelLaptop.node_token,
        body: item.body
      });
      assert.ok(drainRes.status === 200 || drainRes.status === 202);
    }

    // Verify latest state on server reflects final battery level
    const finalCheck = await apiRequest(`/api/v1/fleet/devices/${travelLaptop.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(finalCheck.data.device.battery_percent, 85.0);
  });

  // --------------------------------------------------------------------------
  // Scenario 8: The "Executive Family Fleet Health Audit & Morning Briefing"
  // --------------------------------------------------------------------------
  it('Scenario 8: Daddy PC Morning Briefing aggregates entire fleet health and resolves alerts', async () => {
    // 1. Review Executive KPI overview
    const kpiRes = await apiRequest('/api/v1/fleet/stats', {
      fleetKey: getFleetKey()
    });
    assert.equal(kpiRes.status, 200);
    assert.ok(kpiRes.data.total_devices >= 4);
    assert.ok(kpiRes.data.total_fleet_ram_gb > 50);

    // 2. Query device list with all tags
    const listRes = await apiRequest('/api/v1/fleet/devices', {
      fleetKey: getFleetKey()
    });
    assert.equal(listRes.status, 200);
    assert.ok(listRes.data.devices.length >= 4);

    // 3. Check live audit feed
    const auditRes = await apiRequest('/api/v1/fleet/events', {
      fleetKey: getFleetKey()
    });
    assert.equal(auditRes.status, 200);
    assert.ok(Array.isArray(auditRes.data));
  });
});
