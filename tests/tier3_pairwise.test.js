import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  setupTestEnvironment,
  teardownTestEnvironment,
  apiRequest,
  enrollTestDevice,
  getFleetKey,
  getBaseUrl,
  createEnrollPayload,
  createHeartbeatPayload,
  createTelemetryPayload,
  createEventPayload,
  getDispatchedAlerts,
  clearDispatchedAlerts
} from './harness/test_helper.js';

describe('Tier 3: Cross-Feature Combinations (Multi-Step Interaction Flows)', () => {
  before(async () => {
    await setupTestEnvironment();
  });

  after(async () => {
    await teardownTestEnvironment();
  });

  // --------------------------------------------------------------------------
  // Flow 1: Full Device Lifecycle (Enroll -> Heartbeat -> Deep Telemetry -> Inspect)
  // --------------------------------------------------------------------------
  it('Flow 1: should execute full device lifecycle from enrollment to deep inspection', async () => {
    // 1. Enroll
    const dev = await enrollTestDevice({
      hostname: 'LIFECYCLE-PC-01',
      os_name: 'Microsoft Windows 11 Enterprise',
      cpu_model: 'Intel Core i7-13700K',
      total_ram_bytes: 34359738368
    });
    assert.ok(dev.device_id);
    assert.ok(dev.node_token);

    // 2. Heartbeat Keepalive
    const hbRes = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload({ cpu_usage_percent: 22.5, ram_usage_percent: 45.0 })
    });
    assert.equal(hbRes.status, 200);

    // 3. Deep Telemetry Snapshot
    const telePayload = createTelemetryPayload(dev.device_id, {
      hardware: {
        cpu_usage_percent: 22.5,
        ram_used_bytes: 15461882265,
        ram_free_bytes: 18897856103,
        ram_usage_percent: 45.0,
        disks: [{ drive_letter: 'C:', total_gb: 1000, free_gb: 650, smart_status: 'Healthy' }]
      }
    });
    const teleRes = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });
    assert.equal(teleRes.status, 200);

    // 4. Inspect Birth Certificate via Dashboard API
    const certRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(certRes.status, 200);
    assert.equal(certRes.data.device.hostname, 'LIFECYCLE-PC-01');
    assert.equal(certRes.data.device.cpu_model, 'Intel Core i7-13700K');
    assert.equal(certRes.data.device.total_ram_gb, 32);
    assert.ok(certRes.data.latest_telemetry);
    assert.equal(certRes.data.latest_telemetry.disk_free_gb, 650);
  });

  // --------------------------------------------------------------------------
  // Flow 2: Dynamic Group Auto-Join on Hardware Qualification
  // --------------------------------------------------------------------------
  it('Flow 2: should automatically add node to dynamic group when telemetry qualifies', async () => {
    // 1. Create dynamic group requiring >= 32GB RAM
    const grpId = `grp-ram32-${crypto.randomBytes(3).toString('hex')}`;
    await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: grpId,
        name: `Workstations 32GB ${grpId}`,
        rule_syntax: 'Device.TotalRAM_GB -ge 32'
      }
    });

    // 2. Enroll device with only 16GB RAM (does not qualify initially)
    const dev = await enrollTestDevice({ total_ram_bytes: 17179869184 }); // 16GB
    const check1 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(!check1.data.groups.some(g => g.id === grpId), 'Should not belong to 32GB group yet');

    // 3. Hardware upgrade: re-enroll or update with 32GB RAM
    await enrollTestDevice({
      uuid: dev.payload.uuid,
      serial_number: dev.payload.serial_number,
      hostname: dev.payload.hostname,
      total_ram_bytes: 34359738368 // 32GB
    });

    // 4. Verify membership auto-joined
    const check2 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(check2.data.groups.some(g => g.id === grpId), 'Should now belong to 32GB group');
  });

  // --------------------------------------------------------------------------
  // Flow 3: Dynamic Group Auto-Leave on Hardware Modification
  // --------------------------------------------------------------------------
  it('Flow 3: should automatically remove node from dynamic group when telemetry no longer qualifies', async () => {
    const grpId = `grp-leave-${crypto.randomBytes(3).toString('hex')}`;
    await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: grpId,
        name: `Fast Rigs ${grpId}`,
        rule_syntax: 'Device.TotalRAM_GB -ge 64'
      }
    });

    // Enroll with 64GB
    const dev = await enrollTestDevice({ total_ram_bytes: 68719476736 });
    const check1 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(check1.data.groups.some(g => g.id === grpId), 'Initial qualification');

    // Downgrade to 16GB
    await enrollTestDevice({
      uuid: dev.payload.uuid,
      serial_number: dev.payload.serial_number,
      hostname: dev.payload.hostname,
      total_ram_bytes: 17179869184
    });

    const check2 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(!check2.data.groups.some(g => g.id === grpId), 'Must be removed after downgrade');
  });

  // --------------------------------------------------------------------------
  // Flow 4: Dynamic Group Tag-Based Membership Recalculation
  // --------------------------------------------------------------------------
  it('Flow 4: should recalculate dynamic group memberships when device tags are updated via PATCH', async () => {
    const grpId = `grp-tag-${crypto.randomBytes(3).toString('hex')}`;
    await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: grpId,
        name: `Finance Dept ${grpId}`,
        rule_syntax: "Device.Tags -contains 'finance'"
      }
    });

    // Enroll without tag
    const dev = await enrollTestDevice({ tags: ['unassigned'] });

    // PATCH tag to 'finance'
    await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      method: 'PATCH',
      fleetKey: getFleetKey(),
      body: { tags: ['finance', 'accounting'] }
    });

    const check = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(check.data.groups.some(g => g.id === grpId), 'Device must be assigned to Finance Dept group');
  });

  // --------------------------------------------------------------------------
  // Flow 5: Policy Calculation Pipeline (Group -> Policy Assignment -> Node Policy)
  // --------------------------------------------------------------------------
  it('Flow 5: should calculate effective policy for device based on assigned dynamic group', async () => {
    // 1. Create unique dynamic group and package
    const grpId = `grp-pol-${crypto.randomBytes(3).toString('hex')}`;
    await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: grpId,
        name: `Policy Test Group ${grpId}`,
        rule_syntax: "Device.Tags -contains 'policy_test'"
      }
    });

    const pkgId = `pkg-custom-${crypto.randomBytes(3).toString('hex')}`;
    await apiRequest('/api/v1/fleet/software', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: pkgId,
        name: 'Custom Internal Tool',
        publisher: 'Homelab',
        winget_id: `Homelab.CustomTool.${pkgId}`
      }
    });

    // 2. Assign package as Required to group
    await apiRequest('/api/v1/fleet/policies', {
      method: 'PUT',
      fleetKey: getFleetKey(),
      body: {
        group_id: grpId,
        software_id: pkgId,
        assignment_type: 'Required'
      }
    });

    // 3. Enroll device matching tag
    const dev = await enrollTestDevice({ tags: ['policy_test'] });

    // 4. Query node policy
    const polRes = await apiRequest(`/api/v1/nodes/${dev.device_id}/policy`, {
      nodeToken: dev.node_token
    });

    assert.equal(polRes.status, 200);
    const reqList = polRes.data.policies.required;
    assert.ok(reqList.some(p => p.software_id === pkgId), 'Custom tool must be present in effective required policies');
  });

  // --------------------------------------------------------------------------
  // Flow 6: Prohibited App Detection & Drift Lifecycle
  // --------------------------------------------------------------------------
  it('Flow 6: should detect prohibited app in telemetry, mark device drifted, and create security event', async () => {
    const dev = await enrollTestDevice();

    // Ingest telemetry reporting uTorrent (which is prohibited in default policy)
    const teleRes = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createTelemetryPayload(dev.device_id, {
        installed_software: [
          { name: 'uTorrent', publisher: 'BitTorrent Inc.', winget_id: 'BitTorrent.uTorrent', version: '3.5.5' }
        ]
      })
    });

    assert.equal(teleRes.status, 200);
    assert.equal(teleRes.data.drift_detected, true);

    // Verify device status transitioned to 'drifted'
    const devRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(devRes.data.device.status, 'drifted');

    // Verify security event created
    const eventsRes = await apiRequest('/api/v1/fleet/events?severity=CRITICAL', {
      fleetKey: getFleetKey()
    });
    assert.ok(eventsRes.data.some(e => e.device_id === dev.device_id && e.event_type === 'APP_PROHIBITED_DETECTED'));
  });

  // --------------------------------------------------------------------------
  // Flow 7: Security Watchdog Ingest to Alert Dispatch Chain
  // --------------------------------------------------------------------------
  it('Flow 7: should receive Event 4720 watchdog alert and dispatch toast and multi-channel webhooks', async () => {
    clearDispatchedAlerts();
    const dev = await enrollTestDevice();

    const evtRes = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        event_type: 'USER_CREATED',
        event_id: 4720,
        severity: 'CRITICAL',
        summary: `New local user account 'intruder' created on ${dev.payload.hostname}`,
        details: { TargetUserName: 'intruder', SubjectUserName: 'Dad' }
      })
    });

    assert.equal(evtRes.status, 202);
    assert.equal(evtRes.data.toast_fired, true);

    const alerts = getDispatchedAlerts();
    assert.ok(alerts.toasts.length > 0);
    assert.ok(alerts.discord.length > 0);
    assert.ok(alerts.slack.length > 0);
    assert.ok(alerts.telegram.length > 0);
  });

  // --------------------------------------------------------------------------
  // Flow 8: Alert Acknowledgment Impact on Executive KPI Counters
  // --------------------------------------------------------------------------
  it('Flow 8: should decrement critical alerts counter in executive KPI when alert is acknowledged', async () => {
    const dev = await enrollTestDevice();

    // Trigger critical alert
    const evtRes = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ severity: 'CRITICAL', summary: 'KPI ack test' })
    });
    const eventId = evtRes.data.event_record_id;

    // Check KPI before ack
    const kpiBefore = await apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() });
    const alertsBefore = kpiBefore.data.critical_alerts;
    assert.ok(alertsBefore >= 1);

    // Acknowledge alert
    const ackRes = await apiRequest(`/api/v1/fleet/events/${eventId}/ack`, {
      method: 'POST',
      fleetKey: getFleetKey()
    });
    assert.equal(ackRes.status, 200);

    // Check KPI after ack
    const kpiAfter = await apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() });
    assert.equal(kpiAfter.data.critical_alerts, alertsBefore - 1);
  });

  // --------------------------------------------------------------------------
  // Flow 9: Dual-Mode Connection Route Transition (LAN to Cloudflare Tunnel)
  // --------------------------------------------------------------------------
  it('Flow 9: should track node transition from local LAN to roaming Cloudflare Tunnel', async () => {
    const dev = await enrollTestDevice();

    // 1. Heartbeat on LAN
    await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload({ connection_route: 'LAN', ip_address: '192.168.1.150' })
    });

    const checkLan = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(checkLan.data.device.connection_route, 'LAN');

    // 2. Node moves to coffee shop Wi-Fi and connects via Cloudflare Tunnel
    await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      headers: { 'CF-Connecting-IP': '104.28.210.12' },
      body: createHeartbeatPayload({ ip_address: '10.0.0.45' })
    });

    const checkTunnel = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(checkTunnel.data.device.connection_route, 'Cloudflare');
  });

  // --------------------------------------------------------------------------
  // Flow 10: Device Decommission Cascade Cleanup
  // --------------------------------------------------------------------------
  it('Flow 10: should cascade delete telemetry snapshots and memberships on device removal', async () => {
    const dev = await enrollTestDevice();

    // Ingest telemetry
    await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createTelemetryPayload(dev.device_id)
    });

    // Delete device
    const delRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      method: 'DELETE',
      fleetKey: getFleetKey()
    });
    assert.equal(delRes.status, 200);

    // Device not found
    const getRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(getRes.status, 404);

    // Token should no longer be authorized
    const hbRes = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload()
    });
    assert.equal(hbRes.status, 401);
  });

  // --------------------------------------------------------------------------
  // Flow 11: Dynamic Rule Modification Re-evaluates All Enrolled Nodes
  // --------------------------------------------------------------------------
  it('Flow 11: should re-evaluate all nodes when a dynamic group rule is created or updated', async () => {
    // Enroll 2 nodes
    const nodeA = await enrollTestDevice({ hostname: 'WORKSTATION-A', total_ram_bytes: 17179869184 }); // 16GB
    const nodeB = await enrollTestDevice({ hostname: 'WORKSTATION-B', total_ram_bytes: 34359738368 }); // 32GB

    const grpId = `grp-test-reeval-${crypto.randomBytes(3).toString('hex')}`;
    // Create rule for >= 32GB (only B should match)
    await apiRequest('/api/v1/fleet/groups', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: grpId,
        name: `Reeval Group ${grpId}`,
        rule_syntax: 'Device.TotalRAM_GB -ge 32'
      }
    });

    const checkA1 = await apiRequest(`/api/v1/fleet/devices/${nodeA.device_id}`, { fleetKey: getFleetKey() });
    const checkB1 = await apiRequest(`/api/v1/fleet/devices/${nodeB.device_id}`, { fleetKey: getFleetKey() });

    assert.ok(!checkA1.data.groups.some(g => g.id === grpId));
    assert.ok(checkB1.data.groups.some(g => g.id === grpId));
  });

  // --------------------------------------------------------------------------
  // Flow 12: Fleet Configuration Propagation to Cloudflare Tunnel
  // --------------------------------------------------------------------------
  it('Flow 12: should propagate updated server port to generated Cloudflare ingress rules', async () => {
    // Update port in settings
    await apiRequest('/api/v1/fleet/settings', {
      method: 'PUT',
      fleetKey: getFleetKey(),
      body: { server_port: '9443' }
    });

    // Generate tunnel config
    const genRes = await apiRequest('/api/v1/fleet/tunnel/generate', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: { hostname: 'fleet.customhub.org' }
    });

    assert.equal(genRes.status, 200);
    assert.ok(genRes.data.config_yml.includes('http://localhost:9443'));
    assert.ok(genRes.data.config_yml.includes('fleet.customhub.org'));

    // Revert port back to 8443
    await apiRequest('/api/v1/fleet/settings', {
      method: 'PUT',
      fleetKey: getFleetKey(),
      body: { server_port: '8443' }
    });
  });

  // --------------------------------------------------------------------------
  // Flow 13: Compound Search & Filter Consistency
  // --------------------------------------------------------------------------
  it('Flow 13: should filter devices accurately using combined search and route filters', async () => {
    const suffix = crypto.randomBytes(3).toString('hex').toUpperCase();
    const devLan = await enrollTestDevice({ hostname: `ALPHA-${suffix}`, friendly_name: `Alpha Lan ${suffix}` });
    const devTunnel = await enrollTestDevice({ hostname: `BETA-${suffix}`, friendly_name: `Beta Tunnel ${suffix}` });

    // Set routes
    await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: devLan.node_token,
      body: createHeartbeatPayload({ connection_route: 'LAN' })
    });

    await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: devTunnel.node_token,
      headers: { 'CF-Connecting-IP': '1.1.1.1' },
      body: createHeartbeatPayload()
    });

    // Query LAN only
    const lanQuery = await apiRequest(`/api/v1/fleet/devices?search=${suffix}&route=LAN`, {
      fleetKey: getFleetKey()
    });
    assert.equal(lanQuery.status, 200);
    assert.ok(lanQuery.data.devices.some(d => d.hostname === `ALPHA-${suffix}`));
    assert.ok(!lanQuery.data.devices.some(d => d.hostname === `BETA-${suffix}`));
  });

  // --------------------------------------------------------------------------
  // Flow 14: Server-Sent Events (SSE) Live Feed Protocol
  // --------------------------------------------------------------------------
  it('Flow 14: should establish SSE connection and receive live event stream headers', async () => {
    const sseRes = await fetch(`${getBaseUrl()}/api/v1/fleet/events/stream`);
    assert.equal(sseRes.status, 200);
    assert.equal(sseRes.headers.get('content-type'), 'text/event-stream');

    const reader = sseRes.body.getReader();
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    assert.ok(text.includes('event: connected'));
    await reader.cancel();
  });

  // --------------------------------------------------------------------------
  // Flow 15: Multi-Device Fleet Ingestion & Aggregate KPI Consistency
  // --------------------------------------------------------------------------
  it('Flow 15: should aggregate multiple devices accurately into fleet total devices and RAM sums', async () => {
    const kpiBefore = await apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() });
    const initialDevices = kpiBefore.data.total_devices;
    const initialRam = kpiBefore.data.total_fleet_ram_gb;

    // Enroll 3 new devices: 16GB, 32GB, 64GB
    await enrollTestDevice({ total_ram_bytes: 17179869184 }); // 16GB
    await enrollTestDevice({ total_ram_bytes: 34359738368 }); // 32GB
    await enrollTestDevice({ total_ram_bytes: 68719476736 }); // 64GB

    const kpiAfter = await apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() });
    assert.equal(kpiAfter.data.total_devices, initialDevices + 3);
    assert.equal(kpiAfter.data.total_fleet_ram_gb, initialRam + 112);
  });

  // --------------------------------------------------------------------------
  // Flow 16: Dynamic Group Battery Detection on Roaming Laptop
  // --------------------------------------------------------------------------
  it('Flow 16: should detect battery hardware, auto-join Family Laptops, and track battery discharge', async () => {
    const dev = await enrollTestDevice({
      has_battery: true,
      battery_percent: 100.0,
      tags: ['family', 'laptop']
    });

    // Check membership in 'grp-family-laptops'
    const check1 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.ok(check1.data.groups.some(g => g.id === 'grp-family-laptops'));

    // Discharge battery to 35% on subsequent heartbeat
    await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createHeartbeatPayload({ battery_percent: 35.0, battery_charging: false })
    });

    const check2 = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(check2.data.device.battery_percent, 35.0);
  });
});
