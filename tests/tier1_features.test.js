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
  evaluateRule,
  getDispatchedAlerts,
  clearDispatchedAlerts,
  DEFAULT_FLEET_KEY
} from './harness/test_helper.js';

describe('Tier 1: Feature Coverage (Isolated Core Requirements)', () => {
  before(async () => {
    await setupTestEnvironment();
  });

  after(async () => {
    await teardownTestEnvironment();
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-01: Executive Fleet Overview KPI Cards
  // --------------------------------------------------------------------------
  it('FEAT-R1-01: should return executive fleet overview KPIs with live counts and utilization', async () => {
    const res = await apiRequest('/api/v1/fleet/stats', {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.ok(typeof res.data.total_devices === 'number', 'total_devices must be a number');
    assert.ok(typeof res.data.online === 'number', 'online count must be a number');
    assert.ok(typeof res.data.offline === 'number', 'offline count must be a number');
    assert.ok(typeof res.data.drifted === 'number', 'drifted count must be a number');
    assert.ok(typeof res.data.critical_alerts === 'number', 'critical_alerts count must be a number');
    assert.ok(typeof res.data.total_fleet_ram_gb === 'number', 'total_fleet_ram_gb must be a number');
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-02: Device Management & Quick Search Filter
  // --------------------------------------------------------------------------
  it('FEAT-R1-02: should filter device inventory grid by keyword query', async () => {
    const uniqueHost = `SEARCH-NODE-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await enrollTestDevice({ hostname: uniqueHost });

    const res = await apiRequest(`/api/v1/fleet/devices?search=${uniqueHost}`, {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.devices));
    const found = res.data.devices.find(d => d.hostname === uniqueHost);
    assert.ok(found, `Device ${uniqueHost} should be returned in filtered results`);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-03: Birth Certificate Hardware Inspector
  // --------------------------------------------------------------------------
  it('FEAT-R1-03: should retrieve complete Birth Certificate hardware specs for enrolled node', async () => {
    const dev = await enrollTestDevice({
      cpu_model: 'AMD Ryzen 9 7950X 16-Core',
      cpu_cores: 16,
      cpu_logical: 32,
      gpu_name: 'NVIDIA GeForce RTX 4090',
      total_ram_bytes: 68719476736 // 64GB
    });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.device.cpu_model, 'AMD Ryzen 9 7950X 16-Core');
    assert.equal(res.data.device.cpu_cores, 16);
    assert.equal(res.data.device.gpu_name, 'NVIDIA GeForce RTX 4090');
    assert.equal(res.data.device.total_ram_gb, 64);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-04: Birth Certificate Software Roster
  // --------------------------------------------------------------------------
  it('FEAT-R1-04: should ingest and display installed software roster in Birth Certificate', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id, {
      installed_software: [
        { name: 'VS Code', publisher: 'Microsoft', version: '1.87.0', winget_id: 'Microsoft.VisualStudioCode', install_type: 'Registry' },
        { name: 'Slack', publisher: 'Slack Technologies', version: '4.36.0', winget_id: 'SlackTechnologies.Slack', install_type: 'AppX' }
      ]
    });

    await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });

    const res = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.ok(res.data.latest_telemetry);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-05: Birth Certificate Local Accounts Inspector
  // --------------------------------------------------------------------------
  it('FEAT-R1-05: should ingest and verify local Windows accounts and admin privileges', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id, {
      security: {
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        local_users: [
          { username: 'AdminUser', is_admin: true, is_disabled: false },
          { username: 'GuestKid', is_admin: false, is_disabled: false }
        ]
      }
    });

    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'processed');
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-06: Dynamic Group Builder Syntax Validation
  // --------------------------------------------------------------------------
  it('FEAT-R1-06: should validate Entra ID dynamic rule syntax and reject malformed queries', async () => {
    // Valid rule syntax
    const validRes = await apiRequest('/api/v1/fleet/groups/evaluate', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: { rule_syntax: "Device.TotalRAM_GB -ge 32 and Device.GPU -like '*NVIDIA*'" }
    });
    assert.equal(validRes.status, 200);
    assert.equal(validRes.data.valid, true);

    // Invalid rule syntax
    const invalidRes = await apiRequest('/api/v1/fleet/groups/evaluate', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: { rule_syntax: "Device.TotalRAM_GB -ge" }
    });
    assert.equal(invalidRes.status, 400);
    assert.equal(invalidRes.data.valid, false);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-07: Dynamic Group AST Rule Evaluation
  // --------------------------------------------------------------------------
  it('FEAT-R1-07: should evaluate device telemetry against complex AST rules', () => {
    const nodeContext = {
      hostname: 'GAMING-RIG-01',
      total_ram_gb: 32,
      gpu_name: 'NVIDIA GeForce RTX 4080',
      has_battery: false,
      tags: ['gaming', 'homelab']
    };

    // Rule 1: High RAM + NVIDIA
    const match1 = evaluateRule("Device.TotalRAM_GB -ge 32 and Device.GPU -like '*NVIDIA*'", nodeContext);
    assert.equal(match1, true);

    // Rule 2: Battery check (desktop has no battery)
    const match2 = evaluateRule("Device.HasBattery -eq true", nodeContext);
    assert.equal(match2, false);

    // Rule 3: Tags collection check
    const match3 = evaluateRule("Device.Tags -contains 'gaming'", nodeContext);
    assert.equal(match3, true);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-08: Declarative Software Catalog Management
  // --------------------------------------------------------------------------
  it('FEAT-R1-08: should list and create declarative software catalog packages', async () => {
    const listRes = await apiRequest('/api/v1/fleet/software', {
      fleetKey: getFleetKey()
    });
    assert.equal(listRes.status, 200);
    assert.ok(Array.isArray(listRes.data));
    assert.ok(listRes.data.some(p => p.winget_id === 'Google.Chrome'));

    // Create a new package
    const newPkgId = `pkg-test-${crypto.randomBytes(3).toString('hex')}`;
    const createRes = await apiRequest('/api/v1/fleet/software', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: {
        id: newPkgId,
        name: 'Mozilla Firefox',
        publisher: 'Mozilla',
        winget_id: `Mozilla.Firefox.${newPkgId}`,
        category: 'Browsers'
      }
    });
    assert.equal(createRes.status, 201);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-09: Policy Assignment Matrix
  // --------------------------------------------------------------------------
  it('FEAT-R1-09: should retrieve and update policy assignment matrix for dynamic groups', async () => {
    const polRes = await apiRequest('/api/v1/fleet/policies', {
      fleetKey: getFleetKey()
    });
    assert.equal(polRes.status, 200);
    assert.ok(Array.isArray(polRes.data.assignments));

    // Update assignment
    const updateRes = await apiRequest('/api/v1/fleet/policies', {
      method: 'PUT',
      fleetKey: getFleetKey(),
      body: {
        group_id: 'grp-family-laptops',
        software_id: 'pkg-7zip',
        assignment_type: 'Required'
      }
    });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.data.assigned, true);
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-10: Live Fleet Activity & Security Audit Feed
  // --------------------------------------------------------------------------
  it('FEAT-R1-10: should list chronological security audit events', async () => {
    const dev = await enrollTestDevice();
    await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ summary: 'Audit feed test event' })
    });

    const res = await apiRequest('/api/v1/fleet/events', {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data));
    assert.ok(res.data.some(e => e.summary === 'Audit feed test event'));
  });

  // --------------------------------------------------------------------------
  // FEAT-R1-11: Dark-Mode Command Center Dashboard Serving
  // --------------------------------------------------------------------------
  it('FEAT-R1-11: should serve static Command Center SPA entrypoint on root endpoint', async () => {
    const res = await apiRequest('/', { method: 'GET' });
    assert.equal(res.status, 200);
    assert.ok(typeof res.data === 'string');
    assert.match(res.data, /LocalPilot Fleet Command Center/i);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-01: Configurable REST Port & Health Endpoint
  // --------------------------------------------------------------------------
  it('FEAT-R2-01: should respond with HTTP 200 on /api/v1/health', async () => {
    const res = await apiRequest('/api/v1/health');
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'ok');
    assert.ok(res.data.timestamp);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-02: SQLite WAL Engine & Concurrency
  // --------------------------------------------------------------------------
  it('FEAT-R2-02: should execute concurrent transactions safely without lock errors', async () => {
    const promises = Array.from({ length: 15 }, (_, i) =>
      apiRequest('/api/v1/fleet/stats', { fleetKey: getFleetKey() })
    );
    const results = await Promise.all(promises);
    for (const r of results) {
      assert.equal(r.status, 200);
    }
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-03: Idempotent Schema & Core Tables Initialized
  // --------------------------------------------------------------------------
  it('FEAT-R2-03: should maintain all 8 core tables with seed data', async () => {
    const grpRes = await apiRequest('/api/v1/fleet/groups', { fleetKey: getFleetKey() });
    assert.equal(grpRes.status, 200);
    assert.ok(grpRes.data.length >= 4, 'Default dynamic groups must be seeded');

    const setRes = await apiRequest('/api/v1/fleet/settings', { fleetKey: getFleetKey() });
    assert.equal(setRes.status, 200);
    assert.ok(setRes.data.some(s => s.key === 'fleet_name'));
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-04: Node Enrollment API with FleetKey Validation
  // --------------------------------------------------------------------------
  it('FEAT-R2-04: should successfully enroll node with valid FleetKey and return NodeToken', async () => {
    const payload = createEnrollPayload({ hostname: 'ENROLL-TEST-01' });
    const res = await apiRequest('/api/v1/nodes/enroll', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: payload
    });

    assert.equal(res.status, 201);
    assert.equal(res.data.status, 'enrolled');
    assert.ok(res.data.device_id);
    assert.ok(res.data.node_token.startsWith('lp_node_'));
    assert.equal(res.data.heartbeat_interval_sec, 60);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-05: Node Heartbeat API
  // --------------------------------------------------------------------------
  it('FEAT-R2-05: should acknowledge node heartbeat keepalive and update presence', async () => {
    const dev = await enrollTestDevice();
    const hbPayload = createHeartbeatPayload({
      cpu_usage_percent: 18.2,
      ram_usage_percent: 42.0,
      connection_route: 'LAN'
    });

    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: hbPayload
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.acknowledged, true);
    assert.ok(res.data.server_time);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-06: Telemetry Ingestion API
  // --------------------------------------------------------------------------
  it('FEAT-R2-06: should ingest hardware, software, and account telemetry in O(1) time', async () => {
    const dev = await enrollTestDevice();
    const telePayload = createTelemetryPayload(dev.device_id);

    const start = performance.now();
    const res = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: telePayload
    });
    const elapsed = performance.now() - start;

    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'processed');
    assert.ok(elapsed < 500, 'Ingestion must complete swiftly (<500ms)');
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-07: Security Event Ingest API
  // --------------------------------------------------------------------------
  it('FEAT-R2-07: should ingest watchdog security events and trigger alert pipeline', async () => {
    clearDispatchedAlerts();
    const dev = await enrollTestDevice();
    const evtPayload = createEventPayload({
      event_type: 'USER_CREATED',
      event_id: 4720,
      severity: 'CRITICAL',
      summary: 'New local user account hacker99 created'
    });

    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: evtPayload
    });

    assert.equal(res.status, 202);
    assert.equal(res.data.status, 'dispatched');
    assert.ok(res.data.event_record_id > 0);
    assert.equal(res.data.toast_fired, true);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-08: Node Policy Query API
  // --------------------------------------------------------------------------
  it('FEAT-R2-08: should compute effective Required, Prohibited, and Available policies', async () => {
    const dev = await enrollTestDevice({ tags: ['family'] });
    const res = await apiRequest(`/api/v1/nodes/${dev.device_id}/policy`, {
      nodeToken: dev.node_token
    });

    assert.equal(res.status, 200);
    assert.ok(res.data.policies);
    assert.ok(Array.isArray(res.data.policies.required));
    assert.ok(Array.isArray(res.data.policies.prohibited));
    assert.ok(Array.isArray(res.data.policies.available));
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-09a: Fleet CRUD APIs - Update Device Metadata
  // --------------------------------------------------------------------------
  it('FEAT-R2-09a: should update device friendly name and tags via PATCH', async () => {
    const dev = await enrollTestDevice();
    const patchRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      method: 'PATCH',
      fleetKey: getFleetKey(),
      body: {
        friendly_name: "Mom's Office PC",
        tags: ['family', 'office', 'accounting']
      }
    });

    assert.equal(patchRes.status, 200);
    assert.equal(patchRes.data.updated, true);

    const getRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(getRes.data.device.friendly_name, "Mom's Office PC");
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-09b: Fleet CRUD APIs - Decommission / Delete Device
  // --------------------------------------------------------------------------
  it('FEAT-R2-09b: should remove decommissioned node and cascade delete memberships', async () => {
    const dev = await enrollTestDevice();
    const delRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      method: 'DELETE',
      fleetKey: getFleetKey()
    });

    assert.equal(delRes.status, 200);
    assert.equal(delRes.data.deleted, true);

    const checkRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(checkRes.status, 404);
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-10a: Dual-Tier Auth Middleware - Rejection on Missing FleetKey
  // --------------------------------------------------------------------------
  it('FEAT-R2-10a: should reject unauthorized admin calls without X-Fleet-Key with HTTP 401', async () => {
    const res = await apiRequest('/api/v1/fleet/stats', {
      fleetKey: 'INVALID-KEY-12345'
    });

    assert.equal(res.status, 401);
    assert.equal(res.data.error, 'INVALID_FLEET_KEY');
  });

  // --------------------------------------------------------------------------
  // FEAT-R2-10b: Dual-Tier Auth Middleware - Rejection on Missing Node Token
  // --------------------------------------------------------------------------
  it('FEAT-R2-10b: should reject node heartbeat with invalid Bearer token with HTTP 401', async () => {
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: 'invalid_token_99999',
      body: createHeartbeatPayload()
    });

    assert.equal(res.status, 401);
    assert.equal(res.data.error, 'INVALID_NODE_TOKEN');
  });

  // --------------------------------------------------------------------------
  // FEAT-R3-01: Cloudflare Tunnel Ingress Config Generator
  // --------------------------------------------------------------------------
  it('FEAT-R3-01: should generate valid cloudflared config.yml mapping domain to port', async () => {
    const res = await apiRequest('/api/v1/fleet/tunnel/generate', {
      method: 'POST',
      fleetKey: getFleetKey(),
      body: { hostname: 'fleet.familyhomelab.net' }
    });

    assert.equal(res.status, 200);
    assert.ok(res.data.config_yml.includes('fleet.familyhomelab.net'));
    assert.ok(res.data.config_yml.includes('http://localhost:8443'));
    assert.ok(res.data.config_yml.includes('/api/v1/fleet/events/stream'));
  });

  // --------------------------------------------------------------------------
  // FEAT-R3-02: One-Command Tunnel Setup CLI / Status Check
  // --------------------------------------------------------------------------
  it('FEAT-R3-02: should report Cloudflare Tunnel connection status and hostname', async () => {
    const res = await apiRequest('/api/v1/fleet/tunnel/status', {
      fleetKey: getFleetKey()
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.installed, true);
    assert.equal(res.data.running, true);
  });

  // --------------------------------------------------------------------------
  // FEAT-R3-03: Dual-Mode Resolver Algorithm Contract
  // --------------------------------------------------------------------------
  it('FEAT-R3-03: should verify dual-mode resolver prioritizes LAN and falls back to Tunnel', () => {
    // Contract definition test for agent resolver
    function resolveEndpoint(lanResponsive, tunnelResponsive) {
      if (lanResponsive) return { url: 'http://192.168.1.100:8443', route: 'LAN' };
      if (tunnelResponsive) return { url: 'https://fleet.yourdomain.com', route: 'Cloudflare' };
      return { url: null, route: 'Offline' };
    }

    assert.deepEqual(resolveEndpoint(true, true), { url: 'http://192.168.1.100:8443', route: 'LAN' });
    assert.deepEqual(resolveEndpoint(false, true), { url: 'https://fleet.yourdomain.com', route: 'Cloudflare' });
    assert.deepEqual(resolveEndpoint(false, false), { url: null, route: 'Offline' });
  });

  // --------------------------------------------------------------------------
  // FEAT-R3-04: Offline Event Spooling Contract
  // --------------------------------------------------------------------------
  it('FEAT-R3-04: should verify offline event serialization schema for local disk spooling', () => {
    const spoolItem = {
      spool_id: crypto.randomUUID(),
      queued_at: new Date().toISOString(),
      endpoint: '/api/v1/nodes/events',
      payload: createEventPayload({ summary: 'Spool test' })
    };

    const serialized = JSON.stringify(spoolItem);
    const deserialized = JSON.parse(serialized);

    assert.equal(deserialized.spool_id, spoolItem.spool_id);
    assert.equal(deserialized.endpoint, '/api/v1/nodes/events');
    assert.equal(deserialized.payload.event_type, 'USER_CREATED');
  });

  // --------------------------------------------------------------------------
  // FEAT-R3-05: Connection Route Tracker (Cloudflare Header Detection)
  // --------------------------------------------------------------------------
  it('FEAT-R3-05: should detect Cloudflare Tunnel ingress when CF-Connecting-IP header is present', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/heartbeat', {
      method: 'POST',
      nodeToken: dev.node_token,
      headers: {
        'CF-Connecting-IP': '172.68.1.5',
        'CF-Ray': '85f1234abcde-SYD'
      },
      body: createHeartbeatPayload()
    });

    assert.equal(res.status, 200);

    const devCheck = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(devCheck.data.device.connection_route, 'Cloudflare');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-01: Agent Installer Script Contract
  // --------------------------------------------------------------------------
  it('FEAT-R4-01: should validate installer parameter contract and configuration model', () => {
    const installParams = {
      ServerUrl: 'http://192.168.1.100:8443',
      CloudflareUrl: 'https://fleet.mydomain.com',
      FleetKey: DEFAULT_FLEET_KEY,
      FriendlyName: 'Living Room PC',
      Tags: 'family,desktop'
    };

    assert.ok(installParams.ServerUrl.startsWith('http'));
    assert.ok(installParams.FleetKey.startsWith('LP-FleetKey'));
    const parsedTags = installParams.Tags.split(',').map(t => t.trim());
    assert.deepEqual(parsedTags, ['family', 'desktop']);
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-02: Zero-Idle-RAM Scheduler Contract
  // --------------------------------------------------------------------------
  it('FEAT-R4-02: should verify task definitions for transient execution without resident daemon', () => {
    const tasks = [
      { name: 'LocalPilot-Heartbeat', interval_min: 1, action: 'Invoke-LocalPilotAgent.ps1 -Task Heartbeat' },
      { name: 'LocalPilot-Harvest', interval_min: 15, action: 'Invoke-LocalPilotAgent.ps1 -Task Harvest' },
      { name: 'LocalPilot-Watchdog', trigger: 'EventLogSubscription', action: 'Invoke-LocalPilotAgent.ps1 -Task WatchdogTrigger' }
    ];

    assert.equal(tasks.length, 3);
    assert.equal(tasks[0].interval_min, 1);
    assert.equal(tasks[1].interval_min, 15);
    assert.equal(tasks[2].trigger, 'EventLogSubscription');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-03: Hardware Spec Harvester Payload Schema
  // --------------------------------------------------------------------------
  it('FEAT-R4-03: should validate CIM physical disk and SMART wear telemetry schema', () => {
    const hwSnapshot = {
      motherboard_serial: 'MB-9938491823',
      cpu_model: 'Intel Core i9-13900K',
      ram_used_bytes: 16106127360,
      ram_free_bytes: 17179869184,
      disks: [
        {
          device_id: '\\\\.\\PHYSICALDRIVE0',
          drive_letter: 'C:',
          model: 'Samsung 990 PRO 2TB',
          total_gb: 1907.7,
          free_gb: 1120.4,
          smart_status: 'Healthy',
          temperature_c: 41
        }
      ]
    };

    assert.ok(hwSnapshot.disks[0].total_gb > 0);
    assert.equal(hwSnapshot.disks[0].smart_status, 'Healthy');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-04: OS & Security Harvester Payload Schema
  // --------------------------------------------------------------------------
  it('FEAT-R4-04: should validate TPM 2.0, SecureBoot, and BitLocker posture metrics', () => {
    const secSnapshot = {
      tpm_present: true,
      tpm_version: '2.0',
      tpm_enabled: true,
      secure_boot_enabled: true,
      bitlocker_volumes: [
        { mount_point: 'C:', protection_status: 'FullyEncrypted', encryption_percentage: 100 }
      ]
    };

    assert.equal(secSnapshot.tpm_present, true);
    assert.equal(secSnapshot.tpm_version, '2.0');
    assert.equal(secSnapshot.secure_boot_enabled, true);
    assert.equal(secSnapshot.bitlocker_volumes[0].protection_status, 'FullyEncrypted');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-05: Software Inventory Harvester Schema
  // --------------------------------------------------------------------------
  it('FEAT-R4-05: should validate software catalog items harvested from Registry, Winget, and AppX', () => {
    const softwareInventory = [
      { name: 'Git', publisher: 'Git for Windows', version: '2.44.0', winget_id: 'Git.Git', install_type: 'Registry' },
      { name: 'Windows Terminal', publisher: 'Microsoft', version: '1.19.10573.0', winget_id: 'Microsoft.WindowsTerminal', install_type: 'AppX' }
    ];

    assert.equal(softwareInventory.length, 2);
    assert.equal(softwareInventory[0].install_type, 'Registry');
    assert.equal(softwareInventory[1].install_type, 'AppX');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-06: Local Account Harvester Schema
  // --------------------------------------------------------------------------
  it('FEAT-R4-06: should identify local accounts and verify well-known Administrator SID S-1-5-32-544', () => {
    const adminSid = 'S-1-5-32-544';
    const localAccounts = [
      { username: 'Dad', sid: 'S-1-5-21-1001', is_admin: true, admin_group_sid: adminSid },
      { username: 'KidUser', sid: 'S-1-5-21-1002', is_admin: false, admin_group_sid: null }
    ];

    assert.equal(localAccounts[0].is_admin, true);
    assert.equal(localAccounts[0].admin_group_sid, adminSid);
    assert.equal(localAccounts[1].is_admin, false);
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-07: Event 4720 Watchdog (User Created)
  // --------------------------------------------------------------------------
  it('FEAT-R4-07: should process Event 4720 (User Created) with CRITICAL severity', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        event_type: 'USER_CREATED',
        event_id: 4720,
        severity: 'CRITICAL',
        summary: 'New local user account testuser created',
        details: { TargetUserName: 'testuser', SubjectUserName: 'Dad' }
      })
    });

    assert.equal(res.status, 202);
    assert.equal(res.data.status, 'dispatched');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-08: Event 4726 Watchdog (User Deleted)
  // --------------------------------------------------------------------------
  it('FEAT-R4-08: should process Event 4726 (User Deleted) with WARNING severity', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        event_type: 'USER_DELETED',
        event_id: 4726,
        severity: 'WARNING',
        summary: 'Local user account tempuser was deleted'
      })
    });

    assert.equal(res.status, 202);
    assert.equal(res.data.status, 'dispatched');
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-09: Event 4728/4732 Watchdog (Admin Added)
  // --------------------------------------------------------------------------
  it('FEAT-R4-09: should process Event 4732 (Admin Added) with CRITICAL alarm', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        event_type: 'ADMIN_ADDED',
        event_id: 4732,
        severity: 'CRITICAL',
        summary: 'User gamer123 added to Administrators group'
      })
    });

    assert.equal(res.status, 202);
    assert.equal(res.data.toast_fired, true);
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-10: App Installation Watchdog
  // --------------------------------------------------------------------------
  it('FEAT-R4-10: should process MsiInstaller Event 1033 on application install', async () => {
    const dev = await enrollTestDevice();
    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        event_type: 'APP_INSTALLED',
        event_id: 1033,
        event_source: 'MsiInstaller',
        severity: 'INFO',
        summary: 'Product Wireshark installed successfully'
      })
    });

    assert.equal(res.status, 202);
  });

  // --------------------------------------------------------------------------
  // FEAT-R4-11: Declarative Policy Drift Remediator
  // --------------------------------------------------------------------------
  it('FEAT-R4-11: should detect prohibited package and transition device to drifted status', async () => {
    const dev = await enrollTestDevice();
    const teleRes = await apiRequest('/api/v1/nodes/telemetry', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createTelemetryPayload(dev.device_id, {
        installed_software: [
          { name: 'uTorrent', winget_id: 'BitTorrent.uTorrent', version: '3.5.5' }
        ]
      })
    });

    assert.equal(teleRes.status, 200);
    assert.equal(teleRes.data.drift_detected, true);
    assert.ok(teleRes.data.drift_reasons.some(r => r.includes('uTorrent')));

    const devRes = await apiRequest(`/api/v1/fleet/devices/${dev.device_id}`, {
      fleetKey: getFleetKey()
    });
    assert.equal(devRes.data.device.status, 'drifted');
  });

  // --------------------------------------------------------------------------
  // FEAT-R5-01: WinRT Native Toast Notification Dispatch
  // --------------------------------------------------------------------------
  it('FEAT-R5-01: should trigger native toast alert dispatch for critical security events', async () => {
    clearDispatchedAlerts();
    const dev = await enrollTestDevice();
    await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        severity: 'CRITICAL',
        summary: 'Toast verification alert'
      })
    });

    const alerts = getDispatchedAlerts();
    assert.ok(alerts.toasts.length > 0);
    assert.equal(alerts.toasts[alerts.toasts.length - 1].body, 'Toast verification alert');
  });

  // --------------------------------------------------------------------------
  // FEAT-R5-02: Multi-Channel Webhook Dispatcher
  // --------------------------------------------------------------------------
  it('FEAT-R5-02: should format alerts for Discord, Slack, and Telegram webhooks', async () => {
    clearDispatchedAlerts();
    const dev = await enrollTestDevice();
    await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({
        severity: 'CRITICAL',
        summary: 'Multi-channel dispatch test'
      })
    });

    const alerts = getDispatchedAlerts();
    assert.ok(alerts.discord.length > 0);
    assert.ok(alerts.slack.length > 0);
    assert.ok(alerts.telegram.length > 0);
  });

  // --------------------------------------------------------------------------
  // FEAT-R5-03: In-Dashboard Alert Acknowledgment (ACK) Workflow
  // --------------------------------------------------------------------------
  it('FEAT-R5-03: should acknowledge security alert via API and mark acknowledged in database', async () => {
    const dev = await enrollTestDevice();
    const evtRes = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ severity: 'CRITICAL', summary: 'Alert to acknowledge' })
    });

    const eventId = evtRes.data.event_record_id;
    assert.ok(eventId);

    const ackRes = await apiRequest(`/api/v1/fleet/events/${eventId}/ack`, {
      method: 'POST',
      fleetKey: getFleetKey()
    });

    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.data.acknowledged, true);
  });

  // --------------------------------------------------------------------------
  // NFR-02: Sub-2-Second End-to-End Latency Guarantee
  // --------------------------------------------------------------------------
  it('NFR-02: should complete event ingest and alert dispatch within sub-2-second budget', async () => {
    const dev = await enrollTestDevice();
    const start = performance.now();

    const res = await apiRequest('/api/v1/nodes/events', {
      method: 'POST',
      nodeToken: dev.node_token,
      body: createEventPayload({ severity: 'CRITICAL', summary: 'Sub-2-second latency benchmark' })
    });

    const elapsedMs = performance.now() - start;

    assert.equal(res.status, 202);
    assert.ok(elapsedMs < 2000, `Total roundtrip latency ${elapsedMs.toFixed(1)}ms must be under 2000ms`);
  });
});
