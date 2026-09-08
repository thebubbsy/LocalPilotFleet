/**
 * LocalPilot Fleet — Windows Firewall Rules & Network Perimeter Governance QA
 * server/tests/firewall.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { getDb } from '../src/db.js';

describe('Microsoft Intune Windows Firewall Rules & Network Perimeter QA (firewall.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-firewall-qa';
  let testDeviceId;

  before(async () => {
    app = await createTestApp({
      fleetKey: FLEET_KEY,
      seed: true
    });

    // Enroll a test device via API
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': FLEET_KEY
      },
      body: JSON.stringify({
        hostname: 'QA-FIREWALL-RIG',
        serial_number: 'SN-FW-TEST-999',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.22631',
        total_ram_bytes: 34359738368,
        tpm_present: true,
        tpm_enabled: true,
        secure_boot_enabled: true,
        bitlocker_status: 'FullyEncrypted',
        primary_user: 'qa-tester'
      })
    });
    assert.equal(enrollRes.status, 201);
    const enrollData = await enrollRes.json();
    testDeviceId = enrollData.device_id;
  });

  after(async () => {
    if (app) {
      await app.cleanup();
    }
  });

  // Helper
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
    return { status: res.status, body, headers: res.headers };
  }

  it('FW-01: should return fleet firewall stats with active rules and device counters', async () => {
    const res = await api('/api/v1/fleet/firewall/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_rules >= 4, 'Should have at least 4 seeded firewall rules');
    assert.ok(res.body.enabled_rules >= 4, 'Should have active enabled rules');
    assert.ok(typeof res.body.monitored_devices === 'number');
    assert.ok(typeof res.body.compliant_devices === 'number');
    assert.ok(typeof res.body.total_open_ports === 'number');
  });

  it('FW-02: should list all enterprise firewall rules with profile specs', async () => {
    const res = await api('/api/v1/fleet/firewall/rules');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.rules));
    assert.ok(res.body.rules.length >= 4);

    const rdpRule = res.body.rules.find(r => r.name.includes('Remote Desktop') || r.local_ports === '3389');
    assert.ok(rdpRule, 'Should find RDP block rule');
    assert.equal(rdpRule.action, 'BLOCK');
    assert.equal(rdpRule.direction, 'INBOUND');
    assert.ok(Array.isArray(rdpRule.profiles));
  });

  it('FW-03: should create custom enterprise firewall rule', async () => {
    const payload = {
      name: 'Allow PostgreSQL Database Listener (Port 5432)',
      description: 'Permits inbound SQL query traffic on private development network',
      direction: 'INBOUND',
      action: 'ALLOW',
      protocol: 'TCP',
      local_ports: '5432',
      remote_ports: 'ANY',
      local_addresses: '*',
      remote_addresses: '192.168.1.0/24',
      profiles: ['Private', 'Domain'],
      program_path: '%ProgramFiles%\\PostgreSQL\\bin\\postgres.exe',
      target_group_id: 'grp-all',
      enabled: 1,
      priority: 60
    };

    const res = await api('/api/v1/fleet/firewall/rules', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 201);
    assert.ok(res.body.id.startsWith('fwr-'));
    assert.equal(res.body.name, payload.name);
    assert.equal(res.body.local_ports, '5432');
    assert.deepEqual(res.body.profiles, ['Private', 'Domain']);
  });

  it('FW-04: should reject firewall rule with invalid direction with HTTP 400', async () => {
    const res = await api('/api/v1/fleet/firewall/rules', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Invalid Direction Rule',
        direction: 'SIDEWAYS',
        action: 'ALLOW',
        protocol: 'TCP'
      })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'FIREWALL_RULE_CREATE_ERROR');
  });

  it('FW-05: should reject firewall rule with invalid action with HTTP 400', async () => {
    const res = await api('/api/v1/fleet/firewall/rules', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Invalid Action Rule',
        direction: 'INBOUND',
        action: 'DESTROY',
        protocol: 'TCP'
      })
    });
    assert.equal(res.status, 400);
  });

  it('FW-06: should reject firewall rule with invalid protocol with HTTP 400', async () => {
    const res = await api('/api/v1/fleet/firewall/rules', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Invalid Protocol Rule',
        direction: 'INBOUND',
        action: 'ALLOW',
        protocol: 'SCTP'
      })
    });
    assert.equal(res.status, 400);
  });

  it('FW-07: should fetch specific firewall rule by ID', async () => {
    const listRes = await api('/api/v1/fleet/firewall/rules');
    const firstRule = listRes.body.rules[0];

    const res = await api(`/api/v1/fleet/firewall/rules/${firstRule.id}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, firstRule.id);
    assert.equal(res.body.name, firstRule.name);
    assert.ok(Array.isArray(res.body.profiles));
  });

  it('FW-08: should update firewall rule settings via PATCH', async () => {
    const listRes = await api('/api/v1/fleet/firewall/rules');
    const targetRule = listRes.body.rules.find(r => r.name.includes('PostgreSQL')) || listRes.body.rules[0];

    const res = await api(`/api/v1/fleet/firewall/rules/${targetRule.id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated description for PostgreSQL listener',
        priority: 45,
        profiles: ['Private']
      })
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.priority, 45);
    assert.deepEqual(res.body.profiles, ['Private']);
  });

  it('FW-09: should delete firewall rule via DELETE', async () => {
    const createRes = await api('/api/v1/fleet/firewall/rules', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Temporary Scratch Rule to Delete',
        direction: 'OUTBOUND',
        action: 'BLOCK',
        protocol: 'TCP',
        local_ports: '9999'
      })
    });
    const ruleId = createRes.body.id;

    const delRes = await api(`/api/v1/fleet/firewall/rules/${ruleId}`, { method: 'DELETE' });
    assert.equal(delRes.status, 200);
    assert.equal(delRes.body.success, true);

    const getRes = await api(`/api/v1/fleet/firewall/rules/${ruleId}`);
    assert.equal(getRes.status, 404);
  });

  it('FW-10: should ingest compliant firewall profile status from node agent', async () => {
    const payload = {
      domain_profile_enabled: 1,
      private_profile_enabled: 1,
      public_profile_enabled: 1,
      domain_inbound_action: 'Block',
      private_inbound_action: 'Block',
      public_inbound_action: 'Block',
      stealth_mode_enabled: 1,
      active_rules_count: 320
    };

    const res = await api(`/api/v1/nodes/${testDeviceId}/firewall-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.compliance_status, 'COMPLIANT');
    assert.equal(res.body.domain_profile_enabled, 1);
    assert.equal(res.body.public_profile_enabled, 1);
  });

  it('FW-11: should detect disabled profile, mark NON_COMPLIANT, and log security event', async () => {
    const payload = {
      domain_profile_enabled: 1,
      private_profile_enabled: 1,
      public_profile_enabled: 0, // Disabled public profile!
      domain_inbound_action: 'Block',
      private_inbound_action: 'Block',
      public_inbound_action: 'Allow',
      stealth_mode_enabled: 0,
      active_rules_count: 15
    };

    const res = await api(`/api/v1/nodes/${testDeviceId}/firewall-status`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.compliance_status, 'NON_COMPLIANT');

    // Verify security event logged
    const db = getDb();
    const event = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND event_type = 'FIREWALL_PROFILE_DISABLED'
      ORDER BY id DESC LIMIT 1
    `).get(testDeviceId);

    assert.ok(event, 'Security event FIREWALL_PROFILE_DISABLED should be logged');
    assert.equal(event.severity, 'HIGH');
    assert.ok(event.summary.includes('drift detected'));
  });

  it('FW-12: should ingest open listening ports and classify safe ports as LOW risk', async () => {
    const ports = [
      { protocol: 'TCP', local_address: '127.0.0.1', local_port: 3000, process_name: 'node.exe', owning_process_id: 1100 },
      { protocol: 'TCP', local_address: '0.0.0.0', local_port: 8443, process_name: 'node.exe', owning_process_id: 1200 },
      { protocol: 'TCP', local_address: '0.0.0.0', local_port: 5985, process_name: 'svchost.exe', owning_process_id: 1300 }
    ];

    const res = await api(`/api/v1/nodes/${testDeviceId}/listening-ports`, {
      method: 'POST',
      body: JSON.stringify({ ports })
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.count, 3);

    const devPorts = await api(`/api/v1/fleet/devices/${testDeviceId}/listening-ports`);
    assert.equal(devPorts.status, 200);
    assert.equal(devPorts.body.count, 3);

    const devServerPort = devPorts.body.ports.find(p => p.local_port === 3000);
    assert.equal(devServerPort.risk_level, 'LOW');
    assert.equal(devServerPort.status, 'AUTHORIZED');

    const winrmPort = devPorts.body.ports.find(p => p.local_port === 5985);
    assert.equal(winrmPort.risk_level, 'MEDIUM');
  });

  it('FW-13: should detect high-risk port exposed on 0.0.0.0, mark CRITICAL, and log ROGUE_PORT_DETECTED', async () => {
    const roguePorts = [
      { protocol: 'TCP', local_address: '0.0.0.0', local_port: 445, process_name: 'System', owning_process_id: 4 }, // SMB on public binding!
      { protocol: 'TCP', local_address: '0.0.0.0', local_port: 23, process_name: 'telnetd.exe', owning_process_id: 9999 }  // Telnet!
    ];

    const res = await api(`/api/v1/nodes/${testDeviceId}/listening-ports`, {
      method: 'POST',
      body: JSON.stringify(roguePorts)
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.count, 2);

    const smbPort = res.body.ports.find(p => p.local_port === 445);
    assert.equal(smbPort.risk_level, 'CRITICAL');
    assert.equal(smbPort.status, 'EXPOSED_PUBLIC');

    // Verify security event logged
    const db = getDb();
    const event = db.prepare(`
      SELECT * FROM security_events
      WHERE device_id = ? AND event_type = 'ROGUE_PORT_DETECTED'
      ORDER BY id DESC LIMIT 1
    `).get(testDeviceId);

    assert.ok(event, 'Security event ROGUE_PORT_DETECTED should be logged');
    assert.equal(event.severity, 'CRITICAL');
  });

  it('FW-14: should return fleet-wide open listening ports inventory', async () => {
    const res = await api('/api/v1/fleet/firewall/ports');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.ports));
    assert.ok(res.body.count >= 2);

    const first = res.body.ports[0];
    assert.ok(first.local_port);
    assert.ok(first.hostname);
    assert.ok(first.risk_level);
  });

  it('FW-15: should query device firewall posture including effective dynamic group rules', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/firewall`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(res.body.status);
    assert.ok(Array.isArray(res.body.effective_rules));
    assert.ok(res.body.effective_rules.length >= 4, 'Should inherit grp-all rules');
  });

  it('FW-16: should dispatch immediate firewall policy enforcement action', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/firewall/enforce`, {
      method: 'POST'
    });
    assert.equal(res.status, 202);
    assert.equal(res.body.success, true);
    assert.ok(res.body.action);
    assert.equal(res.body.action.action_type, 'SYNC_MDM');
  });

  it('FW-17: should return firewall_policy in node heartbeat response', async () => {
    const heartbeatRes = await api('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId,
        cpu_usage_percent: 15,
        ram_usage_percent: 45
      })
    });

    assert.equal(heartbeatRes.status, 200);
    assert.ok(heartbeatRes.body.firewall_policy);
    assert.ok(Array.isArray(heartbeatRes.body.firewall_policy.effective_rules));
    assert.ok(heartbeatRes.body.firewall_policy.effective_rules.length >= 4);
  });
});
