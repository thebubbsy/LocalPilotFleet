/**
 * LocalPilot Fleet — Microsoft Defender & Endpoint Security QA Tests
 * server/tests/security.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Microsoft Defender & Endpoint Security QA (security.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-security-qa';
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

  describe('1. Endpoint Security Policy Endpoints', () => {
    it('GET /api/v1/fleet/security/policies returns seed policies with targeted device counts', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies`, { headers: authHeader });
      assert.equal(res.status, 200);
      const policies = await res.json();
      assert.ok(Array.isArray(policies));
      assert.ok(policies.length >= 3);

      const baseline = policies.find(p => p.id === 'sec-baseline-enterprise');
      assert.ok(baseline);
      assert.equal(baseline.real_time_protection, 1);
      assert.equal(baseline.cloud_protection_level, 'HIGH');
      assert.ok(baseline.targeted_devices >= 1);
    });

    it('GET /api/v1/fleet/security/policies/:id returns policy details and parsed exclusions', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies/sec-dev-gaming`, { headers: authHeader });
      assert.equal(res.status, 200);
      const policy = await res.json();
      assert.equal(policy.id, 'sec-dev-gaming');
      assert.ok(policy.exclusions);
      assert.ok(Array.isArray(policy.exclusions.paths));
      assert.ok(policy.exclusions.paths.includes('C:\\dev'));
    });

    it('POST /api/v1/fleet/security/policies creates a new custom endpoint security baseline', async () => {
      const newPolicy = {
        name: 'Family Surface Laptop Security Baseline',
        description: 'Hardened baseline for family roaming laptops with active Ransomware Shield and PUA blocking.',
        target_group_id: 'grp-family-laptops',
        real_time_protection: 1,
        cloud_protection_level: 'HIGH',
        controlled_folder_access: 'ENABLED',
        pua_protection: 'ENABLED',
        network_protection: 'ENABLED',
        tamper_protection: 1,
        scan_schedule_type: 'DAILY_QUICK',
        scan_schedule_time: '01:00',
        exclusions: {
          paths: ['C:\\FamilyPhotos'],
          extensions: ['.raw'],
          processes: []
        }
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newPolicy)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.ok(created.id);
      assert.equal(created.name, 'Family Surface Laptop Security Baseline');
      assert.equal(created.controlled_folder_access, 'ENABLED');
      assert.ok(created.exclusions.paths.includes('C:\\FamilyPhotos'));
    });

    it('PATCH /api/v1/fleet/security/policies/:id updates policy settings', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies/sec-baseline-enterprise`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          scan_schedule_time: '04:30',
          controlled_folder_access: 'ENABLED'
        })
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.scan_schedule_time, '04:30');
      assert.equal(updated.controlled_folder_access, 'ENABLED');
    });

    it('DELETE /api/v1/fleet/security/policies/:id removes a policy', async () => {
      // Create temporary policy
      const createRes = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ name: 'Temp Policy to Delete', target_group_id: 'grp-all' })
      });
      const tempPolicy = await createRes.json();

      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies/${tempPolicy.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      const checkRes = await fetch(`${app.baseUrl}/api/v1/fleet/security/policies/${tempPolicy.id}`, { headers: authHeader });
      assert.equal(checkRes.status, 404);
    });
  });

  describe('2. Antivirus Posture Telemetry & Fleet KPI Stats', () => {
    it('GET /api/v1/fleet/security/stats returns overall security KPI cards', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_devices >= 3);
      assert.ok(typeof stats.protection_rate_percent === 'number');
      assert.ok(stats.outdated_signatures_count >= 1); // LIVINGROOM-PC has 8-day-old signatures
      assert.ok(stats.active_threats_count >= 1); // Living room has Trojan active
    });

    it('GET /api/v1/fleet/security/antivirus-status returns all devices with health classification', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/antivirus-status`, { headers: authHeader });
      assert.equal(res.status, 200);
      const list = await res.json();
      assert.ok(Array.isArray(list));
      assert.ok(list.length >= 3);

      const livingRoom = list.find(d => d.device_id === 'dev-livingroom-pc');
      assert.ok(livingRoom);
      assert.equal(livingRoom.health_status, 'CRITICAL'); // RTP is disabled and active threat
      assert.equal(livingRoom.signature_age_days, 8);
    });

    it('GET /api/v1/fleet/devices/:id/security returns detailed posture and effective policy', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/security`, { headers: authHeader });
      assert.equal(res.status, 200);
      const details = await res.json();
      assert.equal(details.device_id, 'dev-daddy-pc');
      assert.equal(details.health_status, 'HEALTHY');
      assert.ok(details.effective_policy);
      assert.equal(details.effective_policy.real_time_protection, true);
    });
  });

  describe('3. Threat Detections & Malware Incident Management', () => {
    it('GET /api/v1/fleet/security/threats returns list of active and resolved malware events', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/threats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const threats = await res.json();
      assert.ok(Array.isArray(threats));
      assert.ok(threats.length >= 2);

      const activeThreat = threats.find(t => t.remediation_status === 'ACTIVE');
      assert.ok(activeThreat);
      assert.equal(activeThreat.threat_name, 'Trojan:Win32/Wacatac.B!ml');
      assert.ok(Array.isArray(activeThreat.resources));
    });

    it('PATCH /api/v1/fleet/security/threats/:id/remediate resolves an active malware incident', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/security/threats/threat-01/remediate`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({ remediation_status: 'RESOLVED' })
      });

      assert.equal(res.status, 200);
      const resolved = await res.json();
      assert.equal(resolved.remediation_status, 'RESOLVED');

      // Verify active count on dev-livingroom-pc decremented
      const devRes = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-livingroom-pc/security`, { headers: authHeader });
      const devSec = await devRes.json();
      assert.equal(devSec.active_threat_count, 0);
    });
  });

  describe('4. Remote Defender Scans & Signature Updates', () => {
    it('POST /api/v1/fleet/devices/:id/security/scan queues QuickScan command in device_commands', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/security/scan`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ scan_type: 'QuickScan' })
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.ok(result.command_id);
      assert.equal(result.scan_type, 'QuickScan');
      assert.equal(result.status, 'PENDING');
    });

    it('POST /api/v1/fleet/devices/:id/security/scan queues FullScan command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/security/scan`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({ scan_type: 'FullScan' })
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.scan_type, 'FullScan');
    });

    it('POST /api/v1/fleet/devices/:id/security/update-signatures queues signature update command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/security/update-signatures`, {
        method: 'POST',
        headers: authHeader
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.ok(result.command_id);
      assert.equal(result.action, 'UpdateSignatures');
    });
  });

  describe('5. Node Agent Endpoints & Telemetry Ingestion', () => {
    it('GET /api/v1/nodes/:id/security-policy delivers assigned policy to agent', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/security-policy`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.policy);
      assert.equal(data.policy.real_time_protection, true);
    });

    it('POST /api/v1/nodes/:id/antivirus-status ingests fresh Defender telemetry', async () => {
      const payload = {
        antivirus_enabled: 1,
        engine_version: '1.1.24030.1',
        product_version: '4.18.24030.5',
        signature_version: '1.409.112.0',
        signature_last_updated: new Date().toISOString(),
        signature_age_days: 0,
        real_time_protection_enabled: 1,
        cloud_protection_enabled: 1,
        pua_protection_enabled: 1,
        controlled_folder_access_enabled: 1,
        last_quick_scan_at: new Date().toISOString(),
        quick_scan_age_days: 0
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/antivirus-status`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.signature_version, '1.409.112.0');
      assert.equal(updated.health_status, 'HEALTHY');
    });

    it('POST /api/v1/nodes/:id/threat-detection records new live threat and raises alert', async () => {
      const threatPayload = {
        threat_name: 'Exploit:HTML/Axpergle.U',
        threat_id: '2147759902',
        severity: 'CRITICAL',
        category: 'Exploit',
        resources: ['C:\\Users\\Tony\\AppData\\Local\\Temp\\malicious.js'],
        action_taken: 'BLOCKED',
        remediation_status: 'ACTIVE'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/threat-detection`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(threatPayload)
      });

      assert.equal(res.status, 201);
      const threat = await res.json();
      assert.ok(threat.id);
      assert.equal(threat.threat_name, 'Exploit:HTML/Axpergle.U');
      assert.equal(threat.severity, 'CRITICAL');

      // Verify watchdog security event was created
      const eventsRes = await fetch(`${app.baseUrl}/api/v1/fleet/events?severity=CRITICAL`, { headers: authHeader });
      const eventsData = await eventsRes.json();
      const alert = (eventsData.events || eventsData).find(e => e.event_type === 'MALWARE_THREAT_DETECTED');
      assert.ok(alert);
      assert.ok(alert.summary.includes('Exploit:HTML/Axpergle.U'));
    });
  });
});
