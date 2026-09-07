/**
 * LocalPilot Fleet — Configuration Profiles & Settings Catalog QA Tests
 * server/tests/profiles.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Configuration Profiles & Settings Catalog QA (profiles.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-secret-qa';
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

  describe('1. Fleet Configuration Profiles Endpoints', () => {
    it('GET /api/v1/fleet/profiles returns seed profiles with compliance statistics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.profiles));
      assert.ok(data.profiles.length >= 3);

      const baseline = data.profiles.find(p => p.id === 'prof-win11-baseline');
      assert.ok(baseline);
      assert.equal(baseline.name, 'Windows 11 Enterprise Hardened Security Baseline');
      assert.equal(baseline.profile_type, 'SecurityBaseline');
      assert.ok(Array.isArray(baseline.settings));
      assert.equal(baseline.settings.length, 3);
      assert.ok(baseline.compliance);
      assert.ok(baseline.compliance.total_evaluated >= 2);
    });

    it('GET /api/v1/fleet/profiles/stats returns overall fleet configuration compliance', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_profiles >= 3);
      assert.ok(stats.total_evaluations >= 3);
      assert.ok(stats.evaluated_devices >= 2);
      assert.ok(typeof stats.compliance_rate_percent === 'number');
      assert.ok(Array.isArray(stats.profiles_by_type));
    });

    it('GET /api/v1/fleet/profiles/catalog returns the Intune Settings Catalog library', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/catalog`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.catalog));
      assert.ok(data.catalog.length >= 5);

      const firewallSetting = data.catalog.find(s => s.id === 'firewall_all_profiles');
      assert.ok(firewallSetting);
      assert.equal(firewallSetting.category, 'Network & Firewall');

      const uacSetting = data.catalog.find(s => s.id === 'uac_enable_lua');
      assert.ok(uacSetting);
      assert.equal(uacSetting.category, 'User Account Control');
    });

    it('POST /api/v1/fleet/profiles creates a new configuration profile', async () => {
      const newProfile = {
        name: 'Enterprise BitLocker & Encryption Policy',
        description: 'Enforces AES-XTS 256-bit BitLocker volume encryption across all machines',
        profile_type: 'SettingsCatalog',
        target_group_id: 'grp-workstations',
        settings: [
          {
            id: 'bitlocker_os_volume',
            category: 'Storage & Encryption',
            name: 'BitLocker Drive Encryption (OS Volume)',
            setting_type: 'boolean',
            desired_value: true,
            enforce: true
          }
        ]
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newProfile)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.equal(created.name, newProfile.name);
      assert.equal(created.profile_type, 'SettingsCatalog');
      assert.equal(created.target_group_id, 'grp-workstations');
      assert.equal(created.settings.length, 1);
      assert.ok(created.id.startsWith('prof-'));
    });

    it('PATCH /api/v1/fleet/profiles/:id updates profile metadata and settings', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/prof-gaming-tuning`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          description: 'Updated low-latency and game bar presence settings',
          settings: [
            {
              id: 'fast_startup',
              category: 'System & Power',
              name: 'Fast Startup (Hiberboot)',
              setting_type: 'integer',
              desired_value: 0,
              enforce: true
            },
            {
              id: 'game_bar',
              category: 'Gaming & Performance',
              name: 'Game DVR & Bar Presence Writer',
              setting_type: 'integer',
              desired_value: 0,
              enforce: true
            }
          ]
        })
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.description, 'Updated low-latency and game bar presence settings');
      assert.equal(updated.settings.length, 2);
    });

    it('GET /api/v1/fleet/profiles/:id returns detailed profile with device evaluations', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/prof-win11-baseline`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.id, 'prof-win11-baseline');
      assert.ok(Array.isArray(data.evaluations));
      assert.ok(data.evaluations.length >= 2);

      const daddyEval = data.evaluations.find(e => e.device_id === 'dev-daddy-pc');
      assert.ok(daddyEval);
      assert.equal(daddyEval.compliance_status, 'COMPLIANT');
      assert.equal(daddyEval.compliant_count, 3);
      assert.equal(daddyEval.non_compliant_count, 0);

      const livingEval = data.evaluations.find(e => e.device_id === 'dev-livingroom-pc');
      assert.ok(livingEval);
      assert.equal(livingEval.compliance_status, 'NON_COMPLIANT');
      assert.equal(livingEval.non_compliant_count, 1);
    });

    it('GET /api/v1/fleet/devices/:id/profiles returns applicable profiles for a specific device', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/profiles`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.device_id, 'dev-daddy-pc');
      assert.ok(Array.isArray(data.profiles));
      assert.ok(data.profiles.length >= 2);
    });
  });

  describe('2. Node Agent Configuration Profile Compliance Ingest', () => {
    it('GET /api/v1/nodes/:id/profiles returns assigned profiles for node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/profiles`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.profiles));
      assert.ok(data.profiles.length >= 2);
    });

    it('POST /api/v1/nodes/:id/profile-compliance records COMPLIANT evaluation', async () => {
      const payload = {
        profile_id: 'prof-dev-privacy',
        setting_results: [
          {
            id: 'telemetry_level',
            category: 'System & Telemetry',
            name: 'Diagnostic Data Collection Level',
            desired_value: 0,
            current_value: 0,
            status: 'COMPLIANT',
            message: 'AllowTelemetry set to 0'
          },
          {
            id: 'tailored_experiences',
            category: 'Privacy',
            name: 'Windows Tailored Diagnostic Experiences',
            desired_value: 0,
            current_value: 0,
            status: 'COMPLIANT',
            message: 'DisableTailoredExperiencesWithDiagnosticData set to 1'
          }
        ]
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/profile-compliance`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.equal(result.compliance_status, 'COMPLIANT');
      assert.equal(result.compliant_count, 2);
      assert.equal(result.non_compliant_count, 0);
    });

    it('POST /api/v1/nodes/:id/profile-compliance records NON_COMPLIANT when any setting fails', async () => {
      const payload = {
        profile_id: 'prof-dev-privacy',
        setting_results: [
          {
            id: 'telemetry_level',
            category: 'System & Telemetry',
            name: 'Diagnostic Data Collection Level',
            desired_value: 0,
            current_value: 3,
            status: 'NON_COMPLIANT',
            message: 'AllowTelemetry is currently 3 (Full)'
          }
        ]
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-livingroom-pc/profile-compliance`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.equal(result.compliance_status, 'NON_COMPLIANT');
      assert.equal(result.compliant_count, 0);
      assert.equal(result.non_compliant_count, 1);
    });
  });

  describe('3. Profile Deletion & Cascade Clean-up', () => {
    it('DELETE /api/v1/fleet/profiles/:id deletes profile and cascades compliance', async () => {
      // First create temporary profile
      const createRes = await fetch(`${app.baseUrl}/api/v1/fleet/profiles`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Temporary Disposable Profile',
          settings: []
        })
      });
      const created = await createRes.json();

      // Submit compliance
      await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/profile-compliance`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          profile_id: created.id,
          setting_results: []
        })
      });

      // Delete
      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/${created.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      // Verify 404
      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/profiles/${created.id}`, { headers: authHeader });
      assert.equal(getRes.status, 404);
    });
  });
});
