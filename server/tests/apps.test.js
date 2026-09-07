/**
 * LocalPilot Fleet — Application Management & Packaging QA Tests
 * server/tests/apps.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('Intune Application Management & Packaging QA (apps.test.js)', () => {
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

  describe('1. Fleet Application Management Endpoints', () => {
    it('GET /api/v1/fleet/apps returns seed apps with installation metrics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps`, { headers: authHeader });
      assert.equal(res.status, 200);
      const apps = await res.json();
      assert.ok(Array.isArray(apps));
      assert.ok(apps.length >= 4);

      const gitApp = apps.find(a => a.id === 'app-git');
      assert.ok(gitApp);
      assert.equal(gitApp.name, 'Git for Windows');
      assert.equal(gitApp.app_type, 'WINGET');
      assert.equal(gitApp.assignment_intent, 'REQUIRED');
      assert.ok(Array.isArray(gitApp.detection_rules));
      assert.ok(gitApp.stats);
    });

    it('GET /api/v1/fleet/apps/stats returns fleet installation rates', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_apps >= 4);
      assert.ok(typeof stats.fleet_install_rate_percent === 'number');
    });

    it('GET /api/v1/fleet/apps/:id returns details and per-device statuses', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps/app-git`, { headers: authHeader });
      assert.equal(res.status, 200);
      const appData = await res.json();
      assert.equal(appData.id, 'app-git');
      assert.ok(Array.isArray(appData.device_statuses));
      assert.ok(appData.device_statuses.length >= 1);
    });

    it('POST /api/v1/fleet/apps creates a new application package', async () => {
      const newAppPayload = {
        name: 'Google Chrome Enterprise',
        description: 'Enterprise browser with security policy sandboxing',
        publisher: 'Google LLC',
        version: '122.0.6261.95',
        category: 'Productivity',
        app_type: 'WINGET',
        package_identifier: 'Google.Chrome',
        assignment_intent: 'REQUIRED',
        target_group_id: 'grp-all',
        install_command: 'winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements',
        uninstall_command: 'winget uninstall --id Google.Chrome --silent',
        detection_rules: [
          { type: 'FILE', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', exists: true }
        ],
        requirement_rules: {
          min_os_build: '10.0.19041',
          architecture: 'x64',
          min_ram_gb: 4
        }
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newAppPayload)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.ok(created.id);
      assert.equal(created.name, 'Google Chrome Enterprise');
      assert.equal(created.assignment_intent, 'REQUIRED');
      assert.equal(created.detection_rules.length, 1);
      assert.equal(created.requirement_rules.min_ram_gb, 4);
    });

    it('PATCH /api/v1/fleet/apps/:id updates application metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps/app-7zip`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify({
          version: '24.10',
          assignment_intent: 'AVAILABLE'
        })
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.version, '24.10');
      assert.equal(updated.assignment_intent, 'AVAILABLE');
    });

    it('GET /api/v1/fleet/devices/:id/apps resolves assigned applications', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/apps`, { headers: authHeader });
      assert.equal(res.status, 200);
      const assigned = await res.json();
      assert.ok(Array.isArray(assigned));
      assert.ok(assigned.length >= 3);
      assert.ok(assigned.some(a => a.id === 'app-git'));
      assert.ok(assigned.some(a => a.id === 'app-vscode'));
    });

    it('POST /api/v1/fleet/devices/:id/apps/:appId/install-now queues command', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/apps/app-git/install-now`, {
        method: 'POST',
        headers: authHeader
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.ok(result.command_id);
    });
  });

  describe('2. Node Agent App Endpoints & Installation Ingest', () => {
    it('GET /api/v1/nodes/:id/apps returns applications assigned to node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/apps`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.apps));
      assert.ok(data.apps.length >= 3);
    });

    it('POST /api/v1/nodes/:id/app-status records INSTALLED state', async () => {
      const payload = {
        app_id: 'app-sysinternals',
        install_status: 'INSTALLED',
        detection_state: 1,
        installed_version: '2025.1'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/app-status`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.equal(result.install_status, 'INSTALLED');
      assert.equal(result.detection_state, 1);
    });

    it('POST /api/v1/nodes/:id/app-status records FAILED state and triggers security alert', async () => {
      const payload = {
        app_id: 'app-vscode',
        install_status: 'FAILED',
        detection_state: 0,
        error_code: 1603,
        error_message: 'Fatal error during installation: Insufficient disk space on target partition'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-sarah-laptop/app-status`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(payload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.equal(result.install_status, 'FAILED');

      // Check security events
      const evRes = await fetch(`${app.baseUrl}/api/v1/fleet/events?device_id=dev-sarah-laptop`, { headers: authHeader });
      const evData = await evRes.json();
      const failedAlert = evData.events.find(e => e.event_type === 'POLICY_DRIFT' && e.summary.includes('Visual Studio Code'));
      assert.ok(failedAlert);
      assert.equal(failedAlert.severity, 'HIGH');
    });

    it('DELETE /api/v1/fleet/apps/:id removes application and cascades status', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/apps/app-sysinternals`, {
        method: 'DELETE',
        headers: authHeader
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);

      // Verify 404
      const checkRes = await fetch(`${app.baseUrl}/api/v1/fleet/apps/app-sysinternals`, { headers: authHeader });
      assert.equal(checkRes.status, 404);
    });
  });
});
