/**
 * LocalPilot Fleet — Windows Update for Business (WUfB) Update Rings QA Tests
 * server/tests/updates.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';

describe('WUfB Update Rings & Patch Governance QA (updates.test.js)', () => {
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

  describe('1. Fleet Update Rings Endpoints', () => {
    it('GET /api/v1/fleet/updates/rings returns seed update rings with stats', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.rings));
      assert.ok(data.rings.length >= 3);

      const fastRing = data.rings.find(r => r.id === 'ring-fast-insider');
      assert.ok(fastRing);
      assert.equal(fastRing.name, 'Ring 1: Homelab Fast & Canary Ring');
      assert.equal(fastRing.servicing_channel, 'WindowsInsiderBeta');
      assert.equal(fastRing.quality_deferral_days, 0);
      assert.equal(fastRing.feature_deferral_days, 0);
      assert.ok(fastRing.stats);
      assert.ok(typeof fastRing.stats.total_devices === 'number');

      const broadRing = data.rings.find(r => r.id === 'ring-broad-production');
      assert.ok(broadRing);
      assert.equal(broadRing.servicing_channel, 'GeneralAvailability');
      assert.equal(broadRing.quality_deferral_days, 7);
      assert.equal(broadRing.feature_deferral_days, 30);
    });

    it('GET /api/v1/fleet/updates/stats returns overall patch & reboot posture', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/updates/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const stats = await res.json();
      assert.ok(stats.total_rings >= 3);
      assert.ok(stats.total_devices >= 2);
      assert.ok(stats.monitored_devices >= 2);
      assert.ok(typeof stats.reboot_pending_count === 'number');
      assert.ok(typeof stats.compliance_rate_percent === 'number');
      assert.ok(Array.isArray(stats.top_hotfixes));
    });

    it('GET /api/v1/fleet/updates/rings/:id returns ring details and assigned devices', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings/ring-broad-production`, { headers: authHeader });
      assert.equal(res.status, 200);
      const ring = await res.json();
      assert.equal(ring.id, 'ring-broad-production');
      assert.ok(Array.isArray(ring.devices));
      assert.ok(ring.stats);
    });

    it('POST /api/v1/fleet/updates/rings creates a new custom update ring', async () => {
      const newRing = {
        name: 'Executive & C-Suite VIP Ring',
        description: 'Maximum stability with 14-day quality deferral and strict active hours',
        target_group_id: 'grp-workstations',
        servicing_channel: 'GeneralAvailability',
        quality_deferral_days: 14,
        feature_deferral_days: 60,
        active_hours_start: '07:00',
        active_hours_end: '19:00',
        automatic_update_mode: 'AutoInstallAndRebootAtMaintenanceTime',
        restart_deadline_days: 5
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(newRing)
      });

      assert.equal(res.status, 201);
      const created = await res.json();
      assert.equal(created.name, newRing.name);
      assert.equal(created.quality_deferral_days, 14);
      assert.equal(created.feature_deferral_days, 60);
      assert.equal(created.restart_deadline_days, 5);
      assert.equal(created.target_group_id, 'grp-workstations');
    });

    it('PATCH /api/v1/fleet/updates/rings/:id updates ring deferrals and pause status', async () => {
      const patchData = {
        quality_deferral_days: 10,
        is_paused: 1
      };

      const res = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings/ring-gaming-vip`, {
        method: 'PATCH',
        headers: jsonHeader,
        body: JSON.stringify(patchData)
      });

      assert.equal(res.status, 200);
      const updated = await res.json();
      assert.equal(updated.quality_deferral_days, 10);
      assert.equal(updated.is_paused, 1);
    });

    it('GET /api/v1/fleet/devices/:id/update-status returns device patch details', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/update-status`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.device_id, 'dev-daddy-pc');
      assert.ok(data.ring_name);
      assert.ok(Array.isArray(data.installed_hotfixes));
    });

    it('POST /api/v1/fleet/devices/:id/scan-updates triggers remote update scan', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/dev-daddy-pc/scan-updates`, {
        method: 'POST',
        headers: authHeader
      });
      assert.equal(res.status, 202);
      const data = await res.json();
      assert.equal(data.success, true);
      assert.ok(data.command_id);
    });
  });

  describe('2. Node Agent Windows Update Ingest & Heartbeat Assignment', () => {
    it('GET /api/v1/nodes/:id/update-ring returns effective ring for node', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/update-ring`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.update_ring);
      assert.ok(data.update_ring.id);
    });

    it('POST /api/v1/nodes/:id/update-status records reboot pending and hotfixes', async () => {
      const updatePayload = {
        reboot_pending: true,
        reboot_pending_reasons: ['RebootRequired', 'CBS_RebootPending'],
        last_scan_at: '2026-09-08T04:30:00Z',
        last_install_at: '2026-09-08T04:32:00Z',
        installed_hotfixes: [
          { hotfix_id: 'KB5044284', description: 'Security Update for Windows 11', installed_on: '2026-09-08' },
          { hotfix_id: 'KB5044033', description: 'Cumulative Update for .NET Framework', installed_on: '2026-09-07' }
        ],
        update_service_status: 'Running'
      };

      const res = await fetch(`${app.baseUrl}/api/v1/nodes/dev-daddy-pc/update-status`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify(updatePayload)
      });

      assert.equal(res.status, 200);
      const result = await res.json();
      assert.equal(result.success, true);
      assert.equal(result.reboot_pending, true);
      assert.equal(result.compliance_status, 'REBOOT_PENDING');

      // Verify stats reflect the new reboot pending status
      const statsRes = await fetch(`${app.baseUrl}/api/v1/fleet/updates/stats`, { headers: authHeader });
      const stats = await statsRes.json();
      assert.ok(stats.reboot_pending_count >= 1);
    });

    it('POST /api/v1/nodes/heartbeat includes update_ring in payload', async () => {
      const heartbeatRes = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: 'dev-daddy-pc',
          cpu_usage_percent: 15.2,
          ram_used_bytes: 8589934592,
          ram_free_bytes: 8589934592,
          ram_usage_percent: 50.0
        })
      });

      assert.equal(heartbeatRes.status, 200);
      const data = await heartbeatRes.json();
      assert.equal(data.acknowledged, true);
      assert.ok(data.update_ring);
      assert.ok(data.update_ring.id);
      assert.ok(data.update_ring.servicing_channel);
    });
  });

  describe('3. Update Ring Deletion', () => {
    it('DELETE /api/v1/fleet/updates/rings/:id deletes ring', async () => {
      // Create temporary ring
      const createRes = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'Disposable QA Update Ring'
        })
      });
      const created = await createRes.json();

      // Delete ring
      const delRes = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings/${created.id}`, {
        method: 'DELETE',
        headers: authHeader
      });
      assert.equal(delRes.status, 200);

      // Verify 404
      const getRes = await fetch(`${app.baseUrl}/api/v1/fleet/updates/rings/${created.id}`, { headers: authHeader });
      assert.equal(getRes.status, 404);
    });
  });
});
