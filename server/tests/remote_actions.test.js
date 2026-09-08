/**
 * LocalPilot Fleet — Remote Actions, Diagnostics & Bulk Orchestration QA Tests
 * server/tests/remote_actions.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as remoteActionEngine from '../src/services/remoteActionEngine.js';

describe('Remote Actions, Diagnostics & Bulk Orchestrator QA (remote_actions.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-remote-actions-qa';
  const authHeader = { 'X-Fleet-Key': FLEET_KEY };
  const jsonHeader = { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY };

  let testDeviceId;
  let testNodeToken;
  let completedActionId;

  before(async () => {
    app = await createTestApp({
      fleetKey: FLEET_KEY,
      seed: true
    });

    // Enroll a dedicated test node
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: jsonHeader,
      body: JSON.stringify({
        hostname: 'QA-REMOTE-NODE',
        serial_number: 'SN-REMOTE-9988',
        os_name: 'Windows 11 Pro',
        os_version: '23H2',
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
    testNodeToken = enrollData.node_token;

    // Seed completed actions, diagnostics bundle, and bulk action for this device
    const act1 = remoteActionEngine.queueRemoteAction({
      deviceId: testDeviceId,
      actionType: 'SYNC_MDM',
      initiatedBy: 'QA Seeder'
    });
    completedActionId = act1.id;
    remoteActionEngine.completeRemoteAction({
      actionId: act1.id,
      deviceId: testDeviceId,
      status: 'COMPLETED',
      resultData: { exit_code: 0, message: 'Seeded sync completed' }
    });

    const act2 = remoteActionEngine.queueRemoteAction({
      deviceId: testDeviceId,
      actionType: 'COLLECT_DIAGNOSTICS',
      parameters: { categories: ['SYSTEM_LOGS'] },
      initiatedBy: 'QA Seeder'
    });
    remoteActionEngine.saveDiagnosticsBundle({
      deviceId: testDeviceId,
      remoteActionId: act2.id,
      fileName: 'seed-diagnostics.zip',
      base64Data: Buffer.from('SEED_ZIP').toString('base64'),
      categories: ['SYSTEM_LOGS'],
      summary: { event_records: 10 }
    });

    remoteActionEngine.createBulkAction({
      name: 'Seed Bulk Action',
      actionType: 'SYNC_MDM',
      targetGroupId: 'grp-all',
      initiatedBy: 'QA Seeder'
    });
  });

  after(async () => {
    await app.cleanup();
  });

  describe('1. Executive KPI Stats', () => {
    it('GET /api/v1/fleet/remote-actions/stats returns summary metrics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions/stats`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(data.total_actions >= 3, 'Should have seeded actions');
      assert.equal(typeof data.pending_actions, 'number');
      assert.equal(typeof data.in_flight_actions, 'number');
      assert.equal(typeof data.completed_today, 'number');
      assert.equal(typeof data.failed_today, 'number');
      assert.ok(data.total_diagnostics >= 1, 'Should have seeded diagnostics bundle');
      assert.ok(data.total_bulk_actions >= 1, 'Should have seeded bulk action');
    });
  });

  describe('2. Remote Action Dispatch & Validation', () => {
    let queuedActionId;

    it('POST /api/v1/fleet/remote-actions queues REMOTE_LOCK successfully', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: testDeviceId,
          action_type: 'REMOTE_LOCK',
          parameters: { reason: 'Security lock test' },
          initiated_by: 'QA Admin'
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();

      assert.ok(data.id.startsWith('dra-'));
      assert.equal(data.device_id, testDeviceId);
      assert.equal(data.action_type, 'REMOTE_LOCK');
      assert.equal(data.status, 'PENDING');
      assert.equal(data.initiated_by, 'QA Admin');
      queuedActionId = data.id;
    });

    it('GET /api/v1/fleet/remote-actions/:id retrieves the queued action', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions/${queuedActionId}`, {
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.equal(data.id, queuedActionId);
      assert.equal(data.hostname, 'QA-REMOTE-NODE');
      assert.equal(data.status, 'PENDING');
      assert.equal(data.parameters.reason, 'Security lock test');
    });

    it('POST /api/v1/fleet/remote-actions rejects invalid action_type with 400', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: testDeviceId,
          action_type: 'INVALID_EXPLODING_ACTION'
        })
      });
      assert.equal(res.status, 400);
      const err = await res.json();
      assert.match(err.message, /Invalid action_type/);
    });

    it('POST /api/v1/fleet/remote-actions rejects missing device_id with 400', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          action_type: 'RESTART'
        })
      });
      assert.equal(res.status, 400);
    });

    it('POST /api/v1/fleet/remote-actions rejects nonexistent device_id with 400', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: 'nonexistent-uuid-999',
          action_type: 'RESTART'
        })
      });
      assert.equal(res.status, 400);
      const err = await res.json();
      assert.match(err.message, /Device not found/);
    });
  });

  describe('3. Node Agent Action Dispatch & Execution Lifecycle', () => {
    let actionToExecuteId;

    before(async () => {
      // Queue a RESTART action for node execution
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: testDeviceId,
          action_type: 'RESTART',
          parameters: { delay_sec: 30, message: 'Scheduled maintenance reboot' }
        })
      });
      const data = await res.json();
      actionToExecuteId = data.id;
    });

    it('GET /api/v1/nodes/:id/remote-actions/pending retrieves and marks action DISPATCHED', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/remote-actions/pending`, {
        headers: { Authorization: `Bearer ${testNodeToken}` }
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(data.count >= 1);
      const action = data.actions.find(a => a.id === actionToExecuteId);
      assert.ok(action, 'Should include queued restart action');
      assert.equal(action.status, 'DISPATCHED');
      assert.equal(action.action_type, 'RESTART');
    });

    it('POST /api/v1/nodes/:id/remote-actions/:actionId/result reports successful execution', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/remote-actions/${actionToExecuteId}/result`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testNodeToken}`
        },
        body: JSON.stringify({
          status: 'COMPLETED',
          result_data: { exit_code: 0, message: 'Reboot scheduled in 30 seconds' }
        })
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.equal(data.id, actionToExecuteId);
      assert.equal(data.status, 'COMPLETED');
      assert.equal(data.result_data.exit_code, 0);
      assert.ok(data.completed_at);
    });

    it('Heartbeat automatically returns pending remote actions', async () => {
      // Queue another action
      const qRes = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: testDeviceId,
          action_type: 'SYNC_MDM'
        })
      });
      const qData = await qRes.json();

      // Node sends heartbeat
      const hbRes = await fetch(`${app.baseUrl}/api/v1/nodes/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testNodeToken}`
        },
        body: JSON.stringify({
          device_id: testDeviceId,
          cpu_usage_percent: 12.5,
          ram_used_bytes: 8589934592,
          ram_free_bytes: 25769803776
        })
      });
      assert.equal(hbRes.status, 200);
      const hbData = await hbRes.json();

      assert.ok(Array.isArray(hbData.pending_remote_actions));
      const syncAction = hbData.pending_remote_actions.find(a => a.id === qData.id);
      assert.ok(syncAction, 'Heartbeat must deliver pending remote actions');
    });
  });

  describe('4. Remote Action Cancellation', () => {
    let cancelCandidateId;

    it('POST /api/v1/fleet/remote-actions/:id/cancel cancels a pending action', async () => {
      const qRes = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          device_id: testDeviceId,
          action_type: 'SHUTDOWN',
          parameters: { delay_sec: 120 }
        })
      });
      const qData = await qRes.json();
      cancelCandidateId = qData.id;

      const cancelRes = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions/${cancelCandidateId}/cancel`, {
        method: 'POST',
        headers: authHeader
      });
      assert.equal(cancelRes.status, 200);
      const cancelData = await cancelRes.json();

      assert.equal(cancelData.id, cancelCandidateId);
      assert.equal(cancelData.status, 'CANCELLED');
      assert.match(cancelData.error_message, /Cancelled by/);
    });

    it('POST /api/v1/fleet/remote-actions/:id/cancel rejects cancelling completed action with 400', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/remote-actions/${completedActionId}/cancel`, {
        method: 'POST',
        headers: authHeader
      });
      assert.equal(res.status, 400);
      const err = await res.json();
      assert.match(err.message, /Cannot cancel action in status COMPLETED/);
    });
  });

  describe('5. Bulk Device Actions Across Dynamic Groups', () => {
    let createdBulkId;

    it('POST /api/v1/fleet/bulk-actions dispatches action across dynamic group', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bulk-actions`, {
        method: 'POST',
        headers: jsonHeader,
        body: JSON.stringify({
          name: 'QA Fleet Wide Sync',
          action_type: 'SYNC_MDM',
          target_group_id: 'grp-all',
          parameters: { priority: 'HIGH' },
          initiated_by: 'QA Automation'
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();

      assert.ok(data.id.startsWith('bda-'));
      assert.equal(data.name, 'QA Fleet Wide Sync');
      assert.equal(data.action_type, 'SYNC_MDM');
      assert.ok(data.total_devices >= 1);
      assert.equal(data.dispatched_count, data.total_devices);
      createdBulkId = data.id;
    });

    it('GET /api/v1/fleet/bulk-actions returns list including new bulk action', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bulk-actions`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(Array.isArray(data.bulk_actions));
      const found = data.bulk_actions.find(b => b.id === createdBulkId);
      assert.ok(found);
      assert.equal(found.name, 'QA Fleet Wide Sync');
    });

    it('GET /api/v1/fleet/bulk-actions/:id returns child device actions', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/bulk-actions/${createdBulkId}`, { headers: authHeader });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.equal(data.id, createdBulkId);
      assert.ok(Array.isArray(data.child_actions));
      assert.equal(data.child_actions.length, data.total_devices);
    });
  });

  describe('6. Diagnostics Bundle Collection & Download', () => {
    let uploadedBundleId;
    const sampleZipBase64 = Buffer.from('PK\x03\x04FAKE_ZIP_CONTENT_FOR_LOCALPILOT_QA_VERIFICATION').toString('base64');

    it('POST /api/v1/nodes/:id/diagnostics-upload stores zip bundle and metadata', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/diagnostics-upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${testNodeToken}`
        },
        body: JSON.stringify({
          file_name: 'diagnostics-qa-test.zip',
          base64_data: sampleZipBase64,
          categories: ['SYSTEM_LOGS', 'SECURITY_LOGS', 'NETWORK'],
          summary: {
            event_records: 42,
            hotfixes: 5,
            health_score: 98
          }
        })
      });
      assert.equal(res.status, 201);
      const data = await res.json();

      assert.ok(data.id.startsWith('ddb-'));
      assert.equal(data.device_id, testDeviceId);
      assert.equal(data.file_name, 'diagnostics-qa-test.zip');
      assert.equal(data.status, 'READY');
      assert.ok(data.file_size_bytes > 0);
      assert.equal(data.summary.event_records, 42);
      uploadedBundleId = data.id;
    });

    it('GET /api/v1/fleet/devices/:id/diagnostics lists bundles for the device', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/devices/${testDeviceId}/diagnostics`, {
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.equal(data.device_id, testDeviceId);
      assert.ok(data.count >= 1);
      const bundle = data.bundles.find(b => b.id === uploadedBundleId);
      assert.ok(bundle);
      assert.equal(bundle.file_name, 'diagnostics-qa-test.zip');
    });

    it('GET /api/v1/fleet/diagnostics/:id/download streams the binary zip package', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/diagnostics/${uploadedBundleId}/download`, {
        headers: authHeader
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/zip');
      assert.ok(res.headers.get('content-disposition').includes('diagnostics-qa-test.zip'));

      const buffer = await res.arrayBuffer();
      const content = Buffer.from(buffer).toString('utf8');
      assert.ok(content.includes('FAKE_ZIP_CONTENT_FOR_LOCALPILOT_QA_VERIFICATION'));
    });
  });

  describe('7. Security Audit Trail & Event Logging', () => {
    it('Logs security events for dispatched actions and collected diagnostics', async () => {
      const res = await fetch(`${app.baseUrl}/api/v1/fleet/events?device_id=${testDeviceId}&limit=20`, {
        headers: authHeader
      });
      assert.equal(res.status, 200);
      const data = await res.json();

      assert.ok(Array.isArray(data.events));
      const actionEvents = data.events.filter(e =>
        ['REMOTE_ACTION_DISPATCHED', 'REMOTE_ACTION_COMPLETED', 'DIAGNOSTICS_COLLECTED'].includes(e.event_type)
      );
      assert.ok(actionEvents.length >= 2, 'Should have logged audit events for remote actions');
    });
  });
});
