/**
 * LocalPilot Fleet — Windows 365 Cloud PC & Virtual Workstations QA Tests
 * server/tests/cloud_pc.test.js
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as cloudPcEngine from '../src/services/cloudPcEngine.js';

describe('Windows 365 Cloud PC & Virtual Workstation Fleet QA (cloud_pc.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-cloudpc-qa';
  let testDeviceId;
  let testNodeToken;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test workstation
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': FLEET_KEY
      },
      body: JSON.stringify({
        hostname: 'HOST-HYPERV-01',
        friendly_name: 'Hyper-V Host Workstation 01',
        serial_number: 'CPC-TEST-SN-112244',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '24H2',
        total_ram_bytes: 68719476736
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

  // CPC-01
  test('CPC-01: getCloudPcStats returns aggregate fleet metrics', () => {
    const stats = cloudPcEngine.getCloudPcStats(app.db);
    assert.ok(stats);
    assert.ok(stats.total_cloud_pcs >= 2);
    assert.ok(stats.provisioned_count >= 2);
    assert.ok(stats.total_policies >= 2);
    assert.ok(stats.total_storage_allocated_gb > 0);
  });

  // CPC-02
  test('CPC-02: getProvisioningPolicies lists seeded developer and standard policies', () => {
    const policies = cloudPcEngine.getProvisioningPolicies(app.db);
    assert.ok(policies.length >= 2);
    const devPol = policies.find(p => p.id === 'cpc-pol-developer');
    assert.ok(devPol);
    assert.equal(devPol.vcpu_count, 8);
    assert.equal(devPol.ram_gb, 32);
  });

  // CPC-03
  test('CPC-03: createProvisioningPolicy creates new policy', () => {
    const pol = cloudPcEngine.createProvisioningPolicy(app.db, {
      id: 'cpc-pol-ai-lab',
      name: 'AI & GPU Lab Cloud PC',
      sku_name: 'GPU Accelerated 16vCPU / 64GB RAM',
      vcpu_count: 16,
      ram_gb: 64,
      storage_gb: 1024,
      join_type: 'LOCAL_HYPERV_STANDALONE'
    });
    assert.equal(pol.id, 'cpc-pol-ai-lab');
    assert.equal(pol.vcpu_count, 16);
    assert.equal(pol.storage_gb, 1024);
  });

  // CPC-04
  test('CPC-04: getProvisioningPolicy returns policy with details', () => {
    const pol = cloudPcEngine.getProvisioningPolicy(app.db, 'cpc-pol-ai-lab');
    assert.ok(pol);
    assert.equal(pol.name, 'AI & GPU Lab Cloud PC');
  });

  // CPC-05
  test('CPC-05: updateProvisioningPolicy updates SKU and memory specs', () => {
    const updated = cloudPcEngine.updateProvisioningPolicy(app.db, 'cpc-pol-ai-lab', {
      ram_gb: 128,
      description: 'Updated memory limit'
    });
    assert.equal(updated.ram_gb, 128);
    assert.equal(updated.description, 'Updated memory limit');
  });

  // CPC-06
  test('CPC-06: getCloudPcInstances returns seeded instances', () => {
    const instances = cloudPcEngine.getCloudPcInstances(app.db);
    assert.ok(instances.length >= 2);
    const inst1 = instances.find(i => i.id === 'cpc-inst-01');
    assert.ok(inst1);
    assert.equal(inst1.primary_user, 'Tony');
  });

  // CPC-07
  test('CPC-07: createCloudPcInstance provisions new virtual instance', () => {
    const inst = cloudPcEngine.createCloudPcInstance(app.db, {
      id: 'cpc-inst-new',
      policy_id: 'cpc-pol-developer',
      name: 'CloudPC-Sarah-Design',
      hostname: 'CPC-SARAH-01',
      primary_user: 'Sarah',
      host_device_id: testDeviceId,
      ip_address: '192.168.1.190'
    });
    assert.equal(inst.id, 'cpc-inst-new');
    assert.equal(inst.primary_user, 'Sarah');
    assert.equal(inst.provisioning_status, 'PROVISIONED');
  });

  // CPC-08
  test('CPC-08: getCloudPcInstance returns instance with attached restore points', () => {
    const inst = cloudPcEngine.getCloudPcInstance(app.db, 'cpc-inst-01');
    assert.ok(inst);
    assert.equal(inst.id, 'cpc-inst-01');
    assert.ok(Array.isArray(inst.restore_points));
    assert.ok(inst.restore_points.length >= 2);
  });

  // CPC-09
  test('CPC-09: updateCloudPcInstance modifies instance properties', () => {
    const updated = cloudPcEngine.updateCloudPcInstance(app.db, 'cpc-inst-new', {
      hostname: 'CPC-SARAH-RENAMED',
      ip_address: '192.168.1.195'
    });
    assert.equal(updated.hostname, 'CPC-SARAH-RENAMED');
    assert.equal(updated.ip_address, '192.168.1.195');
  });

  // CPC-10
  test('CPC-10: triggerReprovisioning creates safety restore point and transitions state', () => {
    const inst = cloudPcEngine.triggerReprovisioning(app.db, 'cpc-inst-new');
    assert.equal(inst.provisioning_status, 'REPROVISIONING');
    const rps = cloudPcEngine.getRestorePoints(app.db, { cloud_pc_id: 'cpc-inst-new' });
    assert.ok(rps.length >= 1);
    assert.equal(rps[0].restore_point_type, 'AUTOMATIC_DISASTER_RECOVERY');
  });

  // CPC-11
  test('CPC-11: setGracePeriod sets IN_GRACE_PERIOD status and expiration timestamp', () => {
    const inst = cloudPcEngine.setGracePeriod(app.db, 'cpc-inst-new', 14);
    assert.equal(inst.provisioning_status, 'IN_GRACE_PERIOD');
    assert.ok(inst.grace_period_ends_at);
  });

  // CPC-12
  test('CPC-12: getRestorePoints filters by cloud_pc_id and status', () => {
    const rps = cloudPcEngine.getRestorePoints(app.db, { cloud_pc_id: 'cpc-inst-01' });
    assert.ok(rps.length >= 2);
    assert.equal(rps[0].status, 'READY');
  });

  // CPC-13
  test('CPC-13: createRestorePoint creates user checkpoint', () => {
    const rp = cloudPcEngine.createRestorePoint(app.db, {
      id: 'rp-manual-test',
      cloud_pc_id: 'cpc-inst-01',
      name: 'Pre-Deployment Manual Checkpoint',
      restore_point_type: 'USER_SNAPSHOT'
    });
    assert.equal(rp.id, 'rp-manual-test');
    assert.equal(rp.restore_point_type, 'USER_SNAPSHOT');
  });

  // CPC-14
  test('CPC-14: triggerRestorePointRecovery restores Cloud PC instance to healthy state', () => {
    const inst = cloudPcEngine.triggerRestorePointRecovery(app.db, 'rp-manual-test');
    assert.ok(inst);
    assert.equal(inst.provisioning_status, 'PROVISIONED');
  });

  // CPC-15
  test('CPC-15: deleteRestorePoint deletes checkpoint', () => {
    const ok = cloudPcEngine.deleteRestorePoint(app.db, 'rp-manual-test');
    assert.equal(ok, true);
  });

  // CPC-16
  test('CPC-16: generateHyperVProvisionScript synthesizes PowerShell VM commands', () => {
    const pol = cloudPcEngine.getProvisioningPolicy(app.db, 'cpc-pol-developer');
    const script = cloudPcEngine.generateHyperVProvisionScript(pol, 'TestVM-01');
    assert.ok(script.includes('New-VM -Name "TestVM-01"'));
    assert.ok(script.includes('Set-VMProcessor -VMName "TestVM-01" -Count 8'));
    assert.ok(script.includes('EnableSecureBoot On'));
  });

  // CPC-17
  test('CPC-17: deleteCloudPcInstance removes instance and cascades restore points', () => {
    const ok = cloudPcEngine.deleteCloudPcInstance(app.db, 'cpc-inst-new');
    assert.equal(ok, true);
    assert.equal(cloudPcEngine.getCloudPcInstance(app.db, 'cpc-inst-new'), null);
  });

  // CPC-18
  test('CPC-18: deleteProvisioningPolicy removes custom policy', () => {
    const ok = cloudPcEngine.deleteProvisioningPolicy(app.db, 'cpc-pol-ai-lab');
    assert.equal(ok, true);
    assert.equal(cloudPcEngine.getProvisioningPolicy(app.db, 'cpc-pol-ai-lab'), null);
  });

  // CPC-19
  test('CPC-19: REST /api/v1/fleet/cloud-pc/* endpoints return expected payloads', async () => {
    const statsRes = await api('/api/v1/fleet/cloud-pc/stats');
    assert.equal(statsRes.status, 200);
    assert.ok(statsRes.body.total_cloud_pcs >= 2);

    const polRes = await api('/api/v1/fleet/cloud-pc/policies');
    assert.equal(polRes.status, 200);
    assert.ok(polRes.body.count >= 2);

    const instRes = await api('/api/v1/fleet/cloud-pc/instances');
    assert.equal(instRes.status, 200);
    assert.ok(instRes.body.count >= 2);

    const scriptRes = await api('/api/v1/fleet/cloud-pc/provision-script?policy_id=cpc-pol-developer&name=REST-VM-01');
    assert.equal(scriptRes.status, 200);
    assert.ok(scriptRes.body.script.includes('New-VM'));
  });

  // CPC-20
  test('CPC-20: Node API handles /api/v1/nodes/:id/cloud-pc queries and reports', async () => {
    const nodeHeaders = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`
    };

    const getRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/cloud-pc`, {
      headers: nodeHeaders
    });
    assert.equal(getRes.status, 200);
    const getData = await getRes.json();
    assert.equal(getData.device_id, testDeviceId);

    const reportRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/cloud-pc/report`, {
      method: 'POST',
      headers: nodeHeaders,
      body: JSON.stringify({
        vms: [
          { name: 'WSL-Ubuntu', state: 'Running', cpu_cores: 4, memory_mb: 8192 }
        ]
      })
    });
    assert.equal(reportRes.status, 200);
    const reportData = await reportRes.json();
    assert.equal(reportData.success, true);
    assert.equal(reportData.reported_vms_count, 1);
  });
});
