/**
 * LocalPilot Fleet — Enterprise Application Management & Company Portal QA Tests
 * server/tests/enterprise_apps.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as enterpriseEngine from '../src/services/enterpriseAppEngine.js';

describe('Intune Enterprise Application Management & Company Portal QA (enterprise_apps.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-eam-portal-qa';
  let testDeviceId;
  let testNodeToken;

  let createdAppId;
  let createdRequestId;
  let createdLicId;

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
        hostname: 'DEV-WORKSTATION-01',
        friendly_name: 'Developer Rig 01',
        serial_number: 'EAM-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Pro',
        os_version: '23H2',
        total_ram_bytes: 34359738368
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

  // EAM-01
  it('EAM-01: Returns enterprise app management dashboard statistics with seeded catalog data', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/stats');
    assert.equal(status, 200);
    assert.ok(body.total_apps >= 6);
    assert.ok(body.self_service_apps >= 6);
    assert.ok(body.total_licenses >= 75);
    assert.ok(Array.isArray(body.categories));
  });

  // EAM-02
  it('EAM-02: Lists catalog applications with category, self-service, and keyword search filters', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/catalog?search=Code');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.apps));
    assert.ok(body.apps.some(a => a.name.includes('Visual Studio Code')));
  });

  // EAM-03
  it('EAM-03: Successfully creates a new enterprise application in the catalog', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/catalog', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Postman API Platform',
        publisher: 'Postman Inc.',
        category: 'Developer Tools',
        version: '11.10.0',
        package_identifier: 'Postman.Postman',
        source_type: 'WINGET',
        license_type: 'FREE',
        featured: 1,
        self_service_enabled: 1
      })
    });
    assert.equal(status, 201);
    assert.ok(body.success);
    assert.equal(body.app.name, 'Postman API Platform');
    assert.equal(body.app.package_identifier, 'Postman.Postman');
    createdAppId = body.app.id;
  });

  // EAM-04
  it('EAM-04: Rejects creating catalog application with missing mandatory fields', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/catalog', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Incomplete App'
      })
    });
    assert.equal(status, 400);
    assert.equal(body.error, 'EAM_CATALOG_CREATE_ERROR');
  });

  // EAM-05
  it('EAM-05: Retrieves single catalog app by ID with detailed license allocation metrics', async () => {
    const { status, body } = await api(`/api/v1/fleet/eam/catalog/${createdAppId}`);
    assert.equal(status, 200);
    assert.equal(body.app.id, createdAppId);
    assert.equal(body.app.available_licenses, 'UNLIMITED');
  });

  // EAM-06
  it('EAM-06: Updates existing catalog application (version and license seats)', async () => {
    const { status, body } = await api(`/api/v1/fleet/eam/catalog/${createdAppId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        version: '11.11.0',
        license_type: 'PER_USER',
        total_licenses: 10
      })
    });
    assert.equal(status, 200);
    assert.equal(body.app.version, '11.11.0');
    assert.equal(body.app.license_type, 'PER_USER');
    assert.equal(body.app.total_licenses, 10);
    assert.equal(body.app.available_licenses, 10);
  });

  // EAM-07
  it('EAM-07: Deletes catalog application and cascades properly', async () => {
    const tempApp = enterpriseEngine.createCatalogApp(app.db, {
      name: 'Temporary App',
      publisher: 'Temp Corp',
      category: 'Utilities',
      version: '1.0.0',
      package_identifier: 'Temp.App'
    });
    const { status: delStatus, body: delBody } = await api(`/api/v1/fleet/eam/catalog/${tempApp.id}`, {
      method: 'DELETE'
    });
    assert.equal(delStatus, 200);
    assert.ok(delBody.success);

    const { status: getStatus } = await api(`/api/v1/fleet/eam/catalog/${tempApp.id}`);
    assert.equal(getStatus, 404);
  });

  // EAM-08
  it('EAM-08: Queries self-service Company Portal catalog for an enrolled client device', async () => {
    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/catalog`, {
      headers: { 'Authorization': `Bearer ${testNodeToken}` }
    });
    assert.equal(status, 200);
    assert.equal(body.device_id, testDeviceId);
    assert.ok(Array.isArray(body.catalog));
    assert.ok(body.catalog.length >= 6);
  });

  // EAM-09
  it('EAM-09: Client device submits self-service installation request for a free app (auto-approved to QUEUED)', async () => {
    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/request`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({
        catalog_app_id: 'app-7zip',
        user_name: 'DevTester',
        request_type: 'INSTALL',
        justification: 'Need archive extraction utility'
      })
    });
    assert.equal(status, 201);
    assert.ok(body.success);
    assert.equal(body.request.status, 'QUEUED');
    assert.equal(body.request.approval_required, 0);
  });

  // EAM-10
  it('EAM-10: Client device submits request for a licensed enterprise app (sets to PENDING_APPROVAL)', async () => {
    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/request`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({
        catalog_app_id: 'app-slack',
        user_name: 'DevTester',
        request_type: 'INSTALL',
        justification: 'Requires Slack Enterprise seat for team communication'
      })
    });
    assert.equal(status, 201);
    assert.ok(body.success);
    assert.equal(body.request.status, 'PENDING_APPROVAL');
    assert.equal(body.request.approval_required, 1);
    createdRequestId = body.request.id;
  });

  // EAM-11
  it('EAM-11: IT administrator lists pending Company Portal requests with filters', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/requests?status=PENDING_APPROVAL');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.requests));
    assert.ok(body.requests.some(r => r.id === createdRequestId));
  });

  // EAM-12
  it('EAM-12: IT administrator approves pending request, transitioning status to QUEUED and allocating license', async () => {
    const { status, body } = await api(`/api/v1/fleet/eam/requests/${createdRequestId}/review`, {
      method: 'POST',
      body: JSON.stringify({
        action: 'APPROVE',
        approver_user: 'SecOps Lead Admin',
        notes: 'Approved per department budget approval'
      })
    });
    assert.equal(status, 200);
    assert.ok(body.success);
    assert.equal(body.request.status, 'QUEUED');
    assert.equal(body.request.approver_user, 'SecOps Lead Admin');
  });

  // EAM-13
  it('EAM-13: IT administrator rejects pending request with reason', async () => {
    const req = enterpriseEngine.createCompanyPortalRequest(app.db, {
      catalog_app_id: 'app-slack',
      device_id: testDeviceId,
      user_name: 'Contractor',
      request_type: 'INSTALL',
      approval_required: 1,
      justification: 'Temp request'
    });

    const { status, body } = await api(`/api/v1/fleet/eam/requests/${req.id}/review`, {
      method: 'POST',
      body: JSON.stringify({
        action: 'REJECT',
        approver_user: 'SecOps Lead Admin',
        notes: 'Contractors must use web client.'
      })
    });
    assert.equal(status, 200);
    assert.equal(body.request.status, 'REJECTED');
    assert.ok(body.request.error_message.includes('Contractors must use web client'));
  });

  // EAM-14
  it('EAM-14: Client device agent updates installation status to INSTALLING and then COMPLETED', async () => {
    const { status: s1, body: b1 } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/requests/${createdRequestId}/status`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({ status: 'INSTALLING' })
    });
    assert.equal(s1, 200);
    assert.equal(b1.request.status, 'INSTALLING');

    const { status: s2, body: b2 } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/requests/${createdRequestId}/status`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({ status: 'COMPLETED' })
    });
    assert.equal(s2, 200);
    assert.equal(b2.request.status, 'COMPLETED');
    assert.ok(b2.request.resolved_at);
  });

  // EAM-15
  it('EAM-15: Client device agent reports installation failure with error message', async () => {
    const failReq = enterpriseEngine.createCompanyPortalRequest(app.db, {
      catalog_app_id: 'app-vscode',
      device_id: testDeviceId,
      user_name: 'DevTester',
      request_type: 'INSTALL',
      approval_required: 0
    });

    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/company-portal/requests/${failReq.id}/status`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({
        status: 'FAILED',
        error_message: 'WinGet exit code 2316632065: Hash mismatch on downloaded installer'
      })
    });
    assert.equal(status, 200);
    assert.equal(body.request.status, 'FAILED');
    assert.ok(body.request.error_message.includes('Hash mismatch'));
  });

  // EAM-16
  it('EAM-16: Lists enterprise license allocations with device and application details', async () => {
    const { status, body } = await api('/api/v1/fleet/eam/licenses');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.licenses));
    assert.ok(body.licenses.length >= 1);
    assert.ok(body.licenses.some(l => l.status === 'ACTIVE'));
  });

  // EAM-17
  it('EAM-17: Manually allocates license seat and enforces seat limits when full', async () => {
    const limitedApp = enterpriseEngine.createCatalogApp(app.db, {
      name: 'Single Seat Specialized Tool',
      publisher: 'Specialty Tools LLC',
      category: 'Developer Tools',
      version: '1.0.0',
      package_identifier: 'Specialty.Tool',
      license_type: 'PER_DEVICE',
      total_licenses: 1
    });

    const { status: s1, body: b1 } = await api('/api/v1/fleet/eam/licenses', {
      method: 'POST',
      body: JSON.stringify({
        catalog_app_id: limitedApp.id,
        device_id: testDeviceId,
        user_name: 'PowerUser',
        license_key: 'KEY-SPEC-001'
      })
    });
    assert.equal(s1, 201);
    assert.ok(b1.success);
    createdLicId = b1.allocation.id;

    const { status: s2, body: b2 } = await api('/api/v1/fleet/eam/licenses', {
      method: 'POST',
      body: JSON.stringify({
        catalog_app_id: limitedApp.id,
        device_id: testDeviceId,
        user_name: 'SecondUser',
        license_key: 'KEY-SPEC-002'
      })
    });
    assert.equal(s2, 400);
    assert.ok(b2.message.includes('License limit reached'));
  });

  // EAM-18
  it('EAM-18: Revokes license seat successfully', async () => {
    const { status, body } = await api(`/api/v1/fleet/eam/licenses/${createdLicId}/revoke`, {
      method: 'POST'
    });
    assert.equal(status, 200);
    assert.ok(body.success);
    assert.equal(body.revoked_id, createdLicId);
  });

  // EAM-19
  it('EAM-19: Heartbeat endpoint injects pending Company Portal installation jobs for target device', async () => {
    const queuedJob = enterpriseEngine.createCompanyPortalRequest(app.db, {
      catalog_app_id: 'app-git',
      device_id: testDeviceId,
      user_name: 'DevTester',
      request_type: 'INSTALL',
      approval_required: 0
    });

    const { status, body } = await api('/api/v1/nodes/heartbeat', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({
        device_id: testDeviceId,
        status: 'online',
        uptime_seconds: 3600
      })
    });
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.pending_portal_installs));
    assert.ok(body.pending_portal_installs.some(j => j.request_id === queuedJob.id));
  });

  // EAM-20
  it('EAM-20: Generates production-grade WinGet silent installation and uninstallation PowerShell scripts', () => {
    const appDef = {
      package_identifier: 'Microsoft.VisualStudioCode',
      silent_install_args: '--silent --accept-package-agreements',
      silent_uninstall_args: '--silent'
    };

    const installScript = enterpriseEngine.generateWinGetScript(appDef, 'INSTALL');
    assert.ok(installScript.includes('winget.exe'));
    assert.ok(installScript.includes('Microsoft.VisualStudioCode'));
    assert.ok(installScript.includes('install --id'));
    assert.ok(installScript.includes('--accept-package-agreements'));

    const uninstallScript = enterpriseEngine.generateWinGetScript(appDef, 'UNINSTALL');
    assert.ok(uninstallScript.includes('uninstall --id'));
    assert.ok(uninstallScript.includes('Microsoft.VisualStudioCode'));
  });
});
