/**
 * LocalPilot Fleet — Certificate Management & SCEP/PKCS Profiles QA
 * server/tests/certificates.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import { evaluateExpiry } from '../src/services/certificateEngine.js';

describe('Microsoft Intune Certificate Management & SCEP/PKCS Profiles QA (certificates.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-cert-qa';
  let testDeviceId;
  let testNodeToken;
  let createdProfileId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test device
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Fleet-Key': FLEET_KEY },
      body: JSON.stringify({
        hostname: 'CERT-TEST-NODE',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '10.0.26100',
        total_ram_bytes: 34359738368,
        mac_address: '00:15:5D:88:99:AA',
        serial_number: 'VMware-88-99-AA'
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

  async function nodeApi(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${testNodeToken}`,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  // CERT-01
  it('CERT-01: GET /api/v1/fleet/certificates/stats returns initial KPIs with seed profiles', async () => {
    const res = await api('/api/v1/fleet/certificates/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_profiles >= 3, 'Should have at least 3 seeded profiles');
    assert.ok(typeof res.body.active_profiles === 'number');
    assert.ok(typeof res.body.total_certificates === 'number');
    assert.ok(typeof res.body.valid_count === 'number');
    assert.ok(typeof res.body.expiring_soon_count === 'number');
    assert.ok(typeof res.body.expired_count === 'number');
  });

  // CERT-02
  it('CERT-02: POST /api/v1/fleet/certificates/profiles creates new certificate profile (201)', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Custom VPN Client SCEP Profile',
        description: 'Auto-enrolled VPN auth certificate',
        certificateType: 'SCEP',
        targetStore: 'LOCAL_MACHINE_MY',
        targetGroupId: 'grp-all',
        subjectName: 'CN={{DeviceName}}, OU=VPN, O=Fleet Corp',
        validityPeriodDays: 180,
        scepServerUrl: 'https://vpn-ca.localpilot.internal/scep',
        renewalThresholdPct: 15
      })
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.id.startsWith('cert-'));
    assert.equal(res.body.name, 'Custom VPN Client SCEP Profile');
    assert.equal(res.body.certificate_type, 'SCEP');
    assert.equal(res.body.validity_period_days, 180);
    createdProfileId = res.body.id;
  });

  // CERT-03
  it('CERT-03: POST /api/v1/fleet/certificates/profiles rejects missing name (400)', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles', {
      method: 'POST',
      body: JSON.stringify({
        certificateType: 'TRUSTED_ROOT',
        targetStore: 'LOCAL_MACHINE_ROOT'
      })
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'CERTIFICATE_PROFILE_CREATE_ERROR');
  });

  // CERT-04
  it('CERT-04: POST /api/v1/fleet/certificates/profiles rejects invalid certificate_type (400)', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Bad Profile',
        certificateType: 'SELF_SIGNED_INVALID',
        targetStore: 'LOCAL_MACHINE_ROOT'
      })
    });
    assert.equal(res.status, 400);
  });

  // CERT-05
  it('CERT-05: POST /api/v1/fleet/certificates/profiles rejects invalid target_store (400)', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Bad Store Profile',
        certificateType: 'TRUSTED_ROOT',
        targetStore: 'NON_EXISTENT_STORE'
      })
    });
    assert.equal(res.status, 400);
  });

  // CERT-06
  it('CERT-06: GET /api/v1/fleet/certificates/profiles lists all profiles', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.profiles));
    const found = res.body.profiles.find(p => p.id === createdProfileId);
    assert.ok(found, 'Created profile should be in list');
  });

  // CERT-07
  it('CERT-07: GET /api/v1/fleet/certificates/profiles/:id returns single profile with targeted devices', async () => {
    const res = await api(`/api/v1/fleet/certificates/profiles/${createdProfileId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.id, createdProfileId);
    assert.ok(typeof res.body.targeted_devices_count === 'number');
  });

  // CERT-08
  it('CERT-08: GET /api/v1/fleet/certificates/profiles/:id returns 404 for unknown profile', async () => {
    const res = await api('/api/v1/fleet/certificates/profiles/cert-unknown-999');
    assert.equal(res.status, 404);
  });

  // CERT-09
  it('CERT-09: PATCH /api/v1/fleet/certificates/profiles/:id updates profile fields', async () => {
    const res = await api(`/api/v1/fleet/certificates/profiles/${createdProfileId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated description for SCEP profile',
        renewal_threshold_pct: 25
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.description, 'Updated description for SCEP profile');
    assert.equal(res.body.renewal_threshold_pct, 25);
  });

  // CERT-10
  it('CERT-10: PATCH /api/v1/fleet/certificates/profiles/:id rejects invalid certificate_type (400)', async () => {
    const res = await api(`/api/v1/fleet/certificates/profiles/${createdProfileId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        certificate_type: 'INVALID_TYPE'
      })
    });
    assert.equal(res.status, 400);
  });

  // CERT-11
  it('CERT-11: DELETE /api/v1/fleet/certificates/profiles/:id removes profile', async () => {
    const tempRes = await api('/api/v1/fleet/certificates/profiles', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Temporary Cert Profile',
        certificateType: 'PKCS',
        targetStore: 'CURRENT_USER_MY'
      })
    });
    assert.equal(tempRes.status, 201);

    const delRes = await api(`/api/v1/fleet/certificates/profiles/${tempRes.body.id}`, {
      method: 'DELETE'
    });
    assert.equal(delRes.status, 200);

    const checkRes = await api(`/api/v1/fleet/certificates/profiles/${tempRes.body.id}`);
    assert.equal(checkRes.status, 404);
  });

  // CERT-12
  it('CERT-12: POST /api/v1/nodes/heartbeat includes certificate_profiles array', async () => {
    const res = await nodeApi('/api/v1/nodes/heartbeat', {
      method: 'POST',
      body: JSON.stringify({
        device_id: testDeviceId
      })
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.certificate_profiles), 'Heartbeat should include certificate_profiles');
    assert.ok(res.body.certificate_profiles.length >= 3, 'Should have at least 3 profiles assigned');
  });

  // CERT-13
  it('CERT-13: POST /api/v1/nodes/:id/certificates ingests scanned certificates from node agent', async () => {
    const futureDate = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString();
    const expiringDate = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString();
    const expiredDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();

    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/certificates`, {
      method: 'POST',
      body: JSON.stringify({
        certificates: [
          {
            thumbprint: 'AA11BB22CC33DD44EE55FF660011223344556677',
            subject: 'CN=CERT-TEST-NODE, OU=Fleet Workstations',
            issuer: 'CN=LocalPilot Fleet Enterprise Root CA',
            store_location: 'LOCAL_MACHINE',
            store_name: 'My',
            not_before: '2026-01-01T00:00:00Z',
            not_after: futureDate,
            has_private_key: 1
          },
          {
            thumbprint: 'BB22CC33DD44EE55FF6600112233445566778899',
            subject: 'CN=Internal Web Proxy Client',
            issuer: 'CN=LocalPilot Issuing SubCA 01',
            store_location: 'LOCAL_MACHINE',
            store_name: 'My',
            not_before: '2025-01-01T00:00:00Z',
            not_after: expiringDate,
            has_private_key: 1
          },
          {
            thumbprint: 'CC33DD44EE55FF6600112233445566778899AABB',
            subject: 'CN=Old Legacy Radius Client',
            issuer: 'CN=Old Root CA',
            store_location: 'LOCAL_MACHINE',
            store_name: 'My',
            not_before: '2024-01-01T00:00:00Z',
            not_after: expiredDate,
            has_private_key: 0
          }
        ]
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.saved_count, 3);
  });

  // CERT-14
  it('CERT-14: POST /api/v1/nodes/:id/certificates rejects missing auth (401)', async () => {
    const rawRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ certificates: [] })
    });
    assert.equal(rawRes.status, 401);
  });

  // CERT-15
  it('CERT-15: evaluateExpiry correctly calculates status and days to expiry', () => {
    const futureDate = new Date(Date.now() + 100 * 24 * 60 * 60 * 1000).toISOString();
    const eval1 = evaluateExpiry(futureDate);
    assert.equal(eval1.status, 'VALID');
    assert.ok(eval1.daysToExpiry >= 99);

    const expiringDate = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
    const eval2 = evaluateExpiry(expiringDate);
    assert.equal(eval2.status, 'EXPIRING_SOON');
    assert.ok(eval2.daysToExpiry <= 10 && eval2.daysToExpiry >= 9);

    const expiredDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    const eval3 = evaluateExpiry(expiredDate);
    assert.equal(eval3.status, 'EXPIRED');
    assert.ok(eval3.daysToExpiry < 0);
  });

  // CERT-16
  it('CERT-16: GET /api/v1/fleet/devices/:id/certificates returns device certificates', async () => {
    const res = await api(`/api/v1/fleet/devices/${testDeviceId}/certificates`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.equal(res.body.certificates.length, 3);
    const expiredCert = res.body.certificates.find(c => c.status === 'EXPIRED');
    assert.ok(expiredCert, 'Should contain expired certificate');
    const expiringCert = res.body.certificates.find(c => c.status === 'EXPIRING_SOON');
    assert.ok(expiringCert, 'Should contain expiring certificate');
  });

  // CERT-17
  it('CERT-17: GET /api/v1/fleet/certificates/inventory lists all certificates across fleet with hostname', async () => {
    const res = await api('/api/v1/fleet/certificates/inventory');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.certificates));
    assert.ok(res.body.certificates.length >= 3);
    const match = res.body.certificates.find(c => c.device_id === testDeviceId);
    assert.ok(match);
    assert.equal(match.hostname, 'CERT-TEST-NODE');
  });

  // CERT-18
  it('CERT-18: GET /api/v1/fleet/certificates/inventory?status=EXPIRING_SOON filters correctly', async () => {
    const res = await api('/api/v1/fleet/certificates/inventory?status=EXPIRING_SOON');
    assert.equal(res.status, 200);
    assert.ok(res.body.certificates.every(c => c.status === 'EXPIRING_SOON'));
  });

  // CERT-19
  it('CERT-19: GET /api/v1/fleet/certificates/stats reflects ingested certificate counts', async () => {
    const res = await api('/api/v1/fleet/certificates/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_certificates >= 3);
    assert.ok(res.body.valid_count >= 1);
    assert.ok(res.body.expiring_soon_count >= 1);
    assert.ok(res.body.expired_count >= 1);
    assert.ok(res.body.private_key_certs_count >= 2);
  });

  // CERT-20
  it('CERT-20: GET /api/v1/nodes/:id/certificate-profiles returns effective profiles for device', async () => {
    const res = await nodeApi(`/api/v1/nodes/${testDeviceId}/certificate-profiles`);
    assert.equal(res.status, 200);
    assert.equal(res.body.device_id, testDeviceId);
    assert.ok(Array.isArray(res.body.profiles));
    assert.ok(res.body.profiles.length >= 3);
  });
});
