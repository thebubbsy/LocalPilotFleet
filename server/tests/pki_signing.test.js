/**
 * LocalPilot Fleet — Enterprise PKI Code-Signing Authority & Digital Payload Verification QA Tests
 * server/tests/pki_signing.test.js
 *
 * Dimension 3: Cryptographic Identity, Zero Trust & Tamper Resistance
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as pkiEngine from '../src/services/pkiSigningEngine.js';

describe('Enterprise PKI Code-Signing Authority & Verification QA (pki_signing.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-pki-qa';
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
        hostname: 'SECURE-NODE-01',
        friendly_name: 'Zero-Trust Secure Workstation 01',
        serial_number: 'PKI-TEST-SN-998877',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '24H2',
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

  // PKI-01
  test('PKI-01: getPkiStats returns operational status and root authority metrics', () => {
    const stats = pkiEngine.getPkiStats(app.db);
    assert.ok(stats.total_keys >= 1);
    assert.ok(stats.active_keys >= 1);
    assert.equal(stats.status, 'OPERATIONAL');
    assert.ok(stats.active_authority);
    assert.ok(stats.active_authority.thumbprint);
  });

  // PKI-02
  test('PKI-02: getSigningKeys returns all registered keys', () => {
    const keys = pkiEngine.getSigningKeys(app.db, true);
    assert.ok(Array.isArray(keys));
    assert.ok(keys.length >= 1);
    assert.ok(keys[0].public_key_pem.includes('BEGIN PUBLIC KEY'));
    // Private keys must NOT be leaked
    assert.equal(keys[0].private_key_pem, undefined);
  });

  // PKI-03
  test('PKI-03: getSigningKeyById returns key and omits private key by default', () => {
    const active = pkiEngine.getActiveSigningKey(app.db, false);
    const fetched = pkiEngine.getSigningKeyById(app.db, active.id, false);
    assert.ok(fetched);
    assert.equal(fetched.id, active.id);
    assert.equal(fetched.private_key_pem, undefined);
  });

  // PKI-04
  test('PKI-04: generateSigningKey creates a new valid RSA-2048 keypair with SHA256 thumbprint', () => {
    const newKey = pkiEngine.generateSigningKey(app.db, {
      name: 'QA Secondary Signing Key',
      keyType: 'RSA-2048',
      validityYears: 2,
      setAsActive: false
    });
    assert.ok(newKey);
    assert.ok(newKey.id.startsWith('pki-key-'));
    assert.equal(newKey.name, 'QA Secondary Signing Key');
    assert.equal(newKey.is_active, 0);
    assert.ok(newKey.thumbprint.length >= 32);
    assert.ok(newKey.public_key_pem.includes('BEGIN PUBLIC KEY'));
  });

  // PKI-05
  test('PKI-05: rotateSigningKey deactivates previous key and activates newly generated authority', () => {
    const beforeStats = pkiEngine.getPkiStats(app.db);
    const rotation = pkiEngine.rotateSigningKey(app.db, { name: 'Automated Rotated Root Authority' });
    assert.ok(rotation.active_key);
    assert.equal(rotation.active_key.is_active, 1);
    assert.equal(rotation.previous_key.id, beforeStats.active_authority.id);

    const afterActive = pkiEngine.getActiveSigningKey(app.db, false);
    assert.equal(afterActive.id, rotation.active_key.id);
  });

  // PKI-06
  test('PKI-06: revokeSigningKey marks key as revoked, deactivates it, records reason', () => {
    const keyToRevoke = pkiEngine.generateSigningKey(app.db, {
      name: 'Key To Revoke',
      setAsActive: false
    });
    const revoked = pkiEngine.revokeSigningKey(app.db, keyToRevoke.id, 'Compromised simulation test');
    assert.ok(revoked);
    assert.equal(revoked.is_revoked, 1);
    assert.equal(revoked.is_active, 0);
    assert.equal(revoked.revocation_reason, 'Compromised simulation test');
  });

  // PKI-07
  test('PKI-07: signPayload generates valid SHA256-RSA signature and logs manifest', () => {
    const payload = 'Get-Service -Name wuauserv | Restart-Service -Force';
    const signed = pkiEngine.signPayload(app.db, {
      payload,
      payloadType: 'REMEDIATION',
      targetId: 'rem-wuauserv-01'
    });

    assert.ok(signed.manifest_id);
    assert.ok(signed.signature_base64);
    assert.ok(signed.sha256_hash);
    assert.ok(signed.envelope.includes('BEGIN LOCALPILOT ENTERPRISE SIGNATURE'));

    // Manifest recorded in DB
    const row = app.db.prepare('SELECT * FROM signed_payload_manifests WHERE id = ?').get(signed.manifest_id);
    assert.ok(row);
    assert.equal(row.payload_type, 'REMEDIATION');
    assert.equal(row.target_id, 'rem-wuauserv-01');
  });

  // PKI-08
  test('PKI-08: verifyPayload validates matching payload and signature correctly', () => {
    const payload = 'Invoke-Item C:\Windows\System32\notepad.exe';
    const signed = pkiEngine.signPayload(app.db, { payload });

    const result = pkiEngine.verifyPayload(app.db, {
      payload,
      signatureBase64: signed.signature_base64,
      signerThumbprint: signed.signer_thumbprint
    });

    assert.equal(result.valid, true);
    assert.equal(result.is_revoked, false);
    assert.equal(result.error, null);
  });

  // PKI-09
  test('PKI-09: verifyPayload rejects tampered payload (zero-trust tamper resistance)', () => {
    const legitimate = 'Set-ItemProperty -Path "HKLM:\Software\Policies" -Name "SecAudit" -Value 1';
    const tampered = 'Set-ItemProperty -Path "HKLM:\Software\Policies" -Name "SecAudit" -Value 0'; // Attacker injected change!

    const signed = pkiEngine.signPayload(app.db, { payload: legitimate });

    const result = pkiEngine.verifyPayload(app.db, {
      payload: tampered,
      signatureBase64: signed.signature_base64,
      signerThumbprint: signed.signer_thumbprint
    });

    assert.equal(result.valid, false);
    assert.ok(result.error);
    assert.ok(result.error.includes('failed') || result.error.includes('modified'));
  });

  // PKI-10
  test('PKI-10: verifyPayload rejects signature if signing key was revoked', () => {
    const key = pkiEngine.generateSigningKey(app.db, { name: 'Temporary Key for Revocation', setAsActive: false });
    const payload = 'Write-Output "Test Revocation"';
    const signed = pkiEngine.signPayload(app.db, { payload, keyId: key.id });

    // Revoke key
    pkiEngine.revokeSigningKey(app.db, key.id, 'Suspected leak');

    const result = pkiEngine.verifyPayload(app.db, {
      payload,
      signatureBase64: signed.signature_base64,
      keyId: key.id
    });

    assert.equal(result.valid, false);
    assert.equal(result.is_revoked, true);
    assert.ok(result.error.includes('revoked'));
  });

  // PKI-11
  test('PKI-11: wrapScriptWithSignature formats valid PowerShell signature envelope', () => {
    const script = 'Get-BitLockerVolume -MountPoint C:';
    const wrapped = pkiEngine.wrapScriptWithSignature(app.db, script, {
      payloadType: 'SCRIPT',
      targetId: 'bitlocker-check'
    });

    assert.ok(wrapped.wrapped_script.includes(script));
    assert.ok(wrapped.wrapped_script.includes('# SIG # BEGIN LOCALPILOT ENTERPRISE SIGNATURE'));
    assert.ok(wrapped.wrapped_script.includes('# SIG # END LOCALPILOT ENTERPRISE SIGNATURE'));
    assert.ok(wrapped.wrapped_script.includes(`# Key-Id: ${wrapped.key_id}`));
  });

  // PKI-12
  test('PKI-12: extractAndVerifyScriptEnvelope verifies authentic wrapped script', () => {
    const script = 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True';
    const wrapped = pkiEngine.wrapScriptWithSignature(app.db, script);

    const verified = pkiEngine.extractAndVerifyScriptEnvelope(app.db, wrapped.wrapped_script);
    assert.equal(verified.valid, true);
    assert.equal(verified.clean_payload, script);
    assert.equal(verified.extracted_thumbprint, wrapped.signer_thumbprint);
  });

  // PKI-13
  test('PKI-13: extractAndVerifyScriptEnvelope rejects script when body was tampered after wrapping', () => {
    const script = 'Write-Host "Authentic Code"';
    const wrapped = pkiEngine.wrapScriptWithSignature(app.db, script);

    // Tamper with the code while leaving signature block intact
    const tamperedScript = wrapped.wrapped_script.replace('Authentic Code', 'MALICIOUS PAYLOAD INJECTED');

    const verified = pkiEngine.extractAndVerifyScriptEnvelope(app.db, tamperedScript);
    assert.equal(verified.valid, false);
    assert.ok(verified.error);
  });

  // PKI-14
  test('PKI-14: getSigningManifests filters by payload type and returns history', () => {
    const manifests = pkiEngine.getSigningManifests(app.db, { payloadType: 'REMEDIATION' });
    assert.ok(Array.isArray(manifests));
    assert.ok(manifests.length >= 1);
    assert.equal(manifests[0].payload_type, 'REMEDIATION');
  });

  // PKI-15
  test('PKI-15: REST GET /api/v1/fleet/pki/stats returns 200 with operational metrics', async () => {
    const res = await api('/api/v1/fleet/pki/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.total_keys >= 1);
    assert.ok(res.body.status === 'OPERATIONAL');
  });

  // PKI-16
  test('PKI-16: REST GET /api/v1/fleet/pki/keys requires fleet key and returns keys array', async () => {
    const unauthorized = await api('/api/v1/fleet/pki/keys', { headers: { 'X-Fleet-Key': 'wrong-key' } });
    assert.equal(unauthorized.status, 401);

    const authorized = await api('/api/v1/fleet/pki/keys');
    assert.equal(authorized.status, 200);
    assert.ok(Array.isArray(authorized.body.keys));
    assert.ok(authorized.body.count >= 1);
  });

  // PKI-17
  test('PKI-17: REST POST /api/v1/fleet/pki/keys/generate creates key via REST API', async () => {
    const res = await api('/api/v1/fleet/pki/keys/generate', {
      method: 'POST',
      body: JSON.stringify({
        name: 'REST Generated Signing Authority',
        keyType: 'RSA-2048',
        validityYears: 1,
        setAsActive: false
      })
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.success, true);
    assert.ok(res.body.key.id);
  });

  // PKI-18
  test('PKI-18: REST POST /api/v1/fleet/pki/sign signs payload and optionally wraps envelope', async () => {
    const script = 'Get-ComputerInfo | Select-Object WindowsVersion';
    const res = await api('/api/v1/fleet/pki/sign', {
      method: 'POST',
      body: JSON.stringify({
        payload: script,
        payload_type: 'SCRIPT',
        wrap_envelope: true
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.ok(res.body.signature_base64);
    assert.ok(res.body.wrapped_script.includes('# SIG # BEGIN LOCALPILOT ENTERPRISE SIGNATURE'));
  });

  // PKI-19
  test('PKI-19: REST POST /api/v1/fleet/pki/verify verifies envelope or raw signature via REST', async () => {
    // First sign
    const payload = 'Get-Service -Name Spooler | Stop-Service';
    const signRes = await api('/api/v1/fleet/pki/sign', {
      method: 'POST',
      body: JSON.stringify({ payload, wrap_envelope: true })
    });
    assert.equal(signRes.status, 200);

    // Verify envelope text
    const verifyRes = await api('/api/v1/fleet/pki/verify', {
      method: 'POST',
      body: JSON.stringify({ envelope_text: signRes.body.wrapped_script })
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.body.valid, true);
  });

  // PKI-20
  test('PKI-20: REST GET /api/v1/pki/cert & /api/v1/nodes/:id/pki/cert distribute public root cert', async () => {
    // Public unauthenticated route
    const publicRes = await fetch(`${app.baseUrl}/api/v1/pki/cert`);
    assert.equal(publicRes.status, 200);
    const publicCert = await publicRes.json();
    assert.ok(publicCert.public_key_pem.includes('BEGIN PUBLIC KEY'));
    assert.ok(publicCert.thumbprint);

    // Node-authenticated route
    const nodeRes = await fetch(`${app.baseUrl}/api/v1/nodes/${testDeviceId}/pki/cert`, {
      headers: {
        'Authorization': `Bearer ${testNodeToken}`
      }
    });
    assert.equal(nodeRes.status, 200);
    const nodeCert = await nodeRes.json();
    assert.equal(nodeCert.device_id, testDeviceId);
    assert.equal(nodeCert.thumbprint, publicCert.thumbprint);
  });
});
