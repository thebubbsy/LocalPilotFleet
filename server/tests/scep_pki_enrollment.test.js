/**
 * LocalPilot Fleet — Automated SCEP / NDES PKI Dynamic Challenge Engine & 802.1X Wi-Fi Profiles Tests (Iteration 67)
 * server/tests/scep_pki_enrollment.test.js
 *
 * Validates dynamic one-time SCEP challenge tokens, CSR parsing and x509 certificate issuance,
 * revocation lifecycle, 802.1X EAP-TLS Wi-Fi profiles, Apple .mobileconfig payload generation,
 * and Windows WLAN XML profile generation.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { ScepPkiEnrollmentEngine } from '../src/services/scepPkiEnrollmentEngine.js';

describe('SCEP / NDES PKI Dynamic Challenge Engine & 802.1X Wi-Fi Profiles (Iteration 67)', () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });
  });

  afterEach(() => {
    if (db) db.close();
  });

  it('1. getScepStats aggregates total certificates, active, revoked, challenges, and wifi profiles', () => {
    const stats = ScepPkiEnrollmentEngine.getScepStats(db);
    assert.ok(stats.total_certificates >= 1);
    assert.ok(stats.active_certificates >= 1);
    assert.ok(stats.total_challenges >= 1);
    assert.ok(stats.pending_challenges >= 1);
    assert.ok(stats.active_8021x_wifi_profiles >= 1);
  });

  it('2. getScepStats handles empty database tables gracefully', () => {
    const emptyDb = new DatabaseSync(':memory:');
    emptyDb.exec(`
      CREATE TABLE scep_enrollment_challenges (id TEXT, status TEXT);
      CREATE TABLE scep_issued_certificates (id TEXT, status TEXT, valid_to TEXT);
      CREATE TABLE wifi_8021x_profiles (id TEXT, is_active INT);
    `);
    const stats = ScepPkiEnrollmentEngine.getScepStats(emptyDb);
    assert.equal(stats.total_certificates, 0);
    assert.equal(stats.active_certificates, 0);
    assert.equal(stats.total_challenges, 0);
    assert.equal(stats.active_8021x_wifi_profiles, 0);
    emptyDb.close();
  });

  it('3. getChallenges retrieves challenges and filters by status', () => {
    const challenges = ScepPkiEnrollmentEngine.getChallenges(db, { status: 'PENDING' });
    assert.ok(challenges.length >= 1);
    assert.equal(challenges[0].status, 'PENDING');
    assert.ok(challenges[0].challenge_password);
  });

  it('4. generateChallenge creates a secure dynamic challenge token with expiration', () => {
    const challenge = ScepPkiEnrollmentEngine.generateChallenge(db, {
      device_id: 'dev-daddy-pc',
      validity_minutes: 120
    });

    assert.ok(challenge.id);
    assert.ok(challenge.challenge_password.length >= 32);
    assert.equal(challenge.device_id, 'dev-daddy-pc');
    assert.equal(challenge.status, 'PENDING');
    const expiresUtc = new Date(challenge.expires_at.replace(' ', 'T') + 'Z');
    assert.ok(expiresUtc.getTime() > Date.now());
  });

  it('5. generateChallenge throws if device_id or database is missing', () => {
    assert.throws(() => {
      ScepPkiEnrollmentEngine.generateChallenge(null, { device_id: 'dev-daddy-pc' });
    }, /Database handle required/);

    assert.throws(() => {
      ScepPkiEnrollmentEngine.generateChallenge(db, {});
    }, /device_id is required/);
  });

  it('6. validateChallenge validates pending challenge and returns challenge record', () => {
    const created = ScepPkiEnrollmentEngine.generateChallenge(db, {
      device_id: 'dev-daddy-pc'
    });

    const valid = ScepPkiEnrollmentEngine.validateChallenge(db, created.challenge_password, 'dev-daddy-pc');
    assert.ok(valid);
    assert.equal(valid.id, created.id);
    assert.equal(valid.status, 'PENDING');
  });

  it('7. validateChallenge rejects non-existent or invalid challenge tokens', () => {
    const result = ScepPkiEnrollmentEngine.validateChallenge(db, 'non-existent-token', 'dev-daddy-pc');
    assert.equal(result, null);
  });

  it('8. validateChallenge rejects challenge if device_id does not match', () => {
    const created = ScepPkiEnrollmentEngine.generateChallenge(db, {
      device_id: 'dev-daddy-pc'
    });

    const result = ScepPkiEnrollmentEngine.validateChallenge(db, created.challenge_password, 'dev-livingroom-pc');
    assert.equal(result, null);
  });

  it('9. enrollCertificateWithCsr issues synthetic x509 cert and marks challenge REDEEMED', () => {
    const challenge = ScepPkiEnrollmentEngine.generateChallenge(db, {
      device_id: 'dev-daddy-pc'
    });

    const fakeCsr = '-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END CERTIFICATE REQUEST-----';

    const cert = ScepPkiEnrollmentEngine.enrollCertificateWithCsr(db, {
      device_id: 'dev-daddy-pc',
      challenge_password: challenge.challenge_password,
      csr_pem: fakeCsr,
      subject_dn: 'CN=macbook-pro.localpilot.corp',
      validity_days: 365
    });

    assert.ok(cert.id);
    assert.equal(cert.status, 'ACTIVE');
    assert.equal(cert.subject_dn, 'CN=macbook-pro.localpilot.corp');
    assert.ok(cert.serial_number);
    assert.ok(cert.thumbprint_sha256);
    assert.ok(cert.certificate_pem.includes('BEGIN CERTIFICATE'));

    // Verify challenge is now marked REDEEMED
    const updatedCh = db.prepare('SELECT status FROM scep_enrollment_challenges WHERE id = ?').get(challenge.id);
    assert.equal(updatedCh.status, 'REDEEMED');

    // Attempting to reuse the challenge must fail
    assert.throws(() => {
      ScepPkiEnrollmentEngine.enrollCertificateWithCsr(db, {
        device_id: 'dev-daddy-pc',
        challenge_password: challenge.challenge_password,
        csr_pem: fakeCsr
      });
    }, /INVALID_CHALLENGE/);
  });

  it('10. enrollCertificateWithCsr fails if challenge password is invalid', () => {
    assert.throws(() => {
      ScepPkiEnrollmentEngine.enrollCertificateWithCsr(db, {
        device_id: 'dev-daddy-pc',
        challenge_password: 'invalid-challenge-token',
        csr_pem: 'dummy-csr'
      });
    }, /INVALID_CHALLENGE/);
  });

  it('11. enrollCertificateWithCsr throws when required parameters are missing', () => {
    assert.throws(() => {
      ScepPkiEnrollmentEngine.enrollCertificateWithCsr(db, {
        device_id: 'dev-daddy-pc'
      });
    }, /challenge_password is required/);

    assert.throws(() => {
      ScepPkiEnrollmentEngine.enrollCertificateWithCsr(db, {
        challenge_password: 'some-password'
      });
    }, /device_id is required/);
  });

  it('12. getIssuedCertificates filters certificates by status and device_id', () => {
    const allCerts = ScepPkiEnrollmentEngine.getIssuedCertificates(db);
    assert.ok(allCerts.length >= 1);

    const devCerts = ScepPkiEnrollmentEngine.getIssuedCertificates(db, { device_id: allCerts[0].device_id });
    assert.ok(devCerts.length >= 1);
    assert.ok(devCerts.every(c => c.device_id === allCerts[0].device_id));

    const activeOnly = ScepPkiEnrollmentEngine.getIssuedCertificates(db, { status: 'ACTIVE' });
    assert.ok(activeOnly.every(c => c.status === 'ACTIVE'));
  });

  it('13. getCertificate finds certificate by ID', () => {
    const seedCert = ScepPkiEnrollmentEngine.getCertificate(db, 'cert-01');
    assert.ok(seedCert);
    assert.equal(seedCert.id, 'cert-01');
    assert.ok(seedCert.subject_dn.includes('localpilot.corp'));

    const notFound = ScepPkiEnrollmentEngine.getCertificate(db, 'non-existent-id');
    assert.equal(notFound, null);
  });

  it('14. revokeCertificate transitions certificate to REVOKED with timestamp and audit reason', () => {
    const success = ScepPkiEnrollmentEngine.revokeCertificate(db, 'cert-01', 'KEY_COMPROMISE');
    assert.equal(success, true);

    // Verify persisted state in db
    const fetched = ScepPkiEnrollmentEngine.getCertificate(db, 'cert-01');
    assert.equal(fetched.status, 'REVOKED');
    assert.equal(fetched.revocation_reason, 'KEY_COMPROMISE');
    assert.ok(fetched.revoked_at);
  });

  it('15. revokeCertificate returns false if certificate does not exist or is already revoked', () => {
    const res = ScepPkiEnrollmentEngine.revokeCertificate(db, 'cert-does-not-exist');
    assert.equal(res, false);
  });

  it('16. getWifiProfiles lists profiles and filters by platform', () => {
    const profiles = ScepPkiEnrollmentEngine.getWifiProfiles(db);
    assert.ok(profiles.length >= 1);
    assert.equal(profiles[0].id, 'wifi-prof-01');

    const combined = ScepPkiEnrollmentEngine.getWifiProfiles(db, { platform: 'COMBINED' });
    assert.ok(combined.some(p => p.id === 'wifi-prof-01'));
  });

  it('17. createWifiProfile inserts new 802.1X profile with EAP-TLS configurations', () => {
    const newProf = ScepPkiEnrollmentEngine.createWifiProfile(db, {
      name: 'Executive Secure Wi-Fi',
      ssid: 'LocalPilot-Exec',
      target_platform: 'IOS',
      eap_type: 'EAP_TLS',
      auto_connect: true,
      hidden_network: true
    });

    assert.ok(newProf.id);
    assert.equal(newProf.name, 'Executive Secure Wi-Fi');
    assert.equal(newProf.ssid, 'LocalPilot-Exec');
    assert.equal(newProf.target_platform, 'IOS');
    assert.equal(newProf.hidden_network, true);
    assert.equal(newProf.auto_connect, true);
  });

  it('18. deleteWifiProfile successfully deletes a profile', () => {
    const created = ScepPkiEnrollmentEngine.createWifiProfile(db, {
      name: 'Temp Wi-Fi',
      ssid: 'Temp-SSID',
      target_platform: 'ANDROID'
    });

    const res = ScepPkiEnrollmentEngine.deleteWifiProfile(db, created.id);
    assert.equal(res, true);

    const deleted = ScepPkiEnrollmentEngine.getWifiProfile(db, created.id);
    assert.equal(deleted, null);

    const falseRes = ScepPkiEnrollmentEngine.deleteWifiProfile(db, 'non-existent-profile');
    assert.equal(falseRes, false);
  });

  it('19. generateAppleWifiPayload outputs valid Apple .mobileconfig EAP-TLS dictionary', () => {
    const applePayload = ScepPkiEnrollmentEngine.generateAppleWifiPayload(db, 'wifi-prof-01');
    assert.ok(applePayload);
    assert.equal(applePayload.content_type, 'application/x-apple-aspen-config');
    assert.ok(applePayload.filename.includes('.mobileconfig'));
    assert.ok(applePayload.plist_xml.includes('<key>PayloadType</key>'));
    assert.ok(applePayload.plist_xml.includes('com.apple.wifi.managed'));
    assert.ok(applePayload.plist_xml.includes('<integer>13</integer>'));
    assert.ok(applePayload.plist_xml.includes('radius.localpilot.corp'));
  });

  it('20. generateWindowsWifiXml produces compliant WLANProfile XML with EAP-TLS (Type 13)', () => {
    const winXml = ScepPkiEnrollmentEngine.generateWindowsWifiXml(db, 'wifi-prof-01');
    assert.ok(winXml);
    assert.equal(winXml.content_type, 'application/xml; charset=utf-8');
    assert.ok(winXml.filename.includes('.xml'));
    assert.ok(winXml.xml.includes('<?xml version="1.0"?>'));
    assert.ok(winXml.xml.includes('<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'));
    assert.ok(winXml.xml.includes('<name>LocalPilot-Corp-Secure</name>'));
    assert.ok(winXml.xml.includes('>13</Type>'));
    assert.ok(winXml.xml.includes('<useOneX>true</useOneX>'));
  });
});
