/**
 * LocalPilot Fleet — Enterprise VPN & Per-App VPN Profiles Tests (Iteration 68)
 * server/tests/enterprise_vpn_profiles.test.js
 *
 * Validates enterprise micro-tunneling, zero-trust per-app socket isolation,
 * split-tunnel CIDR policy routing, dynamic on-demand rules, Apple .mobileconfig payloads,
 * and Windows VPNv2 CSP XML profiles.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { initDb, applyPragmas } from '../src/db.js';
import { EnterpriseVpnProfileEngine } from '../src/services/enterpriseVpnProfileEngine.js';

describe('Enterprise VPN & Per-App VPN Profiles Engine (Iteration 68)', () => {
  let db;

  beforeEach(() => {
    db = new DatabaseSync(':memory:');
    applyPragmas(db);
    initDb(db, { seed: true });
  });

  afterEach(() => {
    if (db) db.close();
  });

  it('1. getVpnStats aggregates total profiles, active profiles, per-app profiles, and mappings', () => {
    const stats = EnterpriseVpnProfileEngine.getVpnStats(db);
    assert.ok(stats.total_profiles >= 1);
    assert.ok(stats.active_profiles >= 1);
    assert.ok(stats.per_app_vpn_profiles >= 1);
    assert.ok(stats.total_app_mappings >= 2);
    assert.ok(stats.active_app_mappings >= 2);
    assert.ok(stats.total_audit_events >= 1);
    assert.ok(stats.total_bytes_transferred > 0);
  });

  it('2. getVpnStats handles empty database tables gracefully', () => {
    const emptyDb = new DatabaseSync(':memory:');
    emptyDb.exec(`
      CREATE TABLE enterprise_vpn_profiles (id TEXT, is_active INT, is_per_app_vpn INT);
      CREATE TABLE per_app_vpn_mappings (id TEXT, is_active INT);
      CREATE TABLE vpn_connection_audit_logs (id TEXT, event_type TEXT, bytes_in INT, bytes_out INT);
    `);
    const stats = EnterpriseVpnProfileEngine.getVpnStats(emptyDb);
    assert.equal(stats.total_profiles, 0);
    assert.equal(stats.active_profiles, 0);
    assert.equal(stats.total_app_mappings, 0);
    assert.equal(stats.total_bytes_transferred, 0);
    emptyDb.close();
  });

  it('3. getVpnProfiles retrieves profiles and filters by platform', () => {
    const profiles = EnterpriseVpnProfileEngine.getVpnProfiles(db, { platform: 'MACOS' });
    assert.ok(profiles.length >= 1);
    assert.ok(profiles.some(p => p.id === 'vpn-prof-01'));
  });

  it('4. getVpnProfiles filters by connection type', () => {
    const ikev2Profiles = EnterpriseVpnProfileEngine.getVpnProfiles(db, { connection_type: 'IKEV2' });
    assert.ok(ikev2Profiles.length >= 1);
    assert.ok(ikev2Profiles.every(p => p.connection_type === 'IKEV2'));

    const wireguard = EnterpriseVpnProfileEngine.getVpnProfiles(db, { connection_type: 'WIREGUARD' });
    assert.equal(wireguard.length, 0);
  });

  it('5. getVpnProfiles filters by is_per_app_vpn flag', () => {
    const perAppOnly = EnterpriseVpnProfileEngine.getVpnProfiles(db, { is_per_app_vpn: 1 });
    assert.ok(perAppOnly.length >= 1);
    assert.ok(perAppOnly.every(p => p.is_per_app_vpn === true));
  });

  it('6. getVpnProfile returns single profile with parsed JSON arrays and attached app mappings', () => {
    const profile = EnterpriseVpnProfileEngine.getVpnProfile(db, 'vpn-prof-01');
    assert.ok(profile);
    assert.equal(profile.id, 'vpn-prof-01');
    assert.equal(profile.name, 'Corporate Zero-Trust Intranet Gateway');
    assert.ok(Array.isArray(profile.split_tunnel_routes));
    assert.ok(Array.isArray(profile.dns_servers));
    assert.ok(Array.isArray(profile.app_mappings));
    assert.ok(profile.app_mappings.length >= 2);
    assert.equal(profile.is_per_app_vpn, true);
  });

  it('7. getVpnProfile returns null for non-existent profile ID', () => {
    const notFound = EnterpriseVpnProfileEngine.getVpnProfile(db, 'non-existent-profile');
    assert.equal(notFound, null);
  });

  it('8. createVpnProfile inserts new VPN profile with default split-tunnel routes and on-demand rules', () => {
    const created = EnterpriseVpnProfileEngine.createVpnProfile(db, {
      name: 'Engineering WireGuard Tunnel',
      connection_type: 'WIREGUARD',
      server_address: 'wg.localpilot.corp',
      target_platform: 'WINDOWS',
      split_tunneling: true
    });

    assert.ok(created.id);
    assert.equal(created.name, 'Engineering WireGuard Tunnel');
    assert.equal(created.connection_type, 'WIREGUARD');
    assert.equal(created.server_address, 'wg.localpilot.corp');
    assert.equal(created.split_tunneling, true);
    assert.ok(created.split_tunnel_routes.includes('10.0.0.0/8'));
    assert.ok(created.on_demand_rules.length >= 1);
  });

  it('9. createVpnProfile throws when name or server_address is missing', () => {
    assert.throws(() => {
      EnterpriseVpnProfileEngine.createVpnProfile(db, { server_address: 'vpn.test.local' });
    }, /Profile name is required/);

    assert.throws(() => {
      EnterpriseVpnProfileEngine.createVpnProfile(db, { name: 'Test VPN' });
    }, /server_address is required/);
  });

  it('10. updateVpnProfile dynamically modifies profile fields and updates timestamp', () => {
    const updated = EnterpriseVpnProfileEngine.updateVpnProfile(db, 'vpn-prof-01', {
      name: 'Updated Intranet Gateway',
      server_address: 'vpn2.localpilot.corp',
      split_tunneling: false
    });

    assert.equal(updated.name, 'Updated Intranet Gateway');
    assert.equal(updated.server_address, 'vpn2.localpilot.corp');
    assert.equal(updated.split_tunneling, false);

    // Verify persisted state
    const fetched = EnterpriseVpnProfileEngine.getVpnProfile(db, 'vpn-prof-01');
    assert.equal(fetched.name, 'Updated Intranet Gateway');
    assert.equal(fetched.split_tunneling, false);
  });

  it('11. updateVpnProfile throws when profile does not exist', () => {
    assert.throws(() => {
      EnterpriseVpnProfileEngine.updateVpnProfile(db, 'non-existent-profile', { name: 'Test' });
    }, /VPN profile not found/);
  });

  it('12. deleteVpnProfile deletes profile and cascades deletion of app mappings', () => {
    const success = EnterpriseVpnProfileEngine.deleteVpnProfile(db, 'vpn-prof-01');
    assert.equal(success, true);

    const profile = EnterpriseVpnProfileEngine.getVpnProfile(db, 'vpn-prof-01');
    assert.equal(profile, null);

    // Mappings must be cascaded
    const mappings = EnterpriseVpnProfileEngine.getPerAppMappings(db, { vpn_profile_id: 'vpn-prof-01' });
    assert.equal(mappings.length, 0);
  });

  it('13. getPerAppMappings lists mappings and filters by vpn_profile_id and platform', () => {
    const all = EnterpriseVpnProfileEngine.getPerAppMappings(db);
    assert.ok(all.length >= 2);

    const macOnly = EnterpriseVpnProfileEngine.getPerAppMappings(db, { platform: 'MACOS' });
    assert.ok(macOnly.length >= 1);
    assert.ok(macOnly.some(m => m.app_bundle_id === 'com.tinyspeck.slackmacgap'));
  });

  it('14. addPerAppMapping binds new application to VPN profile', () => {
    const mapping = EnterpriseVpnProfileEngine.addPerAppMapping(db, {
      vpn_profile_id: 'vpn-prof-01',
      app_bundle_id: 'com.apple.mobilenotes',
      app_name: 'Apple Notes Corporate',
      platform: 'IOS'
    });

    assert.ok(mapping.id);
    assert.equal(mapping.app_bundle_id, 'com.apple.mobilenotes');
    assert.equal(mapping.app_name, 'Apple Notes Corporate');
    assert.equal(mapping.platform, 'IOS');

    const profile = EnterpriseVpnProfileEngine.getVpnProfile(db, 'vpn-prof-01');
    assert.ok(profile.app_mappings.some(m => m.id === mapping.id));
  });

  it('15. addPerAppMapping throws if required fields are missing or profile not found', () => {
    assert.throws(() => {
      EnterpriseVpnProfileEngine.addPerAppMapping(db, {
        app_bundle_id: 'com.test.app',
        app_name: 'Test'
      });
    }, /vpn_profile_id is required/);

    assert.throws(() => {
      EnterpriseVpnProfileEngine.addPerAppMapping(db, {
        vpn_profile_id: 'non-existent-profile',
        app_bundle_id: 'com.test.app',
        app_name: 'Test'
      });
    }, /VPN profile not found/);
  });

  it('16. removePerAppMapping deletes mapping and returns true', () => {
    const removed = EnterpriseVpnProfileEngine.removePerAppMapping(db, 'vpn-map-01');
    assert.equal(removed, true);

    const mappings = EnterpriseVpnProfileEngine.getPerAppMappings(db, { vpn_profile_id: 'vpn-prof-01' });
    assert.ok(!mappings.some(m => m.id === 'vpn-map-01'));

    const fail = EnterpriseVpnProfileEngine.removePerAppMapping(db, 'non-existent-map');
    assert.equal(fail, false);
  });

  it('17. generateAppleVpnPayload produces valid Apple .mobileconfig with com.apple.vpn.managed.appmapping', () => {
    const applePayload = EnterpriseVpnProfileEngine.generateAppleVpnPayload(db, 'vpn-prof-01');
    assert.ok(applePayload);
    assert.equal(applePayload.content_type, 'application/x-apple-aspen-config');
    assert.ok(applePayload.filename.includes('.mobileconfig'));
    assert.ok(applePayload.plist_xml.includes('com.apple.vpn.managed'));
    assert.ok(applePayload.plist_xml.includes('vpn.localpilot.corp'));
    assert.ok(applePayload.plist_xml.includes('com.apple.vpn.managed.appmapping'));
    assert.ok(applePayload.plist_xml.includes('com.microsoft.Office.Outlook'));
    assert.ok(applePayload.plist_xml.includes('com.tinyspeck.slackmacgap'));
  });

  it('18. generateWindowsVpnXml synthesizes valid Windows VPNv2 CSP XML with TrafficFilter nodes', () => {
    const winXml = EnterpriseVpnProfileEngine.generateWindowsVpnXml(db, 'vpn-prof-01');
    assert.ok(winXml);
    assert.equal(winXml.content_type, 'application/xml; charset=utf-8');
    assert.ok(winXml.filename.includes('.xml'));
    assert.ok(winXml.xml.includes('<VPNv2>'));
    assert.ok(winXml.xml.includes('<ServerAddress>vpn.localpilot.corp</ServerAddress>'));
    assert.ok(winXml.xml.includes('<RoutingPolicyType>SplitTunnel</RoutingPolicyType>'));
    assert.ok(winXml.xml.includes('<TrafficFilters>'));
    assert.ok(winXml.xml.includes('<AppId>com.microsoft.Office.Outlook</AppId>'));
  });

  it('19. logVpnEvent records telemetry audit event with duration and transfer bytes', () => {
    const log = EnterpriseVpnProfileEngine.logVpnEvent(db, {
      device_id: 'dev-daddy-pc',
      vpn_profile_id: 'vpn-prof-01',
      event_type: 'TUNNEL_DISCONNECTED',
      assigned_ip: '10.200.1.45',
      bytes_in: 5000000,
      bytes_out: 2500000,
      duration_seconds: 7200,
      client_os: 'Windows 11 Enterprise'
    });

    assert.ok(log.id);
    assert.equal(log.device_id, 'dev-daddy-pc');
    assert.equal(log.event_type, 'TUNNEL_DISCONNECTED');
    assert.equal(log.duration_seconds, 7200);

    const logs = EnterpriseVpnProfileEngine.getVpnLogs(db, { device_id: 'dev-daddy-pc' });
    assert.ok(logs.some(l => l.id === log.id));
  });

  it('20. getEffectiveDeviceVpn and getDevicePerAppRules resolve active tunnel and per-app routing rules', () => {
    const effective = EnterpriseVpnProfileEngine.getEffectiveDeviceVpn(db, 'dev-daddy-pc');
    assert.ok(effective);
    assert.equal(effective.id, 'vpn-prof-01');

    const appRules = EnterpriseVpnProfileEngine.getDevicePerAppRules(db, 'dev-daddy-pc');
    assert.ok(appRules.length >= 2);
    assert.ok(appRules.some(r => r.app_bundle_id === 'com.microsoft.Office.Outlook'));
    assert.equal(appRules[0].server_address, 'vpn.localpilot.corp');
  });
});
