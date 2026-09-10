/**
 * LocalPilot Fleet — Enterprise VPN & Per-App VPN Profiles Engine (Iteration 68)
 * server/src/services/enterpriseVpnProfileEngine.js
 *
 * Implements enterprise micro-tunneling, zero-trust per-app socket isolation,
 * split-tunnel CIDR policy routing, dynamic on-demand tunnel rules, and payload
 * generation for Apple .mobileconfig, Windows VPNv2 CSP XML, and Android VpnService.
 */

import crypto from 'node:crypto';

export class EnterpriseVpnProfileEngine {

  /**
   * Aggregate fleet-wide VPN profile, per-app routing, and connection metrics
   */
  static getVpnStats(db) {
    if (!db) return {};

    const totalProfiles = db.prepare('SELECT COUNT(*) as count FROM enterprise_vpn_profiles').get()?.count || 0;
    const activeProfiles = db.prepare('SELECT COUNT(*) as count FROM enterprise_vpn_profiles WHERE is_active = 1').get()?.count || 0;
    const perAppProfiles = db.prepare('SELECT COUNT(*) as count FROM enterprise_vpn_profiles WHERE is_per_app_vpn = 1 AND is_active = 1').get()?.count || 0;
    const totalMappings = db.prepare('SELECT COUNT(*) as count FROM per_app_vpn_mappings').get()?.count || 0;
    const activeMappings = db.prepare('SELECT COUNT(*) as count FROM per_app_vpn_mappings WHERE is_active = 1').get()?.count || 0;
    const totalLogs = db.prepare('SELECT COUNT(*) as count FROM vpn_connection_audit_logs').get()?.count || 0;
    const activeTunnels = db.prepare("SELECT COUNT(*) as count FROM vpn_connection_audit_logs WHERE event_type = 'TUNNEL_ESTABLISHED'").get()?.count || 0;
    
    const trafficRow = db.prepare('SELECT COALESCE(SUM(bytes_in), 0) as total_in, COALESCE(SUM(bytes_out), 0) as total_out FROM vpn_connection_audit_logs').get();
    const bytesIn = trafficRow?.total_in || 0;
    const bytesOut = trafficRow?.total_out || 0;

    return {
      total_profiles: totalProfiles,
      active_profiles: activeProfiles,
      per_app_vpn_profiles: perAppProfiles,
      total_app_mappings: totalMappings,
      active_app_mappings: activeMappings,
      total_audit_events: totalLogs,
      active_tunnels: activeTunnels,
      total_bytes_transferred: bytesIn + bytesOut,
      calculated_at: new Date().toISOString()
    };
  }

  /**
   * List Enterprise VPN Profiles with optional platform / per-app filters
   */
  static getVpnProfiles(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM enterprise_vpn_profiles WHERE 1=1';
    const params = [];

    if (query.platform) {
      sql += " AND (target_platform = ? OR target_platform = 'COMBINED')";
      params.push(query.platform.toUpperCase());
    }

    if (query.connection_type) {
      sql += ' AND connection_type = ?';
      params.push(query.connection_type.toUpperCase());
    }

    if (query.is_per_app_vpn !== undefined) {
      sql += ' AND is_per_app_vpn = ?';
      params.push(Number(query.is_per_app_vpn));
    }

    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(Number(query.is_active));
    }

    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => this._hydrateProfile(r));
  }

  /**
   * Get single VPN profile by ID including attached per-app mappings
   */
  static getVpnProfile(db, id) {
    if (!db || !id) return null;

    const profileRow = db.prepare('SELECT * FROM enterprise_vpn_profiles WHERE id = ?').get(id);
    if (!profileRow) return null;

    const profile = this._hydrateProfile(profileRow);
    const mappings = db.prepare('SELECT * FROM per_app_vpn_mappings WHERE vpn_profile_id = ? ORDER BY app_name ASC').all(id);
    profile.app_mappings = mappings.map(m => ({
      ...m,
      is_active: Boolean(m.is_active)
    }));

    return profile;
  }

  /**
   * Create new Enterprise VPN Profile
   */
  static createVpnProfile(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.name) throw new Error('Profile name is required');
    if (!data.server_address) throw new Error('server_address is required');

    const id = data.id || ('vpn-prof-' + crypto.randomBytes(4).toString('hex'));
    const connType = (data.connection_type || 'IKEV2').toUpperCase();
    const platform = (data.target_platform || 'COMBINED').toUpperCase();
    const authMethod = (data.auth_method || 'CERTIFICATE_EAP_TLS').toUpperCase();

    const splitRoutes = Array.isArray(data.split_tunnel_routes) 
      ? data.split_tunnel_routes 
      : ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

    const dnsServers = Array.isArray(data.dns_servers) 
      ? data.dns_servers 
      : ['10.200.0.1', '10.200.0.2'];

    const searchDomains = Array.isArray(data.search_domains) 
      ? data.search_domains 
      : ['localpilot.corp', 'internal.localpilot'];

    const onDemandRules = Array.isArray(data.on_demand_rules) 
      ? data.on_demand_rules 
      : [{ action: 'ConnectIfNeeded', domains: ['*.localpilot.corp'] }];

    const stmt = db.prepare(`
      INSERT INTO enterprise_vpn_profiles (
        id, name, connection_type, server_address, remote_identifier,
        target_platform, auth_method, scep_cert_id, split_tunneling,
        split_tunnel_routes_json, dns_servers_json, search_domains_json,
        on_demand_rules_json, is_per_app_vpn, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      connType,
      data.server_address,
      data.remote_identifier || data.server_address,
      platform,
      authMethod,
      data.scep_cert_id || null,
      data.split_tunneling !== undefined ? (data.split_tunneling ? 1 : 0) : 1,
      JSON.stringify(splitRoutes),
      JSON.stringify(dnsServers),
      JSON.stringify(searchDomains),
      JSON.stringify(onDemandRules),
      data.is_per_app_vpn ? 1 : 0,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return this.getVpnProfile(db, id);
  }

  /**
   * Update existing VPN Profile
   */
  static updateVpnProfile(db, id, data = {}) {
    if (!db || !id) throw new Error('Database and profile ID required');

    const existing = this.getVpnProfile(db, id);
    if (!existing) throw new Error('VPN profile not found');

    const fields = [];
    const params = [];

    if (data.name !== undefined) { fields.push('name = ?'); params.push(data.name); }
    if (data.server_address !== undefined) { fields.push('server_address = ?'); params.push(data.server_address); }
    if (data.remote_identifier !== undefined) { fields.push('remote_identifier = ?'); params.push(data.remote_identifier); }
    if (data.connection_type !== undefined) { fields.push('connection_type = ?'); params.push(data.connection_type.toUpperCase()); }
    if (data.target_platform !== undefined) { fields.push('target_platform = ?'); params.push(data.target_platform.toUpperCase()); }
    if (data.auth_method !== undefined) { fields.push('auth_method = ?'); params.push(data.auth_method.toUpperCase()); }
    if (data.scep_cert_id !== undefined) { fields.push('scep_cert_id = ?'); params.push(data.scep_cert_id); }
    if (data.split_tunneling !== undefined) { fields.push('split_tunneling = ?'); params.push(data.split_tunneling ? 1 : 0); }
    if (data.split_tunnel_routes !== undefined) { fields.push('split_tunnel_routes_json = ?'); params.push(JSON.stringify(data.split_tunnel_routes)); }
    if (data.dns_servers !== undefined) { fields.push('dns_servers_json = ?'); params.push(JSON.stringify(data.dns_servers)); }
    if (data.search_domains !== undefined) { fields.push('search_domains_json = ?'); params.push(JSON.stringify(data.search_domains)); }
    if (data.on_demand_rules !== undefined) { fields.push('on_demand_rules_json = ?'); params.push(JSON.stringify(data.on_demand_rules)); }
    if (data.is_per_app_vpn !== undefined) { fields.push('is_per_app_vpn = ?'); params.push(data.is_per_app_vpn ? 1 : 0); }
    if (data.is_active !== undefined) { fields.push('is_active = ?'); params.push(data.is_active ? 1 : 0); }

    fields.push("updated_at = DATETIME('now')");

    const sql = `UPDATE enterprise_vpn_profiles SET ${fields.join(', ')} WHERE id = ?`;
    params.push(id);

    db.prepare(sql).run(...params);
    return this.getVpnProfile(db, id);
  }

  /**
   * Delete VPN Profile (cascades to mappings)
   */
  static deleteVpnProfile(db, id) {
    if (!db || !id) return false;
    const res = db.prepare('DELETE FROM enterprise_vpn_profiles WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * List Per-App VPN Mappings
   */
  static getPerAppMappings(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT m.*, p.name as vpn_profile_name FROM per_app_vpn_mappings m JOIN enterprise_vpn_profiles p ON m.vpn_profile_id = p.id WHERE 1=1';
    const params = [];

    if (query.vpn_profile_id) {
      sql += ' AND m.vpn_profile_id = ?';
      params.push(query.vpn_profile_id);
    }

    if (query.platform) {
      sql += " AND (m.platform = ? OR m.platform = 'COMBINED')";
      params.push(query.platform.toUpperCase());
    }

    if (query.app_bundle_id) {
      sql += ' AND m.app_bundle_id = ?';
      params.push(query.app_bundle_id);
    }

    sql += ' ORDER BY m.created_at DESC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => ({
      ...r,
      is_active: Boolean(r.is_active)
    }));
  }

  /**
   * Add application to Per-App VPN profile
   */
  static addPerAppMapping(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.vpn_profile_id) throw new Error('vpn_profile_id is required');
    if (!data.app_bundle_id) throw new Error('app_bundle_id is required');
    if (!data.app_name) throw new Error('app_name is required');

    const profile = this.getVpnProfile(db, data.vpn_profile_id);
    if (!profile) throw new Error('VPN profile not found');

    const id = data.id || ('vpn-map-' + crypto.randomBytes(4).toString('hex'));
    const platform = (data.platform || 'COMBINED').toUpperCase();
    const designatedRequirement = data.designated_requirement || `identifier "${data.app_bundle_id}" and anchor apple generic`;

    const stmt = db.prepare(`
      INSERT INTO per_app_vpn_mappings (
        id, vpn_profile_id, app_bundle_id, app_name, platform, designated_requirement, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.vpn_profile_id,
      data.app_bundle_id,
      data.app_name,
      platform,
      designatedRequirement,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return db.prepare('SELECT * FROM per_app_vpn_mappings WHERE id = ?').get(id);
  }

  /**
   * Remove Per-App VPN Mapping
   */
  static removePerAppMapping(db, id) {
    if (!db || !id) return false;
    const res = db.prepare('DELETE FROM per_app_vpn_mappings WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Generate Apple .mobileconfig VPN & Per-App Payload
   */
  static generateAppleVpnPayload(db, profileId) {
    const profile = this.getVpnProfile(db, profileId);
    if (!profile) return null;

    const payloadUuid = crypto.randomUUID().toUpperCase();
    const vpnUuid = crypto.randomUUID().toUpperCase();
    const appMappingUuid = crypto.randomUUID().toUpperCase();

    // Generate AppMapping plist dictionary if per-app VPN
    let appMappingXml = '';
    if (profile.is_per_app_vpn && profile.app_mappings && profile.app_mappings.length > 0) {
      const appArray = profile.app_mappings.map(app => `
            <dict>
                <key>AppIdentifier</key>
                <string>${app.app_bundle_id}</string>
                <key>DesignatedRequirement</key>
                <string>${app.designated_requirement}</string>
            </dict>`).join('');

      appMappingXml = `
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed.appmapping</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>corp.localpilot.vpn.appmapping.${profile.id}</string>
            <key>PayloadUUID</key>
            <string>${appMappingUuid}</string>
            <key>VPNUUID</key>
            <string>${vpnUuid}</string>
            <key>AppMapping</key>
            <array>${appArray}
            </array>
        </dict>`;
    }

    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>corp.localpilot.vpn.${profile.id}</string>
    <key>PayloadUUID</key>
    <string>${payloadUuid}</string>
    <key>PayloadDisplayName</key>
    <string>${profile.name}</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>corp.localpilot.vpn.payload.${profile.id}</string>
            <key>PayloadUUID</key>
            <string>${vpnUuid}</string>
            <key>UserDefinedName</key>
            <string>${profile.name}</string>
            <key>VPNType</key>
            <string>${profile.connection_type}</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>${profile.server_address}</string>
                <key>RemoteIdentifier</key>
                <string>${profile.remote_identifier}</string>
                <key>AuthenticationMethod</key>
                <string>${profile.auth_method === 'CERTIFICATE_EAP_TLS' ? 'Certificate' : 'SharedSecret'}</string>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>1</integer>
            </dict>
            <key>IPv4</key>
            <dict>
                <key>OverridePrimary</key>
                <${profile.split_tunneling ? 'false' : 'true'}/>
            </dict>
            <key>OnDemandEnabled</key>
            <integer>1</integer>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                    <key>DNSDomainMatch</key>
                    <array>
                        <string>localpilot.corp</string>
                        <string>internal.localpilot</string>
                    </array>
                </dict>
            </array>
        </dict>${appMappingXml}
    </array>
</dict>
</plist>`;

    return {
      filename: `${profile.name.replace(/\s+/g, '-')}-VPN.mobileconfig`,
      content_type: 'application/x-apple-aspen-config',
      plist_xml: plist
    };
  }

  /**
   * Generate Native Windows VPNv2 CSP XML Profile with Per-App Traffic Filters
   */
  static generateWindowsVpnXml(db, profileId) {
    const profile = this.getVpnProfile(db, profileId);
    if (!profile) return null;

    let trafficFilterXml = '';
    if (profile.is_per_app_vpn && profile.app_mappings && profile.app_mappings.length > 0) {
      const filters = profile.app_mappings.map(app => `
        <TrafficFilter>
            <AppId>${app.app_bundle_id}</AppId>
            <Direction>Outbound</Direction>
            <RoutingPolicyType>SplitTunnel</RoutingPolicyType>
        </TrafficFilter>`).join('');
      trafficFilterXml = `
    <TrafficFilters>${filters}
    </TrafficFilters>`;
    }

    const routeListXml = profile.split_tunnel_routes.map(r => `
        <Route>
            <Address>${r.split('/')[0]}</Address>
            <PrefixLength>${r.split('/')[1] || '24'}</PrefixLength>
        </Route>`).join('');

    const xml = `<?xml version="1.0" encoding="utf-8"?>
<VPNv2>
    <ProfileName>${profile.name}</ProfileName>
    <ServerAddress>${profile.server_address}</ServerAddress>
    <NativeProfile>
        <Servers>${profile.server_address}</Servers>
        <RoutingPolicyType>${profile.split_tunneling ? 'SplitTunnel' : 'ForceTunnel'}</RoutingPolicyType>
        <NativeProtocolType>${profile.connection_type}</NativeProtocolType>
        <Authentication>
            <UserMethod>${profile.auth_method === 'CERTIFICATE_EAP_TLS' ? 'Eap' : 'PresharedKey'}</UserMethod>
        </Authentication>
    </NativeProfile>
    <RouteList>${routeListXml}
    </RouteList>${trafficFilterXml}
</VPNv2>`;

    return {
      filename: `${profile.name.replace(/\s+/g, '-')}-VPNv2.xml`,
      content_type: 'application/xml; charset=utf-8',
      xml
    };
  }

  /**
   * Record VPN Connection Audit Event
   */
  static logVpnEvent(db, data = {}) {
    if (!db) throw new Error('Database handle required');
    if (!data.device_id) throw new Error('device_id is required');
    if (!data.event_type) throw new Error('event_type is required');

    const id = data.id || ('vpn-log-' + crypto.randomBytes(4).toString('hex'));
    const sessionId = data.session_id || ('sess-' + crypto.randomBytes(6).toString('hex'));

    const stmt = db.prepare(`
      INSERT INTO vpn_connection_audit_logs (
        id, device_id, vpn_profile_id, session_id, event_type,
        assigned_ip, bytes_in, bytes_out, duration_seconds, client_os, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.device_id,
      data.vpn_profile_id || null,
      sessionId,
      data.event_type,
      data.assigned_ip || '10.200.0.100',
      data.bytes_in || 0,
      data.bytes_out || 0,
      data.duration_seconds || 0,
      data.client_os || 'Unknown OS',
      typeof data.details === 'object' ? JSON.stringify(data.details) : (data.details_json || '{}')
    );

    return db.prepare('SELECT * FROM vpn_connection_audit_logs WHERE id = ?').get(id);
  }

  /**
   * Query VPN Audit Logs
   */
  static getVpnLogs(db, query = {}) {
    if (!db) return [];

    let sql = 'SELECT * FROM vpn_connection_audit_logs WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }

    if (query.event_type) {
      sql += ' AND event_type = ?';
      params.push(query.event_type);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(Number(query.limit) || 100);

    const rows = db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      details: JSON.parse(r.details_json || '{}')
    }));
  }

  /**
   * Get effective VPN configuration for specific device
   */
  static getEffectiveDeviceVpn(db, deviceId) {
    if (!db || !deviceId) return null;

    const profile = db.prepare('SELECT * FROM enterprise_vpn_profiles WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1').get();
    if (!profile) return null;

    return this._hydrateProfile(profile);
  }

  /**
   * Get device per-app VPN routing rules
   */
  static getDevicePerAppRules(db, deviceId) {
    if (!db || !deviceId) return [];

    const mappings = db.prepare(`
      SELECT m.*, p.name as vpn_name, p.server_address, p.connection_type
      FROM per_app_vpn_mappings m
      JOIN enterprise_vpn_profiles p ON m.vpn_profile_id = p.id
      WHERE m.is_active = 1 AND p.is_active = 1
      ORDER BY m.app_name ASC
    `).all();

    return mappings.map(m => ({
      ...m,
      is_active: Boolean(m.is_active)
    }));
  }

  /**
   * Internal helper to parse profile JSON fields
   */
  static _hydrateProfile(r) {
    return {
      ...r,
      split_tunneling: Boolean(r.split_tunneling),
      is_per_app_vpn: Boolean(r.is_per_app_vpn),
      is_active: Boolean(r.is_active),
      split_tunnel_routes: JSON.parse(r.split_tunnel_routes_json || '[]'),
      dns_servers: JSON.parse(r.dns_servers_json || '[]'),
      search_domains: JSON.parse(r.search_domains_json || '[]'),
      on_demand_rules: JSON.parse(r.on_demand_rules_json || '[]')
    };
  }
}
