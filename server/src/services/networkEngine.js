import { broadcastEvent } from '../routes/events.js';

/**
 * Enterprise Network & Connectivity Configuration Engine
 * Microsoft Intune Wi-Fi & VPN Profile Governance
 */

/**
 * Generate native Windows WLAN Profile XML
 * Compatible with `netsh wlan add profile filename=...`
 */
export function generateWlanXml(profile) {
  const ssid = profile.ssid || profile.connection_name || 'CorpNet-Secure';
  const name = profile.name || ssid;
  const auth = profile.security_type === 'WPA3_ENTERPRISE' ? 'WPA3' :
               profile.security_type === 'WPA2_ENTERPRISE' ? 'WPA2' :
               profile.security_type === 'WPA3_PERSONAL' ? 'WPA3SAE' :
               profile.security_type === 'WPA2_PERSONAL' ? 'WPA2PSK' : 'open';
  const encryption = auth === 'open' ? 'none' : 'AES';
  const autoConnect = profile.auto_connect !== 0 ? 'auto' : 'manual';

  return `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>${name}</name>
    <SSIDConfig>
        <SSID>
            <name>${ssid}</name>
        </SSID>
        <nonBroadcast>${profile.hidden_network ? 'true' : 'false'}</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>${autoConnect}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>${auth}</authentication>
                <encryption>${encryption}</encryption>
                <useOneX>${profile.network_type === 'WIFI' && profile.security_type.includes('ENTERPRISE') ? 'true' : 'false'}</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>`.trim();
}

/**
 * Get all Network Profiles with assigned device counts
 */
export function getAllProfiles(db) {
  const profiles = db.prepare(`
    SELECT np.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM network_profiles np
    LEFT JOIN dynamic_groups dg ON np.target_group_id = dg.id
    ORDER BY np.network_type ASC, np.name ASC
  `).all();

  const totalDevicesCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status != 'DECOMMISSIONED'").get().count;

  return profiles.map(p => {
    let assignedCount = 0;
    if (p.target_group_id === 'grp-all' || p.target_group_id === 'all-devices') {
      assignedCount = totalDevicesCount;
    } else {
      const row = db.prepare(`
        SELECT COUNT(DISTINCT device_id) as count
        FROM group_memberships
        WHERE group_id = ?
      `).get(p.target_group_id);
      assignedCount = row ? row.count : 0;
    }

    return {
      ...p,
      enabled: Boolean(p.enabled),
      hidden_network: Boolean(p.hidden_network),
      split_tunneling: Boolean(p.split_tunneling),
      always_on: Boolean(p.always_on),
      auto_connect: Boolean(p.auto_connect),
      assigned_devices_count: assignedCount
    };
  });
}

/**
 * Get single Network Profile by ID
 */
export function getProfileById(db, id) {
  const profile = db.prepare(`
    SELECT np.*,
           dg.name as target_group_name,
           dg.color as target_group_color
    FROM network_profiles np
    LEFT JOIN dynamic_groups dg ON np.target_group_id = dg.id
    WHERE np.id = ?
  `).get(id);

  if (!profile) return null;

  // Resolve assigned devices
  let assignedDevices = [];
  if (profile.target_group_id === 'grp-all' || profile.target_group_id === 'all-devices') {
    assignedDevices = db.prepare(`
      SELECT id, hostname, ip_address, status, last_seen_at
      FROM devices
      WHERE status != 'DECOMMISSIONED'
      ORDER BY hostname ASC
    `).all();
  } else {
    assignedDevices = db.prepare(`
      SELECT d.id, d.hostname, d.ip_address, d.status, d.last_seen_at
      FROM group_memberships gm
      JOIN devices d ON gm.device_id = d.id
      WHERE gm.group_id = ? AND d.status != 'DECOMMISSIONED'
      ORDER BY d.hostname ASC
    `).all(profile.target_group_id);
  }

  return {
    ...profile,
    enabled: Boolean(profile.enabled),
    hidden_network: Boolean(profile.hidden_network),
    split_tunneling: Boolean(profile.split_tunneling),
    always_on: Boolean(profile.always_on),
    auto_connect: Boolean(profile.auto_connect),
    assigned_devices: assignedDevices,
    assigned_devices_count: assignedDevices.length,
    wlan_xml_preview: profile.network_type === 'WIFI' ? generateWlanXml(profile) : null
  };
}

/**
 * Create a new Network Profile
 */
export function createProfile(db, data) {
  if (!data.name || !data.name.trim()) {
    throw new Error('Profile name is required');
  }
  if (!data.network_type || !['WIFI', 'VPN'].includes(data.network_type.toUpperCase())) {
    throw new Error('Valid network_type (WIFI or VPN) is required');
  }
  if (!data.connection_name || !data.connection_name.trim()) {
    throw new Error('Connection name (or SSID) is required');
  }

  const id = data.id || `net-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const netType = data.network_type.toUpperCase();
  const connName = data.connection_name.trim();
  const ssid = data.ssid ? data.ssid.trim() : (netType === 'WIFI' ? connName : '');
  const secType = data.security_type || (netType === 'WIFI' ? 'WPA2_ENTERPRISE' : 'WIREGUARD');
  const eapType = data.eap_type || (netType === 'WIFI' ? 'EAP_TLS' : 'CERTIFICATE');
  const targetGroup = data.target_group_id || 'grp-all';
  const serverAddr = data.server_address || '';
  const splitTunnel = data.split_tunneling !== false ? 1 : 0;
  const alwaysOn = data.always_on ? 1 : 0;
  const autoConnect = data.auto_connect !== false ? 1 : 0;
  const hidden = data.hidden_network ? 1 : 0;
  const proxyType = data.proxy_type || 'NONE';
  const proxyServer = data.proxy_server || '';
  const proxyPort = data.proxy_port ? parseInt(data.proxy_port, 10) : 8080;
  const rootThumb = data.root_cert_thumbprint || '';
  const clientThumb = data.client_cert_thumbprint || '';
  const rawXml = data.raw_profile_xml || '';
  const enabled = data.enabled !== false ? 1 : 0;

  db.prepare(`
    INSERT INTO network_profiles (
      id, name, description, network_type, target_group_id,
      connection_name, ssid, hidden_network, security_type, eap_type,
      server_address, split_tunneling, always_on, auto_connect,
      proxy_type, proxy_server, proxy_port, root_cert_thumbprint,
      client_cert_thumbprint, raw_profile_xml, enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, DATETIME('now'), DATETIME('now')
    )
  `).run(
    id, data.name.trim(), data.description || '', netType, targetGroup,
    connName, ssid, hidden, secType, eapType,
    serverAddr, splitTunnel, alwaysOn, autoConnect,
    proxyType, proxyServer, proxyPort, rootThumb,
    clientThumb, rawXml, enabled
  );

  broadcastEvent('NETWORK_PROFILE_CREATED', { id, name: data.name.trim(), network_type: netType });

  return getProfileById(db, id);
}

/**
 * Update an existing Network Profile
 */
export function updateProfile(db, id, data) {
  const existing = getProfileById(db, id);
  if (!existing) return null;

  const updates = [];
  const params = [];

  const allowedFields = [
    'name', 'description', 'network_type', 'target_group_id', 'connection_name',
    'ssid', 'hidden_network', 'security_type', 'eap_type', 'server_address',
    'split_tunneling', 'always_on', 'auto_connect', 'proxy_type', 'proxy_server',
    'proxy_port', 'root_cert_thumbprint', 'client_cert_thumbprint', 'raw_profile_xml', 'enabled'
  ];

  for (const field of allowedFields) {
    if (data[field] !== undefined) {
      updates.push(`${field} = ?`);
      let val = data[field];
      if (['hidden_network', 'split_tunneling', 'always_on', 'auto_connect', 'enabled'].includes(field)) {
        val = val ? 1 : 0;
      }
      params.push(val);
    }
  }

  if (updates.length > 0) {
    updates.push("updated_at = DATETIME('now')");
    params.push(id);
    db.prepare(`UPDATE network_profiles SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    broadcastEvent('NETWORK_PROFILE_UPDATED', { id, name: data.name || existing.name });
  }

  return getProfileById(db, id);
}

/**
 * Delete a Network Profile
 */
export function deleteProfile(db, id) {
  const existing = getProfileById(db, id);
  if (!existing) return false;

  db.prepare('DELETE FROM network_profiles WHERE id = ?').run(id);
  broadcastEvent('NETWORK_PROFILE_DELETED', { id, name: existing.name });
  return true;
}

/**
 * Resolve effective network profiles for a specific device
 */
export function getEffectiveProfilesForDevice(db, deviceId) {
  const groups = db.prepare(`
    SELECT group_id FROM group_memberships WHERE device_id = ?
  `).all(deviceId).map(r => r.group_id);

  groups.push('grp-all', 'all-devices');

  const placeholders = groups.map(() => '?').join(',');
  const profiles = db.prepare(`
    SELECT *
    FROM network_profiles
    WHERE enabled = 1 AND target_group_id IN (${placeholders})
    ORDER BY network_type ASC, name ASC
  `).all(...groups);

  return profiles.map(p => ({
    id: p.id,
    name: p.name,
    network_type: p.network_type,
    connection_name: p.connection_name,
    ssid: p.ssid,
    hidden_network: Boolean(p.hidden_network),
    security_type: p.security_type,
    eap_type: p.eap_type,
    server_address: p.server_address,
    split_tunneling: Boolean(p.split_tunneling),
    always_on: Boolean(p.always_on),
    auto_connect: Boolean(p.auto_connect),
    proxy_type: p.proxy_type,
    proxy_server: p.proxy_server,
    proxy_port: p.proxy_port,
    root_cert_thumbprint: p.root_cert_thumbprint,
    client_cert_thumbprint: p.client_cert_thumbprint,
    wlan_xml: p.network_type === 'WIFI' ? generateWlanXml(p) : null
  }));
}

/**
 * Ingest Workstation Network Posture from agent
 */
export function saveDeviceNetworkPosture(db, deviceId, data) {
  const id = `netposture-${deviceId}`;
  const connectedSsid = data.connected_ssid || '';
  const bssid = data.bssid || '';
  const signalPct = data.signal_quality_pct ? parseInt(data.signal_quality_pct, 10) : 0;
  const radioType = data.radio_type || '';
  const channel = data.channel ? parseInt(data.channel, 10) : 0;
  const activeAdapters = JSON.stringify(data.active_adapters || []);
  const configuredProfiles = JSON.stringify(data.configured_profiles || []);
  const activeVpns = JSON.stringify(data.active_vpns || []);
  const ipv4Addr = data.ipv4_address || '';
  const ipv4Gw = data.ipv4_gateway || '';
  const dnsServers = JSON.stringify(data.dns_servers || []);

  // Determine compliance / security status
  let compliance = 'COMPLIANT';
  if (connectedSsid && (data.security_type === 'OPEN' || data.is_open_network)) {
    compliance = 'WARNING'; // Connecting to unencrypted open Wi-Fi
  }

  const existing = db.prepare('SELECT id FROM device_network_posture WHERE device_id = ?').get(deviceId);

  if (existing) {
    db.prepare(`
      UPDATE device_network_posture SET
        connected_ssid = ?,
        bssid = ?,
        signal_quality_pct = ?,
        radio_type = ?,
        channel = ?,
        active_adapters_json = ?,
        configured_profiles_json = ?,
        active_vpns_json = ?,
        ipv4_address = ?,
        ipv4_gateway = ?,
        dns_servers_json = ?,
        compliance_status = ?,
        last_scanned_at = DATETIME('now'),
        updated_at = DATETIME('now')
      WHERE device_id = ?
    `).run(
      connectedSsid, bssid, signalPct, radioType, channel,
      activeAdapters, configuredProfiles, activeVpns,
      ipv4Addr, ipv4Gw, dnsServers, compliance, deviceId
    );
  } else {
    db.prepare(`
      INSERT INTO device_network_posture (
        id, device_id, connected_ssid, bssid, signal_quality_pct, radio_type, channel,
        active_adapters_json, configured_profiles_json, active_vpns_json,
        ipv4_address, ipv4_gateway, dns_servers_json, compliance_status,
        last_scanned_at, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        DATETIME('now'), DATETIME('now'), DATETIME('now')
      )
    `).run(
      id, deviceId, connectedSsid, bssid, signalPct, radioType, channel,
      activeAdapters, configuredProfiles, activeVpns,
      ipv4Addr, ipv4Gw, dnsServers, compliance
    );
  }

  broadcastEvent('NETWORK_POSTURE_UPDATED', { device_id: deviceId, connected_ssid: connectedSsid, compliance });
  return getDeviceNetworkPosture(db, deviceId);
}

/**
 * Get device network posture
 */
export function getDeviceNetworkPosture(db, deviceId) {
  const row = db.prepare(`
    SELECT dnp.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status
    FROM device_network_posture dnp
    JOIN devices d ON dnp.device_id = d.id
    WHERE dnp.device_id = ?
  `).get(deviceId);

  if (!row) return null;

  return {
    ...row,
    active_adapters: JSON.parse(row.active_adapters_json || '[]'),
    configured_profiles: JSON.parse(row.configured_profiles_json || '[]'),
    active_vpns: JSON.parse(row.active_vpns_json || '[]'),
    dns_servers: JSON.parse(row.dns_servers_json || '[]')
  };
}

/**
 * Get Fleet Network Inventory
 */
export function getFleetNetworkInventory(db, filters = {}) {
  let query = `
    SELECT dnp.*,
           d.hostname,
           d.ip_address as device_ip,
           d.status as device_status
    FROM device_network_posture dnp
    JOIN devices d ON dnp.device_id = d.id
    WHERE 1=1
  `;
  const params = [];

  if (filters.ssid) {
    query += ' AND dnp.connected_ssid LIKE ?';
    params.push(`%${filters.ssid}%`);
  }
  if (filters.compliance) {
    query += ' AND dnp.compliance_status = ?';
    params.push(filters.compliance.toUpperCase());
  }
  if (filters.q) {
    query += ' AND (d.hostname LIKE ? OR dnp.connected_ssid LIKE ? OR dnp.ipv4_address LIKE ?)';
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
  }

  query += ' ORDER BY d.hostname ASC';

  const rows = db.prepare(query).all(...params);
  return rows.map(r => ({
    ...r,
    active_adapters: JSON.parse(r.active_adapters_json || '[]'),
    configured_profiles: JSON.parse(r.configured_profiles_json || '[]'),
    active_vpns: JSON.parse(r.active_vpns_json || '[]'),
    dns_servers: JSON.parse(r.dns_servers_json || '[]')
  }));
}

/**
 * Get Fleet Network KPI Statistics
 */
export function getNetworkStats(db) {
  const totalProfiles = db.prepare('SELECT COUNT(*) as count FROM network_profiles').get().count;
  const activeProfiles = db.prepare('SELECT COUNT(*) as count FROM network_profiles WHERE enabled = 1').get().count;
  const wifiProfiles = db.prepare("SELECT COUNT(*) as count FROM network_profiles WHERE network_type = 'WIFI'").get().count;
  const vpnProfiles = db.prepare("SELECT COUNT(*) as count FROM network_profiles WHERE network_type = 'VPN'").get().count;

  const totalAuditedWorkstations = db.prepare('SELECT COUNT(*) as count FROM device_network_posture').get().count;
  const wifiConnectedCount = db.prepare("SELECT COUNT(*) as count FROM device_network_posture WHERE connected_ssid != ''").get().count;
  const warningsCount = db.prepare("SELECT COUNT(*) as count FROM device_network_posture WHERE compliance_status = 'WARNING'").get().count;

  // Active SSIDs summary
  const activeSsids = db.prepare(`
    SELECT connected_ssid as ssid, COUNT(*) as device_count
    FROM device_network_posture
    WHERE connected_ssid != ''
    GROUP BY connected_ssid
    ORDER BY device_count DESC
    LIMIT 5
  `).all();

  return {
    total_profiles: totalProfiles,
    active_profiles: activeProfiles,
    wifi_profiles_count: wifiProfiles,
    vpn_profiles_count: vpnProfiles,
    total_audited_workstations: totalAuditedWorkstations,
    wifi_connected_count: wifiConnectedCount,
    warnings_count: warningsCount,
    active_ssids: activeSsids
  };
}
