/**
 * LocalPilot Fleet — Wi-Fi & VPN Configuration Profiles Blade
 * dashboard/js/components/networkTable.js
 */

(function () {
  'use strict';

  let currentTab = 'profiles'; // 'profiles' | 'inventory'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getTypeBadge(type) {
    if (type === 'WIFI') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;font-weight:600;">📶 Wi-Fi 802.1X</span>';
    }
    return '<span class="badge" style="background:rgba(168,85,247,0.15);color:#C084FC;font-weight:600;">🔐 VPN Tunnel</span>';
  }

  function getSecurityBadge(sec) {
    const map = {
      WPA3_ENTERPRISE: { bg: 'rgba(16,185,129,0.15)', text: '#10B981', label: '🛡️ WPA3 Enterprise' },
      WPA2_ENTERPRISE: { bg: 'rgba(16,185,129,0.12)', text: '#34D399', label: '🔒 WPA2 Enterprise' },
      WPA3_PERSONAL:   { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '🔑 WPA3 Personal' },
      WPA2_PERSONAL:   { bg: 'rgba(100,116,139,0.15)', text: '#94A3B8', label: 'WPA2 Personal' },
      WIREGUARD:       { bg: 'rgba(139,92,246,0.15)', text: '#A78BFA', label: '⚡ WireGuard' },
      IKEv2:           { bg: 'rgba(14,165,233,0.15)', text: '#38BDF8', label: '🏛️ IKEv2 / IPsec' },
      OPEN:            { bg: 'rgba(239,68,68,0.15)', text: '#EF4444', label: '⚠️ Open (Unencrypted)' }
    };
    const c = map[sec] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: sec };
    return `<span class="badge" style="background:${c.bg};color:${c.text};font-weight:600;">${c.label}</span>`;
  }

  function getSignalBadge(pct) {
    const val = parseInt(pct, 10) || 0;
    let color = '#10B981';
    let icon = '📶 Excellent';
    if (val < 50) {
      color = '#EF4444';
      icon = '📶 Weak';
    } else if (val < 75) {
      color = '#F59E0B';
      icon = '📶 Fair';
    }
    return `
      <div style="display:flex;align-items:center;gap:6px;">
        <div style="width:50px;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;">
          <div style="width:${val}%;height:100%;background:${color};border-radius:3px;"></div>
        </div>
        <span style="font-size:12px;font-weight:600;color:${color};">${val}% (${icon})</span>
      </div>
    `;
  }

  async function loadData() {
    const container = document.getElementById('view-network');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Wi-Fi &amp; VPN Network Profiles Posture…</span>
      </div>
    `;

    try {
      const [stats, profilesData, inventoryData] = await Promise.all([
        window.FleetAPI.getNetworkStats().catch(() => ({})),
        window.FleetAPI.getNetworkProfiles().catch(() => ({ profiles: [] })),
        window.FleetAPI.getNetworkInventory().catch(() => ({ inventory: [] }))
      ]);

      renderBlade(container, {
        stats,
        profiles: profilesData.profiles || [],
        inventory: inventoryData.inventory || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:var(--accent-red);">
          <h3>Error loading network profiles</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.NetworkTable.init()">Retry</button>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const { stats, profiles, inventory } = data;

    container.innerHTML = `
      <div style="padding:20px;max-width:1400px;margin:0 auto;">
        <!-- Header -->
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;">
          <div>
            <h2 style="margin:0 0 4px 0;display:flex;align-items:center;gap:10px;font-size:20px;">
              <span>🌐</span> Wi-Fi &amp; VPN Configuration Profiles
            </h2>
            <p style="margin:0;color:var(--text-muted);font-size:13px;">
              Microsoft Intune 802.1X, WPA3 Enterprise, WireGuard / IKEv2 Mesh &amp; Workstation Network Posture
            </p>
          </div>
          <div style="display:flex;gap:10px;">
            <button class="intune-btn" onclick="window.NetworkTable.refresh()" title="Refresh telemetry">
              🔄 Refresh
            </button>
            <button class="intune-btn intune-btn-primary" onclick="window.NetworkTable.showCreateModal()">
              + Create Network Profile
            </button>
          </div>
        </div>

        <!-- 4 KPI Cards -->
        <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px;">
          <div class="card" style="padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Active Profiles</div>
            <div style="font-size:24px;font-weight:700;color:var(--accent-primary);">
              ${stats.active_profiles || 0} <span style="font-size:14px;font-weight:normal;color:var(--text-muted);">/ ${stats.total_profiles || 0}</span>
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Governance profiles enforced</div>
          </div>

          <div class="card" style="padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Managed Wi-Fi</div>
            <div style="font-size:24px;font-weight:700;color:#38BDF8;">
              ${stats.wifi_profiles_count || 0}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">802.1X &amp; WPA3 Enterprise</div>
          </div>

          <div class="card" style="padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Secure VPN Tunnels</div>
            <div style="font-size:24px;font-weight:700;color:#C084FC;">
              ${stats.vpn_profiles_count || 0}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">WireGuard &amp; IKEv2 Gateways</div>
          </div>

          <div class="card" style="padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Audited Workstations</div>
            <div style="font-size:24px;font-weight:700;color:#10B981;">
              ${stats.total_audited_workstations || 0}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">
              ${stats.wifi_connected_count || 0} on Wi-Fi · ${stats.warnings_count || 0} warnings
            </div>
          </div>
        </div>

        <!-- Sub Tabs -->
        <div style="display:flex;gap:8px;border-bottom:1px solid var(--border-color);margin-bottom:20px;">
          <button id="net-subtab-profiles" class="intune-tab-btn ${currentTab === 'profiles' ? 'active' : ''}" onclick="window.NetworkTable.switchTab('profiles')" style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${currentTab === 'profiles' ? 'var(--accent-primary)' : 'transparent'};color:${currentTab === 'profiles' ? 'var(--accent-primary)' : 'var(--text-muted)'};font-weight:600;cursor:pointer;">
            🌐 Network Profiles (${profiles.length})
          </button>
          <button id="net-subtab-inventory" class="intune-tab-btn ${currentTab === 'inventory' ? 'active' : ''}" onclick="window.NetworkTable.switchTab('inventory')" style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${currentTab === 'inventory' ? 'var(--accent-primary)' : 'transparent'};color:${currentTab === 'inventory' ? 'var(--accent-primary)' : 'var(--text-muted)'};font-weight:600;cursor:pointer;">
            📡 Workstation Network Posture (${inventory.length})
          </button>
        </div>

        <!-- Tab Content -->
        <div id="net-tab-content">
          ${currentTab === 'profiles' ? renderProfilesTab(profiles) : renderInventoryTab(inventory)}
        </div>
      </div>
    `;
  }

  function renderProfilesTab(profiles) {
    if (!profiles || profiles.length === 0) {
      return `
        <div class="card" style="padding:32px;text-align:center;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">🌐</div>
          <p style="margin:0 0 12px 0;">No Network Configuration Profiles found.</p>
          <button class="intune-btn intune-btn-primary" onclick="window.NetworkTable.showCreateModal()">Create Your First Profile</button>
        </div>
      `;
    }

    return `
      <div class="card" style="overflow-x:auto;">
        <table class="data-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);text-align:left;color:var(--text-muted);">
              <th style="padding:12px 16px;">Profile Name</th>
              <th style="padding:12px 16px;">Type</th>
              <th style="padding:12px 16px;">Connection / SSID</th>
              <th style="padding:12px 16px;">Security &amp; Protocol</th>
              <th style="padding:12px 16px;">Target Scope</th>
              <th style="padding:12px 16px;">Assigned Nodes</th>
              <th style="padding:12px 16px;">Status</th>
              <th style="padding:12px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${profiles.map(p => `
              <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-normal);">${esc(p.name)}</div>
                  <div style="font-size:11px;color:var(--text-muted);">${esc(p.description || 'No description')}</div>
                </td>
                <td style="padding:12px 16px;">${getTypeBadge(p.network_type)}</td>
                <td style="padding:12px 16px;">
                  <span style="font-family:monospace;font-weight:600;">${esc(p.ssid || p.connection_name)}</span>
                  ${p.hidden_network ? '<span class="badge" style="background:rgba(255,255,255,0.1);font-size:10px;margin-left:4px;">Hidden</span>' : ''}
                </td>
                <td style="padding:12px 16px;">
                  ${getSecurityBadge(p.security_type)}
                  <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Auth: ${esc(p.eap_type)}</div>
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:rgba(255,255,255,0.08);color:var(--text-muted);">
                    ${esc(p.target_group_name || p.target_group_id)}
                  </span>
                </td>
                <td style="padding:12px 16px;font-weight:600;">
                  ${p.assigned_devices_count || 0} node(s)
                </td>
                <td style="padding:12px 16px;">
                  <label class="switch" style="position:relative;display:inline-block;width:34px;height:18px;">
                    <input type="checkbox" ${p.enabled ? 'checked' : ''} onchange="window.NetworkTable.toggleProfile('${p.id}', this.checked)" style="opacity:0;width:0;height:0;">
                    <span class="slider round" style="position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:${p.enabled ? 'var(--accent-primary)' : 'rgba(255,255,255,0.2)'};border-radius:18px;transition:.2s;"></span>
                  </label>
                </td>
                <td style="padding:12px 16px;text-align:right;">
                  <div style="display:flex;justify-content:flex-end;gap:6px;">
                    ${p.network_type === 'WIFI' ? `
                      <button class="intune-btn" style="padding:4px 8px;font-size:11px;" onclick="window.NetworkTable.showXmlModal('${p.id}')" title="View Windows WLAN XML">
                        📄 XML
                      </button>
                    ` : ''}
                    <button class="intune-btn" style="padding:4px 8px;font-size:11px;color:#EF4444;" onclick="window.NetworkTable.deleteProfile('${p.id}')" title="Delete profile">
                      🗑️
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderInventoryTab(inventory) {
    if (!inventory || inventory.length === 0) {
      return `
        <div class="card" style="padding:32px;text-align:center;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">📡</div>
          <p style="margin:0;">No workstation network posture reports received yet.</p>
          <p style="font-size:12px;margin-top:4px;">Agents report active Wi-Fi, signal quality, and adapter telemetry on every heartbeat loop.</p>
        </div>
      `;
    }

    return `
      <div class="card" style="overflow-x:auto;">
        <table class="data-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);text-align:left;color:var(--text-muted);">
              <th style="padding:12px 16px;">Device Hostname</th>
              <th style="padding:12px 16px;">Connected Wi-Fi</th>
              <th style="padding:12px 16px;">Signal Strength</th>
              <th style="padding:12px 16px;">Radio &amp; Channel</th>
              <th style="padding:12px 16px;">IP / Gateway</th>
              <th style="padding:12px 16px;">Active VPNs</th>
              <th style="padding:12px 16px;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${inventory.map(d => `
              <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-normal);">${esc(d.hostname)}</div>
                  <div style="font-size:11px;color:var(--text-muted);font-family:monospace;">${esc(d.device_id)}</div>
                </td>
                <td style="padding:12px 16px;">
                  ${d.connected_ssid ? `
                    <div style="font-weight:600;color:#60A5FA;">📶 ${esc(d.connected_ssid)}</div>
                    <div style="font-size:11px;color:var(--text-muted);font-family:monospace;">BSSID: ${esc(d.bssid || 'Unknown')}</div>
                  ` : `
                    <span style="color:var(--text-muted);">🔌 Wired / Ethernet</span>
                  `}
                </td>
                <td style="padding:12px 16px;">
                  ${d.connected_ssid ? getSignalBadge(d.signal_quality_pct) : '—'}
                </td>
                <td style="padding:12px 16px;">
                  ${d.radio_type ? `<span class="badge" style="background:rgba(255,255,255,0.08);">${esc(d.radio_type)}</span>` : '—'}
                  ${d.channel ? `<span style="font-size:11px;color:var(--text-muted);margin-left:4px;">Ch ${d.channel}</span>` : ''}
                </td>
                <td style="padding:12px 16px;">
                  <div style="font-family:monospace;font-size:12px;">${esc(d.ipv4_address || d.device_ip || '—')}</div>
                  <div style="font-size:11px;color:var(--text-muted);">GW: ${esc(d.ipv4_gateway || '—')}</div>
                </td>
                <td style="padding:12px 16px;">
                  ${d.active_vpns && d.active_vpns.length > 0 ? d.active_vpns.map(v => `
                    <span class="badge" style="background:rgba(168,85,247,0.15);color:#C084FC;font-weight:600;">🔐 ${esc(v)}</span>
                  `).join(' ') : '<span style="color:var(--text-muted);font-size:12px;">None</span>'}
                </td>
                <td style="padding:12px 16px;">
                  ${d.compliance_status === 'WARNING' ?
                    '<span class="badge" style="background:rgba(239,68,68,0.2);color:#EF4444;font-weight:600;">⚠️ Unencrypted Open Wi-Fi</span>' :
                    '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">✔ Compliant</span>'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function showCreateModal() {
    const modal = document.createElement('div');
    modal.id = 'net-create-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(3px);';

    modal.innerHTML = `
      <div class="card" style="width:600px;max-width:95vw;max-height:90vh;overflow-y:auto;padding:24px;border:1px solid var(--border-color);box-shadow:0 12px 36px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:18px;display:flex;align-items:center;gap:8px;">
            <span>🌐</span> Create Network Configuration Profile
          </h3>
          <button onclick="document.getElementById('net-create-modal').remove()" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;">&times;</button>
        </div>

        <!-- Presets -->
        <div style="margin-bottom:16px;padding:12px;background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--border-color);">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;font-weight:600;">QUICK ENTERPRISE PRESETS:</div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;">
            <button class="intune-btn" type="button" onclick="window.NetworkTable.applyPreset('WIFI_WPA3')" style="font-size:11px;">
              🏢 802.1X WPA3 Enterprise
            </button>
            <button class="intune-btn" type="button" onclick="window.NetworkTable.applyPreset('VPN_WIREGUARD')" style="font-size:11px;">
              ⚡ WireGuard Mesh VPN
            </button>
            <button class="intune-btn" type="button" onclick="window.NetworkTable.applyPreset('VPN_IKEV2')" style="font-size:11px;">
              🏛️ IKEv2 / IPsec Tunnel
            </button>
          </div>
        </div>

        <form id="net-create-form" onsubmit="window.NetworkTable.submitCreate(event)">
          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Profile Name *</label>
            <input type="text" id="net-form-name" class="intune-input" required style="width:100%;box-sizing:border-box;" placeholder="e.g. Corporate Secure 802.1X Wi-Fi">
          </div>

          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>
            <textarea id="net-form-desc" class="intune-input" rows="2" style="width:100%;box-sizing:border-box;" placeholder="Enforces mutual TLS client certificate auth for high-assurance access."></textarea>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Network Type *</label>
              <select id="net-form-type" class="intune-input" style="width:100%;box-sizing:border-box;" onchange="window.NetworkTable.onTypeChange(this.value)">
                <option value="WIFI">Wi-Fi Wireless Network</option>
                <option value="VPN">Virtual Private Network (VPN)</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Connection / SSID Name *</label>
              <input type="text" id="net-form-conn-name" class="intune-input" required style="width:100%;box-sizing:border-box;" placeholder="e.g. CorpNet-Secure">
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Security Type</label>
              <select id="net-form-sec-type" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="WPA3_ENTERPRISE">WPA3 Enterprise (802.1X)</option>
                <option value="WPA2_ENTERPRISE">WPA2 Enterprise (802.1X)</option>
                <option value="WPA3_PERSONAL">WPA3 Personal (SAE)</option>
                <option value="WPA2_PERSONAL">WPA2 Personal (Pre-shared key)</option>
                <option value="WIREGUARD">WireGuard Mesh Protocol</option>
                <option value="IKEv2">IKEv2 / IPsec</option>
                <option value="L2TP">L2TP / IPsec</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">EAP / Auth Protocol</label>
              <select id="net-form-eap-type" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="EAP_TLS">EAP-TLS (Smart Card or Certificate)</option>
                <option value="PEAP">PEAP (EAP-MSCHAPv2)</option>
                <option value="CERTIFICATE">Machine / User Certificate</option>
                <option value="PSK">Pre-Shared Key</option>
                <option value="NONE">None</option>
              </select>
            </div>
          </div>

          <div id="net-vpn-fields" style="display:none;margin-bottom:12px;padding:12px;background:rgba(168,85,247,0.05);border-radius:6px;border:1px solid rgba(168,85,247,0.2);">
            <div style="margin-bottom:8px;">
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">VPN Server Hostname / Port</label>
              <input type="text" id="net-form-server-addr" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="vpn.corp.localpilot.io:51820">
            </div>
            <div style="display:flex;gap:16px;">
              <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;">
                <input type="checkbox" id="net-form-split-tunnel" checked>
                Split Tunneling (Exclude local subnet traffic)
              </label>
              <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;">
                <input type="checkbox" id="net-form-always-on">
                Always-On VPN Trigger
              </label>
            </div>
          </div>

          <div style="margin-bottom:16px;display:flex;gap:16px;">
            <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;">
              <input type="checkbox" id="net-form-auto-connect" checked>
              Connect automatically when in range
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;">
              <input type="checkbox" id="net-form-hidden-network">
              Connect even if network is not broadcasting (Hidden SSID)
            </label>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button type="button" class="intune-btn" onclick="document.getElementById('net-create-modal').remove()">Cancel</button>
            <button type="submit" class="intune-btn intune-btn-primary">Create Profile</button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);
  }

  function applyPreset(preset) {
    const nameEl = document.getElementById('net-form-name');
    const descEl = document.getElementById('net-form-desc');
    const typeEl = document.getElementById('net-form-type');
    const connEl = document.getElementById('net-form-conn-name');
    const secEl = document.getElementById('net-form-sec-type');
    const eapEl = document.getElementById('net-form-eap-type');
    const srvEl = document.getElementById('net-form-server-addr');
    const vpnDiv = document.getElementById('net-vpn-fields');

    if (preset === 'WIFI_WPA3') {
      typeEl.value = 'WIFI';
      nameEl.value = 'Corporate Zero-Trust 802.1X Wi-Fi';
      descEl.value = 'High-assurance WPA3 Enterprise Wi-Fi with 802.1X EAP-TLS client certificate authentication and auto-connect.';
      connEl.value = 'CorpNet-Secure';
      secEl.value = 'WPA3_ENTERPRISE';
      eapEl.value = 'EAP_TLS';
      vpnDiv.style.display = 'none';
    } else if (preset === 'VPN_WIREGUARD') {
      typeEl.value = 'VPN';
      nameEl.value = 'Always-On Zero-Trust Mesh VPN';
      descEl.value = 'Ultra low-latency WireGuard mesh tunnel for seamless homelab and corporate resource access with split tunneling.';
      connEl.value = 'LocalPilot-Mesh';
      secEl.value = 'WIREGUARD';
      eapEl.value = 'CERTIFICATE';
      srvEl.value = 'vpn.corp.localpilot.io:51820';
      vpnDiv.style.display = 'block';
    } else if (preset === 'VPN_IKEV2') {
      typeEl.value = 'VPN';
      nameEl.value = 'Enterprise IKEv2 / IPsec Remote Access';
      descEl.value = 'Standard Microsoft Windows native IKEv2 VPN tunnel for remote branch connectivity and domain controller access.';
      connEl.value = 'Corp-IKEv2-Remote';
      secEl.value = 'IKEv2';
      eapEl.value = 'EAP_TLS';
      srvEl.value = 'gateway.corp.localpilot.io';
      vpnDiv.style.display = 'block';
    }
  }

  function onTypeChange(type) {
    const vpnDiv = document.getElementById('net-vpn-fields');
    if (type === 'VPN') {
      vpnDiv.style.display = 'block';
    } else {
      vpnDiv.style.display = 'none';
    }
  }

  async function submitCreate(e) {
    e.preventDefault();
    const type = document.getElementById('net-form-type').value;
    const data = {
      name: document.getElementById('net-form-name').value.trim(),
      description: document.getElementById('net-form-desc').value.trim(),
      network_type: type,
      connection_name: document.getElementById('net-form-conn-name').value.trim(),
      ssid: document.getElementById('net-form-conn-name').value.trim(),
      security_type: document.getElementById('net-form-sec-type').value,
      eap_type: document.getElementById('net-form-eap-type').value,
      server_address: document.getElementById('net-form-server-addr') ? document.getElementById('net-form-server-addr').value.trim() : '',
      split_tunneling: document.getElementById('net-form-split-tunnel') ? document.getElementById('net-form-split-tunnel').checked : true,
      always_on: document.getElementById('net-form-always-on') ? document.getElementById('net-form-always-on').checked : false,
      auto_connect: document.getElementById('net-form-auto-connect').checked,
      hidden_network: document.getElementById('net-form-hidden-network').checked,
      target_group_id: 'grp-all'
    };

    try {
      await window.FleetAPI.createNetworkProfile(data);
      const modal = document.getElementById('net-create-modal');
      if (modal) modal.remove();
      loadData();
    } catch (err) {
      alert('Failed to create network profile: ' + err.message);
    }
  }

  async function toggleProfile(id, enabled) {
    try {
      await window.FleetAPI.updateNetworkProfile(id, { enabled });
    } catch (err) {
      alert('Failed to update profile: ' + err.message);
      loadData();
    }
  }

  async function deleteProfile(id) {
    if (!confirm('Are you sure you want to delete this network profile? Connected endpoints will lose automatic provisioning.')) return;
    try {
      await window.FleetAPI.deleteNetworkProfile(id);
      loadData();
    } catch (err) {
      alert('Failed to delete profile: ' + err.message);
    }
  }

  async function showXmlModal(id) {
    try {
      const profile = await window.FleetAPI.getNetworkProfile(id);
      if (!profile || !profile.wlan_xml_preview) {
        alert('No XML profile available for this profile type.');
        return;
      }

      const modal = document.createElement('div');
      modal.id = 'net-xml-modal';
      modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(3px);';

      modal.innerHTML = `
        <div class="card" style="width:650px;max-width:95vw;max-height:85vh;overflow-y:auto;padding:24px;border:1px solid var(--border-color);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h3 style="margin:0;font-size:16px;">📄 Windows WLAN Profile XML: ${esc(profile.name)}</h3>
            <button onclick="document.getElementById('net-xml-modal').remove()" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;">&times;</button>
          </div>
          <p style="font-size:12px;color:var(--text-muted);margin:0 0 12px 0;">
            Native Windows XML definition compatible with <code>netsh wlan add profile filename="profile.xml"</code>:
          </p>
          <pre style="background:#0F172A;color:#E2E8F0;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;max-height:350px;">${esc(profile.wlan_xml_preview)}</pre>
          <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;">
            <button class="intune-btn" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(profile.wlan_xml_preview)}'));alert('XML copied to clipboard!');">📋 Copy XML</button>
            <button class="intune-btn" onclick="document.getElementById('net-xml-modal').remove()">Close</button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);
    } catch (err) {
      alert('Failed to fetch profile XML: ' + err.message);
    }
  }

  function switchTab(tab) {
    currentTab = tab;
    loadData();
  }

  window.NetworkTable = {
    init: loadData,
    refresh: loadData,
    switchTab,
    showCreateModal,
    applyPreset,
    onTypeChange,
    submitCreate,
    toggleProfile,
    deleteProfile,
    showXmlModal
  };
})();
