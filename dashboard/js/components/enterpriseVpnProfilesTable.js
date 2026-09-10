/**
 * LocalPilot Fleet — Enterprise VPN & Per-App Tunnels Blade (Iteration 68)
 * dashboard/js/components/enterpriseVpnProfilesTable.js
 *
 * Implements enterprise micro-tunneling, zero-trust per-app socket isolation,
 * split-tunnel CIDR policy routing, dynamic on-demand rules, and payload
 * generation for Apple .mobileconfig, Windows VPNv2 CSP XML, and Android VpnService.
 */

window.EnterpriseVpnProfilesTable = {
  activeTab: 'profiles',

  getHeaders: function() {
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': localStorage.getItem('fleet_key') || '8161bd42-02a7-47b0-b7eb-efbf5fdda1ed'
    };
  },

  render: function() {
    const container = document.getElementById('main-content') || document.getElementById('content-area');
    if (!container) return;
    container.innerHTML = this.getTemplate();

    this.loadStats();
    this.loadProfiles();
    this.loadMappings();
    this.loadLogs();
    this.setupListeners();
  },

  getTemplate: function() {
    return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-blue-500/20 text-blue-400 rounded-lg text-2xl border border-blue-500/30">🌐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Enterprise VPN &amp; Per-App Tunnels
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">Zero-Trust Micro-Tunneling</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated IKEv2 / WireGuard profiles, per-app socket isolation, split-tunnel CIDR routing, and on-demand rules</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-vpn-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-vpn-new-profile" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>➕</span> New VPN Profile
          </button>
          <button id="btn-vpn-map-app" class="px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-purple-500/20">
            <span>📱</span> Map Per-App App
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" id="vpn-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">VPN Profiles</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-vpn-total-profiles">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-vpn-active-profiles">- Active</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Per-App Tunnels</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🔒</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-vpn-perapp-profiles">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-vpn-mapped-apps">- Mapped Apps</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Tunnels</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-vpn-active-tunnels">-</p>
          <p class="text-xs text-slate-500 mt-1">Live Connected</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Encrypted Traffic</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📊</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-vpn-traffic">-</p>
          <p class="text-xs text-slate-500 mt-1">Bytes Transferred</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Zero-Trust Egress</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🏰</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2">Split-Tunnel</p>
          <p class="text-xs text-slate-500 mt-1">Enterprise CIDR Only</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="border-b border-slate-700">
        <nav class="flex space-x-6">
          <button id="tab-btn-vpn-profiles" class="pb-3 text-sm font-medium text-blue-400 border-b-2 border-blue-400 flex items-center gap-2">
            <span>🛡️</span> VPN Profiles (<span id="count-vpn-profiles">0</span>)
          </button>
          <button id="tab-btn-vpn-mappings" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
            <span>📱</span> Per-App Mappings (<span id="count-vpn-mappings">0</span>)
          </button>
          <button id="tab-btn-vpn-logs" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
            <span>📜</span> Tunnel Audit Logs (<span id="count-vpn-logs">0</span>)
          </button>
        </nav>
      </div>

      <!-- Tab Content 1: VPN Profiles -->
      <div id="tab-content-vpn-profiles" class="space-y-4">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>🛡️</span> Enterprise VPN Profile Catalog
            </h3>
            <div class="flex items-center gap-2">
              <select id="vpn-filter-platform" class="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none">
                <option value="">All Platforms</option>
                <option value="COMBINED">Combined (All)</option>
                <option value="MACOS">macOS</option>
                <option value="IOS">iOS</option>
                <option value="ANDROID">Android</option>
                <option value="WINDOWS">Windows</option>
              </select>
            </div>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Profile Name &amp; Gateway</th>
                  <th class="px-4 py-3">Type &amp; Platform</th>
                  <th class="px-4 py-3">Auth &amp; SCEP Binding</th>
                  <th class="px-4 py-3">Routing Mode</th>
                  <th class="px-4 py-3">Per-App Status</th>
                  <th class="px-4 py-3 text-right">Payload Downloads</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="vpn-profiles-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading VPN profiles...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 2: Per-App Mappings -->
      <div id="tab-content-vpn-mappings" class="space-y-4 hidden">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>📱</span> Micro-Tunneling Per-App Application Bindings
            </h3>
            <span class="text-xs text-slate-400">Only mapped applications route traffic through corporate tunnels</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Application Name</th>
                  <th class="px-4 py-3">Bundle / Package ID</th>
                  <th class="px-4 py-3">Assigned VPN Profile</th>
                  <th class="px-4 py-3">Target Platform</th>
                  <th class="px-4 py-3">Designated Requirement</th>
                  <th class="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody id="vpn-mappings-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading per-app mappings...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 3: Tunnel Audit Logs -->
      <div id="tab-content-vpn-logs" class="space-y-4 hidden">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>📜</span> VPN Session Telemetry &amp; Audit Logs
            </h3>
            <span class="text-xs text-slate-400">Live connection lifecycle and bandwidth tracking</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Session &amp; Device</th>
                  <th class="px-4 py-3">Event Type</th>
                  <th class="px-4 py-3">Assigned IP</th>
                  <th class="px-4 py-3">Bytes In / Out</th>
                  <th class="px-4 py-3">Duration</th>
                  <th class="px-4 py-3">Client OS</th>
                  <th class="px-4 py-3">Timestamp</th>
                </tr>
              </thead>
              <tbody id="vpn-logs-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading audit logs...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal: New VPN Profile -->
      <div id="modal-vpn-new-profile" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🛡️</span> Create Enterprise VPN Profile
            </h3>
            <button id="btn-close-new-vpn-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <form id="form-vpn-new-profile" class="space-y-3 text-sm">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Profile Name *</label>
              <input type="text" id="new-vpn-name" required placeholder="e.g. Corporate Zero-Trust Gateway" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Gateway Address / Hostname *</label>
              <input type="text" id="new-vpn-server" required placeholder="e.g. vpn.localpilot.corp" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200 font-mono" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Protocol Type</label>
                <select id="new-vpn-type" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                  <option value="IKEV2">IKEv2 / IPsec</option>
                  <option value="WIREGUARD">WireGuard</option>
                  <option value="OPENVPN">OpenVPN</option>
                  <option value="L2TP_IPSEC">L2TP / IPsec</option>
                </select>
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Target Platform</label>
                <select id="new-vpn-platform" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                  <option value="COMBINED">Combined (All)</option>
                  <option value="MACOS">macOS</option>
                  <option value="IOS">iOS / iPadOS</option>
                  <option value="ANDROID">Android Enterprise</option>
                  <option value="WINDOWS">Windows 10/11</option>
                </select>
              </div>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Authentication Method</label>
              <select id="new-vpn-auth" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                <option value="CERTIFICATE_EAP_TLS">Certificate EAP-TLS (SCEP PKI)</option>
                <option value="MACHINE_CERTIFICATE">Machine Certificate</option>
                <option value="PRE_SHARED_KEY">Pre-Shared Key (PSK)</option>
                <option value="USER_CREDENTIALS">Username &amp; Password</option>
              </select>
            </div>
            <div class="flex items-center gap-6 pt-2">
              <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                <input type="checkbox" id="new-vpn-splittunnel" checked class="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0" />
                <span class="text-xs font-semibold">Split-Tunneling (Enterprise CIDRs Only)</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                <input type="checkbox" id="new-vpn-isperapp" class="rounded bg-slate-900 border-slate-700 text-purple-600 focus:ring-0" />
                <span class="text-xs font-semibold text-purple-300">Per-App VPN Isolation</span>
              </label>
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
              <button type="button" id="btn-cancel-new-vpn" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg text-sm shadow-lg hover:shadow-blue-500/20">Create Profile</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Modal: Map Per-App Application -->
      <div id="modal-vpn-map-app" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>📱</span> Map Application to Per-App VPN
            </h3>
            <button id="btn-close-map-app-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <form id="form-vpn-map-app" class="space-y-3 text-sm">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Select VPN Profile *</label>
              <select id="map-app-profile-select" required class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                <option value="">Loading profiles...</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Application Name *</label>
              <input type="text" id="map-app-name" required placeholder="e.g. Corporate Slack" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Bundle ID / Package Name *</label>
              <input type="text" id="map-app-bundle" required placeholder="e.g. com.tinyspeck.slackmacgap" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200 font-mono" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Platform</label>
              <select id="map-app-platform" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                <option value="COMBINED">Combined (All)</option>
                <option value="MACOS">macOS</option>
                <option value="IOS">iOS</option>
                <option value="ANDROID">Android</option>
                <option value="WINDOWS">Windows</option>
              </select>
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
              <button type="button" id="btn-cancel-map-app" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg text-sm shadow-lg hover:shadow-purple-500/20">Bind App</button>
            </div>
          </form>
        </div>
      </div>
    </div>
    `;
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/vpn/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-vpn-total-profiles').textContent = stats.total_profiles ?? 0;
      document.getElementById('kpi-vpn-active-profiles').textContent = (stats.active_profiles ?? 0) + ' Active';
      document.getElementById('kpi-vpn-perapp-profiles').textContent = stats.per_app_vpn_profiles ?? 0;
      document.getElementById('kpi-vpn-mapped-apps').textContent = (stats.active_app_mappings ?? 0) + ' Mapped Apps';
      document.getElementById('kpi-vpn-active-tunnels').textContent = stats.active_tunnels ?? 0;

      const bytes = stats.total_bytes_transferred || 0;
      const mb = (bytes / (1024 * 1024)).toFixed(1);
      document.getElementById('kpi-vpn-traffic').textContent = mb + ' MB';
    } catch (err) {
      console.error('Failed to load VPN stats:', err);
    }
  },

  loadProfiles: async function() {
    try {
      const platformFilter = document.getElementById('vpn-filter-platform')?.value || '';
      let url = '/api/v1/fleet/vpn/profiles';
      if (platformFilter) url += '?platform=' + encodeURIComponent(platformFilter);

      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const profiles = data.profiles || [];

      const countEl = document.getElementById('count-vpn-profiles');
      if (countEl) countEl.textContent = profiles.length;

      // Populate profile select in Map App modal
      const selectEl = document.getElementById('map-app-profile-select');
      if (selectEl) {
        selectEl.innerHTML = profiles.length === 0
          ? '<option value="">No profiles available</option>'
          : profiles.map(p => `<option value="${p.id}">${this.escapeHtml(p.name)} (${p.connection_type})</option>`).join('');
      }

      const tbody = document.getElementById('vpn-profiles-tbody');
      if (!tbody) return;

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No VPN profiles configured</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map(p => {
        const perAppBadge = p.is_per_app_vpn
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">PER-APP</span>'
          : '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-400">GLOBAL</span>';

        const splitBadge = p.split_tunneling
          ? `<span class="text-xs text-amber-400 font-mono">Split (${p.split_tunnel_routes?.length || 0} CIDRs)</span>`
          : '<span class="text-xs text-rose-400 font-mono">Full Redirect</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3">
              <div class="font-medium text-white">${this.escapeHtml(p.name)}</div>
              <div class="text-xs font-mono text-blue-400">${this.escapeHtml(p.server_address)}</div>
            </td>
            <td class="px-4 py-3">
              <div class="font-semibold text-xs text-slate-200">${this.escapeHtml(p.connection_type)}</div>
              <div class="text-xs text-slate-400">${this.escapeHtml(p.target_platform)}</div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>${this.escapeHtml(p.auth_method)}</div>
              <div class="text-slate-500">${p.scep_cert_id ? 'Cert: ' + p.scep_cert_id : 'No Cert Link'}</div>
            </td>
            <td class="px-4 py-3">${splitBadge}</td>
            <td class="px-4 py-3">${perAppBadge}</td>
            <td class="px-4 py-3 text-right space-x-2">
              <button onclick="window.EnterpriseVpnProfilesTable.downloadPayload('${p.id}', 'apple')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-medium rounded transition">
                🍏 .mobileconfig
              </button>
              <button onclick="window.EnterpriseVpnProfilesTable.downloadPayload('${p.id}', 'windows')" class="px-2.5 py-1 bg-blue-700 hover:bg-blue-600 text-white text-xs font-medium rounded transition">
                🪟 VPNv2 XML
              </button>
            </td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.EnterpriseVpnProfilesTable.deleteProfile('${p.id}')" class="px-2 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                🗑️
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load VPN profiles:', err);
    }
  },

  loadMappings: async function() {
    try {
      const res = await fetch('/api/v1/fleet/vpn/mappings', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const mappings = data.mappings || [];

      const countEl = document.getElementById('count-vpn-mappings');
      if (countEl) countEl.textContent = mappings.length;

      const tbody = document.getElementById('vpn-mappings-tbody');
      if (!tbody) return;

      if (mappings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No Per-App VPN application mappings configured</td></tr>';
        return;
      }

      tbody.innerHTML = mappings.map(m => {
        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-medium text-white">${this.escapeHtml(m.app_name)}</td>
            <td class="px-4 py-3 font-mono text-xs text-purple-300">${this.escapeHtml(m.app_bundle_id)}</td>
            <td class="px-4 py-3 text-xs text-blue-300 font-medium">${this.escapeHtml(m.vpn_profile_name || m.vpn_profile_id)}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${this.escapeHtml(m.platform)}</td>
            <td class="px-4 py-3 font-mono text-xs text-slate-500 truncate max-w-xs">${this.escapeHtml(m.designated_requirement || 'Default Anchor')}</td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.EnterpriseVpnProfilesTable.removeMapping('${m.id}')" class="px-2 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                🗑️ Remove
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load VPN mappings:', err);
    }
  },

  loadLogs: async function() {
    try {
      const res = await fetch('/api/v1/fleet/vpn/logs', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const logs = data.logs || [];

      const countEl = document.getElementById('count-vpn-logs');
      if (countEl) countEl.textContent = logs.length;

      const tbody = document.getElementById('vpn-logs-tbody');
      if (!tbody) return;

      if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No connection logs recorded</td></tr>';
        return;
      }

      tbody.innerHTML = logs.map(l => {
        const eventBadge = l.event_type === 'TUNNEL_ESTABLISHED'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">ESTABLISHED</span>'
          : l.event_type === 'TUNNEL_DISCONNECTED'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-300">DISCONNECTED</span>'
          : '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">FAILED</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3">
              <div class="font-mono text-xs text-slate-300">${this.escapeHtml(l.session_id)}</div>
              <div class="text-xs text-slate-400">${this.escapeHtml(l.device_id)}</div>
            </td>
            <td class="px-4 py-3">${eventBadge}</td>
            <td class="px-4 py-3 font-mono text-xs text-cyan-300">${this.escapeHtml(l.assigned_ip || '-')}</td>
            <td class="px-4 py-3 text-xs text-slate-300 font-mono">${(l.bytes_in / 1024).toFixed(0)} KB / ${(l.bytes_out / 1024).toFixed(0)} KB</td>
            <td class="px-4 py-3 text-xs text-slate-400 font-mono">${l.duration_seconds}s</td>
            <td class="px-4 py-3 text-xs text-slate-400">${this.escapeHtml(l.client_os || '-')}</td>
            <td class="px-4 py-3 text-xs text-slate-500">${new Date(l.created_at).toLocaleString()}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load VPN logs:', err);
    }
  },

  setupListeners: function() {
    const self = this;

    // Tabs switching
    document.getElementById('tab-btn-vpn-profiles')?.addEventListener('click', () => self.switchTab('profiles'));
    document.getElementById('tab-btn-vpn-mappings')?.addEventListener('click', () => self.switchTab('mappings'));
    document.getElementById('tab-btn-vpn-logs')?.addEventListener('click', () => self.switchTab('logs'));

    // Refresh
    document.getElementById('btn-vpn-refresh')?.addEventListener('click', () => {
      self.loadStats();
      self.loadProfiles();
      self.loadMappings();
      self.loadLogs();
    });

    // Filter
    document.getElementById('vpn-filter-platform')?.addEventListener('change', () => self.loadProfiles());

    // Create Profile Modal
    document.getElementById('btn-vpn-new-profile')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-new-profile')?.classList.remove('hidden');
    });
    document.getElementById('btn-close-new-vpn-modal')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-new-profile')?.classList.add('hidden');
    });
    document.getElementById('btn-cancel-new-vpn')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-new-profile')?.classList.add('hidden');
    });

    document.getElementById('form-vpn-new-profile')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('new-vpn-name').value.trim();
      const server = document.getElementById('new-vpn-server').value.trim();
      const connType = document.getElementById('new-vpn-type').value;
      const platform = document.getElementById('new-vpn-platform').value;
      const authMethod = document.getElementById('new-vpn-auth').value;
      const splitTunneling = document.getElementById('new-vpn-splittunnel').checked;
      const isPerApp = document.getElementById('new-vpn-isperapp').checked;

      try {
        const res = await fetch('/api/v1/fleet/vpn/profiles', {
          method: 'POST',
          headers: self.getHeaders(),
          body: JSON.stringify({
            name,
            server_address: server,
            connection_type: connType,
            target_platform: platform,
            auth_method: authMethod,
            split_tunneling: splitTunneling,
            is_per_app_vpn: isPerApp
          })
        });

        if (res.ok) {
          document.getElementById('modal-vpn-new-profile')?.classList.add('hidden');
          document.getElementById('form-vpn-new-profile').reset();
          await self.loadProfiles();
          await self.loadStats();
          self.switchTab('profiles');
        } else {
          const err = await res.json();
          alert('Failed to create VPN profile: ' + (err.message || 'Server error'));
        }
      } catch (err) {
        alert('Error creating VPN profile: ' + err.message);
      }
    });

    // Map Application Modal
    document.getElementById('btn-vpn-map-app')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-map-app')?.classList.remove('hidden');
    });
    document.getElementById('btn-close-map-app-modal')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-map-app')?.classList.add('hidden');
    });
    document.getElementById('btn-cancel-map-app')?.addEventListener('click', () => {
      document.getElementById('modal-vpn-map-app')?.classList.add('hidden');
    });

    document.getElementById('form-vpn-map-app')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const profileId = document.getElementById('map-app-profile-select').value;
      const appName = document.getElementById('map-app-name').value.trim();
      const bundleId = document.getElementById('map-app-bundle').value.trim();
      const platform = document.getElementById('map-app-platform').value;

      try {
        const res = await fetch('/api/v1/fleet/vpn/mappings', {
          method: 'POST',
          headers: self.getHeaders(),
          body: JSON.stringify({
            vpn_profile_id: profileId,
            app_name: appName,
            app_bundle_id: bundleId,
            platform: platform
          })
        });

        if (res.ok) {
          document.getElementById('modal-vpn-map-app')?.classList.add('hidden');
          document.getElementById('form-vpn-map-app').reset();
          await self.loadMappings();
          await self.loadStats();
          self.switchTab('mappings');
        } else {
          const err = await res.json();
          alert('Failed to map application: ' + (err.message || 'Server error'));
        }
      } catch (err) {
        alert('Error mapping application: ' + err.message);
      }
    });
  },

  switchTab: function(tab) {
    this.activeTab = tab;
    ['profiles', 'mappings', 'logs'].forEach(t => {
      const btn = document.getElementById('tab-btn-vpn-' + t);
      const content = document.getElementById('tab-content-vpn-' + t);
      if (t === tab) {
        btn?.classList.remove('text-slate-400', 'border-transparent');
        btn?.classList.add('text-blue-400', 'border-blue-400');
        content?.classList.remove('hidden');
      } else {
        btn?.classList.remove('text-blue-400', 'border-blue-400');
        btn?.classList.add('text-slate-400', 'border-transparent');
        content?.classList.add('hidden');
      }
    });
  },

  downloadPayload: async function(profileId, type) {
    const endpoint = type === 'apple' ? 'apple-payload' : 'windows-xml';
    try {
      const res = await fetch(`/api/v1/fleet/vpn/profiles/${profileId}/${endpoint}`, {
        headers: this.getHeaders()
      });
      if (!res.ok) {
        alert('Failed to download payload');
        return;
      }
      const text = await res.text();
      const ext = type === 'apple' ? 'mobileconfig' : 'xml';
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vpn-profile-${profileId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Download error: ' + err.message);
    }
  },

  deleteProfile: async function(profileId) {
    if (!confirm('Are you sure you want to delete this VPN profile? All associated per-app bindings will also be removed.')) return;

    try {
      const res = await fetch('/api/v1/fleet/vpn/profiles/' + profileId, {
        method: 'DELETE',
        headers: this.getHeaders()
      });

      if (res.ok) {
        await this.loadProfiles();
        await this.loadMappings();
        await this.loadStats();
      } else {
        alert('Failed to delete profile');
      }
    } catch (err) {
      alert('Error deleting profile: ' + err.message);
    }
  },

  removeMapping: async function(mappingId) {
    if (!confirm('Remove this Per-App VPN mapping?')) return;

    try {
      const res = await fetch('/api/v1/fleet/vpn/mappings/' + mappingId, {
        method: 'DELETE',
        headers: this.getHeaders()
      });

      if (res.ok) {
        await this.loadMappings();
        await this.loadStats();
      } else {
        alert('Failed to remove mapping');
      }
    } catch (err) {
      alert('Error removing mapping: ' + err.message);
    }
  },

  escapeHtml: function(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
};
