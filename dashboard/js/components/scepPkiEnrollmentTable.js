/**
 * LocalPilot Fleet — SCEP PKI & 802.1X Enterprise Wi-Fi Blade (Iteration 67)
 * dashboard/js/components/scepPkiEnrollmentTable.js
 *
 * Implements enterprise automated SCEP / NDES PKI dynamic challenge token management,
 * device x509 certificate issuance & revocation lifecycle, and 802.1X EAP-TLS Wi-Fi profiles
 * for Apple macOS/iOS, Android, and Windows.
 */

window.ScepPkiEnrollmentTable = {
  activeTab: 'certs',

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
    this.loadCertificates();
    this.loadChallenges();
    this.loadWifiProfiles();
    this.setupListeners();
  },

  getTemplate: function() {
    return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-2xl border border-emerald-500/30">🔐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                802.1X Wi-Fi & SCEP PKI Engine
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Zero-Touch EAP-TLS</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated SCEP (RFC 8894) one-time dynamic challenge distribution, X.509 device identity certificates, and 802.1X Wi-Fi profiles</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-scep-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-scep-generate-challenge" class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-emerald-500/20">
            <span>🔑</span> New SCEP Challenge
          </button>
          <button id="btn-wifi-new-profile" class="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-cyan-500/20">
            <span>📶</span> New Wi-Fi Profile
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" id="scep-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Issued Certificates</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-scep-total-certs">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-scep-active-certs">- Active Devices</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">SCEP Challenges</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🔑</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-scep-pending-challenges">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-scep-total-challenges">- Total Generated</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">802.1X Wi-Fi Profiles</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📶</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-scep-wifi-profiles">-</p>
          <p class="text-xs text-slate-500 mt-1">EAP-TLS Managed</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Revoked Certs</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚫</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-scep-revoked-certs">-</p>
          <p class="text-xs text-slate-500 mt-1">CRL Synchronized</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Zero-Trust Identity</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2">Zero-Cloud</p>
          <p class="text-xs text-slate-500 mt-1">100% On-Premises PKI</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="border-b border-slate-700">
        <nav class="flex space-x-6">
          <button id="tab-btn-scep-certs" class="pb-3 text-sm font-medium text-emerald-400 border-b-2 border-emerald-400 flex items-center gap-2">
            <span>📜</span> Issued Certificates (<span id="count-scep-certs">0</span>)
          </button>
          <button id="tab-btn-scep-challenges" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
            <span>🔑</span> SCEP Dynamic Challenges (<span id="count-scep-challenges">0</span>)
          </button>
          <button id="tab-btn-scep-wifi" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
            <span>📶</span> 802.1X Wi-Fi Profiles (<span id="count-scep-wifi">0</span>)
          </button>
        </nav>
      </div>

      <!-- Tab Content 1: Issued Certificates -->
      <div id="tab-content-scep-certs" class="space-y-4">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>📜</span> Active & Historical Device Certificates
            </h3>
            <div class="flex items-center gap-2">
              <select id="scep-cert-filter-status" class="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none">
                <option value="">All Statuses</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="REVOKED">REVOKED</option>
                <option value="EXPIRED">EXPIRED</option>
              </select>
            </div>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Device / Subject DN</th>
                  <th class="px-4 py-3">Serial &amp; Thumbprint</th>
                  <th class="px-4 py-3">Algorithm</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Valid Until</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="scep-certs-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading issued certificates...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 2: Dynamic SCEP Challenges -->
      <div id="tab-content-scep-challenges" class="space-y-4 hidden">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>🔑</span> One-Time Dynamic SCEP Enrollment Challenges
            </h3>
            <span class="text-xs text-slate-400">Tokens expire automatically upon redemption or timeout</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Challenge ID</th>
                  <th class="px-4 py-3">Target Device</th>
                  <th class="px-4 py-3">Dynamic Password Token</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Expires At</th>
                  <th class="px-4 py-3">Created</th>
                </tr>
              </thead>
              <tbody id="scep-challenges-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading SCEP challenges...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 3: 802.1X Wi-Fi Profiles -->
      <div id="tab-content-scep-wifi" class="space-y-4 hidden">
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 overflow-hidden shadow-lg">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row justify-between items-center gap-3">
            <h3 class="text-base font-semibold text-white flex items-center gap-2">
              <span>📶</span> Enterprise 802.1X EAP-TLS Wi-Fi Profiles
            </h3>
            <span class="text-xs text-slate-400">Download native Apple .mobileconfig or Windows WLAN XML configurations</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Profile Name &amp; SSID</th>
                  <th class="px-4 py-3">Target Platform</th>
                  <th class="px-4 py-3">Security &amp; EAP</th>
                  <th class="px-4 py-3">Connection Options</th>
                  <th class="px-4 py-3">SCEP Server URL</th>
                  <th class="px-4 py-3 text-right">Payload Downloads</th>
                </tr>
              </thead>
              <tbody id="scep-wifi-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading 802.1X Wi-Fi profiles...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal: View Certificate PEM -->
      <div id="modal-scep-view-cert" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>📜</span> X.509 Device Certificate Details
            </h3>
            <button id="btn-close-scep-cert-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <div class="space-y-3 text-sm">
            <div>
              <p class="text-xs font-semibold text-slate-400 uppercase">Subject DN</p>
              <p id="view-cert-subject" class="font-mono text-emerald-300 break-all"></p>
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <p class="text-xs font-semibold text-slate-400 uppercase">Serial Number</p>
                <p id="view-cert-serial" class="font-mono text-slate-200"></p>
              </div>
              <div>
                <p class="text-xs font-semibold text-slate-400 uppercase">Algorithm</p>
                <p id="view-cert-algo" class="text-slate-200"></p>
              </div>
            </div>
            <div>
              <p class="text-xs font-semibold text-slate-400 uppercase">SHA-256 Thumbprint</p>
              <p id="view-cert-thumbprint" class="font-mono text-xs text-amber-300 break-all"></p>
            </div>
            <div>
              <p class="text-xs font-semibold text-slate-400 uppercase">PEM Certificate Block</p>
              <pre id="view-cert-pem" class="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto"></pre>
            </div>
          </div>
          <div class="flex justify-end pt-3 border-t border-slate-700">
            <button id="btn-copy-scep-pem" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition">
              Copy PEM
            </button>
          </div>
        </div>
      </div>

      <!-- Modal: Revoke Certificate -->
      <div id="modal-scep-revoke-cert" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-rose-400 flex items-center gap-2">
              <span>🚫</span> Revoke Certificate
            </h3>
            <button id="btn-close-revoke-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <p class="text-sm text-slate-300">Revoking this device certificate immediately invalidates 802.1X Enterprise Wi-Fi and VPN EAP-TLS authentication access.</p>
          <input type="hidden" id="revoke-target-cert-id" />
          <div>
            <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Revocation Reason</label>
            <select id="revoke-reason-select" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
              <option value="KEY_COMPROMISE">Key Compromise</option>
              <option value="AFFILIATION_CHANGED">Affiliation Changed / Device Deprovisioned</option>
              <option value="SUPERSEDED">Superseded / Replaced</option>
              <option value="CESSATION_OF_OPERATION">Cessation of Operation</option>
              <option value="UNSPECIFIED">Unspecified</option>
            </select>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="btn-cancel-revoke" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">Cancel</button>
            <button id="btn-confirm-revoke" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg text-sm shadow-lg hover:shadow-rose-500/20">Confirm Revocation</button>
          </div>
        </div>
      </div>

      <!-- Modal: Generate Challenge -->
      <div id="modal-scep-gen-challenge" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🔑</span> Generate Dynamic SCEP Challenge
            </h3>
            <button id="btn-close-gen-challenge-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <form id="form-scep-gen-challenge" class="space-y-3 text-sm">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Target Device ID *</label>
              <input type="text" id="gen-challenge-device-id" required placeholder="e.g. dev-daddy-pc" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Validity (Minutes)</label>
              <input type="number" id="gen-challenge-validity" value="60" min="5" max="1440" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Subject DN (Optional)</label>
              <input type="text" id="gen-challenge-subject" placeholder="CN={deviceId}.localpilot.corp,OU=Workstations" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
              <button type="button" id="btn-cancel-gen-challenge" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg text-sm shadow-lg hover:shadow-emerald-500/20">Generate Token</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Modal: New Wi-Fi Profile -->
      <div id="modal-scep-new-wifi" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center border-b border-slate-700 pb-3">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>📶</span> Create Enterprise 802.1X Wi-Fi Profile
            </h3>
            <button id="btn-close-new-wifi-modal" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
          </div>
          <form id="form-scep-new-wifi" class="space-y-3 text-sm">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Profile Name *</label>
              <input type="text" id="new-wifi-name" required placeholder="e.g. Corporate Secure Wi-Fi" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">SSID *</label>
              <input type="text" id="new-wifi-ssid" required placeholder="e.g. LocalPilot-Secure" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Target Platform</label>
                <select id="new-wifi-platform" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                  <option value="COMBINED">Combined (All)</option>
                  <option value="MACOS">macOS</option>
                  <option value="IOS">iOS / iPadOS</option>
                  <option value="ANDROID">Android Enterprise</option>
                  <option value="WINDOWS">Windows 10/11</option>
                </select>
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase mb-1">Security Type</label>
                <select id="new-wifi-sec" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200">
                  <option value="WPA2_ENTERPRISE">WPA2 Enterprise</option>
                  <option value="WPA3_ENTERPRISE_192BIT">WPA3 Enterprise (192-bit)</option>
                  <option value="WPA2_WPA3_MIXED">WPA2/WPA3 Mixed</option>
                </select>
              </div>
            </div>
            <div class="flex items-center gap-6 pt-2">
              <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                <input type="checkbox" id="new-wifi-autoconnect" checked class="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0" />
                <span class="text-xs">Auto Connect</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                <input type="checkbox" id="new-wifi-hidden" class="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0" />
                <span class="text-xs">Hidden SSID</span>
              </label>
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
              <button type="button" id="btn-cancel-new-wifi" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg text-sm shadow-lg hover:shadow-cyan-500/20">Create Profile</button>
            </div>
          </form>
        </div>
      </div>
    </div>
    `;
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/scep/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-scep-total-certs').textContent = stats.total_certificates ?? 0;
      document.getElementById('kpi-scep-active-certs').textContent = (stats.active_certificates ?? 0) + ' Active Devices';
      document.getElementById('kpi-scep-pending-challenges').textContent = stats.pending_challenges ?? 0;
      document.getElementById('kpi-scep-total-challenges').textContent = (stats.total_challenges ?? 0) + ' Total Generated';
      document.getElementById('kpi-scep-wifi-profiles').textContent = stats.active_8021x_wifi_profiles ?? 0;
      document.getElementById('kpi-scep-revoked-certs').textContent = stats.revoked_certificates ?? 0;
    } catch (err) {
      console.error('Failed to load SCEP stats:', err);
    }
  },

  loadCertificates: async function() {
    try {
      const statusFilter = document.getElementById('scep-cert-filter-status')?.value || '';
      let url = '/api/v1/fleet/scep/certificates';
      if (statusFilter) url += '?status=' + encodeURIComponent(statusFilter);

      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const certs = data.certificates || [];

      const countEl = document.getElementById('count-scep-certs');
      if (countEl) countEl.textContent = certs.length;

      const tbody = document.getElementById('scep-certs-tbody');
      if (!tbody) return;

      if (certs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No issued certificates found</td></tr>';
        return;
      }

      tbody.innerHTML = certs.map(c => {
        const statusBadge = c.status === 'ACTIVE'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">ACTIVE</span>'
          : c.status === 'REVOKED'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">REVOKED</span>'
          : '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-300">EXPIRED</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3">
              <div class="font-medium text-slate-200">${this.escapeHtml(c.device_id)}</div>
              <div class="text-xs font-mono text-slate-400 truncate max-w-xs">${this.escapeHtml(c.subject_dn)}</div>
            </td>
            <td class="px-4 py-3">
              <div class="text-xs font-mono text-slate-300 truncate max-w-xs">SN: ${this.escapeHtml(c.serial_number)}</div>
              <div class="text-xs font-mono text-amber-400/80 truncate max-w-xs">SHA256: ${this.escapeHtml(c.thumbprint_sha256.substring(0, 16))}...</div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">${this.escapeHtml(c.public_key_algorithm)}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${new Date(c.valid_to).toLocaleDateString()}</td>
            <td class="px-4 py-3 text-right space-x-2">
              <button onclick="window.ScepPkiEnrollmentTable.viewCertDetails('${c.id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-medium rounded transition">
                View PEM
              </button>
              ${c.status === 'ACTIVE' ? `
                <button onclick="window.ScepPkiEnrollmentTable.openRevokeModal('${c.id}')" class="px-2.5 py-1 bg-rose-600/80 hover:bg-rose-500 text-white text-xs font-medium rounded transition">
                  Revoke
                </button>
              ` : ''}
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load SCEP certificates:', err);
    }
  },

  loadChallenges: async function() {
    try {
      const res = await fetch('/api/v1/fleet/scep/challenges', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const challenges = data.challenges || [];

      const countEl = document.getElementById('count-scep-challenges');
      if (countEl) countEl.textContent = challenges.length;

      const tbody = document.getElementById('scep-challenges-tbody');
      if (!tbody) return;

      if (challenges.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No active SCEP challenges</td></tr>';
        return;
      }

      tbody.innerHTML = challenges.map(ch => {
        const statusBadge = ch.status === 'PENDING'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">PENDING</span>'
          : ch.status === 'REDEEMED'
          ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">REDEEMED</span>'
          : '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-300">EXPIRED</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-mono text-xs text-slate-300">${this.escapeHtml(ch.id)}</td>
            <td class="px-4 py-3 font-medium text-slate-200">${this.escapeHtml(ch.device_id)}</td>
            <td class="px-4 py-3 font-mono text-xs text-emerald-400 select-all">${this.escapeHtml(ch.challenge_password)}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${new Date(ch.expires_at).toLocaleString()}</td>
            <td class="px-4 py-3 text-xs text-slate-500">${new Date(ch.created_at).toLocaleString()}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load SCEP challenges:', err);
    }
  },

  loadWifiProfiles: async function() {
    try {
      const res = await fetch('/api/v1/fleet/scep/wifi-profiles', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const profiles = data.profiles || [];

      const countEl = document.getElementById('count-scep-wifi');
      if (countEl) countEl.textContent = profiles.length;

      const tbody = document.getElementById('scep-wifi-tbody');
      if (!tbody) return;

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No 802.1X Wi-Fi profiles configured</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map(p => {
        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3">
              <div class="font-medium text-white">${this.escapeHtml(p.name)}</div>
              <div class="text-xs text-cyan-400 font-mono">SSID: ${this.escapeHtml(p.ssid)}</div>
            </td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-slate-700 text-slate-200 border border-slate-600">${this.escapeHtml(p.target_platform)}</span>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>${this.escapeHtml(p.security_type)}</div>
              <div class="text-slate-400">${this.escapeHtml(p.eap_type)}</div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-400">
              <div>AutoConnect: ${p.auto_connect ? '✅ Yes' : '❌ No'}</div>
              <div>Hidden: ${p.hidden_network ? '🔒 Yes' : 'Broadcast'}</div>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-slate-400 truncate max-w-xs">${this.escapeHtml(p.scep_server_url)}</td>
            <td class="px-4 py-3 text-right space-x-2">
              <button onclick="window.ScepPkiEnrollmentTable.downloadPayload('${p.id}', 'apple')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-medium rounded transition">
                🍏 .mobileconfig
              </button>
              <button onclick="window.ScepPkiEnrollmentTable.downloadPayload('${p.id}', 'windows')" class="px-2.5 py-1 bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-medium rounded transition">
                🪟 WLAN XML
              </button>
              <button onclick="window.ScepPkiEnrollmentTable.deleteWifiProfile('${p.id}')" class="px-2 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                🗑️
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load 802.1X Wi-Fi profiles:', err);
    }
  },

  setupListeners: function() {
    const self = this;

    // Tabs switching
    document.getElementById('tab-btn-scep-certs')?.addEventListener('click', () => self.switchTab('certs'));
    document.getElementById('tab-btn-scep-challenges')?.addEventListener('click', () => self.switchTab('challenges'));
    document.getElementById('tab-btn-scep-wifi')?.addEventListener('click', () => self.switchTab('wifi'));

    // Refresh
    document.getElementById('btn-scep-refresh')?.addEventListener('click', () => {
      self.loadStats();
      self.loadCertificates();
      self.loadChallenges();
      self.loadWifiProfiles();
    });

    // Filter
    document.getElementById('scep-cert-filter-status')?.addEventListener('change', () => self.loadCertificates());

    // Generate Challenge Modal
    document.getElementById('btn-scep-generate-challenge')?.addEventListener('click', () => {
      document.getElementById('modal-scep-gen-challenge')?.classList.remove('hidden');
    });
    document.getElementById('btn-close-gen-challenge-modal')?.addEventListener('click', () => {
      document.getElementById('modal-scep-gen-challenge')?.classList.add('hidden');
    });
    document.getElementById('btn-cancel-gen-challenge')?.addEventListener('click', () => {
      document.getElementById('modal-scep-gen-challenge')?.classList.add('hidden');
    });

    document.getElementById('form-scep-gen-challenge')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const deviceId = document.getElementById('gen-challenge-device-id').value.trim();
      const validityMinutes = Number(document.getElementById('gen-challenge-validity').value) || 60;
      const subject = document.getElementById('gen-challenge-subject').value.trim();

      try {
        const res = await fetch('/api/v1/fleet/scep/challenges', {
          method: 'POST',
          headers: self.getHeaders(),
          body: JSON.stringify({
            device_id: deviceId,
            validity_minutes: validityMinutes,
            subject_name: subject || undefined
          })
        });

        if (res.ok) {
          document.getElementById('modal-scep-gen-challenge')?.classList.add('hidden');
          document.getElementById('form-scep-gen-challenge').reset();
          await self.loadChallenges();
          await self.loadStats();
          self.switchTab('challenges');
        } else {
          const err = await res.json();
          alert('Failed to generate challenge: ' + (err.message || 'Server error'));
        }
      } catch (err) {
        alert('Error generating SCEP challenge: ' + err.message);
      }
    });

    // New Wi-Fi Profile Modal
    document.getElementById('btn-wifi-new-profile')?.addEventListener('click', () => {
      document.getElementById('modal-scep-new-wifi')?.classList.remove('hidden');
    });
    document.getElementById('btn-close-new-wifi-modal')?.addEventListener('click', () => {
      document.getElementById('modal-scep-new-wifi')?.classList.add('hidden');
    });
    document.getElementById('btn-cancel-new-wifi')?.addEventListener('click', () => {
      document.getElementById('modal-scep-new-wifi')?.classList.add('hidden');
    });

    document.getElementById('form-scep-new-wifi')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('new-wifi-name').value.trim();
      const ssid = document.getElementById('new-wifi-ssid').value.trim();
      const platform = document.getElementById('new-wifi-platform').value;
      const secType = document.getElementById('new-wifi-sec').value;
      const autoConnect = document.getElementById('new-wifi-autoconnect').checked;
      const hidden = document.getElementById('new-wifi-hidden').checked;

      try {
        const res = await fetch('/api/v1/fleet/scep/wifi-profiles', {
          method: 'POST',
          headers: self.getHeaders(),
          body: JSON.stringify({
            name,
            ssid,
            target_platform: platform,
            security_type: secType,
            auto_connect: autoConnect,
            hidden_network: hidden
          })
        });

        if (res.ok) {
          document.getElementById('modal-scep-new-wifi')?.classList.add('hidden');
          document.getElementById('form-scep-new-wifi').reset();
          await self.loadWifiProfiles();
          await self.loadStats();
          self.switchTab('wifi');
        } else {
          const err = await res.json();
          alert('Failed to create Wi-Fi profile: ' + (err.message || 'Server error'));
        }
      } catch (err) {
        alert('Error creating Wi-Fi profile: ' + err.message);
      }
    });

    // Certificate Modal Handlers
    document.getElementById('btn-close-scep-cert-modal')?.addEventListener('click', () => {
      document.getElementById('modal-scep-view-cert')?.classList.add('hidden');
    });
    document.getElementById('btn-copy-scep-pem')?.addEventListener('click', () => {
      const pem = document.getElementById('view-cert-pem').textContent;
      navigator.clipboard.writeText(pem);
      alert('Certificate PEM copied to clipboard!');
    });

    // Revoke Modal Handlers
    document.getElementById('btn-close-revoke-modal')?.addEventListener('click', () => {
      document.getElementById('modal-scep-revoke-cert')?.classList.add('hidden');
    });
    document.getElementById('btn-cancel-revoke')?.addEventListener('click', () => {
      document.getElementById('modal-scep-revoke-cert')?.classList.add('hidden');
    });
    document.getElementById('btn-confirm-revoke')?.addEventListener('click', async () => {
      const certId = document.getElementById('revoke-target-cert-id').value;
      const reason = document.getElementById('revoke-reason-select').value;

      try {
        const res = await fetch('/api/v1/fleet/scep/certificates/' + certId + '/revoke', {
          method: 'POST',
          headers: self.getHeaders(),
          body: JSON.stringify({ reason })
        });

        if (res.ok) {
          document.getElementById('modal-scep-revoke-cert')?.classList.add('hidden');
          await self.loadCertificates();
          await self.loadStats();
        } else {
          const err = await res.json();
          alert('Failed to revoke certificate: ' + (err.message || 'Server error'));
        }
      } catch (err) {
        alert('Error revoking certificate: ' + err.message);
      }
    });
  },

  switchTab: function(tab) {
    this.activeTab = tab;
    ['certs', 'challenges', 'wifi'].forEach(t => {
      const btn = document.getElementById('tab-btn-scep-' + t);
      const content = document.getElementById('tab-content-scep-' + t);
      if (t === tab) {
        btn?.classList.remove('text-slate-400', 'border-transparent');
        btn?.classList.add('text-emerald-400', 'border-emerald-400');
        content?.classList.remove('hidden');
      } else {
        btn?.classList.remove('text-emerald-400', 'border-emerald-400');
        btn?.classList.add('text-slate-400', 'border-transparent');
        content?.classList.add('hidden');
      }
    });
  },

  viewCertDetails: async function(certId) {
    try {
      const res = await fetch('/api/v1/fleet/scep/certificates/' + certId, { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const cert = data.certificate;
      if (!cert) return;

      document.getElementById('view-cert-subject').textContent = cert.subject_dn;
      document.getElementById('view-cert-serial').textContent = cert.serial_number;
      document.getElementById('view-cert-algo').textContent = cert.public_key_algorithm;
      document.getElementById('view-cert-thumbprint').textContent = cert.thumbprint_sha256;
      document.getElementById('view-cert-pem').textContent = cert.certificate_pem;

      document.getElementById('modal-scep-view-cert')?.classList.remove('hidden');
    } catch (err) {
      console.error('Failed to view certificate:', err);
    }
  },

  openRevokeModal: function(certId) {
    document.getElementById('revoke-target-cert-id').value = certId;
    document.getElementById('modal-scep-revoke-cert')?.classList.remove('hidden');
  },

  downloadPayload: async function(profileId, type) {
    const endpoint = type === 'apple' ? 'apple-payload' : 'windows-xml';
    try {
      const res = await fetch(`/api/v1/fleet/scep/wifi-profiles/${profileId}/${endpoint}`, {
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
      a.download = `wifi-profile-${profileId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Download error: ' + err.message);
    }
  },

  deleteWifiProfile: async function(profileId) {
    if (!confirm('Are you sure you want to delete this 802.1X Wi-Fi profile?')) return;

    try {
      const res = await fetch('/api/v1/fleet/scep/wifi-profiles/' + profileId, {
        method: 'DELETE',
        headers: this.getHeaders()
      });

      if (res.ok) {
        await this.loadWifiProfiles();
        await this.loadStats();
      } else {
        alert('Failed to delete profile');
      }
    } catch (err) {
      alert('Error deleting profile: ' + err.message);
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

// Backwards compatibility functions
function renderScepPkiEnrollmentBlade() {
  return window.ScepPkiEnrollmentTable.getTemplate();
}

function initScepPkiEnrollmentBlade() {
  window.ScepPkiEnrollmentTable.render();
}
