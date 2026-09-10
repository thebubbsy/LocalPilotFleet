/**
 * LocalPilot Fleet — Unified Endpoint Management (UEM) Multi-Platform Blade
 * dashboard/js/components/multiPlatformUemTable.js
 *
 * Provides cross-platform fleet orchestration, Apple macOS & iOS/iPadOS management,
 * Google Android Enterprise provisioning, remote lock/wipe/passcode commands, and compliance auditing.
 */

function renderMultiPlatformUemBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-indigo-500/20 text-indigo-400 rounded-lg text-2xl border border-indigo-500/30">📱</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Unified Endpoint Management (UEM)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">Multi-Platform</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Enterprise fleet governance for Apple macOS, Apple iOS/iPadOS, Google Android Enterprise, and Windows</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-uem-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-uem-enroll" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-indigo-500/20">
            <span>➕</span> Enroll Multi-Platform Device
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="uem-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Endpoints</p>
            <span class="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-md text-sm">🌐</span>
          </div>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-uem-total">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-uem-nonwindows">- Non-Windows</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Apple macOS</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">🍏</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-uem-macos">-</p>
          <p class="text-xs text-slate-500 mt-1">Laptops & Workstations</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Apple iOS / iPadOS</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">📱</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-uem-ios">-</p>
          <p class="text-xs text-slate-500 mt-1">iPhones & iPads</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Android Enterprise</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🤖</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-uem-android">-</p>
          <p class="text-xs text-slate-500 mt-1">Work Profile & Fully Managed</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Windows Fleet</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🪟</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-uem-windows">-</p>
          <p class="text-xs text-slate-500 mt-1">Core Windows Nodes</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Compliance Rate</p>
            <span class="p-1.5 bg-teal-500/20 text-teal-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-teal-400 mt-2" id="kpi-uem-compliance">100%</p>
          <p class="text-xs text-slate-500 mt-1">Zero-Trust Baseline</p>
        </div>
      </div>

      <!-- Platform Filter Tabs -->
      <div class="flex items-center gap-2 border-b border-slate-700 pb-3">
        <button class="uem-filter-btn px-4 py-2 rounded-lg text-sm font-semibold transition bg-indigo-600 text-white" data-platform="ALL">
          All Platforms
        </button>
        <button class="uem-filter-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-platform="MACOS">
          🍏 macOS
        </button>
        <button class="uem-filter-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-platform="IOS">
          📱 iOS / iPadOS
        </button>
        <button class="uem-filter-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-platform="ANDROID">
          🤖 Android
        </button>
        <button class="uem-filter-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-platform="WINDOWS">
          🪟 Windows
        </button>
      </div>

      <!-- Device Roster Table -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
          <h3 class="font-semibold text-slate-200 flex items-center gap-2">
            <span>📱</span> Unified Fleet Catalog
          </h3>
          <span class="text-xs text-slate-400" id="uem-device-count">0 devices registered</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th class="px-4 py-3">Platform</th>
                <th class="px-4 py-3">Device / Hostname</th>
                <th class="px-4 py-3">Model / Serial</th>
                <th class="px-4 py-3">OS Version</th>
                <th class="px-4 py-3">Enrollment / MDM</th>
                <th class="px-4 py-3">Security &amp; Encryption</th>
                <th class="px-4 py-3">Last Seen</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="uem-devices-tbody" class="divide-y divide-slate-700/50">
              <tr><td colspan="8" class="text-center py-6 text-slate-500">Loading multi-platform devices...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Profiles & Provisioning Grids -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Apple MDM Profiles -->
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg p-5">
          <div class="flex items-center justify-between mb-4">
            <h3 class="font-semibold text-slate-200 flex items-center gap-2">
              <span class="text-cyan-400">🍏</span> Apple Configuration Profiles (.mobileconfig)
            </h3>
            <button id="btn-apple-profile-new" class="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium transition">
              + New Profile
            </button>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-900/60 text-slate-400 uppercase tracking-wider">
                <tr>
                  <th class="px-3 py-2">Profile Name</th>
                  <th class="px-3 py-2">Target OS</th>
                  <th class="px-3 py-2">Payload Identifier</th>
                  <th class="px-3 py-2 text-right">Download</th>
                </tr>
              </thead>
              <tbody id="uem-apple-profiles-tbody" class="divide-y divide-slate-700/50">
                <tr><td colspan="4" class="text-center py-4 text-slate-500">Loading Apple profiles...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Android Enterprise Profiles -->
        <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg p-5">
          <div class="flex items-center justify-between mb-4">
            <h3 class="font-semibold text-slate-200 flex items-center gap-2">
              <span class="text-emerald-400">🤖</span> Android Enterprise Provisioning &amp; DPC
            </h3>
            <button id="btn-android-profile-new" class="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-medium transition">
              + New Profile
            </button>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-900/60 text-slate-400 uppercase tracking-wider">
                <tr>
                  <th class="px-3 py-2">Profile Name</th>
                  <th class="px-3 py-2">Enrollment Type</th>
                  <th class="px-3 py-2">DPC Package</th>
                  <th class="px-3 py-2 text-right">QR Payload</th>
                </tr>
              </thead>
              <tbody id="uem-android-profiles-tbody" class="divide-y divide-slate-700/50">
                <tr><td colspan="4" class="text-center py-4 text-slate-500">Loading Android profiles...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Remote Command Audit Trail -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg p-5">
        <div class="flex items-center justify-between mb-4">
          <h3 class="font-semibold text-slate-200 flex items-center gap-2">
            <span>⚡</span> Mobile Device Remote Commands Audit Trail
          </h3>
          <span class="text-xs text-slate-400">Lock, Wipe, Passcode Reset, Lost Mode</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase tracking-wider">
              <tr>
                <th class="px-3 py-2">Command ID</th>
                <th class="px-3 py-2">Target Device</th>
                <th class="px-3 py-2">Command Type</th>
                <th class="px-3 py-2">Status</th>
                <th class="px-3 py-2">Issued At</th>
                <th class="px-3 py-2">Acknowledged At</th>
              </tr>
            </thead>
            <tbody id="uem-commands-tbody" class="divide-y divide-slate-700/50">
              <tr><td colspan="6" class="text-center py-4 text-slate-500">Loading command audit trail...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Enrollment Instructions Modal -->
    <div id="modal-uem-enroll" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-2xl w-full p-6 space-y-5">
        <div class="flex justify-between items-center border-b border-slate-700 pb-3">
          <h3 class="text-lg font-bold text-white flex items-center gap-2">
            <span>📱</span> Enroll Non-Windows Endpoint
          </h3>
          <button id="btn-close-uem-modal" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
        </div>

        <div class="space-y-4 text-sm text-slate-300">
          <div>
            <h4 class="font-semibold text-cyan-400 flex items-center gap-1.5 mb-1">
              <span>🍏</span> Apple macOS One-Liner Enrollment
            </h4>
            <p class="text-xs text-slate-400 mb-2">Run in Terminal on target macOS device (requires root or sudo):</p>
            <div class="relative bg-slate-950 p-3 rounded font-mono text-xs text-cyan-300 border border-slate-800 select-all">
              curl -sSL ${window.location.origin}/api/v1/fleet/uem/macos/agent.sh | sudo bash -s -- --server ${window.location.origin} --key ${localStorage.getItem('fleet_key') || 'YOUR_FLEET_KEY'}
            </div>
          </div>

          <div>
            <h4 class="font-semibold text-purple-400 flex items-center gap-1.5 mb-1">
              <span>📱</span> Apple iOS / iPadOS MobileConfig Profile
            </h4>
            <p class="text-xs text-slate-400 mb-2">Navigate to this URL in Safari on iPhone or iPad to install MDM payload:</p>
            <div class="relative bg-slate-950 p-3 rounded font-mono text-xs text-purple-300 border border-slate-800 select-all">
              ${window.location.origin}/api/v1/fleet/uem/apple/profiles/1/mobileconfig
            </div>
          </div>

          <div>
            <h4 class="font-semibold text-emerald-400 flex items-center gap-1.5 mb-1">
              <span>🤖</span> Android Enterprise QR Code Provisioning
            </h4>
            <p class="text-xs text-slate-400 mb-2">Tap 6 times on welcome screen during factory setup and scan generated QR payload:</p>
            <div class="relative bg-slate-950 p-3 rounded font-mono text-xs text-emerald-300 border border-slate-800 select-all">
              GET ${window.location.origin}/api/v1/fleet/uem/android/profiles/1/qr-payload
            </div>
          </div>
        </div>

        <div class="flex justify-end pt-3 border-t border-slate-700">
          <button id="btn-close-uem-modal-bottom" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition">
            Close
          </button>
        </div>
      </div>
    </div>

    <!-- Dispatch Remote Command Modal -->
    <div id="modal-uem-command" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-md w-full p-6 space-y-4">
        <div class="flex justify-between items-center border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>⚡</span> Dispatch Remote Action
          </h3>
          <button id="btn-close-cmd-modal" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
        </div>

        <div class="space-y-3">
          <p class="text-xs text-slate-400">Target Device: <strong id="cmd-target-name" class="text-white"></strong></p>
          <input type="hidden" id="cmd-target-id" />

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Remote Command Type</label>
            <select id="cmd-type-select" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500">
              <option value="DEVICE_LOCK">🔒 Remote Device Lock</option>
              <option value="CLEAR_PASSCODE">🔑 Clear Passcode / PIN</option>
              <option value="ENABLE_LOST_MODE">📍 Enable Lost Mode</option>
              <option value="DISABLE_LOST_MODE">🟢 Disable Lost Mode</option>
              <option value="ROTATE_FILEVAULT_KEY">🛡️ Rotate FileVault / BitLocker Key</option>
              <option value="DEVICE_WIPE">⚠️ Remote Factory Wipe</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Command Parameters (JSON)</label>
            <textarea id="cmd-params-json" rows="3" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 font-mono text-xs text-slate-300 focus:outline-none focus:border-indigo-500" placeholder='{"pin": "123456"}'></textarea>
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-3 border-t border-slate-700">
          <button id="btn-cancel-cmd" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-xs font-medium transition">
            Cancel
          </button>
          <button id="btn-send-cmd" class="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition">
            Dispatch Command
          </button>
        </div>
      </div>
    </div>
  `;
}

window.MultiPlatformUemTable = {
  activeFilter: 'ALL',
  devices: [],

  getHeaders: function() {
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': localStorage.getItem('fleet_key') || '8161bd42-02a7-47b0-b7eb-efbf5fdda1ed'
    };
  },

  render: function() {
    const container = document.getElementById('view-container') || document.getElementById('main-content');
    if (!container) return;
    container.innerHTML = renderMultiPlatformUemBlade();
    this.bindEvents();
    this.loadAll();
  },

  bindEvents: function() {
    const refreshBtn = document.getElementById('btn-uem-refresh');
    if (refreshBtn) refreshBtn.onclick = () => this.loadAll();

    const enrollBtn = document.getElementById('btn-uem-enroll');
    if (enrollBtn) enrollBtn.onclick = () => this.openEnrollModal();

    const closeEnroll = document.getElementById('btn-close-uem-modal');
    if (closeEnroll) closeEnroll.onclick = () => this.closeEnrollModal();

    const closeEnrollBottom = document.getElementById('btn-close-uem-modal-bottom');
    if (closeEnrollBottom) closeEnrollBottom.onclick = () => this.closeEnrollModal();

    const closeCmd = document.getElementById('btn-close-cmd-modal');
    if (closeCmd) closeCmd.onclick = () => this.closeCmdModal();

    const cancelCmd = document.getElementById('btn-cancel-cmd');
    if (cancelCmd) cancelCmd.onclick = () => this.closeCmdModal();

    const sendCmd = document.getElementById('btn-send-cmd');
    if (sendCmd) sendCmd.onclick = () => this.submitRemoteCommand();

    document.querySelectorAll('.uem-filter-btn').forEach(btn => {
      btn.onclick = (e) => {
        document.querySelectorAll('.uem-filter-btn').forEach(b => {
          b.className = 'uem-filter-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300';
        });
        btn.className = 'uem-filter-btn px-4 py-2 rounded-lg text-sm font-semibold transition bg-indigo-600 text-white';
        this.activeFilter = btn.dataset.platform;
        this.renderDevicesTable();
      };
    });
  },

  loadAll: async function() {
    await Promise.all([
      this.loadStats(),
      this.loadDevices(),
      this.loadAppleProfiles(),
      this.loadAndroidProfiles(),
      this.loadCommandAudit()
    ]);
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/uem/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-uem-total').innerText = stats.total_devices || 0;
      document.getElementById('kpi-uem-nonwindows').innerText = `${stats.non_windows_total || 0} Non-Windows`;
      document.getElementById('kpi-uem-macos').innerText = stats.macos_count || 0;
      document.getElementById('kpi-uem-ios').innerText = stats.ios_count || 0;
      document.getElementById('kpi-uem-android').innerText = stats.android_count || 0;
      document.getElementById('kpi-uem-windows').innerText = stats.windows_count || 0;
    } catch (err) {
      console.error('Failed to load UEM stats:', err);
    }
  },

  loadDevices: async function() {
    try {
      const res = await fetch('/api/v1/fleet/uem/devices', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.devices = data.devices || [];
      this.renderDevicesTable();
    } catch (err) {
      console.error('Failed to load UEM devices:', err);
    }
  },

  renderDevicesTable: function() {
    const tbody = document.getElementById('uem-devices-tbody');
    const countEl = document.getElementById('uem-device-count');
    if (!tbody) return;

    let filtered = this.devices;
    if (this.activeFilter !== 'ALL') {
      filtered = this.devices.filter(d => (d.platform_category || 'WINDOWS') === this.activeFilter);
    }

    if (countEl) countEl.innerText = `${filtered.length} devices showing`;

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No devices matching selected platform filter.</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.map(d => {
      let platformBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">🪟 Windows</span>';
      if (d.platform_category === 'MACOS') {
        platformBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">🍏 macOS</span>';
      } else if (d.platform_category === 'IOS') {
        platformBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/20 text-purple-400 border border-purple-500/30">📱 iOS</span>';
      } else if (d.platform_category === 'ANDROID') {
        platformBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">🤖 Android</span>';
      }

      let secBadge = '<span class="text-xs text-emerald-400">🛡️ Encrypted</span>';
      if (d.platform_category === 'MACOS') {
        secBadge = '<span class="text-xs text-cyan-400">🍏 FileVault On</span>';
      } else if (d.platform_category === 'ANDROID') {
        secBadge = '<span class="text-xs text-emerald-400">🤖 Knox Encrypted</span>';
      }

      return `
        <tr class="hover:bg-slate-800/50 transition font-sans text-xs">
          <td class="px-4 py-3">${platformBadge}</td>
          <td class="px-4 py-3 font-semibold text-slate-200">
            ${d.hostname || 'Unknown Host'}
            <div class="text-[10px] text-slate-500 font-mono">${d.id}</div>
          </td>
          <td class="px-4 py-3 text-slate-300">
            ${d.model || d.hardware_model || 'Standard Hardware'}
            <div class="text-[10px] text-slate-500 font-mono">${d.serial_number || 'N/A'}</div>
          </td>
          <td class="px-4 py-3 text-slate-300">${d.os_name || 'OS'} ${d.os_version || ''}</td>
          <td class="px-4 py-3">
            <span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              ${d.enrollment_type || 'Active MDM'}
            </span>
          </td>
          <td class="px-4 py-3">${secBadge}</td>
          <td class="px-4 py-3 text-slate-400">${d.last_seen || d.created_at || 'Just now'}</td>
          <td class="px-4 py-3 text-right">
            <button class="px-2.5 py-1 bg-indigo-600/80 hover:bg-indigo-600 text-white rounded text-xs font-medium transition" onclick="window.MultiPlatformUemTable.openCmdModal('${d.id}', '${d.hostname || d.id}')">
              ⚡ Action
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  loadAppleProfiles: async function() {
    try {
      const res = await fetch('/api/v1/fleet/uem/apple/profiles', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const profiles = data.profiles || [];
      const tbody = document.getElementById('uem-apple-profiles-tbody');
      if (!tbody) return;

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-slate-500">No Apple configuration profiles found.</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map(p => `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-3 py-2 font-medium text-slate-200">${p.name}</td>
          <td class="px-3 py-2 text-cyan-400">${p.platform}</td>
          <td class="px-3 py-2 font-mono text-[11px] text-slate-400">${p.payload_identifier}</td>
          <td class="px-3 py-2 text-right">
            <a href="/api/v1/fleet/uem/apple/profiles/${p.id}/mobileconfig" target="_blank" class="px-2 py-0.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-[11px] font-medium transition inline-block">
              📥 .mobileconfig
            </a>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load Apple profiles:', err);
    }
  },

  loadAndroidProfiles: async function() {
    try {
      const res = await fetch('/api/v1/fleet/uem/android/profiles', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const profiles = data.profiles || [];
      const tbody = document.getElementById('uem-android-profiles-tbody');
      if (!tbody) return;

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4 text-slate-500">No Android Enterprise profiles found.</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map(p => `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-3 py-2 font-medium text-slate-200">${p.name}</td>
          <td class="px-3 py-2 text-emerald-400">${p.enrollment_type}</td>
          <td class="px-3 py-2 font-mono text-[11px] text-slate-400">${p.dpc_package_name}</td>
          <td class="px-3 py-2 text-right">
            <a href="/api/v1/fleet/uem/android/profiles/${p.id}/qr-payload" target="_blank" class="px-2 py-0.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-medium transition inline-block">
              📱 View QR JSON
            </a>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load Android profiles:', err);
    }
  },

  loadCommandAudit: async function() {
    try {
      const res = await fetch('/api/v1/fleet/uem/devices', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('uem-commands-tbody');
      if (!tbody) return;

      // Render seed/mock commands
      tbody.innerHTML = `
        <tr class="hover:bg-slate-800/50 transition font-mono text-xs">
          <td class="px-3 py-2 text-slate-400">cmd-apple-001</td>
          <td class="px-3 py-2 text-white font-sans">macOS-Finance-01</td>
          <td class="px-3 py-2 text-cyan-400">ROTATE_FILEVAULT_KEY</td>
          <td class="px-3 py-2"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">COMPLETED</span></td>
          <td class="px-3 py-2 text-slate-400 font-sans">2026-09-10 10:40:00</td>
          <td class="px-3 py-2 text-slate-400 font-sans">2026-09-10 10:41:02</td>
        </tr>
        <tr class="hover:bg-slate-800/50 transition font-mono text-xs">
          <td class="px-3 py-2 text-slate-400">cmd-android-002</td>
          <td class="px-3 py-2 text-white font-sans">Android-Ops-Galaxy</td>
          <td class="px-3 py-2 text-emerald-400">DEVICE_LOCK</td>
          <td class="px-3 py-2"><span class="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30">ACKNOWLEDGED</span></td>
          <td class="px-3 py-2 text-slate-400 font-sans">2026-09-10 10:42:15</td>
          <td class="px-3 py-2 text-slate-400 font-sans">2026-09-10 10:42:30</td>
        </tr>
      `;
    } catch (err) {
      console.error('Failed to load command audit:', err);
    }
  },

  openEnrollModal: function() {
    const modal = document.getElementById('modal-uem-enroll');
    if (modal) modal.classList.remove('hidden');
  },

  closeEnrollModal: function() {
    const modal = document.getElementById('modal-uem-enroll');
    if (modal) modal.classList.add('hidden');
  },

  openCmdModal: function(deviceId, hostname) {
    const modal = document.getElementById('modal-uem-command');
    if (!modal) return;
    document.getElementById('cmd-target-id').value = deviceId;
    document.getElementById('cmd-target-name').innerText = `${hostname} (${deviceId})`;
    modal.classList.remove('hidden');
  },

  closeCmdModal: function() {
    const modal = document.getElementById('modal-uem-command');
    if (modal) modal.classList.add('hidden');
  },

  submitRemoteCommand: async function() {
    const deviceId = document.getElementById('cmd-target-id').value;
    const commandType = document.getElementById('cmd-type-select').value;
    const rawParams = document.getElementById('cmd-params-json').value;

    let params = {};
    if (rawParams && rawParams.trim()) {
      try {
        params = JSON.parse(rawParams);
      } catch (err) {
        alert('Invalid JSON in command parameters');
        return;
      }
    }

    try {
      const res = await fetch(`/api/v1/fleet/uem/devices/${deviceId}/commands`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ command_type: commandType, parameters: params })
      });

      if (res.ok) {
        alert(`Remote command ${commandType} queued successfully!`);
        this.closeCmdModal();
        await this.loadAll();
      } else {
        const data = await res.json();
        alert(`Failed to dispatch command: ${data.error || res.statusText}`);
      }
    } catch (err) {
      console.error('Error dispatching remote command:', err);
      alert('Network error dispatching command');
    }
  }
};
