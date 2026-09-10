/**
 * LocalPilot Fleet — Mobile Application Management (MAM) & App Protection Blade
 * dashboard/js/components/mamAppProtectionTable.js
 *
 * Implements enterprise mobile data containerization, clipboard sandboxing,
 * app-level biometric authentication, and selective corporate wipe management.
 */

function renderMamAppProtectionBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">💼</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Mobile Application Management (MAM)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">App Protection</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Enterprise data containerization, clipboard DLP sandboxing, biometric/PIN access locks, and selective corporate wipe</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-mam-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-mam-new-policy" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>➕</span> New MAM Policy
          </button>
          <button id="btn-mam-selective-wipe" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>⚡</span> Issue Selective Wipe
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="mam-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Policies</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-mam-policies">-</p>
          <p class="text-xs text-slate-500 mt-1">iOS, Android &amp; Windows</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Managed Apps</p>
            <span class="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-md text-sm">📱</span>
          </div>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-mam-apps">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-mam-enlightened">- SDK Enlightened</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Selective Wipes</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-mam-wipes">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-mam-pending-wipes">- Pending Dispatches</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Clipboard DLP</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📋</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2">Sandboxed</p>
          <p class="text-xs text-slate-500 mt-1">Managed Apps Only</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Biometric Auth</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🔐</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2">Enforced</p>
          <p class="text-xs text-slate-500 mt-1">FaceID / TouchID / PIN</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Offline Grace</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">⏱️</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2">12 Hours</p>
          <p class="text-xs text-slate-500 mt-1">720 min timeout</p>
        </div>
      </div>

      <!-- Navigation Sub-Tabs -->
      <div class="flex items-center gap-2 border-b border-slate-700 pb-3">
        <button class="mam-tab-btn px-4 py-2 rounded-lg text-sm font-semibold transition bg-rose-600 text-white" data-tab="policies">
          📜 App Protection Policies
        </button>
        <button class="mam-tab-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-tab="apps">
          📱 Managed Apps Catalog
        </button>
        <button class="mam-tab-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300" data-tab="wipes">
          ⚡ Selective Wipe Orchestrator
        </button>
      </div>

      <!-- Section: App Protection Policies Table -->
      <div id="mam-view-policies" class="mam-view-section bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
          <h3 class="font-semibold text-slate-200 flex items-center gap-2">
            <span>📜</span> Corporate Application Protection Policies
          </h3>
          <span class="text-xs text-slate-400" id="mam-policies-count">0 policies active</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th class="px-4 py-3">Policy Name</th>
                <th class="px-4 py-3">Platform</th>
                <th class="px-4 py-3">Clipboard Sandbox</th>
                <th class="px-4 py-3">Save-As Restriction</th>
                <th class="px-4 py-3">Biometric / PIN</th>
                <th class="px-4 py-3">Offline Limit</th>
                <th class="px-4 py-3">Apps</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="mam-policies-tbody" class="divide-y divide-slate-700/50">
              <tr><td colspan="8" class="text-center py-6 text-slate-500">Loading MAM policies...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section: Managed Apps Catalog Table (Hidden by default) -->
      <div id="mam-view-apps" class="mam-view-section bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
          <h3 class="font-semibold text-slate-200 flex items-center gap-2">
            <span>📱</span> Managed Corporate Applications Catalog
          </h3>
          <button id="btn-mam-add-app" class="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-medium transition">
            + Add Managed App
          </button>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th class="px-4 py-3">Application</th>
                <th class="px-4 py-3">Bundle / Package Identifier</th>
                <th class="px-4 py-3">Platform</th>
                <th class="px-4 py-3">Assigned Policy</th>
                <th class="px-4 py-3">SDK Enlightened</th>
                <th class="px-4 py-3">Min Version</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="mam-apps-tbody" class="divide-y divide-slate-700/50">
              <tr><td colspan="7" class="text-center py-6 text-slate-500">Loading managed apps...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section: Selective Wipe Orchestrator Table (Hidden by default) -->
      <div id="mam-view-wipes" class="mam-view-section bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between">
          <div>
            <h3 class="font-semibold text-slate-200 flex items-center gap-2">
              <span>⚡</span> Selective Corporate Wipe Audit Trail
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Revokes enterprise accounts and cryptographic keys without deleting personal photos, texts, or apps</p>
          </div>
          <span class="text-xs text-slate-400" id="mam-wipes-count">0 wipe orders</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th class="px-4 py-3">Wipe ID</th>
                <th class="px-4 py-3">Target Corporate Identity</th>
                <th class="px-4 py-3">Reason</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Issued By</th>
                <th class="px-4 py-3">Issued At</th>
                <th class="px-4 py-3">Completed At</th>
                <th class="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="mam-wipes-tbody" class="divide-y divide-slate-700/50">
              <tr><td colspan="8" class="text-center py-6 text-slate-500">Loading selective wipe audit trail...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Create MAM Policy Modal -->
    <div id="modal-mam-policy" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-xl w-full p-6 space-y-4">
        <div class="flex justify-between items-center border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>📜</span> Create MAM App Protection Policy
          </h3>
          <button id="btn-close-mam-policy-modal" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block font-semibold text-slate-300 mb-1">Policy Name</label>
            <input type="text" id="input-mam-pol-name" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200" placeholder="e.g. Strict Zero-Trust Mobile MAM Baseline" />
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block font-semibold text-slate-300 mb-1">Target Platform</label>
              <select id="select-mam-pol-plat" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200">
                <option value="COMBINED">Universal (iOS &amp; Android)</option>
                <option value="IOS">Apple iOS / iPadOS</option>
                <option value="ANDROID">Google Android</option>
                <option value="WINDOWS">Windows Endpoint MAM</option>
              </select>
            </div>
            <div>
              <label class="block font-semibold text-slate-300 mb-1">Clipboard Sharing Mode</label>
              <select id="select-mam-pol-clip" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200">
                <option value="POLICY_MANAGED_APPS_ONLY">Policy Managed Apps Only (Sandboxed)</option>
                <option value="POLICY_MANAGED_WITH_PASTE_IN">Allow Paste In From External</option>
                <option value="BLOCKED">Completely Block Clipboard</option>
                <option value="ANY_APP">Unrestricted (Not Recommended)</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block font-semibold text-slate-300 mb-1">Allowed Storage Relocation</label>
              <select id="select-mam-pol-storage" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200">
                <option value="MANAGED_STORAGE_ONLY">Managed Corporate Storage Only</option>
                <option value="LOCAL_STORAGE_BLOCKED">Block Local Device Storage</option>
                <option value="ANY_STORAGE">Any Storage Destination</option>
              </select>
            </div>
            <div>
              <label class="block font-semibold text-slate-300 mb-1">Max Offline Grace Period (minutes)</label>
              <input type="number" id="input-mam-pol-offline" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200" value="720" />
            </div>
          </div>

          <div class="space-y-2 pt-2 border-t border-slate-700">
            <label class="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input type="checkbox" id="check-mam-pol-saveas" checked class="rounded bg-slate-900 border-slate-700 text-rose-600" />
              <span>Prevent Save As of corporate documents to personal cloud or SD cards</span>
            </label>
            <label class="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input type="checkbox" id="check-mam-pol-screen" checked class="rounded bg-slate-900 border-slate-700 text-rose-600" />
              <span>Block screenshots on Android / blur task switcher on iOS</span>
            </label>
            <label class="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input type="checkbox" id="check-mam-pol-pin" checked class="rounded bg-slate-900 border-slate-700 text-rose-600" />
              <span>Require biometric auth (Face ID / Touch ID) or PIN to open app</span>
            </label>
            <label class="flex items-center gap-2 text-slate-300 cursor-pointer">
              <input type="checkbox" id="check-mam-pol-jailbreak" checked class="rounded bg-slate-900 border-slate-700 text-rose-600" />
              <span>Trigger instant corporate wipe if device is jailbroken or rooted</span>
            </label>
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-3 border-t border-slate-700">
          <button id="btn-cancel-mam-policy" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-xs font-medium transition">
            Cancel
          </button>
          <button id="btn-submit-mam-policy" class="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition">
            Create Policy
          </button>
        </div>
      </div>
    </div>

    <!-- Issue Selective Wipe Modal -->
    <div id="modal-mam-wipe" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
      <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-md w-full p-6 space-y-4">
        <div class="flex justify-between items-center border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>⚡</span> Issue Selective Corporate Wipe
          </h3>
          <button id="btn-close-mam-wipe-modal" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
        </div>

        <div class="space-y-3 text-xs">
          <p class="text-slate-400">
            This will selectively purge all corporate accounts, encrypted documents, and cached emails from managed apps without resetting personal photos or apps.
          </p>

          <div>
            <label class="block font-semibold text-slate-300 mb-1">Target Corporate User Email</label>
            <input type="email" id="input-wipe-email" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200" placeholder="e.g. sarah.connor@localpilot.corp" />
          </div>

          <div>
            <label class="block font-semibold text-slate-300 mb-1">Wipe Reason</label>
            <select id="select-wipe-reason" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-200">
              <option value="USER_OFFBOARDED">User Offboarded / Resigned</option>
              <option value="DEVICE_LOST">Device Reported Lost / Stolen</option>
              <option value="COMPROMISED">Security Compromise / Malware Detected</option>
              <option value="ADMIN_REQUEST">Administrative Revocation</option>
              <option value="POLICY_NON_COMPLIANT">Persistent Policy Non-Compliance</option>
            </select>
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-3 border-t border-slate-700">
          <button id="btn-cancel-mam-wipe" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-xs font-medium transition">
            Cancel
          </button>
          <button id="btn-submit-mam-wipe" class="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition">
            Dispatch Selective Wipe
          </button>
        </div>
      </div>
    </div>
  `;
}

window.MamAppProtectionTable = {
  activeTab: 'policies',

  getHeaders: function() {
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': localStorage.getItem('fleet_key') || '8161bd42-02a7-47b0-b7eb-efbf5fdda1ed'
    };
  },

  render: function() {
    const container = document.getElementById('view-container') || document.getElementById('main-content');
    if (!container) return;
    container.innerHTML = renderMamAppProtectionBlade();
    this.bindEvents();
    this.loadAll();
  },

  bindEvents: function() {
    const refreshBtn = document.getElementById('btn-mam-refresh');
    if (refreshBtn) refreshBtn.onclick = () => this.loadAll();

    const newPolBtn = document.getElementById('btn-mam-new-policy');
    if (newPolBtn) newPolBtn.onclick = () => this.openPolicyModal();

    const closePolModal = document.getElementById('btn-close-mam-policy-modal');
    if (closePolModal) closePolModal.onclick = () => this.closePolicyModal();

    const cancelPolModal = document.getElementById('btn-cancel-mam-policy');
    if (cancelPolModal) cancelPolModal.onclick = () => this.closePolicyModal();

    const submitPolBtn = document.getElementById('btn-submit-mam-policy');
    if (submitPolBtn) submitPolBtn.onclick = () => this.submitPolicy();

    const wipeBtn = document.getElementById('btn-mam-selective-wipe');
    if (wipeBtn) wipeBtn.onclick = () => this.openWipeModal();

    const closeWipeModal = document.getElementById('btn-close-mam-wipe-modal');
    if (closeWipeModal) closeWipeModal.onclick = () => this.closeWipeModal();

    const cancelWipeModal = document.getElementById('btn-cancel-mam-wipe');
    if (cancelWipeModal) cancelWipeModal.onclick = () => this.closeWipeModal();

    const submitWipeBtn = document.getElementById('btn-submit-mam-wipe');
    if (submitWipeBtn) submitWipeBtn.onclick = () => this.submitWipe();

    document.querySelectorAll('.mam-tab-btn').forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll('.mam-tab-btn').forEach(b => {
          b.className = 'mam-tab-btn px-4 py-2 rounded-lg text-sm font-medium transition bg-slate-800 hover:bg-slate-700 text-slate-300';
        });
        btn.className = 'mam-tab-btn px-4 py-2 rounded-lg text-sm font-semibold transition bg-rose-600 text-white';

        document.querySelectorAll('.mam-view-section').forEach(sec => sec.classList.add('hidden'));
        const activeView = document.getElementById(`mam-view-${btn.dataset.tab}`);
        if (activeView) activeView.classList.remove('hidden');
      };
    });
  },

  loadAll: async function() {
    await Promise.all([
      this.loadStats(),
      this.loadPolicies(),
      this.loadApps(),
      this.loadWipes()
    ]);
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/mam/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-mam-policies').innerText = stats.total_policies || 0;
      document.getElementById('kpi-mam-apps').innerText = stats.total_managed_apps || 0;
      document.getElementById('kpi-mam-enlightened').innerText = `${stats.enlightened_apps || 0} SDK Enlightened`;
      document.getElementById('kpi-mam-wipes').innerText = stats.total_selective_wipes || 0;
      document.getElementById('kpi-mam-pending-wipes').innerText = `${stats.pending_selective_wipes || 0} Pending`;
    } catch (err) {
      console.error('Failed to load MAM stats:', err);
    }
  },

  loadPolicies: async function() {
    try {
      const res = await fetch('/api/v1/fleet/mam/policies', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const policies = data.policies || [];
      const tbody = document.getElementById('mam-policies-tbody');
      const countEl = document.getElementById('mam-policies-count');
      if (!tbody) return;

      if (countEl) countEl.innerText = `${policies.length} policies active`;

      if (policies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No MAM App Protection policies found.</td></tr>';
        return;
      }

      tbody.innerHTML = policies.map(p => {
        let platBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">🌐 Universal</span>';
        if (p.platform === 'IOS') platBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/30">🍏 iOS</span>';
        if (p.platform === 'ANDROID') platBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">🤖 Android</span>';

        let clipBadge = '<span class="text-xs text-cyan-400">📋 Managed Only</span>';
        if (p.clipboard_sharing_mode === 'BLOCKED') clipBadge = '<span class="text-xs text-rose-400">🚫 Blocked</span>';
        if (p.clipboard_sharing_mode === 'POLICY_MANAGED_WITH_PASTE_IN') clipBadge = '<span class="text-xs text-teal-400">📥 Paste-In Allowed</span>';

        return `
          <tr class="hover:bg-slate-800/50 transition font-sans text-xs">
            <td class="px-4 py-3 font-semibold text-slate-200">
              ${p.name}
              <div class="text-[10px] text-slate-500 font-mono">${p.id}</div>
            </td>
            <td class="px-4 py-3">${platBadge}</td>
            <td class="px-4 py-3">${clipBadge}</td>
            <td class="px-4 py-3 text-slate-300">${p.prevent_save_as ? '🛡️ Prevented' : 'Allowed'}</td>
            <td class="px-4 py-3 text-emerald-400 font-medium">${p.require_pin_or_biometrics ? `🔐 FaceID / ${p.min_pin_length}-PIN` : 'None'}</td>
            <td class="px-4 py-3 text-slate-400">${p.max_offline_grace_minutes} mins</td>
            <td class="px-4 py-3 text-slate-300">${p.assigned_apps_count || 0} apps</td>
            <td class="px-4 py-3 text-right">
              <a href="/api/v1/fleet/mam/policies/${p.id}/config" target="_blank" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs font-medium transition inline-block">
                📥 SDK Config
              </a>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load MAM policies:', err);
    }
  },

  loadApps: async function() {
    try {
      const res = await fetch('/api/v1/fleet/mam/apps', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const apps = data.apps || [];
      const tbody = document.getElementById('mam-apps-tbody');
      if (!tbody) return;

      if (apps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-slate-500">No managed corporate apps registered.</td></tr>';
        return;
      }

      tbody.innerHTML = apps.map(a => `
        <tr class="hover:bg-slate-800/50 transition font-sans text-xs">
          <td class="px-4 py-3 font-semibold text-slate-200">${a.app_name}</td>
          <td class="px-4 py-3 font-mono text-slate-400">${a.bundle_id}</td>
          <td class="px-4 py-3 text-slate-300">${a.platform}</td>
          <td class="px-4 py-3 text-rose-400">${a.policy_name || a.policy_id}</td>
          <td class="px-4 py-3 text-emerald-400">${a.is_enlightened ? '✅ Enlightened SDK' : 'App Wrapping'}</td>
          <td class="px-4 py-3 text-slate-400">${a.min_app_version || '1.0.0'}</td>
          <td class="px-4 py-3 text-right">
            <button onclick="window.MamAppProtectionTable.deleteApp('${a.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-700 text-slate-300 hover:text-white rounded text-xs transition">
              Remove
            </button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load MAM apps:', err);
    }
  },

  loadWipes: async function() {
    try {
      const res = await fetch('/api/v1/fleet/mam/selective-wipes', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const wipes = data.wipes || [];
      const tbody = document.getElementById('mam-wipes-tbody');
      const countEl = document.getElementById('mam-wipes-count');
      if (!tbody) return;

      if (countEl) countEl.innerText = `${wipes.length} wipe orders`;

      if (wipes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No selective wipe orders recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = wipes.map(w => {
        let statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">COMPLETED</span>';
        if (w.status === 'PENDING') {
          statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse">PENDING DISPATCH</span>';
        } else if (w.status === 'CANCELLED') {
          statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-slate-700 text-slate-400">CANCELLED</span>';
        }

        return `
          <tr class="hover:bg-slate-800/50 transition font-mono text-xs">
            <td class="px-4 py-3 text-slate-400">${w.id}</td>
            <td class="px-4 py-3 font-sans font-semibold text-white">${w.target_user_email}</td>
            <td class="px-4 py-3 text-slate-300 font-sans">${w.wipe_reason}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 text-slate-400 font-sans">${w.issued_by}</td>
            <td class="px-4 py-3 text-slate-400 font-sans">${w.issued_at}</td>
            <td class="px-4 py-3 text-slate-400 font-sans">${w.completed_at || '-'}</td>
            <td class="px-4 py-3 text-right">
              ${w.status === 'PENDING' ? `
                <button onclick="window.MamAppProtectionTable.cancelWipe('${w.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-700 text-slate-300 hover:text-white rounded text-xs transition">
                  Cancel
                </button>
              ` : '-'}
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load selective wipes:', err);
    }
  },

  openPolicyModal: function() {
    const modal = document.getElementById('modal-mam-policy');
    if (modal) modal.classList.remove('hidden');
  },

  closePolicyModal: function() {
    const modal = document.getElementById('modal-mam-policy');
    if (modal) modal.classList.add('hidden');
  },

  submitPolicy: async function() {
    const name = document.getElementById('input-mam-pol-name').value;
    if (!name) {
      alert('Policy name is required');
      return;
    }

    const payload = {
      name,
      platform: document.getElementById('select-mam-pol-plat').value,
      clipboard_sharing_mode: document.getElementById('select-mam-pol-clip').value,
      allowed_data_storage: document.getElementById('select-mam-pol-storage').value,
      max_offline_grace_minutes: Number(document.getElementById('input-mam-pol-offline').value) || 720,
      prevent_save_as: document.getElementById('check-mam-pol-saveas').checked,
      prevent_screen_capture: document.getElementById('check-mam-pol-screen').checked,
      require_pin_or_biometrics: document.getElementById('check-mam-pol-pin').checked,
      block_jailbroken_rooted: document.getElementById('check-mam-pol-jailbreak').checked
    };

    try {
      const res = await fetch('/api/v1/fleet/mam/policies', {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        this.closePolicyModal();
        await this.loadAll();
      } else {
        const err = await res.json();
        alert('Failed to create MAM policy: ' + (err.message || res.statusText));
      }
    } catch (err) {
      console.error('Error creating MAM policy:', err);
    }
  },

  openWipeModal: function() {
    const modal = document.getElementById('modal-mam-wipe');
    if (modal) modal.classList.remove('hidden');
  },

  closeWipeModal: function() {
    const modal = document.getElementById('modal-mam-wipe');
    if (modal) modal.classList.add('hidden');
  },

  submitWipe: async function() {
    const userEmail = document.getElementById('input-wipe-email').value;
    if (!userEmail) {
      alert('Target user email is required');
      return;
    }

    const payload = {
      target_user_email: userEmail,
      wipe_reason: document.getElementById('select-wipe-reason').value
    };

    try {
      const res = await fetch('/api/v1/fleet/mam/selective-wipes', {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        this.closeWipeModal();
        await this.loadAll();
      } else {
        const err = await res.json();
        alert('Failed to issue selective wipe: ' + (err.message || res.statusText));
      }
    } catch (err) {
      console.error('Error issuing selective wipe:', err);
    }
  },

  cancelWipe: async function(id) {
    if (!confirm('Cancel this pending selective wipe order?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/mam/selective-wipes/${id}/cancel`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) {
        await this.loadWipes();
      } else {
        alert('Failed to cancel selective wipe');
      }
    } catch (err) {
      console.error('Error cancelling wipe:', err);
    }
  },

  deleteApp: async function(id) {
    if (!confirm('Remove this app from MAM protection catalog?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/mam/apps/${id}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        await this.loadAll();
      } else {
        alert('Failed to delete managed app');
      }
    } catch (err) {
      console.error('Error deleting app:', err);
    }
  }
};
