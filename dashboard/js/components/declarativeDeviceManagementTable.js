/**
 * LocalPilot Fleet — Apple Declarative Device Management (DDM) Blade (Iteration 70)
 * dashboard/js/components/declarativeDeviceManagementTable.js
 *
 * Implements Apple DDM declarative management, autonomous state engine tracking,
 * declaration item catalog management, per-device synchronization manifests,
 * and real-time status channel telemetry inspection.
 */

window.DeclarativeDeviceManagementTable = {
  activeTab: 'declarations',

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
    this.loadDeclarations();
    this.loadManifests();
    this.loadStatusReports();
    this.setupListeners();
  },

  getTemplate: function() {
    return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-indigo-500/20 text-indigo-400 rounded-lg text-2xl border border-indigo-500/30">🍏</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Apple Declarative Device Management (DDM)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">Autonomous State Engine</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">macOS 13+ &amp; iOS 15+ client-side predicate evaluation, declaration items manifests, and status channel telemetry</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-ddm-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-ddm-new-dec" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-indigo-500/20">
            <span>➕</span> New Declaration
          </button>
          <button id="btn-ddm-assign" class="px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-purple-500/20">
            <span>📱</span> Assign to Device
          </button>
        </div>
      </div>

      <!-- KPI Overview Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" id="ddm-kpis">
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Declarations</p>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-ddm-total-decs">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-ddm-active-decs">- Active Items</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Configurations</p>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-ddm-configs">-</p>
          <p class="text-xs text-slate-500 mt-1">Passcode, Wi-Fi, Accounts</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Synchronized Manifests</p>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-ddm-synced">-</p>
          <p class="text-xs text-slate-500 mt-1">Confirmed applied by client</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Enrolled DDM Nodes</p>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-ddm-devices">-</p>
          <p class="text-xs text-slate-500 mt-1">Active subscriber devices</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Status Channel Ingests</p>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-ddm-reports">-</p>
          <p class="text-xs text-slate-500 mt-1">Autonomous status events</p>
        </div>
      </div>

      <!-- Tab Navigation -->
      <div class="border-b border-slate-700 flex gap-6 px-1">
        <button id="tab-btn-ddm-declarations" class="pb-3 text-sm font-medium text-indigo-400 border-b-2 border-indigo-400 flex items-center gap-2">
          <span>📜</span> Declarations Catalog (<span id="count-ddm-declarations">0</span>)
        </button>
        <button id="tab-btn-ddm-manifests" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
          <span>📱</span> Device Manifests (<span id="count-ddm-manifests">0</span>)
        </button>
        <button id="tab-btn-ddm-status" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
          <span>📡</span> Status Channel Telemetry (<span id="count-ddm-status">0</span>)
        </button>
      </div>

      <!-- Tab Content 1: Declarations -->
      <div id="tab-content-ddm-declarations" class="space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>🍏</span> Registered Apple DDM Declarations
          </h3>
          <div class="flex items-center gap-3">
            <select id="ddm-filter-type" class="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none">
              <option value="">All Declaration Types</option>
              <option value="configuration">Configurations</option>
              <option value="activation">Activations</option>
              <option value="asset">Assets</option>
              <option value="management">Management</option>
            </select>
          </div>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Type</th>
                  <th class="px-4 py-3">Identifier</th>
                  <th class="px-4 py-3">Server Token</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Created</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="ddm-declarations-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading declarations...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 2: Device Manifests -->
      <div id="tab-content-ddm-manifests" class="space-y-4 hidden">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>📱</span> Device Declaration Sets &amp; Sync State
          </h3>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Device ID</th>
                  <th class="px-4 py-3">Declaration Identifier</th>
                  <th class="px-4 py-3">Type</th>
                  <th class="px-4 py-3">Sync Status</th>
                  <th class="px-4 py-3">Applied Token</th>
                  <th class="px-4 py-3">Last Synced</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="ddm-manifests-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading device manifests...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 3: Status Channel Telemetry -->
      <div id="tab-content-ddm-status" class="space-y-4 hidden">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>📡</span> Ingested Status Channel Telemetry Ledger
          </h3>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Device ID</th>
                  <th class="px-4 py-3">Status Key</th>
                  <th class="px-4 py-3">Reported Value</th>
                  <th class="px-4 py-3">Received At</th>
                </tr>
              </thead>
              <tbody id="ddm-status-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="4" class="px-4 py-8 text-center text-slate-500">Loading status reports...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal Container -->
      <div id="ddm-modal-container" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden p-4"></div>
    </div>
    `;
  },

  escapeHtml: function(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  setupListeners: function() {
    const refreshBtn = document.getElementById('btn-ddm-refresh');
    if (refreshBtn) refreshBtn.onclick = () => {
      this.loadStats();
      this.loadDeclarations();
      this.loadManifests();
      this.loadStatusReports();
    };

    const newDecBtn = document.getElementById('btn-ddm-new-dec');
    if (newDecBtn) newDecBtn.onclick = () => this.showNewDeclarationModal();

    const assignBtn = document.getElementById('btn-ddm-assign');
    if (assignBtn) assignBtn.onclick = () => this.showAssignModal();

    // Tab buttons
    const btnDecs = document.getElementById('tab-btn-ddm-declarations');
    const btnMans = document.getElementById('tab-btn-ddm-manifests');
    const btnStats = document.getElementById('tab-btn-ddm-status');

    const contentDecs = document.getElementById('tab-content-ddm-declarations');
    const contentMans = document.getElementById('tab-content-ddm-manifests');
    const contentStats = document.getElementById('tab-content-ddm-status');

    const switchTab = (tab) => {
      this.activeTab = tab;
      [btnDecs, btnMans, btnStats].forEach(b => {
        b.className = 'pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2';
      });
      [contentDecs, contentMans, contentStats].forEach(c => c.classList.add('hidden'));

      if (tab === 'declarations') {
        btnDecs.className = 'pb-3 text-sm font-medium text-indigo-400 border-b-2 border-indigo-400 flex items-center gap-2';
        contentDecs.classList.remove('hidden');
      } else if (tab === 'manifests') {
        btnMans.className = 'pb-3 text-sm font-medium text-purple-400 border-b-2 border-purple-400 flex items-center gap-2';
        contentMans.classList.remove('hidden');
      } else if (tab === 'status') {
        btnStats.className = 'pb-3 text-sm font-medium text-cyan-400 border-b-2 border-cyan-400 flex items-center gap-2';
        contentStats.classList.remove('hidden');
      }
    };

    if (btnDecs) btnDecs.onclick = () => switchTab('declarations');
    if (btnMans) btnMans.onclick = () => switchTab('manifests');
    if (btnStats) btnStats.onclick = () => switchTab('status');

    const filterType = document.getElementById('ddm-filter-type');
    if (filterType) filterType.onchange = () => this.loadDeclarations();
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/ddm/stats', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-ddm-total-decs').textContent = stats.total_declarations ?? 0;
      document.getElementById('kpi-ddm-active-decs').textContent = `${stats.active_declarations ?? 0} Active Items`;
      document.getElementById('kpi-ddm-configs').textContent = stats.by_type?.configuration ?? 0;
      document.getElementById('kpi-ddm-synced').textContent = stats.synchronized_manifests ?? 0;
      document.getElementById('kpi-ddm-devices').textContent = stats.enrolled_ddm_devices ?? 0;
      document.getElementById('kpi-ddm-reports').textContent = stats.total_status_reports ?? 0;
    } catch (e) {
      console.error('Failed to load DDM stats:', e);
    }
  },

  loadDeclarations: async function() {
    const tbody = document.getElementById('ddm-declarations-tbody');
    if (!tbody) return;

    const type = document.getElementById('ddm-filter-type')?.value || '';
    let url = '/api/v1/fleet/ddm/declarations';
    if (type) url += `?declaration_type=${encodeURIComponent(type)}`;

    try {
      const res = await fetch(url, { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load declarations');
      const data = await res.json();
      const decs = data.declarations || [];

      document.getElementById('count-ddm-declarations').textContent = decs.length;

      if (decs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No declarations found.</td></tr>';
        return;
      }

      tbody.innerHTML = decs.map(d => {
        let badgeColor = 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
        if (d.declaration_type === 'activation') badgeColor = 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
        else if (d.declaration_type === 'asset') badgeColor = 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        else if (d.declaration_type === 'management') badgeColor = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs rounded font-medium ${badgeColor}">${this.escapeHtml(d.declaration_type)}</span>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-indigo-300">${this.escapeHtml(d.identifier)}</td>
            <td class="px-4 py-3 font-mono text-xs text-slate-400">${this.escapeHtml(d.server_token)}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs rounded-full ${d.is_active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-400'}">
                ${d.is_active ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </td>
            <td class="px-4 py-3 text-xs text-slate-400">${new Date(d.created_at).toLocaleDateString()}</td>
            <td class="px-4 py-3 text-right space-x-2">
              <button onclick="window.DeclarativeDeviceManagementTable.inspectPayload('${d.id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-medium rounded transition">
                Payload
              </button>
              <button onclick="window.DeclarativeDeviceManagementTable.deleteDeclaration('${d.id}')" class="px-2.5 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                Delete
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-rose-400">Error loading declarations</td></tr>';
    }
  },

  loadManifests: async function() {
    const tbody = document.getElementById('ddm-manifests-tbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/v1/fleet/ddm/manifests', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load manifests');
      const data = await res.json();
      const manifests = data.manifests || [];

      document.getElementById('count-ddm-manifests').textContent = manifests.length;

      if (manifests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No device manifests assigned.</td></tr>';
        return;
      }

      tbody.innerHTML = manifests.map(m => {
        let statusBadge = 'bg-slate-700 text-slate-300';
        if (m.sync_status === 'SYNCHRONIZED') statusBadge = 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        else if (m.sync_status === 'PENDING') statusBadge = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
        else if (m.sync_status === 'FAILED') statusBadge = 'bg-rose-500/20 text-rose-400 border border-rose-500/30';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-mono text-xs text-amber-300">${this.escapeHtml(m.device_id)}</td>
            <td class="px-4 py-3 font-mono text-xs text-indigo-300">${this.escapeHtml(m.identifier)}</td>
            <td class="px-4 py-3 text-xs capitalize">${this.escapeHtml(m.declaration_type)}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs rounded font-medium ${statusBadge}">${this.escapeHtml(m.sync_status)}</span>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-slate-400">${this.escapeHtml(m.applied_server_token || '-')}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${m.last_synced_at ? new Date(m.last_synced_at).toLocaleString() : '-'}</td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.DeclarativeDeviceManagementTable.unassignManifest('${m.id}')" class="px-2.5 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                Unassign
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-rose-400">Error loading manifests</td></tr>';
    }
  },

  loadStatusReports: async function() {
    const tbody = document.getElementById('ddm-status-tbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/v1/fleet/ddm/status-reports?limit=50', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load status reports');
      const data = await res.json();
      const reports = data.reports || [];

      document.getElementById('count-ddm-status').textContent = reports.length;

      if (reports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-500">No status channel events received yet.</td></tr>';
        return;
      }

      tbody.innerHTML = reports.map(r => `
        <tr class="hover:bg-slate-700/30 transition">
          <td class="px-4 py-3 font-mono text-xs text-amber-300">${this.escapeHtml(r.device_id)}</td>
          <td class="px-4 py-3 font-mono text-xs font-semibold text-cyan-300">${this.escapeHtml(r.status_key)}</td>
          <td class="px-4 py-3 text-xs font-mono text-slate-300 max-w-xs truncate">${this.escapeHtml(JSON.stringify(r.value))}</td>
          <td class="px-4 py-3 text-xs text-slate-400">${new Date(r.received_at).toLocaleString()}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="4" class="px-4 py-8 text-center text-rose-400">Error loading status reports</td></tr>';
    }
  },

  inspectPayload: async function(declarationId) {
    try {
      const res = await fetch(`/api/v1/fleet/ddm/declarations/${declarationId}`, { headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch declaration payload');
      const data = await res.json();
      const d = data.declaration;

      const modal = document.getElementById('ddm-modal-container');
      modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-lg w-full space-y-4 shadow-2xl">
          <div class="flex items-center justify-between border-b border-slate-700 pb-3">
            <h3 class="text-base font-bold text-white flex items-center gap-2">
              <span>🍏</span> DDM Payload: ${this.escapeHtml(d.identifier)}
            </h3>
            <button onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs text-slate-300">
            <div class="grid grid-cols-2 gap-2">
              <div><span class="text-slate-500">Type:</span> <span class="capitalize font-semibold text-indigo-400">${this.escapeHtml(d.declaration_type)}</span></div>
              <div><span class="text-slate-500">Token:</span> <span class="font-mono">${this.escapeHtml(d.server_token)}</span></div>
            </div>
            <div>
              <span class="text-slate-500">JSON Payload:</span>
              <pre class="mt-1 bg-slate-900/80 p-3 rounded text-slate-300 overflow-x-auto max-h-56 font-mono text-[11px]">${this.escapeHtml(JSON.stringify(d.payload, null, 2))}</pre>
            </div>
          </div>
          <div class="flex justify-end pt-2">
            <button onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-xs font-semibold">Close</button>
          </div>
        </div>
      `;
      modal.classList.remove('hidden');
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  deleteDeclaration: async function(declarationId) {
    if (!confirm('Are you sure you want to delete this Apple DDM declaration item?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/ddm/declarations/${declarationId}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (!res.ok) throw new Error('Failed to delete declaration');
      this.loadStats();
      this.loadDeclarations();
      this.loadManifests();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  unassignManifest: async function(manifestId) {
    if (!confirm('Unassign this declaration from target device?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/ddm/manifests/${manifestId}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (!res.ok) throw new Error('Failed to unassign manifest');
      this.loadStats();
      this.loadManifests();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  showNewDeclarationModal: function() {
    const modal = document.getElementById('ddm-modal-container');
    modal.innerHTML = `
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>➕</span> New Apple DDM Declaration
          </h3>
          <button onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
        </div>
        <form id="form-new-dec" class="space-y-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Declaration Type</label>
            <select id="input-dec-type" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
              <option value="configuration">Configuration</option>
              <option value="activation">Activation</option>
              <option value="asset">Asset</option>
              <option value="management">Management</option>
            </select>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Reverse-DNS Identifier</label>
            <input id="input-dec-ident" type="text" placeholder="com.localpilot.declaration.security.sample" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-indigo-500 font-mono" required />
          </div>
          <div>
            <label class="block text-slate-400 mb-1">JSON Payload</label>
            <textarea id="input-dec-payload" rows="5" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-indigo-500 font-mono text-[11px]" required>{
  "sample_key": "sample_value"
}</textarea>
          </div>
          <div class="flex justify-end gap-2 pt-3">
            <button type="button" onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded font-medium">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-semibold">Create Item</button>
          </div>
        </form>
      </div>
    `;
    modal.classList.remove('hidden');

    document.getElementById('form-new-dec').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const payloadJson = JSON.parse(document.getElementById('input-dec-payload').value);
        const payload = {
          declaration_type: document.getElementById('input-dec-type').value,
          identifier: document.getElementById('input-dec-ident').value.trim(),
          payload: payloadJson
        };

        const res = await fetch('/api/v1/fleet/ddm/declarations', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Failed to create declaration');
        modal.classList.add('hidden');
        this.loadStats();
        this.loadDeclarations();
      } catch (err) {
        alert('Error: ' + err.message);
      }
    };
  },

  showAssignModal: async function() {
    const modal = document.getElementById('ddm-modal-container');
    modal.innerHTML = `
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>📱</span> Assign Declaration to Device
          </h3>
          <button onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
        </div>
        <form id="form-assign-dec" class="space-y-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Target Device ID</label>
            <input id="input-assign-dev-id" type="text" placeholder="Device ID (e.g. dev-daddy-pc)" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-purple-500 font-mono" required />
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Declaration Identifier / ID</label>
            <input id="input-assign-dec-id" type="text" placeholder="e.g. com.localpilot.declaration.security.passcode" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-purple-500 font-mono" required />
          </div>
          <div class="flex justify-end gap-2 pt-3">
            <button type="button" onclick="document.getElementById('ddm-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded font-medium">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded font-semibold">Assign Declaration</button>
          </div>
        </form>
      </div>
    `;
    modal.classList.remove('hidden');

    document.getElementById('form-assign-dec').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const payload = {
          device_id: document.getElementById('input-assign-dev-id').value.trim(),
          declaration_id: document.getElementById('input-assign-dec-id').value.trim()
        };

        const res = await fetch('/api/v1/fleet/ddm/manifests/assign', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Failed to assign declaration');
        modal.classList.add('hidden');
        this.loadStats();
        this.loadManifests();
      } catch (err) {
        alert('Error: ' + err.message);
      }
    };
  }
};
