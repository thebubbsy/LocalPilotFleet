/**
 * LocalPilot Fleet — Mobile Threat Defense (MTD) & Device Risk Posture Blade (Iteration 69)
 * dashboard/js/components/mobileThreatDefenseTable.js
 *
 * Implements multi-platform jailbreak/root detection, behavioral anomaly tracking,
 * dynamic device risk scoring, compliance policy evaluation, and automated
 * cross-subsystem MAM selective wipe orchestration.
 */

window.MobileThreatDefenseTable = {
  activeTab: 'signals',

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
    this.loadSignals();
    this.loadPolicies();
    this.loadRemediations();
    this.setupListeners();
  },

  getTemplate: function() {
    return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-amber-500/20 text-amber-400 rounded-lg text-2xl border border-amber-500/30">🛡️</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Mobile Threat Defense (MTD) &amp; Device Risk Posture
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">Zero-Trust CA</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Real-time jailbreak/root telemetry, multi-factor risk scores, and automated MAM selective wipe remediation</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-mtd-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-mtd-new-signal" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>⚠️</span> Ingest Threat Signal
          </button>
          <button id="btn-mtd-new-policy" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>➕</span> New Risk Policy
          </button>
        </div>
      </div>

      <!-- KPI Overview Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" id="mtd-kpis">
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Threat Signals</p>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-mtd-total-signals">-</p>
          <p class="text-xs text-slate-500 mt-1" id="kpi-mtd-active-signals">- Active Threats</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Risk Devices</p>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-mtd-critical-devices">-</p>
          <p class="text-xs text-slate-500 mt-1">Immediate CA action required</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">High Risk Devices</p>
          <p class="text-2xl font-bold text-orange-400 mt-2" id="kpi-mtd-high-devices">-</p>
          <p class="text-xs text-slate-500 mt-1">Elevated risk state</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Compliance Policies</p>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-mtd-policies">-</p>
          <p class="text-xs text-slate-500 mt-1">Multi-platform active</p>
        </div>
        <div class="bg-slate-800/60 border border-slate-700/60 rounded-xl p-4 shadow-sm backdrop-blur-sm">
          <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediations Triggered</p>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-mtd-remediations">-</p>
          <p class="text-xs text-slate-500 mt-1">Auto-wipe &amp; Quarantines</p>
        </div>
      </div>

      <!-- Tab Navigation -->
      <div class="border-b border-slate-700 flex gap-6 px-1">
        <button id="tab-btn-mtd-signals" class="pb-3 text-sm font-medium text-amber-400 border-b-2 border-amber-400 flex items-center gap-2">
          <span>⚠️</span> Threat Signals (<span id="count-mtd-signals">0</span>)
        </button>
        <button id="tab-btn-mtd-policies" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
          <span>📋</span> Risk Compliance Policies (<span id="count-mtd-policies">0</span>)
        </button>
        <button id="tab-btn-mtd-remediations" class="pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2">
          <span>⚡</span> Remediation Ledger (<span id="count-mtd-remediations">0</span>)
        </button>
      </div>

      <!-- Tab Content 1: Threat Signals -->
      <div id="tab-content-mtd-signals" class="space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>🛡️</span> Ingested Device Threat Signals
          </h3>
          <div class="flex items-center gap-3">
            <select id="mtd-filter-threat-level" class="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none">
              <option value="">All Threat Levels</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
            <select id="mtd-filter-status" class="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none">
              <option value="">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Device ID</th>
                  <th class="px-4 py-3">Platform</th>
                  <th class="px-4 py-3">Threat Type</th>
                  <th class="px-4 py-3">Threat Level</th>
                  <th class="px-4 py-3">Detection Engine</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Reported At</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="mtd-signals-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="8" class="px-4 py-8 text-center text-slate-500">Loading threat signals...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 2: Risk Compliance Policies -->
      <div id="tab-content-mtd-policies" class="space-y-4 hidden">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>📋</span> Active Risk-Based Compliance Policies
          </h3>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Policy Name</th>
                  <th class="px-4 py-3">Platform</th>
                  <th class="px-4 py-3">Max Allowed Risk</th>
                  <th class="px-4 py-3">Enforce Controls</th>
                  <th class="px-4 py-3">Auto-Remediation</th>
                  <th class="px-4 py-3">Created</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="mtd-policies-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading compliance policies...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab Content 3: Remediation Ledger -->
      <div id="tab-content-mtd-remediations" class="space-y-4 hidden">
        <div class="flex items-center justify-between">
          <h3 class="text-base font-semibold text-slate-200 flex items-center gap-2">
            <span>⚡</span> Automated &amp; Manual Remediation Execution Ledger
          </h3>
        </div>

        <div class="bg-slate-800/80 border border-slate-700/60 rounded-xl overflow-hidden shadow-sm">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/60 text-xs uppercase font-semibold text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Remediation ID</th>
                  <th class="px-4 py-3">Device ID</th>
                  <th class="px-4 py-3">Action Type</th>
                  <th class="px-4 py-3">Trigger Reason</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Executed At</th>
                </tr>
              </thead>
              <tbody id="mtd-remediations-tbody" class="divide-y divide-slate-700/40">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading remediation ledger...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Modal Container -->
      <div id="mtd-modal-container" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden p-4"></div>
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
    const refreshBtn = document.getElementById('btn-mtd-refresh');
    if (refreshBtn) refreshBtn.onclick = () => {
      this.loadStats();
      this.loadSignals();
      this.loadPolicies();
      this.loadRemediations();
    };

    const newSignalBtn = document.getElementById('btn-mtd-new-signal');
    if (newSignalBtn) newSignalBtn.onclick = () => this.showIngestSignalModal();

    const newPolicyBtn = document.getElementById('btn-mtd-new-policy');
    if (newPolicyBtn) newPolicyBtn.onclick = () => this.showNewPolicyModal();

    // Tab buttons
    const btnSignals = document.getElementById('tab-btn-mtd-signals');
    const btnPolicies = document.getElementById('tab-btn-mtd-policies');
    const btnRemediations = document.getElementById('tab-btn-mtd-remediations');

    const contentSignals = document.getElementById('tab-content-mtd-signals');
    const contentPolicies = document.getElementById('tab-content-mtd-policies');
    const contentRemediations = document.getElementById('tab-content-mtd-remediations');

    const switchTab = (tab) => {
      this.activeTab = tab;
      [btnSignals, btnPolicies, btnRemediations].forEach(b => {
        b.className = 'pb-3 text-sm font-medium text-slate-400 hover:text-slate-200 border-b-2 border-transparent flex items-center gap-2';
      });
      [contentSignals, contentPolicies, contentRemediations].forEach(c => c.classList.add('hidden'));

      if (tab === 'signals') {
        btnSignals.className = 'pb-3 text-sm font-medium text-amber-400 border-b-2 border-amber-400 flex items-center gap-2';
        contentSignals.classList.remove('hidden');
      } else if (tab === 'policies') {
        btnPolicies.className = 'pb-3 text-sm font-medium text-blue-400 border-b-2 border-blue-400 flex items-center gap-2';
        contentPolicies.classList.remove('hidden');
      } else if (tab === 'remediations') {
        btnRemediations.className = 'pb-3 text-sm font-medium text-emerald-400 border-b-2 border-emerald-400 flex items-center gap-2';
        contentRemediations.classList.remove('hidden');
      }
    };

    if (btnSignals) btnSignals.onclick = () => switchTab('signals');
    if (btnPolicies) btnPolicies.onclick = () => switchTab('policies');
    if (btnRemediations) btnRemediations.onclick = () => switchTab('remediations');

    const filterLevel = document.getElementById('mtd-filter-threat-level');
    const filterStatus = document.getElementById('mtd-filter-status');
    if (filterLevel) filterLevel.onchange = () => this.loadSignals();
    if (filterStatus) filterStatus.onchange = () => this.loadSignals();
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/mtd/stats', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || {};

      document.getElementById('kpi-mtd-total-signals').textContent = stats.total_signals ?? 0;
      document.getElementById('kpi-mtd-active-signals').textContent = `${stats.active_signals ?? 0} Active Threats`;
      document.getElementById('kpi-mtd-critical-devices').textContent = stats.critical_risk_devices ?? 0;
      document.getElementById('kpi-mtd-high-devices').textContent = stats.high_risk_devices ?? 0;
      document.getElementById('kpi-mtd-policies').textContent = stats.total_policies ?? 0;
      document.getElementById('kpi-mtd-remediations').textContent = stats.total_remediations ?? 0;
    } catch (e) {
      console.error('Failed to load MTD stats:', e);
    }
  },

  loadSignals: async function() {
    const tbody = document.getElementById('mtd-signals-tbody');
    if (!tbody) return;

    const level = document.getElementById('mtd-filter-threat-level')?.value || '';
    const status = document.getElementById('mtd-filter-status')?.value || '';

    let url = '/api/v1/fleet/mtd/signals?limit=100';
    if (level) url += `&threat_level=${encodeURIComponent(level)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;

    try {
      const res = await fetch(url, { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load signals');
      const data = await res.json();
      const signals = data.signals || [];

      document.getElementById('count-mtd-signals').textContent = signals.length;

      if (signals.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500">No threat signals found. All devices secure.</td></tr>';
        return;
      }

      tbody.innerHTML = signals.map(s => {
        let badgeColor = 'bg-slate-700 text-slate-300';
        if (s.threat_level === 'CRITICAL') badgeColor = 'bg-rose-500/20 text-rose-400 border border-rose-500/30';
        else if (s.threat_level === 'HIGH') badgeColor = 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
        else if (s.threat_level === 'MEDIUM') badgeColor = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
        else if (s.threat_level === 'LOW') badgeColor = 'bg-blue-500/20 text-blue-400 border border-blue-500/30';

        const statusBadge = s.status === 'ACTIVE' 
          ? '<span class="px-2 py-0.5 text-xs rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">ACTIVE</span>'
          : '<span class="px-2 py-0.5 text-xs rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">RESOLVED</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-mono text-xs text-amber-300">${this.escapeHtml(s.device_id)}</td>
            <td class="px-4 py-3 text-xs capitalize">${this.escapeHtml(s.platform || 'all')}</td>
            <td class="px-4 py-3 font-semibold text-slate-200">${this.escapeHtml(s.signal_type || s.threat_type)}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs rounded font-medium ${badgeColor}">${this.escapeHtml(s.threat_level)}</span>
            </td>
            <td class="px-4 py-3 text-xs text-slate-400">${this.escapeHtml(s.detection_engine || 'Native Agent')}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${new Date(s.reported_at).toLocaleString()}</td>
            <td class="px-4 py-3 text-right space-x-2">
              ${s.status === 'ACTIVE' ? `
                <button onclick="window.MobileThreatDefenseTable.resolveSignal('${s.id}')" class="px-2.5 py-1 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium rounded transition">
                  ✓ Resolve
                </button>
              ` : ''}
              <button onclick="window.MobileThreatDefenseTable.showSignalDetails('${s.id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-medium rounded transition">
                Details
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-rose-400">Error loading signals</td></tr>';
    }
  },

  loadPolicies: async function() {
    const tbody = document.getElementById('mtd-policies-tbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/v1/fleet/mtd/policies', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load policies');
      const data = await res.json();
      const policies = data.policies || [];

      document.getElementById('count-mtd-policies').textContent = policies.length;

      if (policies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No MTD compliance policies defined.</td></tr>';
        return;
      }

      tbody.innerHTML = policies.map(p => {
        const controls = [];
        if (p.block_jailbroken_rooted) controls.push('Block Root/Jailbreak');
        if (p.require_sip_enabled) controls.push('Require SIP');
        if (p.require_selinux_enforcing) controls.push('Require SELinux');

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-slate-200">${this.escapeHtml(p.name)}</td>
            <td class="px-4 py-3 text-xs uppercase font-mono">${this.escapeHtml(p.target_platform)}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 text-xs rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                ${this.escapeHtml(p.max_allowed_risk_level)}
              </span>
            </td>
            <td class="px-4 py-3 text-xs text-slate-400">${controls.join(', ') || 'None'}</td>
            <td class="px-4 py-3 font-mono text-xs text-amber-300">${this.escapeHtml(p.auto_remediation_action)}</td>
            <td class="px-4 py-3 text-xs text-slate-400">${new Date(p.created_at).toLocaleDateString()}</td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.MobileThreatDefenseTable.deletePolicy('${p.id}')" class="px-2.5 py-1 bg-rose-900/40 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-medium rounded transition">
                Delete
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-rose-400">Error loading policies</td></tr>';
    }
  },

  loadRemediations: async function() {
    const tbody = document.getElementById('mtd-remediations-tbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/v1/fleet/mtd/remediations', { credentials: 'include', headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to load remediations');
      const data = await res.json();
      const remediations = data.remediations || [];

      document.getElementById('count-mtd-remediations').textContent = remediations.length;

      if (remediations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No remediation actions executed yet.</td></tr>';
        return;
      }

      tbody.innerHTML = remediations.map(r => `
        <tr class="hover:bg-slate-700/30 transition">
          <td class="px-4 py-3 font-mono text-xs text-slate-400">${this.escapeHtml(r.id)}</td>
          <td class="px-4 py-3 font-mono text-xs text-amber-300">${this.escapeHtml(r.device_id)}</td>
          <td class="px-4 py-3 font-semibold text-rose-400">${this.escapeHtml(r.action_type)}</td>
          <td class="px-4 py-3 text-xs text-slate-300">${this.escapeHtml(r.trigger_reason)}</td>
          <td class="px-4 py-3">
            <span class="px-2 py-0.5 text-xs rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              ${this.escapeHtml(r.status)}
            </span>
          </td>
          <td class="px-4 py-3 text-xs text-slate-400">${new Date(r.dispatched_at).toLocaleString()}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
      tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-rose-400">Error loading remediations</td></tr>';
    }
  },

  resolveSignal: async function(signalId) {
    const notes = prompt('Enter resolution notes (e.g. "Device restored to factory stock, root binary verified removed"):');
    if (!notes) return;

    try {
      const res = await fetch(`/api/v1/fleet/mtd/signals/${signalId}/resolve`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ resolution_notes: notes })
      });
      if (!res.ok) throw new Error('Failed to resolve signal');
      this.loadStats();
      this.loadSignals();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  showSignalDetails: async function(signalId) {
    try {
      const res = await fetch(`/api/v1/fleet/mtd/signals/${signalId}`, { headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch details');
      const data = await res.json();
      const s = data.signal;

      const modal = document.getElementById('mtd-modal-container');
      modal.innerHTML = `
        <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-lg w-full space-y-4 shadow-2xl">
          <div class="flex items-center justify-between border-b border-slate-700 pb-3">
            <h3 class="text-base font-bold text-white flex items-center gap-2">
              <span>⚠️</span> Threat Signal Inspection: ${this.escapeHtml(s.threat_type)}
            </h3>
            <button onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs text-slate-300">
            <div class="grid grid-cols-2 gap-2">
              <div><span class="text-slate-500">Device ID:</span> <span class="font-mono text-amber-300">${this.escapeHtml(s.device_id)}</span></div>
              <div><span class="text-slate-500">Platform:</span> <span class="capitalize">${this.escapeHtml(s.platform)}</span></div>
              <div><span class="text-slate-500">Threat Level:</span> <span class="font-bold text-rose-400">${this.escapeHtml(s.threat_level)}</span></div>
              <div><span class="text-slate-500">Status:</span> <span>${this.escapeHtml(s.status)}</span></div>
            </div>
            <div>
              <span class="text-slate-500">Detection Engine:</span> ${this.escapeHtml(s.detection_engine)}
            </div>
            <div>
              <span class="text-slate-500">Raw Threat Details:</span>
              <pre class="mt-1 bg-slate-900/80 p-3 rounded text-slate-300 overflow-x-auto max-h-48 font-mono text-[11px]">${this.escapeHtml(JSON.stringify(s.threat_details, null, 2))}</pre>
            </div>
          </div>
          <div class="flex justify-end pt-2">
            <button onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-xs font-semibold">Close</button>
          </div>
        </div>
      `;
      modal.classList.remove('hidden');
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  deletePolicy: async function(policyId) {
    if (!confirm('Are you sure you want to delete this risk compliance policy?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/mtd/policies/${policyId}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (!res.ok) throw new Error('Failed to delete policy');
      this.loadStats();
      this.loadPolicies();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  },

  showIngestSignalModal: function() {
    const modal = document.getElementById('mtd-modal-container');
    modal.innerHTML = `
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>⚠️</span> Ingest Mobile Threat Signal
          </h3>
          <button onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
        </div>
        <form id="form-ingest-signal" class="space-y-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Target Device ID</label>
            <input id="input-sig-device-id" type="text" value="dev-daddy-pc" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-amber-500 font-mono" required />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-slate-400 mb-1">Platform</label>
              <select id="input-sig-platform" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
                <option value="ios">iOS</option>
                <option value="android">Android</option>
                <option value="macos">macOS</option>
                <option value="windows">Windows</option>
              </select>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Threat Level</label>
              <select id="input-sig-level" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Threat Type</label>
            <select id="input-sig-type" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
              <option value="JAILBREAK_DETECTED">JAILBREAK_DETECTED</option>
              <option value="ROOT_DETECTED">ROOT_DETECTED</option>
              <option value="SIDELOADED_APP">SIDELOADED_APP</option>
              <option value="DEBUGGER_ATTACHED">DEBUGGER_ATTACHED</option>
              <option value="SELINUX_PERMISSIVE">SELINUX_PERMISSIVE</option>
              <option value="SYSTEM_INTEGRITY_DISABLED">SYSTEM_INTEGRITY_DISABLED</option>
              <option value="UNKNOWN_CERT_AUTHORITY">UNKNOWN_CERT_AUTHORITY</option>
              <option value="MALICIOUS_PROFILE_INSTALLED">MALICIOUS_PROFILE_INSTALLED</option>
            </select>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Detection Engine</label>
            <input id="input-sig-engine" type="text" value="LocalPilot Mobile Sensor" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none" />
          </div>
          <div class="flex justify-end gap-2 pt-3">
            <button type="button" onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded font-medium">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded font-semibold">Ingest Signal</button>
          </div>
        </form>
      </div>
    `;
    modal.classList.remove('hidden');

    document.getElementById('form-ingest-signal').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        device_id: document.getElementById('input-sig-device-id').value.trim(),
        platform: document.getElementById('input-sig-platform').value,
        threat_level: document.getElementById('input-sig-level').value,
        signal_type: document.getElementById('input-sig-type').value,
        threat_type: document.getElementById('input-sig-type').value,
        detection_engine: document.getElementById('input-sig-engine').value.trim(),
        threat_details: { manual_test: true, timestamp: new Date().toISOString() }
      };

      try {
        const res = await fetch('/api/v1/fleet/mtd/signals', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Failed to ingest threat signal');
        modal.classList.add('hidden');
        this.loadStats();
        this.loadSignals();
        this.loadRemediations();
      } catch (err) {
        alert('Error: ' + err.message);
      }
    };
  },

  showNewPolicyModal: function() {
    const modal = document.getElementById('mtd-modal-container');
    modal.innerHTML = `
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>➕</span> New Risk Compliance Policy
          </h3>
          <button onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">✕</button>
        </div>
        <form id="form-new-policy" class="space-y-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Policy Name</label>
            <input id="input-pol-name" type="text" placeholder="e.g. Strict Zero-Trust Mobile Policy" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none focus:border-blue-500" required />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-slate-400 mb-1">Target Platform</label>
              <select id="input-pol-platform" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
                <option value="all">All Platforms</option>
                <option value="ios">iOS</option>
                <option value="android">Android</option>
                <option value="macos">macOS</option>
                <option value="windows">Windows</option>
              </select>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Max Allowed Risk</label>
              <select id="input-pol-risk" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
                <option value="SECURE">SECURE</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM" selected>MEDIUM</option>
                <option value="HIGH">HIGH</option>
              </select>
            </div>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Auto-Remediation Action</label>
            <select id="input-pol-action" class="w-full bg-slate-900 border border-slate-700 text-slate-200 px-3 py-2 rounded focus:outline-none">
              <option value="TRIGGER_MAM_SELECTIVE_WIPE">TRIGGER_MAM_SELECTIVE_WIPE (MAM Sandbox Purge)</option>
              <option value="QUARANTINE_DEVICE">QUARANTINE_DEVICE (Network Micro-Isolation)</option>
              <option value="BLOCK_ACCESS">BLOCK_ACCESS (Revoke Corporate Tokens)</option>
              <option value="ALERT_ONLY">ALERT_ONLY (Audit Ledger Only)</option>
            </select>
          </div>
          <div class="space-y-1.5 pt-1">
            <label class="flex items-center gap-2 text-slate-300">
              <input type="checkbox" id="input-pol-block-root" checked class="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0">
              Block Jailbroken / Rooted Devices
            </label>
            <label class="flex items-center gap-2 text-slate-300">
              <input type="checkbox" id="input-pol-sip" checked class="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0">
              Require macOS System Integrity Protection (SIP)
            </label>
            <label class="flex items-center gap-2 text-slate-300">
              <input type="checkbox" id="input-pol-selinux" checked class="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0">
              Require Android SELinux Enforcing
            </label>
          </div>
          <div class="flex justify-end gap-2 pt-3">
            <button type="button" onclick="document.getElementById('mtd-modal-container').classList.add('hidden')" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded font-medium">Cancel</button>
            <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-semibold">Create Policy</button>
          </div>
        </form>
      </div>
    `;
    modal.classList.remove('hidden');

    document.getElementById('form-new-policy').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('input-pol-name').value.trim(),
        target_platform: document.getElementById('input-pol-platform').value,
        max_allowed_risk_level: document.getElementById('input-pol-risk').value,
        auto_remediation_action: document.getElementById('input-pol-action').value,
        block_jailbroken_rooted: document.getElementById('input-pol-block-root').checked ? 1 : 0,
        require_sip_enabled: document.getElementById('input-pol-sip').checked ? 1 : 0,
        require_selinux_enforcing: document.getElementById('input-pol-selinux').checked ? 1 : 0
      };

      try {
        const res = await fetch('/api/v1/fleet/mtd/policies', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Failed to create policy');
        modal.classList.add('hidden');
        this.loadStats();
        this.loadPolicies();
      } catch (err) {
        alert('Error: ' + err.message);
      }
    };
  }
};
