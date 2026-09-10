/**
 * LocalPilot Fleet — Automated Ransomware Canary & File Integrity Trap Blade
 * dashboard/js/components/ransomwareCanaryTable.js
 *
 * Provides real-time canary file deployment, entropy & SHA256 integrity monitoring,
 * tamper detection stream, and automated endpoint containment (host isolation / process kill).
 */

function renderRansomwareCanaryBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">🪤</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Ransomware Canary Traps &amp; File Integrity Engine
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">Ransomware Defense</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated honeytoken canary files, entropy &amp; hash tamper detection, and instant sub-second host isolation</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-canary-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-canary-script" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>📜</span> Deploy Script
          </button>
          <button id="btn-canary-new" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>➕</span> Deploy Canary Trap
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="canary-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Traps</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🪤</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-canary-total">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Healthy</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">✅</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-canary-healthy">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tampered</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-canary-tampered">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Encrypted</p>
            <span class="p-1.5 bg-red-500/20 text-red-400 rounded-md text-sm">🔒</span>
          </div>
          <p class="text-2xl font-bold text-red-500 mt-2" id="kpi-canary-encrypted">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tamper Events</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-canary-detections">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Contained</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-canary-contained">-</p>
        </div>
      </div>

      <!-- Main Layout: Stacked Cards -->
      <div class="grid grid-cols-1 gap-6">
        <!-- Canary Traps Catalog Card -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">📁</span>
              <h3 class="font-semibold text-slate-200">Deployed Canary Honeytoken Traps</h3>
            </div>
            <div class="flex items-center gap-2">
              <input type="text" id="filter-canary-search" placeholder="Search filename or path..." class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-rose-500">
              <select id="filter-canary-status" class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-rose-500">
                <option value="">All Statuses</option>
                <option value="HEALTHY">HEALTHY</option>
                <option value="TAMPERED">TAMPERED</option>
                <option value="ENCRYPTED">ENCRYPTED</option>
              </select>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Trap ID</th>
                  <th class="px-4 py-3">Canary Filename</th>
                  <th class="px-4 py-3">Target Directory</th>
                  <th class="px-4 py-3">Baseline Entropy</th>
                  <th class="px-4 py-3">Baseline SHA256</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Last Verified</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="canary-traps-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading canary honeytoken traps...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Tamper Detections & Rapid Containment Log -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">🚨</span>
              <h3 class="font-semibold text-slate-200">Tamper Detections &amp; Rapid Containment Stream</h3>
            </div>
            <div class="text-xs text-slate-400">
              Live file integrity alarms &amp; automated quarantine actions
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Detected At</th>
                  <th class="px-4 py-3">Device / Host</th>
                  <th class="px-4 py-3">Tamper Type</th>
                  <th class="px-4 py-3">Process / App</th>
                  <th class="px-4 py-3">Severity</th>
                  <th class="px-4 py-3">Containment Action</th>
                  <th class="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody id="canary-detections-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="7" class="text-center py-8 text-slate-500">Loading tamper detections...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Deploy Canary Trap Modal -->
      <div id="modal-canary-deploy" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full p-6 text-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🪤</span> Deploy New Canary Honeytoken Trap
            </h3>
            <button id="modal-canary-close" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>
          <form id="form-canary-deploy" class="space-y-4 mt-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Canary Filename</label>
              <input type="text" id="input-canary-filename" required placeholder="e.g. Corporate_Payroll_Q4_2026.xlsx" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-rose-500">
              <p class="text-xs text-slate-500 mt-1">High-value bait name that attackers or ransomware scripts target first.</p>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Directory Path</label>
              <input type="text" id="input-canary-path" required placeholder="e.g. C:\\Users\\Public\\Documents" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-rose-500">
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Baseline Entropy</label>
                <input type="number" step="0.1" id="input-canary-entropy" value="4.2" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-rose-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">File Size (Bytes)</label>
                <input type="number" id="input-canary-size" value="4096" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-rose-500">
              </div>
            </div>
            <div class="flex justify-end gap-3 pt-4 border-t border-slate-700">
              <button type="button" id="modal-canary-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold">Deploy Trap</button>
            </div>
          </form>
        </div>
      </div>

      <!-- View Deployment Script Modal -->
      <div id="modal-canary-script-view" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-2xl w-full p-6 text-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>📜</span> PowerShell Fleet Canary Deployment Script
            </h3>
            <button id="modal-canary-script-close" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>
          <div class="mt-4 space-y-3">
            <p class="text-xs text-slate-400">Run this script on enrolled endpoints or distribute via GPO / LocalPilot Fleet Script Execution engine:</p>
            <pre id="canary-script-content" class="bg-slate-950 p-4 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto max-h-96 border border-slate-800"></pre>
          </div>
          <div class="flex justify-end gap-3 pt-4 border-t border-slate-700">
            <button type="button" id="btn-copy-canary-script" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold flex items-center gap-1.5">
              <span>📋</span> Copy PowerShell Script
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

window.RansomwareCanaryTable = {
  getHeaders: function() {
    const key = localStorage.getItem('fleetKey') || '';
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': key
    };
  },

  render: async function() {
    const container = document.getElementById('ransomware-container');
    if (!container) return;
    container.innerHTML = renderRansomwareCanaryBlade();

    this.bindEvents();
    await this.loadAll();
  },

  bindEvents: function() {
    document.getElementById('btn-canary-refresh')?.addEventListener('click', () => this.loadAll());

    const modalDeploy = document.getElementById('modal-canary-deploy');
    document.getElementById('btn-canary-new')?.addEventListener('click', () => modalDeploy?.classList.remove('hidden'));
    document.getElementById('modal-canary-close')?.addEventListener('click', () => modalDeploy?.classList.add('hidden'));
    document.getElementById('modal-canary-cancel')?.addEventListener('click', () => modalDeploy?.classList.add('hidden'));

    const modalScript = document.getElementById('modal-canary-script-view');
    document.getElementById('btn-canary-script')?.addEventListener('click', async () => {
      modalScript?.classList.remove('hidden');
      await this.loadDeployScript();
    });
    document.getElementById('modal-canary-script-close')?.addEventListener('click', () => modalScript?.classList.add('hidden'));

    document.getElementById('btn-copy-canary-script')?.addEventListener('click', () => {
      const content = document.getElementById('canary-script-content')?.innerText || '';
      navigator.clipboard?.writeText(content).then(() => {
        alert('PowerShell Canary Deployment Script copied to clipboard!');
      });
    });

    document.getElementById('form-canary-deploy')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        filename: document.getElementById('input-canary-filename').value.trim(),
        directory_path: document.getElementById('input-canary-path').value.trim(),
        baseline_entropy: parseFloat(document.getElementById('input-canary-entropy').value) || 4.2,
        original_size_bytes: parseInt(document.getElementById('input-canary-size').value, 10) || 4096
      };

      try {
        const res = await fetch('/api/v1/fleet/ransomware/traps', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          modalDeploy?.classList.add('hidden');
          document.getElementById('form-canary-deploy').reset();
          await this.loadAll();
        } else {
          alert('Failed to deploy canary trap: ' + res.statusText);
        }
      } catch (err) {
        console.error('Error deploying canary trap:', err);
      }
    });

    document.getElementById('filter-canary-search')?.addEventListener('input', () => this.filterTraps());
    document.getElementById('filter-canary-status')?.addEventListener('change', () => this.filterTraps());
  },

  trapsData: [],

  loadAll: async function() {
    await Promise.all([
      this.loadStats(),
      this.loadTraps(),
      this.loadDetections()
    ]);
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/ransomware/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || data;

      document.getElementById('kpi-canary-total').textContent = stats.totalTraps || 0;
      document.getElementById('kpi-canary-healthy').textContent = stats.healthyTraps || 0;
      document.getElementById('kpi-canary-tampered').textContent = stats.tamperedTraps || 0;
      document.getElementById('kpi-canary-encrypted').textContent = stats.encryptedTraps || 0;
      document.getElementById('kpi-canary-detections').textContent = stats.totalDetections || 0;
      document.getElementById('kpi-canary-contained').textContent = stats.containedIncidents || 0;
    } catch (err) {
      console.error('Failed to load canary stats:', err);
    }
  },

  loadTraps: async function() {
    try {
      const res = await fetch('/api/v1/fleet/ransomware/traps', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.trapsData = data.traps || data;
      this.renderTraps(this.trapsData);
    } catch (err) {
      console.error('Failed to load traps:', err);
    }
  },

  filterTraps: function() {
    const search = (document.getElementById('filter-canary-search')?.value || '').toLowerCase();
    const status = document.getElementById('filter-canary-status')?.value || '';

    const filtered = (this.trapsData || []).filter(t => {
      const matchesSearch = !search ||
        (t.filename && t.filename.toLowerCase().includes(search)) ||
        (t.directory_path && t.directory_path.toLowerCase().includes(search));
      const matchesStatus = !status || t.status === status;
      return matchesSearch && matchesStatus;
    });

    this.renderTraps(filtered);
  },

  renderTraps: function(traps) {
    const tbody = document.getElementById('canary-traps-tbody');
    if (!tbody) return;

    if (!traps || traps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No canary traps match filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = traps.map(t => {
      let statusBadge = '<span class="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">HEALTHY</span>';
      if (t.status === 'TAMPERED') {
        statusBadge = '<span class="px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">TAMPERED</span>';
      } else if (t.status === 'ENCRYPTED') {
        statusBadge = '<span class="px-2 py-0.5 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">ENCRYPTED</span>';
      }

      const shortSha = t.original_sha256 ? t.original_sha256.substring(0, 12) + '...' : '-';

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 text-slate-400">${t.id}</td>
          <td class="px-4 py-3 font-medium text-slate-200">${t.filename}</td>
          <td class="px-4 py-3 text-slate-400 font-sans">${t.directory_path}</td>
          <td class="px-4 py-3 text-slate-300">${t.baseline_entropy ? t.baseline_entropy.toFixed(2) : '-'}</td>
          <td class="px-4 py-3 text-slate-400" title="${t.original_sha256}">${shortSha}</td>
          <td class="px-4 py-3">${statusBadge}</td>
          <td class="px-4 py-3 text-slate-400">${t.last_verified_at || 'Pending'}</td>
          <td class="px-4 py-3 text-right">
            <button onclick="window.RansomwareCanaryTable.deleteTrap('${t.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-700 text-slate-300 hover:text-white rounded text-xs transition">
              Delete
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  deleteTrap: async function(id) {
    if (!confirm(`Are you sure you want to delete canary trap ${id}?`)) return;
    try {
      const res = await fetch(`/api/v1/fleet/ransomware/traps/${id}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        await this.loadAll();
      } else {
        alert('Failed to delete trap');
      }
    } catch (err) {
      console.error('Error deleting trap:', err);
    }
  },

  loadDetections: async function() {
    try {
      const res = await fetch('/api/v1/fleet/ransomware/detections', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.renderDetections(data.detections || data);
    } catch (err) {
      console.error('Failed to load detections:', err);
    }
  },

  renderDetections: function(detections) {
    const tbody = document.getElementById('canary-detections-tbody');
    if (!tbody) return;

    if (!detections || detections.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-6 text-slate-500">No ransomware tamper detections recorded. Fleet intact.</td></tr>';
      return;
    }

    tbody.innerHTML = detections.map(d => {
      let sevBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-400">CRITICAL</span>';
      if (d.severity === 'HIGH') {
        sevBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-orange-500/20 text-orange-400">HIGH</span>';
      } else if (d.severity === 'MEDIUM') {
        sevBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400">MEDIUM</span>';
      }

      let actionBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-300">NONE</span>';
      if (d.containment_action === 'ISOLATE_HOST') {
        actionBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-red-600/30 text-red-300 border border-red-500/40">HOST ISOLATED</span>';
      } else if (d.containment_action === 'KILL_PROCESS') {
        actionBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-amber-600/30 text-amber-300 border border-amber-500/40">PROCESS KILLED</span>';
      }

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 text-slate-400">${d.detected_at}</td>
          <td class="px-4 py-3 font-semibold text-slate-200">${d.hostname || d.device_id}</td>
          <td class="px-4 py-3 text-rose-300 font-bold">${d.tamper_type}</td>
          <td class="px-4 py-3 text-slate-300 font-mono">${d.process_name || '-'} ${d.process_id ? '(' + d.process_id + ')' : ''}</td>
          <td class="px-4 py-3">${sevBadge}</td>
          <td class="px-4 py-3">${actionBadge}</td>
          <td class="px-4 py-3 text-slate-400">${d.containment_status || 'PENDING'}</td>
        </tr>
      `;
    }).join('');
  },

  loadDeployScript: async function() {
    try {
      const res = await fetch('/api/v1/fleet/ransomware/deploy-script', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const codeEl = document.getElementById('canary-script-content');
      if (codeEl) {
        codeEl.textContent = (data.script && data.script.script_content) || data.script_content || 'No script content returned.';
      }
    } catch (err) {
      console.error('Failed to load deploy script:', err);
    }
  }
};
