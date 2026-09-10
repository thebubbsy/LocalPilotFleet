/**
 * LocalPilot Fleet — Cloud App Discovery & Shadow SaaS Governance Blade
 * dashboard/js/components/cloudAppDiscoveryTable.js
 *
 * Provides real-time Shadow IT discovery, SaaS application risk evaluation (0-100),
 * Sanctioned/Unsanctioned governance, endpoint cloud traffic telemetry, and automated access blocking.
 */

function renderCloudAppsBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-sky-500/20 text-sky-400 rounded-lg text-2xl border border-sky-500/30">☁️</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Cloud App Discovery &amp; Shadow SaaS Governance
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/30">Endpoint CASB</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Continuous Shadow IT discovery, SaaS risk rating (0–100), sanctioned status governance, and automated access blocking</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-cloud-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-cloud-blocklist" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🛡️</span> View Blocklist
          </button>
          <button id="btn-cloud-new-app" class="px-3.5 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-sky-500/20">
            <span>➕</span> Add Cloud App
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="cloud-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Discovered SaaS</p>
            <span class="p-1.5 bg-sky-500/20 text-sky-400 rounded-md text-sm">☁️</span>
          </div>
          <p class="text-2xl font-bold text-sky-400 mt-2" id="kpi-cloud-total">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Sanctioned</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">✅</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-cloud-sanctioned">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Unsanctioned</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚫</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-cloud-unsanctioned">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Monitored</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">👁️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-cloud-monitored">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Cloud Traffic</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">🌐</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-cloud-traffic">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Block Policies</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-cloud-policies">-</p>
        </div>
      </div>

      <!-- Section 1: Discovered Cloud Apps Catalog -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Discovered Cloud Applications Catalog</h3>
            <p class="text-xs text-slate-400 mt-0.5">SaaS services accessed by endpoint fleet with risk scores and compliance metrics</p>
          </div>
          <div class="flex items-center gap-3">
            <select id="select-cloud-filter" class="px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300">
              <option value="">All Categories</option>
              <option value="CLOUD_STORAGE">Cloud Storage</option>
              <option value="GENERATIVE_AI">Generative AI</option>
              <option value="COLLABORATION">Collaboration</option>
              <option value="DEVELOPER_TOOLS">Developer Tools</option>
              <option value="SHADOW_VPN">Shadow VPN</option>
            </select>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Application Name</th>
                <th class="px-4 py-3">Domain</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Risk Score (0–100)</th>
                <th class="px-4 py-3">Compliance</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Traffic</th>
                <th class="px-4 py-3 text-right">Sanction Action</th>
              </tr>
            </thead>
            <tbody id="cloud-apps-tbody" class="divide-y divide-slate-700/40 text-xs">
              <tr><td colspan="8" class="px-4 py-8 text-center text-slate-500">Loading cloud applications...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Endpoint Cloud Usage Telemetry -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Endpoint Cloud Connection Telemetry</h3>
            <p class="text-xs text-slate-400 mt-0.5">Recent cloud transactions, upload/download volumes, and active user accounts</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="cloud-usage-count">0 Telemetry Events</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Application</th>
                <th class="px-4 py-3">Endpoint Host</th>
                <th class="px-4 py-3">User Principal</th>
                <th class="px-4 py-3">Uploaded</th>
                <th class="px-4 py-3">Downloaded</th>
                <th class="px-4 py-3">Sessions</th>
                <th class="px-4 py-3 text-right">Last Observed</th>
              </tr>
            </thead>
            <tbody id="cloud-usage-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">Loading cloud telemetry...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Modal: Add Cloud App -->
      <div id="modal-cloud-app" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>☁️</span> Register Cloud Application
            </h3>
            <button id="modal-cloud-app-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Application Name</label>
              <input id="input-cac-name" type="text" placeholder="DeepSeek Chat" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Primary Domain</label>
              <input id="input-cac-domain" type="text" placeholder="chat.deepseek.com" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono lowercase" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Category</label>
                <select id="select-cac-category" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="GENERATIVE_AI">GENERATIVE_AI</option>
                  <option value="CLOUD_STORAGE">CLOUD_STORAGE</option>
                  <option value="COLLABORATION">COLLABORATION</option>
                  <option value="DEVELOPER_TOOLS">DEVELOPER_TOOLS</option>
                  <option value="SHADOW_VPN">SHADOW_VPN</option>
                  <option value="SOCIAL_MEDIA">SOCIAL_MEDIA</option>
                  <option value="WEBMAIL">WEBMAIL</option>
                </select>
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Risk Score (0-100)</label>
                <input id="input-cac-risk" type="number" min="0" max="100" value="70" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Sanction Status</label>
              <select id="select-cac-status" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                <option value="MONITORED">MONITORED</option>
                <option value="SANCTIONED">SANCTIONED</option>
                <option value="UNSANCTIONED">UNSANCTIONED (Block)</option>
              </select>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-cloud-app-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-cloud-app-submit" class="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold">Save Application</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function initCloudAppsBlade() {
  const getFleetKey = () => localStorage.getItem('fleetKey') || '';

  async function loadStats() {
    try {
      const res = await fetch('/api/v1/fleet/cloud-apps/stats', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        document.getElementById('kpi-cloud-total').textContent = data.stats.totalApps ?? 0;
        document.getElementById('kpi-cloud-sanctioned').textContent = data.stats.sanctionedApps ?? 0;
        document.getElementById('kpi-cloud-unsanctioned').textContent = data.stats.unsanctionedApps ?? 0;
        document.getElementById('kpi-cloud-monitored').textContent = data.stats.monitoredApps ?? 0;
        document.getElementById('kpi-cloud-traffic').textContent = formatBytes(data.stats.totalBytesTransferred ?? 0);
        document.getElementById('kpi-cloud-policies').textContent = data.stats.activePolicies ?? 0;
      }
    } catch (e) {
      console.error('Failed to load cloud app stats:', e);
    }
  }

  async function loadApps() {
    try {
      const category = document.getElementById('select-cloud-filter')?.value || '';
      const query = new URLSearchParams();
      if (category) query.set('category', category);

      const res = await fetch(`/api/v1/fleet/cloud-apps/catalog?${query.toString()}`, {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('cloud-apps-tbody');
      if (!tbody) return;

      const apps = data.apps || [];
      if (apps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500">No cloud applications found.</td></tr>';
        return;
      }

      tbody.innerHTML = apps.map(a => {
        const statusBadge = a.sanctioned_status === 'SANCTIONED' ?
          '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">SANCTIONED</span>' :
          a.sanctioned_status === 'UNSANCTIONED' ?
          '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">UNSANCTIONED</span>' :
          '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-semibold border border-amber-500/30">MONITORED</span>';

        const riskColor = a.risk_score >= 80 ? 'text-rose-400' :
                          a.risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400';

        const certs = (a.compliance_certifications || []).map(c =>
          `<span class="px-1.5 py-0.5 bg-slate-700/80 rounded text-[10px] text-slate-300 font-mono">${c}</span>`
        ).join(' ') || '<span class="text-slate-500">None</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white">
              ${a.app_name}
              <div class="text-[11px] text-slate-400 truncate max-w-xs">${a.description || ''}</div>
            </td>
            <td class="px-4 py-3 font-mono text-cyan-400">${a.domain_name}</td>
            <td class="px-4 py-3 text-slate-300">${a.category}</td>
            <td class="px-4 py-3 font-bold font-mono ${riskColor}">
              <div class="flex items-center gap-2">
                <span>${a.risk_score}</span>
                <div class="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div class="h-full bg-current" style="width: ${a.risk_score}%"></div>
                </div>
              </div>
            </td>
            <td class="px-4 py-3">${certs}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 font-mono text-slate-200 font-semibold">${formatBytes(a.total_bytes_transferred)}</td>
            <td class="px-4 py-3 text-right space-x-1 font-sans">
              <button onclick="window.sanctionCloudApp('${a.id}', 'SANCTIONED')" class="px-2 py-0.5 bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 rounded text-xs transition border border-emerald-500/30">Sanction</button>
              <button onclick="window.sanctionCloudApp('${a.id}', 'UNSANCTIONED')" class="px-2 py-0.5 bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 rounded text-xs transition border border-rose-500/30">Block</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load cloud apps:', e);
    }
  }

  async function loadUsage() {
    try {
      const res = await fetch('/api/v1/fleet/cloud-apps/usage', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('cloud-usage-tbody');
      const countEl = document.getElementById('cloud-usage-count');
      if (!tbody) return;

      const telemetry = data.telemetry || [];
      if (countEl) countEl.textContent = `${telemetry.length} Telemetry Events`;

      if (telemetry.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No cloud usage telemetry recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = telemetry.map(t => {
        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white font-sans">${t.app_name}</td>
            <td class="px-4 py-3 text-slate-300">${t.hostname}</td>
            <td class="px-4 py-3 text-cyan-400 font-sans">${t.user_principal}</td>
            <td class="px-4 py-3 text-amber-400">${formatBytes(t.bytes_uploaded)}</td>
            <td class="px-4 py-3 text-emerald-400">${formatBytes(t.bytes_downloaded)}</td>
            <td class="px-4 py-3 text-slate-300">${t.session_count}</td>
            <td class="px-4 py-3 text-right text-slate-400 text-xs">${t.last_observed_at || ''}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load usage telemetry:', e);
    }
  }

  // Global window helpers
  window.sanctionCloudApp = async (id, status) => {
    try {
      const res = await fetch(`/api/v1/fleet/cloud-apps/catalog/${id}/sanction`, {
        method: 'PATCH',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ sanctioned_status: status })
      });
      if (res.ok) {
        loadApps();
        loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Event handlers
  document.getElementById('btn-cloud-refresh')?.addEventListener('click', () => {
    loadStats();
    loadApps();
    loadUsage();
  });

  document.getElementById('select-cloud-filter')?.addEventListener('change', () => loadApps());

  document.getElementById('btn-cloud-blocklist')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/v1/nodes/local/cloud-apps/blocklist', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (res.ok) {
        const data = await res.json();
        alert('Active Endpoint CASB Blocklist (' + data.blocklist.total_blocked_domains + ' domains):\n\n' + data.blocklist.domains.join('\n'));
      }
    } catch (e) {
      console.error(e);
    }
  });

  document.getElementById('btn-cloud-new-app')?.addEventListener('click', () => {
    document.getElementById('modal-cloud-app').classList.remove('hidden');
  });
  document.getElementById('modal-cloud-app-close')?.addEventListener('click', () => {
    document.getElementById('modal-cloud-app').classList.add('hidden');
  });
  document.getElementById('modal-cloud-app-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-cloud-app').classList.add('hidden');
  });
  document.getElementById('modal-cloud-app-submit')?.addEventListener('click', async () => {
    const app_name = document.getElementById('input-cac-name').value.trim();
    const domain_name = document.getElementById('input-cac-domain').value.trim();
    const category = document.getElementById('select-cac-category').value;
    const risk_score = parseInt(document.getElementById('input-cac-risk').value, 10) || 50;
    const sanctioned_status = document.getElementById('select-cac-status').value;

    if (!app_name || !domain_name) { alert('Application Name and Domain are required'); return; }

    try {
      const res = await fetch('/api/v1/fleet/cloud-apps/catalog', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_name, domain_name, category, risk_score, sanctioned_status })
      });
      if (res.ok) {
        document.getElementById('modal-cloud-app').classList.add('hidden');
        loadApps();
        loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadStats();
  loadApps();
  loadUsage();
}

window.renderCloudAppsBlade = renderCloudAppsBlade;
window.initCloudAppsBlade = initCloudAppsBlade;

window.CloudAppDiscoveryTable = {
  async render() {
    const container = document.getElementById('tab-cloud-apps');
    if (!container) return;
    container.innerHTML = renderCloudAppsBlade();
    initCloudAppsBlade();
  }
};
