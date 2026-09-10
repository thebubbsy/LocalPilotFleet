/**
 * LocalPilot Fleet — Web Content Filtering, Network Protection & SmartScreen Blade
 * Microsoft Defender SmartScreen, category-based content filters, and custom URL/FQDN indicator rules.
 */

function renderWebProtectionBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-blue-500/20 text-blue-400 rounded-lg text-2xl border border-blue-500/30">🌐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Web Content Filtering &amp; SmartScreen
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">Network Protection</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Defender SmartScreen policies, category-based content blocks, and custom URL/FQDN/IP indicators</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-web-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-web-new-policy" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>🛡️</span> New Policy
          </button>
          <button id="btn-web-new-indicator" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>🚫</span> Add Indicator
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="web-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Intercepts</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🌐</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-web-total">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Blocked Connections</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚫</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-web-blocked">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Phishing Stops</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-web-phishing">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Policies</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-web-policies">-</p>
        </div>
      </div>

      <!-- Main Layout: Filtering Policies & Custom Indicators -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Policies Table (2 cols) -->
        <div class="lg:col-span-2 bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📋</span> Category Filtering Policies
            </h3>
            <span class="text-xs text-slate-400" id="policy-count-badge">0 configured</span>
          </div>
          <div class="overflow-x-auto flex-1">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider">
                <tr>
                  <th class="px-4 py-3">Policy Name</th>
                  <th class="px-4 py-3">Scope</th>
                  <th class="px-4 py-3">Network Prot</th>
                  <th class="px-4 py-3">SmartScreen</th>
                  <th class="px-4 py-3">Blocked Categories</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="web-policies-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">Loading web policies...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Custom Indicators & Overrides (1 col) -->
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>⚡</span> Custom Indicator Rules
            </h3>
            <span class="text-xs text-slate-400" id="indicator-count-badge">0 rules</span>
          </div>
          <div class="overflow-y-auto max-h-[380px] p-3 space-y-2.5" id="web-indicators-list">
            <div class="text-center text-slate-500 py-6 text-sm">Loading indicators...</div>
          </div>
        </div>
      </div>

      <!-- Live Web Protection Audit Events Stream -->
      <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden">
        <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📡</span> Live Web Interception Telemetry Stream
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time URL blocks, malicious downloads, and SmartScreen bypass attempts</p>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="web-filter-query" placeholder="Filter URL or Device..." class="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-blue-500">
          </div>
        </div>
        <div class="overflow-x-auto max-h-96">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider sticky top-0 backdrop-blur-sm">
              <tr>
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Type</th>
                <th class="px-4 py-3">Target URL / Domain</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Process</th>
                <th class="px-4 py-3">Device ID</th>
              </tr>
            </thead>
            <tbody id="web-events-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No web events recorded yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function loadWebProtectionData() {
  try {
    const [statsRes, polRes, indRes, evtRes] = await Promise.all([
      fetch('/api/v1/fleet/web-protection/stats', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/web-protection/policies', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/web-protection/indicators', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/web-protection/events?limit=50', { credentials: 'same-origin' })
    ]);

    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('kpi-web-total').textContent = stats.total_events ?? 0;
      document.getElementById('kpi-web-blocked').textContent = stats.blocked_events ?? 0;
      document.getElementById('kpi-web-phishing').textContent = stats.phishing_blocks ?? 0;
      document.getElementById('kpi-web-policies').textContent = stats.active_policies ?? 0;
    }

    if (polRes.ok) {
      const policies = await polRes.json();
      renderWebPolicies(policies);
    }

    if (indRes.ok) {
      const indicators = await indRes.json();
      renderWebIndicators(indicators);
    }

    if (evtRes.ok) {
      const events = await evtRes.json();
      renderWebEvents(events);
    }
  } catch (err) {
    console.error('Error loading web protection data:', err);
  }
}

function renderWebPolicies(policies) {
  const tbody = document.getElementById('web-policies-tbody');
  const countBadge = document.getElementById('policy-count-badge');
  if (countBadge) countBadge.textContent = `${policies.length} configured`;
  if (!tbody) return;

  if (!policies || policies.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No web content filtering policies configured.</td></tr>`;
    return;
  }

  tbody.innerHTML = policies.map(p => {
    let cats = [];
    try {
      cats = JSON.parse(p.blocked_categories || '[]');
    } catch (e) {
      cats = [];
    }

    const netBadge = p.network_protection_mode === 'BLOCK'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (p.network_protection_mode === 'AUDIT' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-700 text-slate-300 border-slate-600');

    const ssBadge = p.smartscreen_mode === 'BLOCK'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (p.smartscreen_mode === 'WARN' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-700 text-slate-300 border-slate-600');

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-3">
          <div class="font-bold font-sans text-white text-sm">${escapeHtml(p.name)}</div>
          <div class="text-[11px] text-slate-400 font-sans truncate max-w-xs">${escapeHtml(p.description || '')}</div>
        </td>
        <td class="px-4 py-3 font-sans">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(p.target_group || 'All')}</span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${netBadge}">${escapeHtml(p.network_protection_mode)}</span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${ssBadge}">${escapeHtml(p.smartscreen_mode)}</span>
        </td>
        <td class="px-4 py-3">
          <div class="flex flex-wrap gap-1">
            ${cats.map(c => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-700/40 text-slate-300 border border-slate-600/50">${escapeHtml(c)}</span>`).join('')}
          </div>
        </td>
        <td class="px-4 py-3 text-right">
          <button class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition mr-1" onclick="viewWebScript('${escapeHtml(p.id)}')">
            <span>📜</span> Script
          </button>
          <button class="px-2 py-1 bg-rose-900/30 hover:bg-rose-900/60 text-rose-300 rounded text-xs transition border border-rose-700/30" onclick="deleteWebPolicy('${escapeHtml(p.id)}')">
            <span>🗑️</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderWebIndicators(indicators) {
  const container = document.getElementById('web-indicators-list');
  const countBadge = document.getElementById('indicator-count-badge');
  if (countBadge) countBadge.textContent = `${indicators.length} rules`;
  if (!container) return;

  if (!indicators || indicators.length === 0) {
    container.innerHTML = `<div class="text-center text-slate-500 py-6 text-sm">No custom indicators configured.</div>`;
    return;
  }

  container.innerHTML = indicators.map(ind => {
    const actColor = ind.action === 'BLOCK'
      ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
      : (ind.action === 'WARN' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30');

    return `
      <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs">
        <div class="min-w-0 flex-1 pr-2">
          <div class="flex items-center gap-1.5 mb-1">
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border ${actColor}">${escapeHtml(ind.action)}</span>
            <span class="text-slate-400 text-[10px] uppercase">${escapeHtml(ind.indicator_type)}</span>
          </div>
          <div class="font-mono text-slate-200 truncate font-semibold">${escapeHtml(ind.indicator_value)}</div>
          <div class="text-[10px] text-slate-400 mt-0.5 truncate">${escapeHtml(ind.target_group || 'Global Fleet')}</div>
        </div>
        <button class="p-1 text-slate-400 hover:text-rose-400 transition" onclick="deleteWebIndicator('${escapeHtml(ind.id)}')">
          <span>🗑️</span>
        </button>
      </div>
    `;
  }).join('');
}

function renderWebEvents(events) {
  const tbody = document.getElementById('web-events-tbody');
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No web events recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(evt => {
    const actBadge = evt.action_taken === 'BLOCKED'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (evt.action_taken === 'WARNED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30');

    const d = new Date(evt.timestamp);
    const timeStr = isNaN(d.getTime()) ? evt.timestamp : d.toLocaleTimeString();

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-2.5 text-slate-400">${timeStr}</td>
        <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-xs border ${actBadge}">${escapeHtml(evt.action_taken)}</span></td>
        <td class="px-4 py-2.5 text-slate-300">${escapeHtml(evt.event_type)}</td>
        <td class="px-4 py-2.5 text-slate-200 font-medium truncate max-w-xs" title="${escapeHtml(evt.url)}">${escapeHtml(evt.url)}</td>
        <td class="px-4 py-2.5 text-slate-400">${escapeHtml(evt.category || 'Unrated')}</td>
        <td class="px-4 py-2.5 text-slate-400 truncate max-w-[120px]">${escapeHtml(evt.process_name || 'msedge.exe')}</td>
        <td class="px-4 py-2.5 text-slate-500 truncate max-w-[80px]">${escapeHtml(evt.device_id.substring(0, 8))}...</td>
      </tr>
    `;
  }).join('');
}

function initWebProtectionBlade() {
  const refreshBtn = document.getElementById('btn-web-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', loadWebProtectionData);

  const newPolicyBtn = document.getElementById('btn-web-new-policy');
  if (newPolicyBtn) {
    newPolicyBtn.addEventListener('click', () => {
      const name = prompt('Policy Name:', 'Executive Web Security Baseline');
      if (!name) return;
      const netMode = prompt('Network Protection Mode (BLOCK, AUDIT, DISABLED):', 'BLOCK');
      if (!netMode) return;

      fetch('/api/v1/fleet/web-protection/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          target_group: 'All',
          network_protection_mode: netMode,
          smartscreen_mode: 'BLOCK',
          blocked_categories: ['AdultContent', 'HighLiability', 'LegalLiability', 'Malware']
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadWebProtectionData());
    });
  }

  const newIndicatorBtn = document.getElementById('btn-web-new-indicator');
  if (newIndicatorBtn) {
    newIndicatorBtn.addEventListener('click', () => {
      const val = prompt('Indicator Value (Domain / URL / IP):', 'phishing-login.com');
      if (!val) return;
      const act = prompt('Action (BLOCK, WARN, ALLOW):', 'BLOCK');
      if (!act) return;

      fetch('/api/v1/fleet/web-protection/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator_value: val,
          indicator_type: val.startsWith('http') ? 'URL' : (val.includes('/') ? 'URL' : 'DOMAIN'),
          action: act,
          target_group: 'All'
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadWebProtectionData());
    });
  }

  const filterInput = document.getElementById('web-filter-query');
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#web-events-tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  loadWebProtectionData();
}

async function deleteWebPolicy(id) {
  if (!confirm('Are you sure you want to delete this web filtering policy?')) return;
  await fetch(`/api/v1/fleet/web-protection/policies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadWebProtectionData();
}

async function deleteWebIndicator(id) {
  if (!confirm('Delete this indicator override?')) return;
  await fetch(`/api/v1/fleet/web-protection/indicators/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadWebProtectionData();
}

async function viewWebScript(id) {
  try {
    const res = await fetch(`/api/v1/fleet/web-protection/script/default`, { credentials: 'same-origin' });
    if (res.ok) {
      const script = await res.text();
      alert('PowerShell Defender Configuration Script:\n\n' + script.substring(0, 500) + '...');
    }
  } catch (e) {
    console.error(e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderWebProtectionBlade = renderWebProtectionBlade;
window.initWebProtectionBlade = initWebProtectionBlade;
window.loadWebProtectionData = loadWebProtectionData;
window.deleteWebPolicy = deleteWebPolicy;
window.deleteWebIndicator = deleteWebIndicator;
window.viewWebScript = viewWebScript;

window.WebProtectionTable = {
  async render() {
    const container = document.getElementById('tab-web-protection');
    if (!container) return;
    container.innerHTML = renderWebProtectionBlade();
    initWebProtectionBlade();
  }
};
