/**
 * LocalPilot Fleet — Distributed Threat Hunting & IoC Sweeper Blade
 * Real-Time YARA Pattern Sweeper, Sigma Rules, and Fleet-Wide Hash Sweeps.
 */

function renderThreatHuntingBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-amber-500/20 text-amber-400 rounded-lg text-2xl border border-amber-500/30">🎯</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Distributed Threat Hunting &amp; IoC Sweeper
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">Sub-Second Sweeps</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Fleet-wide YARA memory scanning, Sigma log detections, and automated threat containment</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-hunt-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-hunt-new-campaign" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>🎯</span> Launch Threat Hunt
          </button>
          <button id="btn-hunt-new-ioc" class="px-3.5 py-2 bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg text-sm font-semibold transition flex items-center gap-1.5 border border-slate-600">
            <span>➕</span> Add IoC Watchlist
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="hunt-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Threat Hunts</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🎯</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-hunt-active">-</p>
          <p class="text-xs text-amber-300 mt-1 flex items-center gap-1">Sweeping Workstations</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total IoC Matches</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-hunt-matches">-</p>
          <p class="text-xs text-rose-300 mt-1 flex items-center gap-1">Detections Confirmed</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Watched Indicators</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-hunt-iocs">-</p>
          <p class="text-xs text-cyan-400 mt-1">Hashes, IPs &amp; Mutexes</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Fleet Sweeper SLA</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">⏱️</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2">&lt; 1s</p>
          <p class="text-xs text-emerald-300 mt-1">Push Broadcast Response</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="hunt-subtab px-4 py-2 text-sm font-semibold border-b-2 border-amber-500 text-amber-400" data-tab="campaigns">
          🎯 Threat Hunting Campaigns
        </button>
        <button class="hunt-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="matches">
          🚨 IoC Matches &amp; Detections Matrix
        </button>
        <button class="hunt-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="iocs">
          📜 Threat Intelligence Watchlist
        </button>
      </div>

      <!-- Tab Content 1: Campaigns -->
      <div id="subtab-content-campaigns" class="hunt-tab-panel space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🎯</span> Active &amp; Historical Threat Hunt Campaigns
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Dispatched YARA rules, Sigma telemetry sweeps, and targeted malware campaigns</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Campaign Name</th>
                <th class="px-4 py-3">Hunt Type</th>
                <th class="px-4 py-3">Severity / MITRE</th>
                <th class="px-4 py-3">Matches Found</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="hunt-campaigns-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading threat hunts...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Content 2: Matches Matrix -->
      <div id="subtab-content-matches" class="hunt-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🚨</span> Fleet-Wide Threat Matches &amp; Detections
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Forensic evidence snippets, infected processes, and automated containment actions</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Matched Detection</th>
                <th class="px-4 py-3">Workstation</th>
                <th class="px-4 py-3">Target File / Process</th>
                <th class="px-4 py-3">MITRE ATT&amp;CK</th>
                <th class="px-4 py-3">Action Taken</th>
                <th class="px-4 py-3 text-right">Detected At</th>
              </tr>
            </thead>
            <tbody id="hunt-matches-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading match findings...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Content 3: IoC Watchlist -->
      <div id="subtab-content-iocs" class="hunt-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>📜</span> Threat Intelligence IoC Watchlist Indicators
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Known malicious SHA-256 hashes, C2 IP addresses, domains, and malware named pipes</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Threat Name</th>
                <th class="px-4 py-3">Indicator Type</th>
                <th class="px-4 py-3">Indicator Value</th>
                <th class="px-4 py-3">Confidence</th>
                <th class="px-4 py-3">Action on Match</th>
                <th class="px-4 py-3 text-right">Delete</th>
              </tr>
            </thead>
            <tbody id="hunt-iocs-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading indicators...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Modal: View Hunt Script -->
    <div id="modal-hunt-script" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-2xl shadow-2xl space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="p-2 bg-amber-500/20 text-amber-400 rounded-lg text-xl border border-amber-500/30">📜</span>
            <div>
              <h3 class="font-bold text-white text-base" id="modal-script-title">Threat Hunting Payload Script</h3>
              <p class="text-xs text-slate-400" id="modal-script-subtitle">PowerShell Endpoint Sweeper</p>
            </div>
          </div>
          <button id="modal-script-close" class="text-slate-400 hover:text-white text-xl">&times;</button>
        </div>
        <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-amber-300 border border-slate-800 overflow-x-auto max-h-80 whitespace-pre" id="modal-script-code">
          Loading script...
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="modal-script-copy" class="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md">
            <span>📋</span> Copy Script
          </button>
        </div>
      </div>
    </div>
  `;
}

async function initThreatHuntingBlade(api) {
  // Tab switching
  document.querySelectorAll('.hunt-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.hunt-subtab').forEach(b => {
        b.classList.remove('border-amber-500', 'text-amber-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.remove('border-transparent', 'text-slate-400');
      btn.classList.add('border-amber-500', 'text-amber-400');

      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.hunt-tab-panel').forEach(panel => panel.classList.add('hidden'));
      const activePanel = document.getElementById(`subtab-content-${targetTab}`);
      if (activePanel) activePanel.classList.remove('hidden');
    });
  });

  const scriptModal = document.getElementById('modal-hunt-script');
  document.getElementById('modal-script-close')?.addEventListener('click', () => scriptModal.classList.add('hidden'));
  document.getElementById('btn-hunt-refresh')?.addEventListener('click', () => loadAllHuntingData(api));

  document.getElementById('modal-script-copy')?.addEventListener('click', () => {
    const code = document.getElementById('modal-script-code').textContent;
    navigator.clipboard.writeText(code).then(() => {
      if (window.showToast) window.showToast('PowerShell hunt script copied to clipboard', 'info');
    });
  });

  await loadAllHuntingData(api);

  async function loadAllHuntingData(api) {
    try {
      // 1. Stats
      const stats = await api.get('/api/v1/fleet/hunting/stats');
      if (stats) {
        document.getElementById('kpi-hunt-active').textContent = stats.activeCampaigns || 0;
        document.getElementById('kpi-hunt-matches').textContent = stats.totalMatchesDetected || 0;
        document.getElementById('kpi-hunt-iocs').textContent = stats.activeWatchlistIndicators || 0;
      }

      // 2. Campaigns
      const campRes = await api.get('/api/v1/fleet/hunting/campaigns');
      const campaigns = (campRes && campRes.campaigns) ? campRes.campaigns : [];
      const campTbody = document.getElementById('hunt-campaigns-tbody');
      if (campTbody) {
        if (campaigns.length === 0) {
          campTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No threat hunting campaigns created yet.</td></tr>';
        } else {
          campTbody.innerHTML = campaigns.map(c => `
            <tr class="hover:bg-slate-800/40 transition">
              <td class="px-4 py-3">
                <div class="font-bold text-white flex items-center gap-1.5">
                  <span>🎯</span> ${escapeHtml(c.name)}
                </div>
                <div class="text-[10px] text-slate-500 truncate max-w-xs">${escapeHtml(c.description || '')}</div>
              </td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  ${escapeHtml(c.hunt_type)}
                </span>
              </td>
              <td class="px-4 py-3">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${c.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'}">
                  ${escapeHtml(c.severity)}
                </span>
                <span class="text-slate-400 font-mono text-[10px] ml-1">${escapeHtml(c.mitre_technique || '')}</span>
              </td>
              <td class="px-4 py-3 font-bold ${c.matches_detected > 0 ? 'text-rose-400' : 'text-slate-400'}">
                ${c.matches_detected} matches
              </td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${c.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-400'}">
                  ${escapeHtml(c.status)}
                </span>
              </td>
              <td class="px-4 py-3 text-right">
                <button class="btn-view-script px-2.5 py-1 bg-amber-700/80 hover:bg-amber-600 text-amber-100 rounded text-xs font-semibold transition"
                  data-id="${c.id}" data-name="${escapeHtml(c.name)}">
                  📜 Script
                </button>
              </td>
            </tr>
          `).join('');

          campTbody.querySelectorAll('.btn-view-script').forEach(btn => {
            btn.addEventListener('click', async () => {
              const hId = btn.getAttribute('data-id');
              const hName = btn.getAttribute('data-name');
              try {
                const s = await api.get(`/api/v1/fleet/hunting/campaigns/${hId}/script`);
                document.getElementById('modal-script-title').textContent = `Threat Hunt: ${hName}`;
                document.getElementById('modal-script-subtitle').textContent = `Type: ${s.hunt_type} | Campaign ID: ${s.hunt_id}`;
                document.getElementById('modal-script-code').textContent = s.script || 'No script available';
                scriptModal.classList.remove('hidden');
              } catch(e) {
                alert('Failed to load script: ' + e.message);
              }
            });
          });
        }
      }

      // 3. Matches
      const matchRes = await api.get('/api/v1/fleet/hunting/matches');
      const matches = (matchRes && matchRes.matches) ? matchRes.matches : [];
      const matchTbody = document.getElementById('hunt-matches-tbody');
      if (matchTbody) {
        if (matches.length === 0) {
          matchTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No threat detections found across active fleet.</td></tr>';
        } else {
          matchTbody.innerHTML = matches.map(m => `
            <tr class="hover:bg-slate-800/40 transition">
              <td class="px-4 py-3">
                <div class="font-bold text-rose-400 flex items-center gap-1.5">
                  <span>🚨</span> ${escapeHtml(m.matched_item)}
                </div>
                <div class="text-[10px] text-slate-500">${escapeHtml(m.match_type)}</div>
              </td>
              <td class="px-4 py-3 font-semibold text-white">${escapeHtml(m.hostname)}</td>
              <td class="px-4 py-3 font-mono text-[11px] text-slate-300 truncate max-w-xs" title="${escapeHtml(m.file_path)}">
                ${escapeHtml(m.file_path || 'Memory Injection')}
              </td>
              <td class="px-4 py-3 font-mono text-cyan-400">${escapeHtml(m.mitre_technique || 'T1059')}</td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${m.action_taken === 'CONTAIN_HOST' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-amber-500/20 text-amber-300'}">
                  ${escapeHtml(m.action_taken)}
                </span>
              </td>
              <td class="px-4 py-3 text-slate-400 text-[11px] text-right">
                ${m.detected_at ? new Date(m.detected_at).toLocaleTimeString() : '—'}
              </td>
            </tr>
          `).join('');
        }
      }

      // 4. IoC Watchlist
      const iocRes = await api.get('/api/v1/fleet/hunting/iocs');
      const iocs = (iocRes && iocRes.iocs) ? iocRes.iocs : [];
      const iocTbody = document.getElementById('hunt-iocs-tbody');
      if (iocTbody) {
        if (iocs.length === 0) {
          iocTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No threat indicators in watchlist.</td></tr>';
        } else {
          iocTbody.innerHTML = iocs.map(ioc => `
            <tr class="hover:bg-slate-800/40 transition">
              <td class="px-4 py-3">
                <div class="font-bold text-white flex items-center gap-1.5">
                  <span>📜</span> ${escapeHtml(ioc.threat_name)}
                </div>
              </td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-300">
                  ${escapeHtml(ioc.indicator_type)}
                </span>
              </td>
              <td class="px-4 py-3 font-mono text-[11px] text-cyan-300 truncate max-w-sm" title="${escapeHtml(ioc.indicator_value)}">
                ${escapeHtml(ioc.indicator_value)}
              </td>
              <td class="px-4 py-3 text-[11px] text-slate-300">${escapeHtml(ioc.confidence)}</td>
              <td class="px-4 py-3">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${ioc.action_on_match === 'CONTAIN_HOST' ? 'bg-rose-900/40 text-rose-300' : 'bg-slate-700 text-slate-300'}">
                  ${escapeHtml(ioc.action_on_match)}
                </span>
              </td>
              <td class="px-4 py-3 text-right">
                <button class="btn-del-ioc text-rose-400 hover:text-rose-300 text-xs font-semibold transition" data-id="${ioc.id}">
                  Delete
                </button>
              </td>
            </tr>
          `).join('');

          iocTbody.querySelectorAll('.btn-del-ioc').forEach(btn => {
            btn.addEventListener('click', async () => {
              const iId = btn.getAttribute('data-id');
              if (confirm('Delete this threat intelligence indicator?')) {
                try {
                  await api.delete(`/api/v1/fleet/hunting/iocs/${iId}`);
                  if (window.showToast) window.showToast('Indicator deleted', 'info');
                  await loadAllHuntingData(api);
                } catch(e) {
                  alert('Failed to delete indicator: ' + e.message);
                }
              }
            });
          });
        }
      }

    } catch (err) {
      console.error('Failed loading threat hunting blade data:', err);
    }
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

window.ThreatHuntingTable = {
  render: async function() {
    const container = document.getElementById('tab-threat-hunting');
    if (!container) return;
    container.innerHTML = renderThreatHuntingBlade();
    const client = {
      get: async (url) => {
        if (typeof window.apiFetch === 'function') {
          return window.apiFetch(url);
        }
        const key = localStorage.getItem('fleet_key') || '';
        const base = (localStorage.getItem('fleet_server_url') || '').replace(/\/$/, '') || window.location.origin;
        const res = await fetch(`${base}${url}`, {
          headers: { 'X-Fleet-Key': key, 'Content-Type': 'application/json' }
        });
        return res.json();
      },
      post: async (url, body) => {
        if (typeof window.apiFetch === 'function') {
          return window.apiFetch(url, { method: 'POST', body: JSON.stringify(body) });
        }
        const key = localStorage.getItem('fleet_key') || '';
        const base = (localStorage.getItem('fleet_server_url') || '').replace(/\/$/, '') || window.location.origin;
        const res = await fetch(`${base}${url}`, {
          method: 'POST',
          headers: { 'X-Fleet-Key': key, 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        return res.json();
      },
      delete: async (url) => {
        if (typeof window.apiFetch === 'function') {
          return window.apiFetch(url, { method: 'DELETE' });
        }
        const key = localStorage.getItem('fleet_key') || '';
        const base = (localStorage.getItem('fleet_server_url') || '').replace(/\/$/, '') || window.location.origin;
        const res = await fetch(`${base}${url}`, {
          method: 'DELETE',
          headers: { 'X-Fleet-Key': key, 'Content-Type': 'application/json' }
        });
        return res.json();
      }
    };
    await initThreatHuntingBlade(client);
  }
};
