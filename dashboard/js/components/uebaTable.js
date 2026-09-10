/**
 * LocalPilot Fleet — User & Entity Behavior Analytics (UEBA) & Insider Risk Blade
 * dashboard/js/components/uebaTable.js
 *
 * Real-time monitoring of anomalous user behavior (mass data exfiltration, after-hours logins,
 * privilege creep, flight-risk markers), composite risk scoring (0-100), and 1-click automated containment.
 */

function renderUebaBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-violet-500/20 text-violet-400 rounded-lg text-2xl border border-violet-500/30">👤</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                User &amp; Entity Behavior Analytics (UEBA)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-violet-500/20 text-violet-300 border border-violet-500/30">Insider Risk</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Continuous behavioral baseline deviation detection, composite risk scoring (0–100), and autonomous containment</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-ueba-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-ueba-new-indicator" class="px-3.5 py-2 bg-violet-600 hover:bg-violet-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-violet-500/20">
            <span>➕</span> Add Indicator
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" id="ueba-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Risk Indicators</p>
            <span class="p-1.5 bg-violet-500/20 text-violet-400 rounded-md text-sm">📊</span>
          </div>
          <p class="text-2xl font-bold text-violet-400 mt-2" id="kpi-ueba-indicators">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Open Anomalies</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-ueba-anomalies">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">High Risk Users</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-ueba-highrisk">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Flight Risk Flags</p>
            <span class="p-1.5 bg-fuchsia-500/20 text-fuchsia-400 rounded-md text-sm">✈️</span>
          </div>
          <p class="text-2xl font-bold text-fuchsia-400 mt-2" id="kpi-ueba-flightrisk">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mean Risk Score</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📈</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-ueba-meanscore">-</p>
        </div>
      </div>

      <!-- Section 1: User Insider Risk Profiles -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">User Insider Risk Profiles</h3>
            <p class="text-xs text-slate-400 mt-0.5">Composite risk scoring based on behavioral deviation events and weighted telemetry</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="ueba-profiles-count">0 Users</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">User Principal</th>
                <th class="px-4 py-3">Department</th>
                <th class="px-4 py-3">Risk Score (0–100)</th>
                <th class="px-4 py-3">Level</th>
                <th class="px-4 py-3">Flight Risk</th>
                <th class="px-4 py-3">Containment</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ueba-profiles-tbody" class="divide-y divide-slate-700/40 text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading user risk profiles...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Live Behavior Anomalies Stream -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Behavioral Anomaly Stream</h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time deviations exceeding normal baseline thresholds</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="ueba-anomalies-count">0 Anomalies</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">User</th>
                <th class="px-4 py-3">Hostname</th>
                <th class="px-4 py-3">Anomaly Type</th>
                <th class="px-4 py-3">Observed / Baseline</th>
                <th class="px-4 py-3">Deviation</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="ueba-anomalies-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">Loading behavior anomalies...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 3: Risk Indicators Catalog -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Behavioral Risk Indicators Catalog</h3>
            <p class="text-xs text-slate-400 mt-0.5">Defined heuristic models and baseline deviation multipliers</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="ueba-indicators-count">0 Indicators</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Indicator Name</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Risk Weight</th>
                <th class="px-4 py-3">Threshold Multiplier</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody id="ueba-indicators-tbody" class="divide-y divide-slate-700/40 text-xs">
              <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading risk indicators...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Modal: Add Risk Indicator -->
      <div id="modal-ueba-indicator" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>👤</span> Add Risk Indicator
            </h3>
            <button id="modal-ueba-indicator-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Indicator Name (Code)</label>
              <input id="input-uri-name" type="text" placeholder="RAPID_MASS_RENAME_SPIKE" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono uppercase" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Category</label>
                <select id="select-uri-category" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
                  <option value="ANOMALOUS_LOGON">ANOMALOUS_LOGON</option>
                  <option value="PRIVILEGE_ABUSE">PRIVILEGE_ABUSE</option>
                  <option value="FLIGHT_RISK">FLIGHT_RISK</option>
                  <option value="RESOURCE_SNOOPING">RESOURCE_SNOOPING</option>
                </select>
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Severity</label>
                <select id="select-uri-severity" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM" selected>MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Risk Weight (1-50)</label>
                <input id="input-uri-weight" type="number" min="1" max="50" value="25" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Threshold Multiplier</label>
                <input id="input-uri-threshold" type="number" step="0.5" value="3.0" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Description</label>
              <textarea id="input-uri-desc" rows="2" placeholder="Detects anomalous activity exceeding baseline..." class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white"></textarea>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-ueba-indicator-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-ueba-indicator-submit" class="px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white rounded-lg text-xs font-semibold">Save Indicator</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function initUebaBlade() {
  const getFleetKey = () => localStorage.getItem('fleetKey') || '';

  async function loadStats() {
    try {
      const res = await fetch('/api/v1/fleet/ueba/stats', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        document.getElementById('kpi-ueba-indicators').textContent = data.stats.totalIndicators ?? 0;
        document.getElementById('kpi-ueba-anomalies').textContent = data.stats.openAnomalies ?? 0;
        document.getElementById('kpi-ueba-highrisk').textContent = data.stats.highRiskUsersCount ?? 0;
        document.getElementById('kpi-ueba-flightrisk').textContent = data.stats.flightRiskUsersCount ?? 0;
        document.getElementById('kpi-ueba-meanscore').textContent = data.stats.meanUserRiskScore ?? 0;
      }
    } catch (e) {
      console.error('Failed to load UEBA stats:', e);
    }
  }

  async function loadProfiles() {
    try {
      const res = await fetch('/api/v1/fleet/ueba/profiles', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('ueba-profiles-tbody');
      const countEl = document.getElementById('ueba-profiles-count');
      if (!tbody) return;

      const profiles = data.profiles || [];
      if (countEl) countEl.textContent = `${profiles.length} Users`;

      if (profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No user risk profiles found.</td></tr>';
        return;
      }

      tbody.innerHTML = profiles.map(p => {
        const levelBadge = p.risk_level === 'CRITICAL' ?
          '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">CRITICAL</span>' :
          p.risk_level === 'HIGH' ?
          '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">HIGH</span>' :
          p.risk_level === 'MEDIUM' ?
          '<span class="px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">MEDIUM</span>' :
          '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">LOW</span>';

        const flightBadge = p.flight_risk_flag ?
          '<span class="px-2 py-0.5 rounded bg-fuchsia-500/20 text-fuchsia-300 font-semibold border border-fuchsia-500/30 text-xs">✈️ FLIGHT RISK</span>' :
          '<span class="text-slate-500 font-sans">None</span>';

        const containmentBadge = p.containment_status === 'CONTAINED' ?
          '<span class="px-2 py-0.5 rounded bg-rose-600/30 text-rose-300 font-bold border border-rose-500/40">CONTAINED</span>' :
          p.containment_status === 'RESTRICTED' ?
          '<span class="px-2 py-0.5 rounded bg-amber-600/30 text-amber-300 font-bold border border-amber-500/40">RESTRICTED</span>' :
          '<span class="text-slate-400 font-sans">MONITORED</span>';

        const scoreColor = p.composite_risk_score >= 80 ? 'text-rose-400' :
                           p.composite_risk_score >= 60 ? 'text-amber-400' :
                           p.composite_risk_score >= 30 ? 'text-yellow-400' : 'text-emerald-400';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white">
              ${p.display_name || p.user_principal}
              <div class="text-xs text-slate-400 font-mono">${p.user_principal}</div>
            </td>
            <td class="px-4 py-3 text-slate-300">${p.department || 'Enterprise'}</td>
            <td class="px-4 py-3 font-mono font-bold ${scoreColor}">
              <div class="flex items-center gap-2">
                <span>${p.composite_risk_score}</span>
                <div class="w-16 h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div class="h-full bg-current" style="width: ${Math.min(p.composite_risk_score, 100)}%"></div>
                </div>
              </div>
            </td>
            <td class="px-4 py-3">${levelBadge}</td>
            <td class="px-4 py-3">${flightBadge}</td>
            <td class="px-4 py-3">${containmentBadge}</td>
            <td class="px-4 py-3 text-right space-x-1.5 font-sans">
              <button onclick="window.containUser('${p.user_principal}', 'RESTRICTED')" class="px-2.5 py-1 bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 rounded text-xs border border-amber-500/30 transition">Restrict</button>
              <button onclick="window.containUser('${p.user_principal}', 'CONTAINED')" class="px-2.5 py-1 bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 rounded text-xs border border-rose-500/30 transition">Contain</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load UEBA profiles:', e);
    }
  }

  async function loadAnomalies() {
    try {
      const res = await fetch('/api/v1/fleet/ueba/anomalies', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('ueba-anomalies-tbody');
      const countEl = document.getElementById('ueba-anomalies-count');
      if (!tbody) return;

      const anomalies = data.anomalies || [];
      if (countEl) countEl.textContent = `${anomalies.length} Anomalies`;

      if (anomalies.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No behavior anomalies recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = anomalies.map(a => {
        const statusBadge = a.status === 'OPEN' ?
          '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 font-bold border border-rose-500/30 text-xs animate-pulse">OPEN</span>' :
          a.status === 'INVESTIGATING' ?
          '<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs">INVESTIGATING</span>' :
          '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs">RESOLVED</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white font-sans">${a.user_principal}</td>
            <td class="px-4 py-3 text-slate-400">${a.hostname}</td>
            <td class="px-4 py-3 text-violet-400 font-bold">${a.anomaly_type}</td>
            <td class="px-4 py-3 text-slate-300">${a.observed_value} / ${a.baseline_value}</td>
            <td class="px-4 py-3 text-rose-400 font-bold">+${a.deviation_score}x</td>
            <td class="px-4 py-3 font-sans">${statusBadge}</td>
            <td class="px-4 py-3 text-right font-sans">
              <button onclick="window.resolveAnomaly('${a.id}')" class="px-2 py-0.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs transition">Resolve</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load anomalies:', e);
    }
  }

  async function loadIndicators() {
    try {
      const res = await fetch('/api/v1/fleet/ueba/indicators', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('ueba-indicators-tbody');
      const countEl = document.getElementById('ueba-indicators-count');
      if (!tbody) return;

      const indicators = data.indicators || [];
      if (countEl) countEl.textContent = `${indicators.length} Indicators`;

      tbody.innerHTML = indicators.map(i => {
        const sevBadge = i.severity === 'CRITICAL' ? '<span class="text-rose-400 font-bold">CRITICAL</span>' :
                         i.severity === 'HIGH' ? '<span class="text-amber-400 font-bold">HIGH</span>' :
                         '<span class="text-slate-300">MEDIUM</span>';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-mono font-bold text-violet-400">${i.indicator_name}</td>
            <td class="px-4 py-3 text-slate-300 font-mono">${i.category}</td>
            <td class="px-4 py-3 font-mono text-cyan-400 font-bold">+${i.risk_weight}</td>
            <td class="px-4 py-3 font-mono text-amber-400">${i.threshold_value}x</td>
            <td class="px-4 py-3 font-mono">${sevBadge}</td>
            <td class="px-4 py-3 text-slate-400 max-w-sm truncate" title="${i.description}">${i.description}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load indicators:', e);
    }
  }

  // Global window helpers
  window.containUser = async (userPrincipal, containmentStatus) => {
    try {
      const res = await fetch('/api/v1/fleet/ueba/contain-user', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_principal: userPrincipal, containment_status: containmentStatus })
      });
      if (res.ok) {
        loadProfiles();
        loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  window.resolveAnomaly = async (id) => {
    try {
      const res = await fetch(`/api/v1/fleet/ueba/anomalies/${id}`, {
        method: 'PATCH',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'RESOLVED' })
      });
      if (res.ok) {
        loadAnomalies();
        loadProfiles();
        loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Event handlers
  document.getElementById('btn-ueba-refresh')?.addEventListener('click', () => {
    loadStats();
    loadProfiles();
    loadAnomalies();
    loadIndicators();
  });

  document.getElementById('btn-ueba-new-indicator')?.addEventListener('click', () => {
    document.getElementById('modal-ueba-indicator').classList.remove('hidden');
  });
  document.getElementById('modal-ueba-indicator-close')?.addEventListener('click', () => {
    document.getElementById('modal-ueba-indicator').classList.add('hidden');
  });
  document.getElementById('modal-ueba-indicator-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-ueba-indicator').classList.add('hidden');
  });
  document.getElementById('modal-ueba-indicator-submit')?.addEventListener('click', async () => {
    const indicator_name = document.getElementById('input-uri-name').value.trim();
    const category = document.getElementById('select-uri-category').value;
    const severity = document.getElementById('select-uri-severity').value;
    const risk_weight = parseInt(document.getElementById('input-uri-weight').value, 10) || 20;
    const threshold_value = parseFloat(document.getElementById('input-uri-threshold').value) || 3.0;
    const description = document.getElementById('input-uri-desc').value.trim();

    if (!indicator_name) { alert('Indicator name is required'); return; }

    try {
      const res = await fetch('/api/v1/fleet/ueba/indicators', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator_name, category, severity, risk_weight, threshold_value, description })
      });
      if (res.ok) {
        document.getElementById('modal-ueba-indicator').classList.add('hidden');
        loadIndicators();
        loadStats();
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadStats();
  loadProfiles();
  loadAnomalies();
  loadIndicators();
}

window.renderUebaBlade = renderUebaBlade;
window.initUebaBlade = initUebaBlade;

window.UebaTable = {
  async render() {
    const container = document.getElementById('tab-ueba');
    if (!container) return;
    container.innerHTML = renderUebaBlade();
    initUebaBlade();
  }
};
