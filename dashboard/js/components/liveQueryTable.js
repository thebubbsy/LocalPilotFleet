/**
 * LocalPilot Fleet — Live Distributed Query Blade (CMPivot / Tanium Sensor Architecture)
 * Sub-3-second real-time distributed endpoint querying and live streaming aggregation.
 */

function renderLiveQueryBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-cyan-500/20 text-cyan-400 rounded-lg text-2xl border border-cyan-500/30">⚡</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Live Distributed Query Engine (CMPivot / Tanium)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">Sub-3s Response</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Real-time in-memory distributed query across active workstations via WebSocket push channel</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-query-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh Sessions
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="query-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Queries Run</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-query-total">-</p>
          <p class="text-xs text-cyan-400 mt-1 flex items-center gap-1">Distributed Sessions</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Available Sensors</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">📡</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-query-sensors">-</p>
          <p class="text-xs text-emerald-400 mt-1 flex items-center gap-1">CMPivot Entity Types</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mean Response Latency</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">⏱️</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-query-latency">-</p>
          <p class="text-xs text-purple-300 mt-1">WebSocket Push Dispatch</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Rows Captured</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">📊</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-query-rows">-</p>
          <p class="text-xs text-amber-300 mt-1">Live In-Memory Telemetry</p>
        </div>
      </div>

      <!-- Live Query Composer Card -->
      <div class="bg-slate-800/50 p-5 rounded-xl border border-slate-700/60 shadow space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
          <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>💻</span> Live Query Bar (CMPivot KQL / osquery)
          </h3>
          <div class="flex items-center gap-2 text-xs text-slate-400">
            <span>Target:</span>
            <select id="query-target-scope" class="bg-slate-900 text-slate-200 px-2.5 py-1 rounded border border-slate-700 font-medium">
              <option value="ALL_FLEET">Entire Fleet (All Online Workstations)</option>
              <option value="DEVICE">Single Workstation (DESKTOP-R0H12DJ)</option>
            </select>
          </div>
        </div>

        <!-- Query Input Field -->
        <div class="flex gap-2">
          <input type="text" id="input-query-text" placeholder="e.g. ProcessList | where WorkingSetMB > 250 or ServiceList | where State == 'Running'" 
            class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-cyan-300 font-mono placeholder:text-slate-500 focus:outline-none focus:border-cyan-500" />
          <button id="btn-dispatch-query" class="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg text-sm transition flex items-center gap-2 shadow-md hover:shadow-cyan-500/20">
            <span>⚡</span> Run Query
          </button>
        </div>

        <!-- Quick Template Chips -->
        <div class="flex flex-wrap gap-2 pt-1 items-center">
          <span class="text-xs text-slate-400 font-medium">Quick Sensors:</span>
          <button class="chip-template px-2.5 py-1 bg-slate-700/60 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-600/60" data-query="ProcessList | where WorkingSetMB > 250">
            🔥 High RAM Processes
          </button>
          <button class="chip-template px-2.5 py-1 bg-slate-700/60 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-600/60" data-query="ServiceList | where State == 'Running'">
            ⚙️ Running Services
          </button>
          <button class="chip-template px-2.5 py-1 bg-slate-700/60 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-600/60" data-query="ActiveNetworkConnections | where LocalPort == 8443">
            🌐 Port 8443 Listeners
          </button>
          <button class="chip-template px-2.5 py-1 bg-slate-700/60 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-600/60" data-query="CimInstance('Win32_OperatingSystem')">
            🖥️ OS Version CIM
          </button>
          <button class="chip-template px-2.5 py-1 bg-slate-700/60 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-600/60" data-query="Registry('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate')">
            🔑 WindowsUpdate RegKeys
          </button>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="query-subtab px-4 py-2 text-sm font-semibold border-b-2 border-cyan-500 text-cyan-400" data-tab="results">
          📊 Live Query Results
        </button>
        <button class="query-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="sessions">
          🕒 Query Sessions History
        </button>
        <button class="query-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="entities">
          📡 CMPivot Entity Catalog
        </button>
      </div>

      <!-- Tab 1: Live Results -->
      <div id="query-tab-results" class="query-tab-content space-y-4">
        <div class="flex justify-between items-center bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400">Active Query:</span>
            <span id="active-query-text-badge" class="font-mono text-xs text-cyan-400 bg-slate-900 px-2.5 py-1 rounded border border-slate-700">ProcessList | where WorkingSetMB > 250</span>
            <span id="active-query-status-badge" class="text-xs px-2 py-0.5 rounded font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">COMPLETED</span>
          </div>
          <div class="flex items-center gap-2">
            <button id="btn-export-csv" class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs font-semibold transition border border-slate-600 flex items-center gap-1">
              <span>📥</span> Export CSV
            </button>
          </div>
        </div>

        <div class="bg-slate-800/40 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-800/80 text-xs font-semibold text-slate-400 uppercase border-b border-slate-700">
                <tr>
                  <th class="px-4 py-3">Device ID & Hostname</th>
                  <th class="px-4 py-3">Latency (ms)</th>
                  <th class="px-4 py-3">Result Payload (JSON)</th>
                  <th class="px-4 py-3">Timestamp</th>
                </tr>
              </thead>
              <tbody id="query-results-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="4" class="px-4 py-8 text-center text-slate-500">No active query results. Run a query above.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 2: Sessions List -->
      <div id="query-tab-sessions" class="query-tab-content hidden space-y-4">
        <div class="bg-slate-800/40 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-800/80 text-xs font-semibold text-slate-400 uppercase border-b border-slate-700">
                <tr>
                  <th class="px-4 py-3">Session ID</th>
                  <th class="px-4 py-3">Query Expression</th>
                  <th class="px-4 py-3">Target Scope</th>
                  <th class="px-4 py-3">Progress</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Initiated By</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="query-sessions-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading query sessions...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 3: Entity Catalog -->
      <div id="query-tab-entities" class="query-tab-content hidden space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" id="query-entities-grid">
          <div class="p-8 text-center text-slate-500 col-span-3">Loading sensor catalog...</div>
        </div>
      </div>
    </div>
  `;
}

async function initLiveQueryBlade(api) {
  let currentSessionId = 'qry-default-process-audit';

  const refreshBtn = document.getElementById('btn-query-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', () => loadQueryBladeData(api, currentSessionId));

  // Quick chip templates
  document.querySelectorAll('.chip-template').forEach(btn => {
    btn.addEventListener('click', () => {
      const q = btn.getAttribute('data-query');
      const input = document.getElementById('input-query-text');
      if (input) input.value = q;
    });
  });

  // Dispatch button
  const dispatchBtn = document.getElementById('btn-dispatch-query');
  if (dispatchBtn) {
    dispatchBtn.addEventListener('click', async () => {
      const input = document.getElementById('input-query-text');
      const targetScopeSelect = document.getElementById('query-target-scope');
      const text = input ? input.value.trim() : '';
      if (!text) {
        alert('Please enter a query expression.');
        return;
      }

      try {
        const scope = targetScopeSelect ? targetScopeSelect.value : 'ALL_FLEET';
        const res = await api.post('/api/v1/fleet/queries/sessions', {
          query_text: text,
          query_type: 'CMPIVOT_KQL',
          target_scope: scope,
          target_id: scope === 'DEVICE' ? 'DESKTOP-R0H12DJ' : null
        });

        if (res && res.id) {
          currentSessionId = res.id;
          const textBadge = document.getElementById('active-query-text-badge');
          if (textBadge) textBadge.textContent = text;
          await loadQueryBladeData(api, currentSessionId);
        }
      } catch (err) {
        alert('Failed to dispatch query: ' + err.message);
      }
    });
  }

  // Export CSV
  const exportBtn = document.getElementById('btn-export-csv');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      window.open(`/api/v1/fleet/queries/sessions/${currentSessionId}/export`, '_blank');
    });
  }

  // Subtabs
  document.querySelectorAll('.query-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.query-subtab').forEach(b => {
        b.classList.remove('border-cyan-500', 'text-cyan-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.add('border-cyan-500', 'text-cyan-400');
      btn.classList.remove('border-transparent', 'text-slate-400');

      document.querySelectorAll('.query-tab-content').forEach(c => c.classList.add('hidden'));
      const tabId = `query-tab-${btn.getAttribute('data-tab')}`;
      const target = document.getElementById(tabId);
      if (target) target.classList.remove('hidden');
    });
  });

  await loadQueryBladeData(api, currentSessionId);
}

async function loadQueryBladeData(api, sessionId) {
  try {
    const stats = await api.get('/api/v1/fleet/queries/stats');
    if (stats) {
      document.getElementById('kpi-query-total').textContent = stats.totalSessions || 0;
      document.getElementById('kpi-query-sensors').textContent = stats.availableSensors || 0;
      document.getElementById('kpi-query-latency').textContent = (stats.averageExecutionLatencyMs || 350) + ' ms';
      document.getElementById('kpi-query-rows').textContent = stats.totalRowsIngested || 0;
    }

    // Load active session results
    if (sessionId) {
      const resultsRes = await api.get(`/api/v1/fleet/queries/sessions/${sessionId}/results`);
      const tbody = document.getElementById('query-results-tbody');
      if (tbody && resultsRes && resultsRes.results) {
        if (resultsRes.results.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-500">Awaiting endpoint responses...</td></tr>';
        } else {
          tbody.innerHTML = resultsRes.results.map(r => `
            <tr class="hover:bg-slate-800/50 transition">
              <td class="px-4 py-3 font-semibold text-slate-100">${escapeHtml(r.hostname)} <span class="text-[10px] text-slate-400 font-mono">(${escapeHtml(r.device_id)})</span></td>
              <td class="px-4 py-3 text-cyan-400">${r.execution_duration_ms} ms</td>
              <td class="px-4 py-3 text-slate-300"><pre class="text-[11px] font-mono bg-slate-900/80 p-2 rounded border border-slate-700/60 max-h-32 overflow-x-auto">${escapeHtml(JSON.stringify(r.data, null, 2))}</pre></td>
              <td class="px-4 py-3 text-slate-400 text-[11px]">${escapeHtml(r.received_at)}</td>
            </tr>
          `).join('');
        }
      }
    }

    // Load sessions table
    const sessionsRes = await api.get('/api/v1/fleet/queries/sessions?limit=20');
    const sessionsTbody = document.getElementById('query-sessions-tbody');
    if (sessionsTbody && sessionsRes && sessionsRes.sessions) {
      sessionsTbody.innerHTML = sessionsRes.sessions.map(s => `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 font-mono text-cyan-300">${escapeHtml(s.id)}</td>
          <td class="px-4 py-3 font-mono text-slate-200">${escapeHtml(s.query_text)}</td>
          <td class="px-4 py-3 text-slate-400">${escapeHtml(s.target_scope)}</td>
          <td class="px-4 py-3">
            <div class="flex items-center gap-2">
              <div class="w-16 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                <div class="bg-cyan-400 h-1.5" style="width: ${s.completion_percent || 0}%"></div>
              </div>
              <span class="text-[10px] text-slate-400">${s.responded_targets}/${s.total_targets}</span>
            </div>
          </td>
          <td class="px-4 py-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${s.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'} border">
              ${escapeHtml(s.status)}
            </span>
          </td>
          <td class="px-4 py-3 text-slate-400">${escapeHtml(s.initiated_by)}</td>
          <td class="px-4 py-3 text-right">
            <button class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs transition" onclick="window.open('/api/v1/fleet/queries/sessions/${s.id}/export', '_blank')">
              📥 CSV
            </button>
          </td>
        </tr>
      `).join('');
    }

    // Load entities grid
    const entitiesRes = await api.get('/api/v1/fleet/queries/entities');
    const entitiesGrid = document.getElementById('query-entities-grid');
    if (entitiesGrid && entitiesRes && entitiesRes.entities) {
      entitiesGrid.innerHTML = entitiesRes.entities.map(e => `
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow flex flex-col justify-between">
          <div>
            <div class="flex justify-between items-center mb-2">
              <h4 class="font-bold text-white text-sm flex items-center gap-1.5">
                <span>📡</span> ${escapeHtml(e.entity_name)}
              </h4>
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-700 text-slate-300">${escapeHtml(e.category)}</span>
            </div>
            <p class="text-xs text-slate-400 mb-3">${escapeHtml(e.description)}</p>
          </div>
          <div class="pt-2 border-t border-slate-700/40">
            <div class="text-[10px] text-slate-500 font-semibold uppercase mb-1">Sample Expression:</div>
            <code class="text-[11px] text-cyan-300 bg-slate-900 px-2 py-1 rounded block overflow-x-auto font-mono border border-slate-800">${escapeHtml(e.sample_query)}</code>
          </div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed loading query blade data:', err);
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

window.LiveQueryTable = {
  render: async function() {
    const container = document.getElementById('tab-live-queries');
    if (!container) return;
    container.innerHTML = renderLiveQueryBlade();
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
      }
    };
    await initLiveQueryBlade(client);
  }
};

