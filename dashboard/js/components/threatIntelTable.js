/**
 * LocalPilot Fleet — Automated Threat Intelligence & Indicator Matching Blade
 * STIX/TAXII 2.1, AbuseIPDB, AlienVault OTX, URLhaus feed management, IOC caching, and live interception stream.
 */

function renderThreatIntelBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-amber-500/20 text-amber-400 rounded-lg text-2xl border border-amber-500/30">🌐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Threat Intelligence &amp; Indicator Matching
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">IOC Cache</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated STIX/TAXII, AbuseIPDB &amp; OTX ingest, real-time IOC caching, and live interception stream</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-ti-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-ti-new-feed" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>📡</span> Add Feed Source
          </button>
          <button id="btn-ti-new-ioc" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>➕</span> Add Custom IOC
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="ti-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Feeds</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">📡</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-ti-feeds">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Cached Indicators</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-ti-indicators">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Interceptions</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">⛔</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-ti-matches">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Severity</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🔥</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-ti-critical">-</p>
        </div>
      </div>

      <!-- Feed Sources Table -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Threat Intelligence Feed Sources</h3>
            <p class="text-xs text-slate-400 mt-0.5">Automated inbound STIX/TAXII 2.1, AbuseIPDB, AlienVault OTX, and URLhaus collectors</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="ti-feeds-count">0 Feeds</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Feed Name</th>
                <th class="px-4 py-3">Format</th>
                <th class="px-4 py-3">Schedule</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Indicators</th>
                <th class="px-4 py-3">Last Sync</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ti-feeds-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading feed sources...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Threat Indicators Cache -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Threat Indicators Cache (IOCs)</h3>
            <p class="text-xs text-slate-400 mt-0.5">Known malicious IP addresses, domain names, URLs, and file hashes</p>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="ti-ioc-search" placeholder="Search indicator value..." class="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 font-mono focus:ring-1 focus:ring-amber-500" />
            <span class="text-xs text-slate-400 font-mono" id="ti-iocs-count">0 Indicators</span>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Indicator Value</th>
                <th class="px-4 py-3">Type</th>
                <th class="px-4 py-3">Threat Category</th>
                <th class="px-4 py-3">Confidence</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">MITRE ATT&amp;CK</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ti-iocs-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading cached indicators...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Live Match Interceptions Stream -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Live Threat Match Interceptions</h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time endpoint hits against cached threat intelligence</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="ti-matches-count">0 Interceptions</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Matched Indicator</th>
                <th class="px-4 py-3">Host</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Context &amp; Details</th>
                <th class="px-4 py-3 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody id="ti-matches-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading threat interceptions...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function initThreatIntelBlade() {
  const btnRefresh = document.getElementById('btn-ti-refresh');
  if (btnRefresh) btnRefresh.onclick = () => loadThreatIntelData();

  const btnNewFeed = document.getElementById('btn-ti-new-feed');
  if (btnNewFeed) {
    btnNewFeed.onclick = async () => {
      const name = prompt('Feed Source Name:', 'Custom Threat Exchange Feed');
      if (!name) return;
      const url = prompt('Feed URL endpoint:');
      if (!url) return;

      try {
        const res = await fetch('/api/v1/fleet/threat-intel/feeds', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name,
            feed_url: url,
            feed_format: 'STIX_TAXII_21',
            poll_interval_hours: 6,
            default_action: 'BLOCK'
          }),
          credentials: 'same-origin'
        });
        if (res.ok) {
          alert('Threat feed source registered successfully!');
          loadThreatIntelData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  const btnNewIoc = document.getElementById('btn-ti-new-ioc');
  if (btnNewIoc) {
    btnNewIoc.onclick = async () => {
      const type = prompt('Indicator Type (IPV4_ADDRESS, DOMAIN_FQDN, URL, SHA256_HASH):', 'IPV4_ADDRESS');
      if (!type) return;
      const val = prompt('Indicator Value:');
      if (!val) return;

      try {
        const res = await fetch('/api/v1/fleet/threat-intel/indicators', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            indicator_type: type.toUpperCase(),
            indicator_value: val.trim(),
            threat_type: 'MALWARE',
            severity: 'HIGH',
            confidence_score: 95
          }),
          credentials: 'same-origin'
        });
        if (res.ok) {
          alert('Indicator added to threat intelligence cache!');
          loadThreatIntelData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  const searchInput = document.getElementById('ti-ioc-search');
  if (searchInput) {
    searchInput.oninput = () => {
      loadThreatIntelIndicators(searchInput.value);
    };
  }

  await loadThreatIntelData();
}

async function loadThreatIntelData() {
  try {
    // 1. Stats
    const statsRes = await fetch('/api/v1/fleet/threat-intel/stats', { credentials: 'same-origin' });
    if (statsRes.ok) {
      const s = await statsRes.json();
      const elFeeds = document.getElementById('kpi-ti-feeds');
      const elIoc = document.getElementById('kpi-ti-indicators');
      const elMat = document.getElementById('kpi-ti-matches');
      const elCrit = document.getElementById('kpi-ti-critical');
      if (elFeeds) elFeeds.innerText = s.activeFeeds || 0;
      if (elIoc) elIoc.innerText = s.totalIndicators || 0;
      if (elMat) elMat.innerText = s.totalMatches || 0;
      if (elCrit) elCrit.innerText = s.criticalIndicators || 0;
    }

    // 2. Feeds
    const feedsRes = await fetch('/api/v1/fleet/threat-intel/feeds', { credentials: 'same-origin' });
    if (feedsRes.ok) {
      const data = await feedsRes.json();
      renderFeedsTable(data.feeds || []);
    }

    // 3. Indicators
    await loadThreatIntelIndicators();

    // 4. Matches
    const matchesRes = await fetch('/api/v1/fleet/threat-intel/matches', { credentials: 'same-origin' });
    if (matchesRes.ok) {
      const data = await matchesRes.json();
      renderMatchesTable(data.matches || []);
    }
  } catch (err) {
    console.error('Failed to load threat intelligence telemetry:', err);
  }
}

async function loadThreatIntelIndicators(search = '') {
  try {
    const url = search ? `/api/v1/fleet/threat-intel/indicators?search=${encodeURIComponent(search)}` : '/api/v1/fleet/threat-intel/indicators';
    const res = await fetch(url, { credentials: 'same-origin' });
    if (res.ok) {
      const data = await res.json();
      renderIndicatorsTable(data.indicators || []);
    }
  } catch (e) {
    console.error(e);
  }
}

function renderFeedsTable(feeds) {
  const tbody = document.getElementById('ti-feeds-tbody');
  const countEl = document.getElementById('ti-feeds-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${feeds.length} Feeds`;

  if (!feeds.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No threat feed sources configured.</td></tr>';
    return;
  }

  tbody.innerHTML = feeds.map(f => `
    <tr class="hover:bg-slate-750/50 transition">
      <td class="px-4 py-3 font-medium text-slate-200">
        <div class="font-bold text-white">${escapeHtml(f.name)}</div>
        <div class="text-[10px] text-slate-400 font-mono truncate max-w-xs">${escapeHtml(f.feed_url)}</div>
      </td>
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
          ${escapeHtml(f.feed_format)}
        </span>
      </td>
      <td class="px-4 py-3 text-slate-300">Every ${f.poll_interval_hours}h</td>
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
          ${escapeHtml(f.default_action)}
        </span>
      </td>
      <td class="px-4 py-3 font-bold text-blue-400">${f.indicator_count || 0}</td>
      <td class="px-4 py-3 text-slate-400 text-[11px]">${escapeHtml(f.last_sync_time || 'Never')}</td>
      <td class="px-4 py-3 text-right">
        <button onclick="syncThreatFeed('${f.id}')" class="px-2 py-1 bg-amber-600/20 hover:bg-amber-600 text-amber-300 hover:text-white rounded text-[11px] border border-amber-500/30 mr-1">
          🔄 Sync
        </button>
        <button onclick="deleteThreatFeed('${f.id}')" class="px-2 py-1 bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white rounded text-[11px] border border-rose-500/30">
          🗑️
        </button>
      </td>
    </tr>
  `).join('');
}

function renderIndicatorsTable(indicators) {
  const tbody = document.getElementById('ti-iocs-tbody');
  const countEl = document.getElementById('ti-iocs-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${indicators.length} IOCs`;

  if (!indicators.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No cached indicators match filter.</td></tr>';
    return;
  }

  tbody.innerHTML = indicators.map(i => {
    const sevColor = i.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
      (i.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-blue-500/20 text-blue-300 border-blue-500/30');

    return `
      <tr class="hover:bg-slate-750/50 transition">
        <td class="px-4 py-3 font-mono font-bold text-slate-200">
          <div>${escapeHtml(i.indicator_value)}</div>
          <div class="text-[10px] text-slate-500 font-sans font-normal">${escapeHtml(i.description || 'Verified threat indicator')}</div>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-700 text-slate-300">
            ${escapeHtml(i.indicator_type)}
          </span>
        </td>
        <td class="px-4 py-3 text-slate-300 font-bold">${escapeHtml(i.threat_type)}</td>
        <td class="px-4 py-3 font-bold text-emerald-400">${i.confidence_score}%</td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-[11px] font-semibold border ${sevColor}">
            ${escapeHtml(i.severity)}
          </span>
        </td>
        <td class="px-4 py-3 text-slate-400 font-mono text-[11px]">${escapeHtml(i.mitre_techniques || 'N/A')}</td>
        <td class="px-4 py-3 text-right">
          <button onclick="deleteIndicatorItem('${i.id}')" class="px-2 py-1 bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white rounded text-[11px] border border-rose-500/30">
            🗑️
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderMatchesTable(matches) {
  const tbody = document.getElementById('ti-matches-tbody');
  const countEl = document.getElementById('ti-matches-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${matches.length} Interceptions`;

  if (!matches.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No threat match events detected.</td></tr>';
    return;
  }

  tbody.innerHTML = matches.map(m => `
    <tr class="hover:bg-slate-750/50 transition">
      <td class="px-4 py-3 font-mono font-bold text-rose-400">
        ⛔ ${escapeHtml(m.matched_value)}
        <span class="text-[10px] text-slate-500 block font-normal">${escapeHtml(m.indicator_type)}</span>
      </td>
      <td class="px-4 py-3 text-slate-200">${escapeHtml(m.hostname)}</td>
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
          ${escapeHtml(m.action_taken)}
        </span>
      </td>
      <td class="px-4 py-3 text-rose-400 font-bold">${escapeHtml(m.severity)}</td>
      <td class="px-4 py-3 text-slate-300 text-xs">
        <div class="truncate max-w-sm">${escapeHtml(m.source_context || m.details || 'Interception')}</div>
      </td>
      <td class="px-4 py-3 text-slate-400 text-[11px] text-right">${escapeHtml(m.timestamp)}</td>
    </tr>
  `).join('');
}

async function syncThreatFeed(id) {
  try {
    const res = await fetch(`/api/v1/fleet/threat-intel/feeds/${id}/sync`, {
      method: 'POST',
      credentials: 'same-origin'
    });
    if (res.ok) {
      alert('Threat intelligence feed synchronized successfully!');
      loadThreatIntelData();
    }
  } catch (e) {
    console.error(e);
  }
}

async function deleteThreatFeed(id) {
  if (!confirm('Delete this threat intelligence feed source?')) return;
  await fetch(`/api/v1/fleet/threat-intel/feeds/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadThreatIntelData();
}

async function deleteIndicatorItem(id) {
  if (!confirm('Delete this indicator from the threat intelligence cache?')) return;
  await fetch(`/api/v1/fleet/threat-intel/indicators/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadThreatIntelData();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderThreatIntelBlade = renderThreatIntelBlade;
window.initThreatIntelBlade = initThreatIntelBlade;
window.loadThreatIntelData = loadThreatIntelData;
window.syncThreatFeed = syncThreatFeed;
window.deleteThreatFeed = deleteThreatFeed;
window.deleteIndicatorItem = deleteIndicatorItem;

window.ThreatIntelTable = {
  async render() {
    const container = document.getElementById('tab-threat-intel');
    if (!container) return;
    container.innerHTML = renderThreatIntelBlade();
    initThreatIntelBlade();
  }
};
