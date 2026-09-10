/**
 * LocalPilot Fleet — Network Isolation & Host Quarantine Governance Blade
 * Real-time endpoint network containment, selective out-of-band SecOps exceptions, and dropped packet audit telemetry.
 */

function renderNetworkIsolationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">☣️</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Network Isolation &amp; Host Quarantine
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">WFP Containment</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Zero-trust network quarantine, out-of-band SecOps management, and real-time packet drop telemetry</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-isolation-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-isolation-new-policy" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>🛡️</span> New Isolation Policy
          </button>
          <button id="btn-isolation-new-endpoint" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>➕</span> Add SecOps Endpoint
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="isolation-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Quarantined Hosts</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">☣️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-iso-quarantined">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Policies</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-iso-policies">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">SecOps Exclusions</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🔑</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-iso-exclusions">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Dropped Packets</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🚫</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-iso-dropped">-</p>
        </div>
      </div>

      <!-- Main Layout: Policies (2 cols) & SecOps Exclusions (1 col) -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Policies Table (2 cols) -->
        <div class="lg:col-span-2 bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📋</span> Quarantine Profiles &amp; Modes
            </h3>
            <span class="text-xs text-slate-400" id="iso-policy-count">0 configured</span>
          </div>
          <div class="overflow-x-auto flex-1">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider">
                <tr>
                  <th class="px-4 py-3">Profile Name</th>
                  <th class="px-4 py-3">Isolation Mode</th>
                  <th class="px-4 py-3">Protocols Allowed</th>
                  <th class="px-4 py-3">Scope</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="iso-policies-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="5" class="px-4 py-8 text-center text-slate-500 font-sans">Loading isolation profiles...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Out-of-band SecOps Exclusions (1 col) -->
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>🔑</span> Out-of-Band Exclusions
            </h3>
            <span class="text-xs text-slate-400" id="iso-exclusion-count">0 rules</span>
          </div>
          <div class="overflow-y-auto max-h-[380px] p-3 space-y-2.5" id="iso-exclusions-list">
            <div class="text-center text-slate-500 py-6 text-sm">Loading exclusions...</div>
          </div>
        </div>
      </div>

      <!-- Live Quarantine Transition & Dropped Traffic Stream -->
      <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden">
        <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📡</span> Live Containment State &amp; Packet Interception Stream
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time audit log of host isolations, releases, and unauthorized egress drops</p>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="iso-filter-query" placeholder="Filter node, initiator or reason..." class="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-rose-500">
          </div>
        </div>
        <div class="overflow-x-auto max-h-96">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider sticky top-0 backdrop-blur-sm">
              <tr>
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Transition</th>
                <th class="px-4 py-3">Node / Hostname</th>
                <th class="px-4 py-3">Initiated By</th>
                <th class="px-4 py-3">Containment Reason / Packet</th>
                <th class="px-4 py-3 text-right">Quick Action</th>
              </tr>
            </thead>
            <tbody id="iso-logs-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No isolation logs recorded.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function loadNetworkIsolationData() {
  try {
    const [statsRes, polRes, excRes, logRes] = await Promise.all([
      fetch('/api/v1/fleet/network-isolation/stats', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/network-isolation/policies', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/network-isolation/exclusions', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/network-isolation/logs?limit=50', { credentials: 'same-origin' })
    ]);

    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('kpi-iso-quarantined').textContent = stats.isolatedHosts ?? 0;
      document.getElementById('kpi-iso-policies').textContent = stats.activePolicies ?? 0;
      document.getElementById('kpi-iso-exclusions').textContent = stats.totalExclusions ?? 0;
      document.getElementById('kpi-iso-dropped').textContent = stats.droppedPackets ?? 0;
    }

    if (polRes.ok) {
      const policies = await polRes.json();
      renderIsolationPolicies(policies);
    }

    if (excRes.ok) {
      const exclusions = await excRes.json();
      renderIsolationExclusions(exclusions);
    }

    if (logRes.ok) {
      const data = await logRes.json();
      renderIsolationLogs(data.logs || []);
    }
  } catch (err) {
    console.error('Error loading network isolation data:', err);
  }
}

function renderIsolationPolicies(policies) {
  const tbody = document.getElementById('iso-policies-tbody');
  const countBadge = document.getElementById('iso-policy-count');
  if (countBadge) countBadge.textContent = `${policies.length} configured`;
  if (!tbody) return;

  if (!policies || policies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-8 text-center text-slate-500 font-sans">No isolation profiles configured.</td></tr>';
    return;
  }

  tbody.innerHTML = policies.map(p => {
    const modeBadge = p.isolation_mode === 'FULL_DISCONNECT'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (p.isolation_mode === 'SELECTIVE_MANAGEMENT' ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30');

    const protocols = [];
    if (p.allow_dns) protocols.push('DNS (53)');
    if (p.allow_dhcp) protocols.push('DHCP (67/68)');
    if (p.allow_fleet_telemetry) protocols.push('Fleet Telemetry');

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-3">
          <div class="font-bold font-sans text-white text-sm">${escapeHtml(p.name)}</div>
          <div class="text-[11px] text-slate-400 font-sans truncate max-w-xs">${escapeHtml(p.description || '')}</div>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${modeBadge}">${escapeHtml(p.isolation_mode)}</span>
        </td>
        <td class="px-4 py-3">
          <div class="flex flex-wrap gap-1">
            ${protocols.map(pt => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(pt)}</span>`).join('')}
          </div>
        </td>
        <td class="px-4 py-3 font-sans">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(p.target_scope)}</span>
        </td>
        <td class="px-4 py-3 text-right">
          <button class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition mr-1" onclick="viewIsolationScript('${escapeHtml(p.id)}')">
            <span>📜</span> Script
          </button>
          <button class="px-2 py-1 bg-rose-900/30 hover:bg-rose-900/60 text-rose-300 rounded text-xs transition border border-rose-700/30" onclick="deleteIsolationPolicy('${escapeHtml(p.id)}')">
            <span>🗑️</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderIsolationExclusions(exclusions) {
  const container = document.getElementById('iso-exclusions-list');
  const countBadge = document.getElementById('iso-exclusion-count');
  if (countBadge) countBadge.textContent = `${exclusions.length} rules`;
  if (!container) return;

  if (!exclusions || exclusions.length === 0) {
    container.innerHTML = '<div class="text-center text-slate-500 py-6 text-sm">No SecOps exclusions.</div>';
    return;
  }

  container.innerHTML = exclusions.map(exc => {
    return `
      <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs">
        <div class="min-w-0 flex-1 pr-2">
          <div class="flex items-center gap-1.5 mb-1">
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border bg-blue-500/10 text-blue-300 border-blue-500/30">${escapeHtml(exc.endpoint_type)}</span>
            <span class="font-sans font-semibold text-white truncate">${escapeHtml(exc.friendly_name)}</span>
          </div>
          <div class="font-mono text-slate-200 text-[11px] truncate" title="${escapeHtml(exc.endpoint_value)}">
            ${escapeHtml(exc.endpoint_value)} ${exc.port ? ':' + exc.port : ''} (${escapeHtml(exc.direction)})
          </div>
        </div>
        <button class="p-1 text-slate-400 hover:text-rose-400 transition" onclick="deleteIsolationExclusion('${escapeHtml(exc.id)}')">
          <span>🗑️</span>
        </button>
      </div>
    `;
  }).join('');
}

function renderIsolationLogs(logs) {
  const tbody = document.getElementById('iso-logs-tbody');
  if (!tbody) return;

  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No isolation logs recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const isIso = l.transition_type === 'HOST_ISOLATED';
    const isRel = l.transition_type === 'HOST_RELEASED';
    const badgeClass = isIso ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : (isRel ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30');

    const d = new Date(l.timestamp);
    const timeStr = isNaN(d.getTime()) ? l.timestamp : d.toLocaleTimeString();

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-2.5 text-slate-400">${timeStr}</td>
        <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-xs border ${badgeClass}">${escapeHtml(l.transition_type)}</span></td>
        <td class="px-4 py-2.5">
          <div class="font-bold text-white font-sans">${escapeHtml(l.hostname)}</div>
          <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(l.device_id.substring(0, 8))}...</div>
        </td>
        <td class="px-4 py-2.5 text-slate-300 font-sans">${escapeHtml(l.initiated_by)}</td>
        <td class="px-4 py-2.5">
          <div class="text-slate-300 truncate max-w-xs" title="${escapeHtml(l.reason)}">${escapeHtml(l.reason)}</div>
          <div class="text-[10px] text-slate-500 font-mono truncate max-w-xs">${escapeHtml(l.packet_summary || '')}</div>
        </td>
        <td class="px-4 py-2.5 text-right">
          ${isIso ? `
            <button class="px-2 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs transition shadow" onclick="releaseHost('${escapeHtml(l.device_id)}')">
              <span>🔓</span> Release
            </button>
          ` : `
            <button class="px-2 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs transition shadow" onclick="isolateHost('${escapeHtml(l.device_id)}')">
              <span>☣️</span> Isolate
            </button>
          `}
        </td>
      </tr>
    `;
  }).join('');
}

function initNetworkIsolationBlade() {
  const refreshBtn = document.getElementById('btn-isolation-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', loadNetworkIsolationData);

  const newPolicyBtn = document.getElementById('btn-isolation-new-policy');
  if (newPolicyBtn) {
    newPolicyBtn.addEventListener('click', () => {
      const name = prompt('Policy Name:', 'Emergency Outbreak Containment');
      if (!name) return;
      const mode = prompt('Isolation Mode (SELECTIVE_MANAGEMENT, FULL_DISCONNECT, HONEYPOT_REDIRECT):', 'SELECTIVE_MANAGEMENT');
      if (!mode) return;

      fetch('/api/v1/fleet/network-isolation/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          isolation_mode: mode,
          allow_dns: true,
          allow_dhcp: true,
          allow_fleet_telemetry: true
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadNetworkIsolationData());
    });
  }

  const newEndpointBtn = document.getElementById('btn-isolation-new-endpoint');
  if (newEndpointBtn) {
    newEndpointBtn.addEventListener('click', () => {
      const name = prompt('SecOps Endpoint Friendly Name:', 'Emergency Cloudflare Proxy Ingress');
      if (!name) return;
      const val = prompt('Endpoint Value (IP, CIDR, FQDN):', '198.41.128.0/17');
      if (!val) return;

      fetch('/api/v1/fleet/network-isolation/exclusions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          friendly_name: name,
          endpoint_type: val.includes('/') ? 'CIDR_SUBNET' : 'IP_ADDRESS',
          endpoint_value: val,
          direction: 'BOTH',
          port: 443
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadNetworkIsolationData());
    });
  }

  const filterInput = document.getElementById('iso-filter-query');
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#iso-logs-tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  loadNetworkIsolationData();
}

async function isolateHost(deviceId) {
  const reason = prompt('Specify reason for emergency network isolation:', 'Threat Containment Action');
  if (!reason) return;

  await fetch(`/api/v1/fleet/network-isolation/isolate/${deviceId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason, initiated_by: 'SecOps Administrator' }),
    credentials: 'same-origin'
  });
  loadNetworkIsolationData();
}

async function releaseHost(deviceId) {
  if (!confirm('Are you sure you want to restore full network connectivity for this host?')) return;

  await fetch(`/api/v1/fleet/network-isolation/release/${deviceId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'SecOps verification clean' }),
    credentials: 'same-origin'
  });
  loadNetworkIsolationData();
}

async function deleteIsolationPolicy(id) {
  if (!confirm('Delete this network isolation policy?')) return;
  await fetch(`/api/v1/fleet/network-isolation/policies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadNetworkIsolationData();
}

async function deleteIsolationExclusion(id) {
  if (!confirm('Delete this SecOps exclusion endpoint?')) return;
  await fetch(`/api/v1/fleet/network-isolation/exclusions/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadNetworkIsolationData();
}

async function viewIsolationScript(id) {
  try {
    const res = await fetch('/api/v1/fleet/network-isolation/script/default', { credentials: 'same-origin' });
    if (res.ok) {
      const script = await res.text();
      alert('Windows Filtering Platform (WFP) Containment Script:\n\n' + script.substring(0, 500) + '...');
    }
  } catch (e) {
    console.error(e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderNetworkIsolationBlade = renderNetworkIsolationBlade;
window.initNetworkIsolationBlade = initNetworkIsolationBlade;
window.loadNetworkIsolationData = loadNetworkIsolationData;
window.isolateHost = isolateHost;
window.releaseHost = releaseHost;
window.deleteIsolationPolicy = deleteIsolationPolicy;
window.deleteIsolationExclusion = deleteIsolationExclusion;
window.viewIsolationScript = viewIsolationScript;

window.NetworkIsolationTable = {
  async render() {
    const container = document.getElementById('tab-network-isolation');
    if (!container) return;
    container.innerHTML = renderNetworkIsolationBlade();
    initNetworkIsolationBlade();
  }
};
