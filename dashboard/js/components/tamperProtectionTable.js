/**
 * LocalPilot Fleet — Tamper Protection & Antivirus Exclusion Governance Blade
 * Microsoft Defender core anti-tamper locks, governed exclusions with risk tiers, and real-time audit stream.
 */

function renderTamperProtectionBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-red-500/20 text-red-400 rounded-lg text-2xl border border-red-500/30">🔒</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Tamper Protection &amp; Exclusion Governance
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-300 border border-red-500/30">Anti-Snooping</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Locks Defender services &amp; registry keys against local tampering, and governs AV exclusions</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-tamper-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-tamper-new-policy" class="px-3.5 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-red-500/20">
            <span>🛡️</span> New Tamper Policy
          </button>
          <button id="btn-tamper-new-exclusion" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>➕</span> Add Governed Exclusion
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="tamper-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Policies</p>
            <span class="p-1.5 bg-red-500/20 text-red-400 rounded-md text-sm">🔒</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-tamper-policies">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Governed Exclusions</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">📂</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-tamper-exclusions">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">High-Risk Exclusions</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-tamper-highrisk">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Thwarted Attacks</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-tamper-blocked">-</p>
        </div>
      </div>

      <!-- Main Layout: Policies (2 cols) & Exclusions (1 col) -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Policies Table (2 cols) -->
        <div class="lg:col-span-2 bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📋</span> Tamper Protection Baselines
            </h3>
            <span class="text-xs text-slate-400" id="tamper-policy-count">0 configured</span>
          </div>
          <div class="overflow-x-auto flex-1">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider">
                <tr>
                  <th class="px-4 py-3">Policy Name</th>
                  <th class="px-4 py-3">State</th>
                  <th class="px-4 py-3">Lock Services</th>
                  <th class="px-4 py-3">Safe Mode</th>
                  <th class="px-4 py-3">Scope</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="tamper-policies-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">Loading policies...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Governed AV Exclusions (1 col) -->
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📂</span> Governed AV Exclusions
            </h3>
            <span class="text-xs text-slate-400" id="tamper-exclusion-count">0 rules</span>
          </div>
          <div class="overflow-y-auto max-h-[380px] p-3 space-y-2.5" id="tamper-exclusions-list">
            <div class="text-center text-slate-500 py-6 text-sm">Loading exclusions...</div>
          </div>
        </div>
      </div>

      <!-- Live Tamper Audit Stream -->
      <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden">
        <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📡</span> Live Security Tampering &amp; Exclusion Audit Log
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time alerts on registry disables, service kills, and unauthorized exclusion injections</p>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="tamper-filter-query" placeholder="Filter resource, attacker or event..." class="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-red-500">
          </div>
        </div>
        <div class="overflow-x-auto max-h-96">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider sticky top-0 backdrop-blur-sm">
              <tr>
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Event Type</th>
                <th class="px-4 py-3">Target Resource</th>
                <th class="px-4 py-3">Attacker Process</th>
                <th class="px-4 py-3">User</th>
                <th class="px-4 py-3">Node ID</th>
              </tr>
            </thead>
            <tbody id="tamper-events-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No tamper events recorded.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function loadTamperProtectionData() {
  try {
    const [statsRes, polRes, excRes, evtRes] = await Promise.all([
      fetch('/api/v1/fleet/tamper-protection/stats', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/tamper-protection/policies', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/tamper-protection/exclusions', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/tamper-protection/events?limit=50', { credentials: 'same-origin' })
    ]);

    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('kpi-tamper-policies').textContent = stats.activePolicies ?? 0;
      document.getElementById('kpi-tamper-exclusions').textContent = stats.totalExclusions ?? 0;
      document.getElementById('kpi-tamper-highrisk').textContent = stats.highRiskExclusions ?? 0;
      document.getElementById('kpi-tamper-blocked').textContent = stats.blockedTamperAttempts ?? 0;
    }

    if (polRes.ok) {
      const policies = await polRes.json();
      renderTamperPolicies(policies);
    }

    if (excRes.ok) {
      const exclusions = await excRes.json();
      renderTamperExclusions(exclusions);
    }

    if (evtRes.ok) {
      const data = await evtRes.json();
      renderTamperEvents(data.events || []);
    }
  } catch (err) {
    console.error('Error loading tamper protection data:', err);
  }
}

function renderTamperPolicies(policies) {
  const tbody = document.getElementById('tamper-policies-tbody');
  const countBadge = document.getElementById('tamper-policy-count');
  if (countBadge) countBadge.textContent = `${policies.length} configured`;
  if (!tbody) return;

  if (!policies || policies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No tamper protection policies configured.</td></tr>';
    return;
  }

  tbody.innerHTML = policies.map(p => {
    const stateBadge = p.tamper_protection_state === 'ENFORCED'
      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
      : (p.tamper_protection_state === 'AUDIT_ONLY' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-700 text-slate-300 border-slate-600');

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-3">
          <div class="font-bold font-sans text-white text-sm">${escapeHtml(p.name)}</div>
          <div class="text-[11px] text-slate-400 font-sans truncate max-w-xs">${escapeHtml(p.description || '')}</div>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${stateBadge}">${escapeHtml(p.tamper_protection_state)}</span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs ${p.lock_security_services ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'bg-slate-700 text-slate-400'}">
            ${p.lock_security_services ? 'Locked' : 'Unlocked'}
          </span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs ${p.prevent_safe_mode_bypass ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-slate-700 text-slate-400'}">
            ${p.prevent_safe_mode_bypass ? 'Protected' : 'Standard'}
          </span>
        </td>
        <td class="px-4 py-3 font-sans">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(p.target_scope)}</span>
        </td>
        <td class="px-4 py-3 text-right">
          <button class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition mr-1" onclick="viewTamperScript('${escapeHtml(p.id)}')">
            <span>📜</span> Script
          </button>
          <button class="px-2 py-1 bg-rose-900/30 hover:bg-rose-900/60 text-rose-300 rounded text-xs transition border border-rose-700/30" onclick="deleteTamperPolicy('${escapeHtml(p.id)}')">
            <span>🗑️</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderTamperExclusions(exclusions) {
  const container = document.getElementById('tamper-exclusions-list');
  const countBadge = document.getElementById('tamper-exclusion-count');
  if (countBadge) countBadge.textContent = `${exclusions.length} rules`;
  if (!container) return;

  if (!exclusions || exclusions.length === 0) {
    container.innerHTML = '<div class="text-center text-slate-500 py-6 text-sm">No governed exclusions.</div>';
    return;
  }

  container.innerHTML = exclusions.map(exc => {
    const riskBadge = exc.risk_tier === 'HIGH' || exc.risk_tier === 'CRITICAL'
      ? 'text-rose-400 bg-rose-500/10 border-rose-500/30'
      : (exc.risk_tier === 'MEDIUM' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' : 'text-blue-400 bg-blue-500/10 border-blue-500/30');

    return `
      <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs">
        <div class="min-w-0 flex-1 pr-2">
          <div class="flex items-center gap-1.5 mb-1">
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border ${riskBadge}">${escapeHtml(exc.risk_tier)}</span>
            <span class="text-slate-400 text-[10px] uppercase font-bold">${escapeHtml(exc.exclusion_type)}</span>
          </div>
          <div class="font-mono text-slate-200 truncate font-semibold" title="${escapeHtml(exc.exclusion_value)}">
            ${escapeHtml(exc.exclusion_value)}
          </div>
          <div class="text-[10px] text-slate-400 mt-0.5 truncate font-sans">
            ${escapeHtml(exc.justification)}
          </div>
        </div>
        <button class="p-1 text-slate-400 hover:text-rose-400 transition" onclick="deleteTamperExclusion('${escapeHtml(exc.id)}')">
          <span>🗑️</span>
        </button>
      </div>
    `;
  }).join('');
}

function renderTamperEvents(events) {
  const tbody = document.getElementById('tamper-events-tbody');
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No tamper events recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = events.map(evt => {
    const actBadge = evt.action_taken === 'BLOCKED'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (evt.action_taken === 'RESTORED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30');

    const d = new Date(evt.timestamp);
    const timeStr = isNaN(d.getTime()) ? evt.timestamp : d.toLocaleTimeString();

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-2.5 text-slate-400">${timeStr}</td>
        <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-xs border ${actBadge}">${escapeHtml(evt.action_taken)}</span></td>
        <td class="px-4 py-2.5 text-slate-300 font-sans font-medium">${escapeHtml(evt.event_type)}</td>
        <td class="px-4 py-2.5 text-slate-200 font-mono truncate max-w-xs" title="${escapeHtml(evt.target_resource)}">
          ${escapeHtml(evt.target_resource)}
        </td>
        <td class="px-4 py-2.5 text-slate-300 truncate max-w-xs font-mono" title="${escapeHtml(evt.attacker_process)}">
          ${escapeHtml(evt.attacker_process)}
        </td>
        <td class="px-4 py-2.5 text-slate-400 font-sans">${escapeHtml(evt.username || 'System')}</td>
        <td class="px-4 py-2.5 text-slate-500 truncate max-w-[80px] font-mono">${escapeHtml(evt.device_id.substring(0, 8))}...</td>
      </tr>
    `;
  }).join('');
}

function initTamperProtectionBlade() {
  const refreshBtn = document.getElementById('btn-tamper-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', loadTamperProtectionData);

  const newPolicyBtn = document.getElementById('btn-tamper-new-policy');
  if (newPolicyBtn) {
    newPolicyBtn.addEventListener('click', () => {
      const name = prompt('Policy Name:', 'Executive Anti-Snooping Tamper Baseline');
      if (!name) return;
      const state = prompt('Tamper Protection State (ENFORCED, AUDIT_ONLY, DISABLED):', 'ENFORCED');
      if (!state) return;

      fetch('/api/v1/fleet/tamper-protection/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          tamper_protection_state: state,
          lock_security_services: true,
          protect_antivirus_exclusions: true,
          prevent_safe_mode_bypass: true
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadTamperProtectionData());
    });
  }

  const newExclusionBtn = document.getElementById('btn-tamper-new-exclusion');
  if (newExclusionBtn) {
    newExclusionBtn.addEventListener('click', () => {
      const val = prompt('Exclusion Value (Path / Folder / Extension / Process):', 'C:\\Program Files\\CustomApp\\app.exe');
      if (!val) return;
      const type = prompt('Exclusion Type (PATH, FOLDER, EXTENSION, PROCESS):', 'PATH');
      if (!type) return;
      const just = prompt('Business Justification:', 'Application latency optimization');
      if (!just) return;

      fetch('/api/v1/fleet/tamper-protection/exclusions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exclusion_value: val,
          exclusion_type: type,
          risk_tier: 'LOW',
          justification: just
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadTamperProtectionData());
    });
  }

  const filterInput = document.getElementById('tamper-filter-query');
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#tamper-events-tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  loadTamperProtectionData();
}

async function deleteTamperPolicy(id) {
  if (!confirm('Are you sure you want to delete this tamper protection policy?')) return;
  await fetch(`/api/v1/fleet/tamper-protection/policies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadTamperProtectionData();
}

async function deleteTamperExclusion(id) {
  if (!confirm('Delete this governed antivirus exclusion?')) return;
  await fetch(`/api/v1/fleet/tamper-protection/exclusions/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadTamperProtectionData();
}

async function viewTamperScript(id) {
  try {
    const res = await fetch('/api/v1/fleet/tamper-protection/script/default', { credentials: 'same-origin' });
    if (res.ok) {
      const script = await res.text();
      alert('Windows Defender Tamper Protection Enforcement Script:\n\n' + script.substring(0, 500) + '...');
    }
  } catch (e) {
    console.error(e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderTamperProtectionBlade = renderTamperProtectionBlade;
window.initTamperProtectionBlade = initTamperProtectionBlade;
window.loadTamperProtectionData = loadTamperProtectionData;
window.deleteTamperPolicy = deleteTamperPolicy;
window.deleteTamperExclusion = deleteTamperExclusion;
window.viewTamperScript = viewTamperScript;

window.TamperProtectionTable = {
  async render() {
    const container = document.getElementById('tab-tamper-protection');
    if (!container) return;
    container.innerHTML = renderTamperProtectionBlade();
    initTamperProtectionBlade();
  }
};
