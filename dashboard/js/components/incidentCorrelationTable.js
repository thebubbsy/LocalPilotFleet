/**
 * LocalPilot Fleet — EDR Incident Correlation & Multi-Stage Attack Storyline Blade
 * Cross-module alert aggregation, interactive kill-chain attack trees, and automated incident triage.
 */

function renderIncidentCorrelationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">🎯</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                EDR Incident Correlation &amp; Attack Storylines
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">Kill-Chain Graph</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Cross-signal alert aggregation, MITRE ATT&amp;CK phase alignment, and automated multi-stage incident triage</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-inc-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-inc-correlate" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>⚡</span> Run Correlation Sweep
          </button>
          <button id="btn-inc-new" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>➕</span> New Incident Case
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="inc-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Incidents</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-inc-active">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Severity</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🔥</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-inc-critical">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Correlated Alerts</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🔗</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-inc-alerts">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mean Risk Score</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">📊</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-inc-risk">-</p>
        </div>
      </div>

      <!-- Attack Storyline Visualizer Panel (Active Incident) -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg p-5 space-y-4" id="inc-storyline-panel">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-700/60 pb-3">
          <div class="flex items-center gap-2.5">
            <span class="text-lg">🗺️</span>
            <div>
              <h3 class="text-md font-bold text-white tracking-wide" id="storyline-incident-title">Attack Storyline: Multi-Stage Macro Execution &amp; Lateral Movement</h3>
              <p class="text-xs text-slate-400">Sequential process lineage, evasion attempts, and containment events</p>
            </div>
          </div>
          <span class="px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30" id="storyline-risk-badge">Risk: 88/100</span>
        </div>

        <!-- Storyline Kill-Chain Flow -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2" id="storyline-nodes-container">
          <div class="bg-slate-900/80 p-3.5 rounded-lg border border-slate-700/80 space-y-1.5">
            <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">1. Initial Access</span>
            <div class="text-xs font-semibold text-slate-200">Phishing Attachment</div>
            <div class="text-[11px] text-slate-400 font-mono">invoice_oct_macro.xlsm</div>
          </div>
          <div class="bg-slate-900/80 p-3.5 rounded-lg border border-slate-700/80 space-y-1.5">
            <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">2. Execution</span>
            <div class="text-xs font-semibold text-slate-200">PowerShell Stager</div>
            <div class="text-[11px] text-slate-400 font-mono">powershell.exe -enc ...</div>
          </div>
          <div class="bg-slate-900/80 p-3.5 rounded-lg border border-slate-700/80 space-y-1.5">
            <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">3. Defense Evasion</span>
            <div class="text-xs font-semibold text-slate-200">Tamper Intercepted</div>
            <div class="text-[11px] text-slate-400 font-mono">RTP Disable BLOCKED</div>
          </div>
          <div class="bg-slate-900/80 p-3.5 rounded-lg border border-slate-700/80 space-y-1.5">
            <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">4. Remediation</span>
            <div class="text-xs font-semibold text-slate-200">WFP Isolation Engaged</div>
            <div class="text-[11px] text-slate-400 font-mono">Host Contained</div>
          </div>
        </div>
      </div>

      <!-- Security Incidents Table -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Security Incidents &amp; Investigation Cases</h3>
            <p class="text-xs text-slate-400 mt-0.5">Aggregated multi-signal threat cases with kill-chain evidence</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="inc-cases-count">0 Incidents</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Incident Case</th>
                <th class="px-4 py-3">Target Host</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Risk</th>
                <th class="px-4 py-3">Assigned Analyst</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="inc-cases-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading incident cases...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function initIncidentCorrelationBlade() {
  const btnRefresh = document.getElementById('btn-inc-refresh');
  if (btnRefresh) btnRefresh.onclick = () => loadIncidentData();

  const btnCorrelate = document.getElementById('btn-inc-correlate');
  if (btnCorrelate) {
    btnCorrelate.onclick = async () => {
      const devId = prompt('Enter Target Device ID for correlation sweep:', 'DESKTOP-R0H12DJ');
      if (!devId) return;
      try {
        const res = await fetch(`/api/v1/fleet/incidents/correlate/${devId}`, {
          method: 'POST',
          credentials: 'same-origin'
        });
        const data = await res.json();
        if (res.ok) {
          alert(data.correlated ?
            `Correlation sweep synthesized ${data.totalSignals} signals into Incident Case: ${data.incident.title}` :
            'No multi-signal threats detected for this host.'
          );
          loadIncidentData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  const btnNew = document.getElementById('btn-inc-new');
  if (btnNew) {
    btnNew.onclick = async () => {
      const title = prompt('Incident Title:');
      if (!title) return;
      const deviceId = prompt('Primary Target Device ID:', 'DESKTOP-R0H12DJ');
      if (!deviceId) return;

      try {
        const res = await fetch('/api/v1/fleet/incidents', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title,
            primary_device_id: deviceId,
            severity: 'HIGH',
            status: 'ACTIVE',
            assigned_analyst: 'SecOps Console Analyst'
          }),
          credentials: 'same-origin'
        });
        if (res.ok) {
          alert('Security incident case created!');
          loadIncidentData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  await loadIncidentData();
}

async function loadIncidentData() {
  try {
    // 1. Stats
    const statsRes = await fetch('/api/v1/fleet/incidents/stats', { credentials: 'same-origin' });
    if (statsRes.ok) {
      const s = await statsRes.json();
      const elAct = document.getElementById('kpi-inc-active');
      const elCrit = document.getElementById('kpi-inc-critical');
      const elAl = document.getElementById('kpi-inc-alerts');
      const elRk = document.getElementById('kpi-inc-risk');
      if (elAct) elAct.innerText = s.activeIncidents || 0;
      if (elCrit) elCrit.innerText = s.criticalIncidents || 0;
      if (elAl) elAl.innerText = s.totalAssociatedAlerts || 0;
      if (elRk) elRk.innerText = `${s.meanRiskScore || 0}/100`;
    }

    // 2. Cases
    const casesRes = await fetch('/api/v1/fleet/incidents', { credentials: 'same-origin' });
    if (casesRes.ok) {
      const data = await casesRes.json();
      renderIncidentTable(data.incidents || []);
      if (data.incidents && data.incidents.length > 0) {
        renderStoryline(data.incidents[0]);
      }
    }
  } catch (err) {
    console.error('Failed to load incident telemetry:', err);
  }
}

function renderIncidentTable(incidents) {
  const tbody = document.getElementById('inc-cases-tbody');
  const countEl = document.getElementById('inc-cases-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${incidents.length} Incidents`;

  if (!incidents.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No security incidents detected. Fleet is secure.</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevColor = inc.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
      (inc.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-blue-500/20 text-blue-300 border-blue-500/30');

    const statusColor = inc.status === 'RESOLVED' ? 'text-slate-500' :
      (inc.status === 'CONTAINED' ? 'text-emerald-400' : 'text-rose-400');

    return `
      <tr class="hover:bg-slate-750/50 transition">
        <td class="px-4 py-3 font-medium text-slate-200">
          <div class="font-bold text-white">${escapeHtml(inc.title)}</div>
          <div class="text-[11px] text-slate-400 font-sans mt-0.5">${escapeHtml(inc.id)} • ${escapeHtml(inc.description || 'Multi-stage correlated attack')}</div>
        </td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(inc.primary_hostname)}</td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-[11px] font-semibold border ${sevColor}">
            ${escapeHtml(inc.severity)}
          </span>
        </td>
        <td class="px-4 py-3 ${statusColor} font-bold">● ${escapeHtml(inc.status)}</td>
        <td class="px-4 py-3">
          <span class="font-bold ${inc.risk_score >= 80 ? 'text-rose-400' : (inc.risk_score >= 50 ? 'text-amber-400' : 'text-blue-400')}">
            ${inc.risk_score}/100
          </span>
        </td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(inc.assigned_analyst)}</td>
        <td class="px-4 py-3 text-right">
          <button onclick="inspectStoryline('${inc.id}')" class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-[11px] mr-1">
            🗺️ Storyline
          </button>
          ${inc.status !== 'RESOLVED' ?
            `<button onclick="closeIncidentCase('${inc.id}')" class="px-2 py-1 bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white rounded text-[11px] border border-emerald-500/30">
              ✔️ Resolve
            </button>` :
            `<span class="text-[11px] text-slate-500">Resolved</span>`
          }
        </td>
      </tr>
    `;
  }).join('');
}

function renderStoryline(incident) {
  const titleEl = document.getElementById('storyline-incident-title');
  const riskBadge = document.getElementById('storyline-risk-badge');
  const container = document.getElementById('storyline-nodes-container');

  if (titleEl) titleEl.innerText = `Attack Storyline: ${incident.title} (${incident.primary_hostname})`;
  if (riskBadge) riskBadge.innerText = `Risk: ${incident.risk_score}/100`;

  if (!container) return;

  const nodes = incident.attack_storyline || [];
  if (!nodes.length) {
    container.innerHTML = '<div class="col-span-4 p-4 text-center text-slate-500 text-xs">No kill-chain milestones recorded for this incident.</div>';
    return;
  }

  container.innerHTML = nodes.map((n, i) => `
    <div class="bg-slate-900/80 p-3.5 rounded-lg border border-slate-700/80 space-y-1.5">
      <span class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
        ${i + 1}. ${escapeHtml(n.phase || 'PHASE')}
      </span>
      <div class="text-xs font-semibold text-slate-200">${escapeHtml(n.title || 'Event')}</div>
      <div class="text-[11px] text-slate-400 font-mono truncate" title="${escapeHtml(n.detail || n.details || '')}">${escapeHtml(n.detail || n.details || '')}</div>
    </div>
  `).join('');
}

async function inspectStoryline(id) {
  try {
    const res = await fetch(`/api/v1/fleet/incidents/${id}`, { credentials: 'same-origin' });
    if (res.ok) {
      const inc = await res.json();
      renderStoryline(inc);
      const panel = document.getElementById('inc-storyline-panel');
      if (panel) panel.scrollIntoView({ behavior: 'smooth' });
    }
  } catch (e) {
    console.error(e);
  }
}

async function closeIncidentCase(id) {
  const rootCause = prompt('Resolution summary / Root cause:', 'Threat neutralized by SecOps');
  if (!rootCause) return;

  await fetch(`/api/v1/fleet/incidents/${id}/close`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resolution: 'RESOLVED', classification: 'TRUE_POSITIVE', rootCause }),
    credentials: 'same-origin'
  });
  loadIncidentData();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderIncidentCorrelationBlade = renderIncidentCorrelationBlade;
window.initIncidentCorrelationBlade = initIncidentCorrelationBlade;
window.loadIncidentData = loadIncidentData;
window.inspectStoryline = inspectStoryline;
window.closeIncidentCase = closeIncidentCase;

window.IncidentCorrelationTable = {
  async render() {
    const container = document.getElementById('tab-incident-correlation');
    if (!container) return;
    container.innerHTML = renderIncidentCorrelationBlade();
    initIncidentCorrelationBlade();
  }
};
