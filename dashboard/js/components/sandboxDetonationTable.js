/**
 * LocalPilot Fleet — Endpoint Behavioral Sandbox Detonation & Process Lineage Blade
 * Dynamic malware analysis, parent-child process execution trees, and micro-telemetry.
 */

function renderSandboxDetonationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">🧪</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Behavioral Sandbox &amp; Process Lineage
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">Dynamic Detonation</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated Windows Sandbox (.wsb) execution, deep process lineage trees &amp; MITRE behavioral telemetry</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-sandbox-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-sandbox-new-job" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>🧪</span> Detonate Sample
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="sandbox-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Detonations</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🧪</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-det-total">-</p>
          <p class="text-xs text-slate-400 mt-1">Submitted Binaries &amp; Scripts</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Malicious Verdicts</p>
            <span class="p-1.5 bg-red-500/20 text-red-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-red-400 mt-2" id="kpi-det-malicious">-</p>
          <p class="text-xs text-red-300 mt-1">Autonomous Host Isolation Triggered</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Executions</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⏳</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-det-active">-</p>
          <p class="text-xs text-amber-300 mt-1">Detonating in Isolated Sandbox</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Process Tree Nodes</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🌳</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-det-nodes">-</p>
          <p class="text-xs text-emerald-300 mt-1">Lineage Telemetry Recorded</p>
        </div>
      </div>

      <!-- Navigation Subtabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="sandbox-subtab px-4 py-2 text-sm font-semibold border-b-2 border-rose-500 text-rose-400" data-tab="jobs">
          🧪 Detonation Tasks
        </button>
        <button class="sandbox-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="lineage">
          🌳 EDR Process Lineage Graphs
        </button>
        <button class="sandbox-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="events">
          ⚡ Behavioral Telemetry Stream
        </button>
      </div>

      <!-- Tab Content 1: Jobs -->
      <div id="subtab-content-jobs" class="sandbox-tab-panel space-y-4">
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Sample Name</th>
                <th class="px-4 py-3">Type</th>
                <th class="px-4 py-3">Device / Host</th>
                <th class="px-4 py-3">Risk Score</th>
                <th class="px-4 py-3">Verdict</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Remediation</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="sandbox-jobs-tbody" class="divide-y divide-slate-700/30">
              <tr><td colspan="8" class="px-4 py-6 text-center text-slate-500">Loading detonation jobs...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Content 2: Process Lineage Tree View -->
      <div id="subtab-content-lineage" class="sandbox-tab-panel space-y-4 hidden">
        <div class="bg-slate-800/60 p-5 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-center mb-4">
            <div>
              <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>🌳</span> Hierarchical Process Lineage Execution Tree
              </h3>
              <p class="text-xs text-slate-400 mt-0.5">Interactive Parent-Child process breakdown showing injected processes and abnormal execution chains</p>
            </div>
            <div class="flex items-center gap-2">
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 text-xs border border-rose-500/30">
                <span>⚠️</span> Anomalous Execution Detected
              </span>
            </div>
          </div>
          <div id="sandbox-tree-container" class="space-y-3 font-mono text-xs">
            <div class="text-slate-500 p-4 text-center">Select a sample from Detonation Tasks to inspect its process lineage tree.</div>
          </div>
        </div>
      </div>

      <!-- Tab Content 3: Behavioral Telemetry Events -->
      <div id="subtab-content-events" class="sandbox-tab-panel space-y-4 hidden">
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Timestamp</th>
                <th class="px-4 py-3">Process</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Target Object</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">MITRE</th>
              </tr>
            </thead>
            <tbody id="sandbox-events-tbody" class="divide-y divide-slate-700/30">
              <tr><td colspan="7" class="px-4 py-6 text-center text-slate-500">Loading behavioral events...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function loadSandboxDetonationData() {
  try {
    const statsRes = await fetch('/api/v1/fleet/sandbox/stats', { credentials: 'same-origin' });
    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('kpi-det-total').textContent = stats.totalJobs || 0;
      document.getElementById('kpi-det-malicious').textContent = stats.maliciousCount || 0;
      document.getElementById('kpi-det-active').textContent = stats.activeJobs || 0;
      document.getElementById('kpi-det-nodes').textContent = stats.totalProcessNodes || 0;
    }

    const jobsRes = await fetch('/api/v1/fleet/sandbox/jobs', { credentials: 'same-origin' });
    if (jobsRes.ok) {
      const { jobs } = await jobsRes.json();
      renderSandboxJobsTable(jobs || []);
    }

    const eventsRes = await fetch('/api/v1/fleet/sandbox/events', { credentials: 'same-origin' });
    if (eventsRes.ok) {
      const { events } = await eventsRes.json();
      renderSandboxEventsTable(events || []);
    }
  } catch (err) {
    console.error('Error loading sandbox detonation data:', err);
  }
}

function renderSandboxJobsTable(jobs) {
  const tbody = document.getElementById('sandbox-jobs-tbody');
  if (!tbody) return;

  if (jobs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-6 text-center text-slate-500">No detonation tasks found.</td></tr>';
    return;
  }

  tbody.innerHTML = jobs.map(j => {
    let verdictBadge = '<span class="px-2 py-0.5 rounded bg-slate-700 text-slate-300">PENDING</span>';
    if (j.verdict === 'MALICIOUS') verdictBadge = '<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 font-semibold">MALICIOUS</span>';
    else if (j.verdict === 'SUSPICIOUS') verdictBadge = '<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-semibold">SUSPICIOUS</span>';
    else if (j.verdict === 'BENIGN') verdictBadge = '<span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">BENIGN</span>';

    const riskColor = j.risk_score >= 70 ? 'text-red-400' : (j.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400');

    return `
      <tr class="hover:bg-slate-700/20 transition">
        <td class="px-4 py-3 font-medium text-white flex items-center gap-2">
          <span>🧪</span> ${escapeHtml(j.sample_name)}
        </td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(j.sample_type)}</td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(j.hostname)}</td>
        <td class="px-4 py-3 font-bold ${riskColor}">
          ${j.risk_score}/100
        </td>
        <td class="px-4 py-3">${verdictBadge}</td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs ${j.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}">
            ${j.status}
          </span>
        </td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(j.automated_remediation)}</td>
        <td class="px-4 py-3 text-right space-x-2">
          <button onclick="viewProcessLineage('${j.id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-cyan-300 rounded text-xs transition">
            🌳 Tree
          </button>
          <button onclick="viewSandboxScript('${j.id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition">
            📜 WSB
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderSandboxEventsTable(events) {
  const tbody = document.getElementById('sandbox-events-tbody');
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-6 text-center text-slate-500">No behavioral telemetry events recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = events.map(e => {
    let sevBadge = '<span class="px-2 py-0.5 rounded bg-slate-700 text-slate-300">INFO</span>';
    if (e.severity === 'CRITICAL') sevBadge = '<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 font-bold">CRITICAL</span>';
    else if (e.severity === 'HIGH') sevBadge = '<span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">HIGH</span>';
    else if (e.severity === 'MEDIUM') sevBadge = '<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">MEDIUM</span>';

    return `
      <tr class="hover:bg-slate-700/20 transition">
        <td class="px-4 py-3 text-slate-400">${e.timestamp ? e.timestamp.substring(11, 19) : '-'}</td>
        <td class="px-4 py-3 font-semibold text-white">${escapeHtml(e.process_name)} (PID: ${e.process_id})</td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(e.event_category)}</td>
        <td class="px-4 py-3 text-slate-300">${escapeHtml(e.event_action)}</td>
        <td class="px-4 py-3 font-mono text-slate-300 truncate max-w-xs" title="${escapeHtml(e.target_object)}">${escapeHtml(e.target_object)}</td>
        <td class="px-4 py-3">${sevBadge}</td>
        <td class="px-4 py-3 text-amber-300 font-mono">${escapeHtml(e.mitre_technique || '-')}</td>
      </tr>
    `;
  }).join('');
}

async function viewProcessLineage(detonationId) {
  try {
    const res = await fetch(`/api/v1/fleet/sandbox/jobs/${detonationId}/graph`, { credentials: 'same-origin' });
    if (!res.ok) return;
    const graph = await res.json();

    // Switch to lineage subtab
    document.querySelectorAll('.sandbox-subtab').forEach(b => b.classList.remove('border-rose-500', 'text-rose-400'));
    document.querySelectorAll('.sandbox-tab-panel').forEach(p => p.classList.add('hidden'));
    const lineageBtn = document.querySelector('.sandbox-subtab[data-tab="lineage"]');
    if (lineageBtn) lineageBtn.classList.add('border-rose-500', 'text-rose-400');
    document.getElementById('subtab-content-lineage').classList.remove('hidden');

    const container = document.getElementById('sandbox-tree-container');
    if (!container) return;

    function renderNode(node, depth = 0) {
      const indent = depth * 24;
      const isAnom = node.is_anomalous === 1;
      const anomBadge = isAnom ? '<span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs ml-2">⚠️ ANOMALOUS</span>' : '';

      return `
        <div class="p-3 bg-slate-900/60 rounded-lg border ${isAnom ? 'border-rose-500/40' : 'border-slate-700/40'} my-1.5" style="margin-left: ${indent}px">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-base">${depth === 0 ? '💻' : '↳ ⚙️'}</span>
              <span class="font-bold text-white">${escapeHtml(node.process_name)}</span>
              <span class="text-xs text-slate-400">(PID: ${node.process_id} | PPID: ${node.parent_process_id})</span>
              ${anomBadge}
            </div>
            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">${node.integrity_level || 'MEDIUM'}</span>
          </div>
          <div class="mt-1 text-slate-400 text-xs truncate" title="${escapeHtml(node.command_line || '')}">
            <span class="text-slate-500">Cmd:</span> ${escapeHtml(node.command_line || node.executable_path)}
          </div>
        </div>
        ${(node.children || []).map(c => renderNode(c, depth + 1)).join('')}
      `;
    }

    if (!graph.tree || graph.tree.length === 0) {
      container.innerHTML = '<div class="text-slate-500 p-4 text-center">No process tree recorded for this detonation job.</div>';
      return;
    }

    container.innerHTML = graph.tree.map(root => renderNode(root, 0)).join('');
  } catch (err) {
    console.error('Error viewing process lineage:', err);
  }
}

async function viewSandboxScript(jobId) {
  try {
    const res = await fetch(`/api/v1/fleet/sandbox/jobs/${jobId}/script`, { credentials: 'same-origin' });
    if (!res.ok) return;
    const script = await res.json();
    alert(`Windows Sandbox Configuration (.wsb):\n\n${script.sandbox_wsb_xml}`);
  } catch (err) {
    console.error('Error viewing sandbox script:', err);
  }
}

function initSandboxDetonationBlade() {
  document.querySelectorAll('.sandbox-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sandbox-subtab').forEach(b => {
        b.classList.remove('border-rose-500', 'text-rose-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.add('border-rose-500', 'text-rose-400');
      btn.classList.remove('border-transparent', 'text-slate-400');

      document.querySelectorAll('.sandbox-tab-panel').forEach(p => p.classList.add('hidden'));
      const tabName = btn.dataset.tab;
      const targetPanel = document.getElementById(`subtab-content-${tabName}`);
      if (targetPanel) targetPanel.classList.remove('hidden');
    });
  });

  const refreshBtn = document.getElementById('btn-sandbox-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadSandboxDetonationData);
  }

  const newJobBtn = document.getElementById('btn-sandbox-new-job');
  if (newJobBtn) {
    newJobBtn.addEventListener('click', () => {
      const sampleName = prompt('Enter sample binary or script name to detonate (e.g. keygen.exe, drop.ps1):');
      if (!sampleName) return;
      const sha = prompt('Enter SHA-256 hash:', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      if (!sha) return;

      fetch('/api/v1/fleet/sandbox/jobs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sample_name: sampleName,
          sample_type: sampleName.endsWith('.ps1') ? 'POWERSHELL_SCRIPT' : 'EXECUTABLE',
          sample_sha256: sha,
          automated_remediation: 'ISOLATE_ENDPOINT'
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => {
        loadSandboxDetonationData();
      });
    });
  }

  loadSandboxDetonationData();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderSandboxDetonationBlade = renderSandboxDetonationBlade;
window.initSandboxDetonationBlade = initSandboxDetonationBlade;
window.loadSandboxDetonationData = loadSandboxDetonationData;
window.viewProcessLineage = viewProcessLineage;
window.viewSandboxScript = viewSandboxScript;

window.SandboxDetonationTable = {
  async render() {
    const container = document.getElementById('tab-sandbox-detonation');
    if (!container) return;
    container.innerHTML = renderSandboxDetonationBlade();
    initSandboxDetonationBlade();
  }
};
