/**
 * LocalPilot Fleet — Custom Remediation Automation & Live Response Blade
 * Interactive remote command terminal, automated detection/remediation playbooks, and secure malware quarantine vault.
 */

function renderLiveResponseBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-2xl border border-emerald-500/30">⚡</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Live Response &amp; Remediation Automation
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">EDR Terminal</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Interactive remote investigation console, automated remediation playbooks, and malware quarantine vault</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-lr-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-lr-new-session" class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-emerald-500/20">
            <span>💻</span> Start Live Session
          </button>
          <button id="btn-lr-new-playbook" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>📜</span> New Playbook
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="lr-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Sessions</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">💻</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-lr-sessions">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediation Playbooks</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-lr-playbooks">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Executed Commands</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-lr-commands">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Quarantine Vault</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">☣️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-lr-quarantine">-</p>
        </div>
      </div>

      <!-- Live Response Interactive Terminal Console -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div class="flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-rose-500"></span>
            <span class="w-3 h-3 rounded-full bg-amber-500"></span>
            <span class="w-3 h-3 rounded-full bg-emerald-500"></span>
            <h3 class="text-md font-bold text-white tracking-wide ml-2 font-mono">Live Response Terminal Console</h3>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400 font-mono">Session ID: <span id="lr-active-session-id" class="text-emerald-400 font-bold">lrs-session-77</span></span>
          </div>
        </div>

        <div class="p-4 bg-slate-900/90 font-mono text-xs text-slate-300 space-y-3 min-h-[160px] max-h-[260px] overflow-y-auto" id="lr-terminal-output">
          <div class="text-slate-500">// Connected to LocalPilot Live Response Daemon v2.5.0</div>
          <div class="text-emerald-400">[SecOps Lead Analyst@DESKTOP-R0H12DJ] # dir C:\Windows\System32\drivers\etc</div>
          <div class="text-slate-300 whitespace-pre-wrap pl-4 bg-slate-950/50 p-2 rounded border border-slate-800">hosts
lmhosts.sam
networks
protocol
services</div>
          <div class="text-emerald-400">[SecOps Lead Analyst@DESKTOP-R0H12DJ] # Get-Process | Sort-Object CPU -Descending | Select-Object -First 5</div>
          <div class="text-slate-300 whitespace-pre-wrap pl-4 bg-slate-950/50 p-2 rounded border border-slate-800">ProcessName Id CPU
----------- -- ---
System 4 214.5
LocalPilotAgent 3480 45.2</div>
        </div>

        <!-- Command Input Bar -->
        <div class="p-4 bg-slate-850 border-t border-slate-700/60 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <select id="lr-cmd-type" class="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono focus:ring-1 focus:ring-emerald-500">
            <option value="EXEC_POWERSHELL">EXEC_POWERSHELL</option>
            <option value="EXEC_CMD">EXEC_CMD</option>
            <option value="LIST_DIRECTORY">LIST_DIRECTORY</option>
            <option value="TERMINATE_PROCESS">TERMINATE_PROCESS</option>
            <option value="GET_FILE">GET_FILE</option>
            <option value="PUT_FILE">PUT_FILE</option>
            <option value="PROCESS_DUMP">PROCESS_DUMP</option>
            <option value="REGISTRY_QUERY">REGISTRY_QUERY</option>
          </select>
          <input type="text" id="lr-cmd-input" placeholder="Enter command or target process / path (e.g. Get-Service, pid:9944, C:\...)" class="flex-1 bg-slate-900 border border-slate-700 text-slate-100 text-xs rounded-lg px-3 py-2 font-mono focus:ring-1 focus:ring-emerald-500" />
          <button id="btn-lr-send-cmd" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold font-mono transition flex items-center justify-center gap-1.5 shadow">
            <span>⚡</span> Dispatch
          </button>
        </div>
      </div>

      <!-- Remediation Playbooks Table -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Automated Remediation Playbooks</h3>
            <p class="text-xs text-slate-400 mt-0.5">Continuous compliance, self-healing scripts, and security baselines</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="lr-playbooks-count">0 Playbooks</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Playbook Name</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Schedule</th>
                <th class="px-4 py-3">Scope</th>
                <th class="px-4 py-3">Run As</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="lr-playbooks-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading remediation playbooks...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Quarantined Artifacts Vault -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Quarantined Artifacts Vault</h3>
            <p class="text-xs text-slate-400 mt-0.5">Secure containment repository for suspicious binaries, scripts, and macros</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="lr-quarantine-count">0 Artifacts</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Threat Classification</th>
                <th class="px-4 py-3">File / Artifact</th>
                <th class="px-4 py-3">Host</th>
                <th class="px-4 py-3">SHA-256 Hash</th>
                <th class="px-4 py-3">Vault Status</th>
                <th class="px-4 py-3">Quarantined At</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="lr-quarantine-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading quarantine vault...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function initLiveResponseBlade() {
  const btnRefresh = document.getElementById('btn-lr-refresh');
  if (btnRefresh) btnRefresh.onclick = () => loadLiveResponseData();

  const btnNewSession = document.getElementById('btn-lr-new-session');
  if (btnNewSession) {
    btnNewSession.onclick = async () => {
      const devId = prompt('Enter Target Device ID for Live Response Session:', 'DESKTOP-R0H12DJ');
      if (!devId) return;
      try {
        const res = await fetch('/api/v1/fleet/live-response/sessions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_id: devId, operator: 'SecOps Console' }),
          credentials: 'same-origin'
        });
        if (res.ok) {
          const data = await res.json();
          alert('Live Response Session Started!\nID: ' + data.session.session_id);
          const el = document.getElementById('lr-active-session-id');
          if (el) el.innerText = data.session.session_id;
          loadLiveResponseData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  const btnNewPlaybook = document.getElementById('btn-lr-new-playbook');
  if (btnNewPlaybook) {
    btnNewPlaybook.onclick = async () => {
      const name = prompt('Playbook Name:');
      if (!name) return;
      const detect = prompt('PowerShell Detection Script (Exit 1 if non-compliant):', 'if ((Get-Service Spooler).Status -eq "Running") { exit 1 } else { exit 0 }');
      if (!detect) return;
      const remediate = prompt('PowerShell Remediation Script:', 'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled');
      if (!remediate) return;

      try {
        const res = await fetch('/api/v1/fleet/remediation-packages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name,
            detection_script: detect,
            remediation_script: remediate,
            category: 'SECURITY_HARDENING',
            run_frequency: 'DAILY',
            run_as_account: 'SYSTEM'
          }),
          credentials: 'same-origin'
        });
        if (res.ok) {
          alert('Remediation playbook created successfully!');
          loadLiveResponseData();
        }
      } catch (e) {
        console.error(e);
      }
    };
  }

  const btnSendCmd = document.getElementById('btn-lr-send-cmd');
  if (btnSendCmd) {
    btnSendCmd.onclick = async () => {
      const cmdType = document.getElementById('lr-cmd-type')?.value || 'EXEC_POWERSHELL';
      const cmdPayload = document.getElementById('lr-cmd-input')?.value;
      if (!cmdPayload) return;

      const termOutput = document.getElementById('lr-terminal-output');
      if (termOutput) {
        termOutput.innerHTML += `
          <div class="text-emerald-400">[SecOps Operator] # [${cmdType}] ${escapeHtml(cmdPayload)}</div>
          <div class="text-amber-400 pl-4">[QUEUED] Dispatched to agent command queue...</div>
        `;
        termOutput.scrollTop = termOutput.scrollHeight;
      }

      document.getElementById('lr-cmd-input').value = '';
      loadLiveResponseData();
    };
  }

  await loadLiveResponseData();
}

async function loadLiveResponseData() {
  try {
    // 1. Stats
    const statsRes = await fetch('/api/v1/fleet/live-response/stats', { credentials: 'same-origin' });
    if (statsRes.ok) {
      const s = await statsRes.json();
      const elSess = document.getElementById('kpi-lr-sessions');
      const elPkg = document.getElementById('kpi-lr-playbooks');
      const elCmd = document.getElementById('kpi-lr-commands');
      const elQuar = document.getElementById('kpi-lr-quarantine');
      if (elSess) elSess.innerText = s.activeSessions || 0;
      if (elPkg) elPkg.innerText = s.totalPackages || 0;
      if (elCmd) elCmd.innerText = s.totalCommands || 0;
      if (elQuar) elQuar.innerText = s.quarantinedFiles || 0;
    }

    // 2. Remediation Playbooks
    const pkgRes = await fetch('/api/v1/fleet/remediation-packages', { credentials: 'same-origin' });
    if (pkgRes.ok) {
      const data = await pkgRes.json();
      renderPlaybooksTable(data.packages || []);
    }

    // 3. Quarantined Files
    const quarRes = await fetch('/api/v1/fleet/live-response/quarantine', { credentials: 'same-origin' });
    if (quarRes.ok) {
      const data = await quarRes.json();
      renderQuarantineTable(data.files || []);
    }
  } catch (err) {
    console.error('Failed to load Live Response telemetry:', err);
  }
}

function renderPlaybooksTable(packages) {
  const tbody = document.getElementById('lr-playbooks-tbody');
  const countEl = document.getElementById('lr-playbooks-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${packages.length} Playbooks`;

  if (!packages.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No remediation playbooks found.</td></tr>';
    return;
  }

  tbody.innerHTML = packages.map(p => `
    <tr class="hover:bg-slate-750/50 transition">
      <td class="px-4 py-3 font-medium text-slate-200">
        <div class="font-bold text-white">${escapeHtml(p.name)}</div>
        <div class="text-[11px] text-slate-400 font-sans mt-0.5">${escapeHtml(p.description || 'Automated self-healing script')}</div>
      </td>
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">
          ${escapeHtml(p.category)}
        </span>
      </td>
      <td class="px-4 py-3 text-slate-300">${escapeHtml(p.run_frequency)}</td>
      <td class="px-4 py-3 text-slate-300">${escapeHtml(p.target_scope)}</td>
      <td class="px-4 py-3 text-slate-400">${escapeHtml(p.run_as_account)}</td>
      <td class="px-4 py-3">
        ${p.is_active ?
          '<span class="text-emerald-400 flex items-center gap-1">● Active</span>' :
          '<span class="text-slate-500 flex items-center gap-1">○ Disabled</span>'
        }
      </td>
      <td class="px-4 py-3 text-right">
        <button onclick="viewRemediationScript('${p.id}')" class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-[11px] mr-1">
          📜 Script
        </button>
        <button onclick="deletePlaybook('${p.id}')" class="px-2 py-1 bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white rounded text-[11px] border border-rose-500/30">
          🗑️
        </button>
      </td>
    </tr>
  `).join('');
}

function renderQuarantineTable(files) {
  const tbody = document.getElementById('lr-quarantine-tbody');
  const countEl = document.getElementById('lr-quarantine-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${files.length} Artifacts`;

  if (!files.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Quarantine vault is empty.</td></tr>';
    return;
  }

  tbody.innerHTML = files.map(f => `
    <tr class="hover:bg-slate-750/50 transition">
      <td class="px-4 py-3 text-rose-400 font-bold">
        ☣️ ${escapeHtml(f.threat_name)}
      </td>
      <td class="px-4 py-3 text-slate-200">
        <div>${escapeHtml(f.file_name)}</div>
        <div class="text-[10px] text-slate-500 truncate max-w-xs">${escapeHtml(f.original_path)}</div>
      </td>
      <td class="px-4 py-3 text-slate-300">${escapeHtml(f.hostname)}</td>
      <td class="px-4 py-3 text-slate-400 text-[10px]">${escapeHtml(f.sha256_hash.substring(0, 16))}...</td>
      <td class="px-4 py-3">
        <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${f.status === 'QUARANTINED' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-slate-700 text-slate-300'}">
          ${escapeHtml(f.status)}
        </span>
      </td>
      <td class="px-4 py-3 text-slate-400 text-[11px]">${escapeHtml(f.quarantined_at)}</td>
      <td class="px-4 py-3 text-right">
        ${f.status === 'QUARANTINED' ?
          `<button onclick="restoreQuarantinedFile('${f.id}')" class="px-2 py-1 bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white rounded text-[11px] border border-emerald-500/30">
            ♻️ Restore
          </button>` :
          `<span class="text-xs text-slate-500">Restored</span>`
        }
      </td>
    </tr>
  `).join('');
}

async function viewRemediationScript(id) {
  try {
    const res = await fetch(`/api/v1/fleet/remediation-packages/${id}/script`, { credentials: 'same-origin' });
    if (res.ok) {
      const script = await res.text();
      alert('Playbook Execution Wrapper Script:\n\n' + script.substring(0, 600) + '...');
    }
  } catch (e) {
    console.error(e);
  }
}

async function deletePlaybook(id) {
  if (!confirm('Delete this remediation playbook?')) return;
  await fetch(`/api/v1/fleet/remediation-packages/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadLiveResponseData();
}

async function restoreQuarantinedFile(id) {
  if (!confirm('Restore this quarantined file back to the host filesystem?')) return;
  await fetch(`/api/v1/fleet/live-response/quarantine/${id}/restore`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: 'Restored via SecOps Dashboard' }),
    credentials: 'same-origin'
  });
  loadLiveResponseData();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderLiveResponseBlade = renderLiveResponseBlade;
window.initLiveResponseBlade = initLiveResponseBlade;
window.loadLiveResponseData = loadLiveResponseData;
window.viewRemediationScript = viewRemediationScript;
window.deletePlaybook = deletePlaybook;
window.restoreQuarantinedFile = restoreQuarantinedFile;

window.LiveResponseTable = {
  async render() {
    const container = document.getElementById('tab-live-response');
    if (!container) return;
    container.innerHTML = renderLiveResponseBlade();
    initLiveResponseBlade();
  }
};
