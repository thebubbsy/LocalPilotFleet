/**
 * LocalPilot Fleet — Automated Incident Response & Forensic Timeline Capture Blade
 * Host Network Containment, Automated IR Playbooks, and Memory Triage Acquisition.
 */

function renderIncidentResponseBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-rose-500/20 text-rose-400 rounded-lg text-2xl border border-rose-500/30">🚨</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Automated Incident Response &amp; Forensic Triage
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">Sub-10s Containment</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated host network containment, incident response playbooks, and forensic timeline acquisition</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-ir-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-ir-new-playbook" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>⚡</span> New Playbook
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="ir-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Contained Workstations</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-ir-contained">-</p>
          <p class="text-xs text-rose-300 mt-1 flex items-center gap-1">Network Quarantined</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active IR Playbooks</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-ir-playbooks">-</p>
          <p class="text-xs text-cyan-400 mt-1 flex items-center gap-1">Automated Event Triggers</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Forensic Packages</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">📦</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-ir-triage">-</p>
          <p class="text-xs text-purple-300 mt-1">Acquired Artifact Bundles</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Containment SLA</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">⏱️</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-ir-sla">&lt; 10s</p>
          <p class="text-xs text-emerald-300 mt-1">Automated Push Dispatch</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="ir-subtab px-4 py-2 text-sm font-semibold border-b-2 border-rose-500 text-rose-400" data-tab="containment">
          🛡️ Host Containment &amp; Isolation
        </button>
        <button class="ir-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="playbooks">
          ⚡ Automated IR Playbooks
        </button>
        <button class="ir-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="triage">
          📦 Forensic Triage Packages
        </button>
      </div>

      <!-- Tab Content 1: Host Containment Ledger -->
      <div id="subtab-content-containment" class="ir-tab-panel space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🛡️</span> Workstation Network Isolation Status
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Isolate compromised endpoints via Windows Filtering Platform (WFP) while preserving fleet management channel</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Workstation</th>
                <th class="px-4 py-3">Containment Status</th>
                <th class="px-4 py-3">Isolation Mode</th>
                <th class="px-4 py-3">Isolated At</th>
                <th class="px-4 py-3">Trigger Reason</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ir-containment-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading containment ledger...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Content 2: Automated IR Playbooks -->
      <div id="subtab-content-playbooks" class="ir-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>⚡</span> Configured Incident Response Playbooks
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Rules that automatically trigger host containment, triage capture, and process termination upon critical security alarms</p>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" id="ir-playbooks-grid">
          <div class="col-span-full p-8 text-center text-slate-400">Loading automated playbooks...</div>
        </div>
      </div>

      <!-- Tab Content 3: Forensic Triage Packages -->
      <div id="subtab-content-triage" class="ir-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>📦</span> Acquired Forensic Memory &amp; Timeline Bundles
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">SHA-256 cryptographically verified triage archives containing ProcessTree, NetworkConnections, Prefetch, and EventLogs</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Package ID &amp; Target</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Trigger Source</th>
                <th class="px-4 py-3">Size / Hash</th>
                <th class="px-4 py-3">Created</th>
                <th class="px-4 py-3 text-right">Download</th>
              </tr>
            </thead>
            <tbody id="ir-triage-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading forensic packages...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Modal: Isolate Host -->
    <div id="modal-ir-isolate" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md shadow-2xl space-y-4">
        <div class="flex items-center gap-3">
          <span class="p-2 bg-rose-500/20 text-rose-400 rounded-lg text-xl border border-rose-500/30">🔴</span>
          <div>
            <h3 class="font-bold text-white text-base">Isolate Workstation</h3>
            <p class="text-xs text-slate-400" id="modal-isolate-host-label">Target: -</p>
          </div>
        </div>
        <div class="space-y-3">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Isolation Type</label>
            <select id="modal-isolate-type" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200">
              <option value="ALLOW_FLEET_MANAGEMENT_ONLY">Allow Fleet Management Only (Preserves Remediation Channel)</option>
              <option value="TOTAL_AIR_GAP">Total Air-Gap (Block All Network I/O)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Justification / Incident Reason</label>
            <textarea id="modal-isolate-reason" rows="3" placeholder="e.g. Active ransomware canary triggered or unauthorized admin credential dump detected." 
              class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"></textarea>
          </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="modal-isolate-cancel" class="px-3.5 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-medium transition">Cancel</button>
          <button id="modal-isolate-confirm" class="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md">
            <span>🔒</span> Apply Isolation
          </button>
        </div>
      </div>
    </div>

    <!-- Modal: Release Host -->
    <div id="modal-ir-release" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md shadow-2xl space-y-4">
        <div class="flex items-center gap-3">
          <span class="p-2 bg-emerald-500/20 text-emerald-400 rounded-lg text-xl border border-emerald-500/30">🟢</span>
          <div>
            <h3 class="font-bold text-white text-base">Release Host Containment</h3>
            <p class="text-xs text-slate-400" id="modal-release-host-label">Target: -</p>
          </div>
        </div>
        <p class="text-xs text-slate-300">
          Are you sure you want to release network containment on this endpoint? Normal inbound and outbound network connectivity will be restored immediately.
        </p>
        <div class="flex justify-end gap-2 pt-2">
          <button id="modal-release-cancel" class="px-3.5 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-medium transition">Cancel</button>
          <button id="modal-release-confirm" class="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md">
            <span>🔓</span> Confirm Release
          </button>
        </div>
      </div>
    </div>

    <!-- Modal: New Playbook -->
    <div id="modal-ir-playbook" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4">
        <div class="flex items-center gap-3">
          <span class="p-2 bg-cyan-500/20 text-cyan-400 rounded-lg text-xl border border-cyan-500/30">⚡</span>
          <div>
            <h3 class="font-bold text-white text-base">Create Automated IR Playbook</h3>
            <p class="text-xs text-slate-400">Configure automated containment rules triggered on security events</p>
          </div>
        </div>
        <div class="space-y-3">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Playbook Name</label>
            <input type="text" id="modal-pb-name" placeholder="e.g. Rogue Admin Auto-Containment" 
              class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500" />
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Trigger Event Type</label>
            <select id="modal-pb-trigger" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200">
              <option value="RANSOMWARE_SUSPECT">RANSOMWARE_SUSPECT (Canary File Encryption / MBR Tamper)</option>
              <option value="ROGUE_ADMIN">ROGUE_ADMIN (Unauthorized Admin Group Addition Event 4732)</option>
              <option value="MALWARE_DETECTED">MALWARE_DETECTED (Defender Real-Time Protection Signature)</option>
              <option value="PROCESS_INJECTION">PROCESS_INJECTION (Reflective DLL / Hollow Process)</option>
              <option value="TAMPER_DETECTED">TAMPER_DETECTED (Agent Service Stopped or Hooked)</option>
              <option value="ALL_CRITICAL">ALL_CRITICAL (Any Critical Severity Event)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Automated Actions (Select all that apply)</label>
            <div class="grid grid-cols-2 gap-2 text-xs text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-700">
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="modal-pb-act-isolate" checked class="accent-rose-500" />
                <span>🛡️ ISOLATE_NETWORK</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="modal-pb-act-triage" checked class="accent-rose-500" />
                <span>📦 COLLECT_TRIAGE</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="modal-pb-act-kill" class="accent-rose-500" />
                <span>💀 KILL_PROCESS_TREE</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="modal-pb-act-toast" checked class="accent-rose-500" />
                <span>📢 DISPATCH_TOAST</span>
              </label>
            </div>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Description</label>
            <textarea id="modal-pb-desc" rows="2" placeholder="Explain the rationale and scope of this automated playbook..."
              class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"></textarea>
          </div>
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="modal-pb-cancel" class="px-3.5 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-medium transition">Cancel</button>
          <button id="modal-pb-submit" class="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md">
            <span>💾</span> Save Playbook
          </button>
        </div>
      </div>
    </div>
  `;
}

async function initIncidentResponseBlade(api) {
  let targetDeviceId = null;
  let targetHostname = '';
  let allDevices = [];

  // Tab switching logic
  document.querySelectorAll('.ir-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.ir-subtab').forEach(b => {
        b.classList.remove('border-rose-500', 'text-rose-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.remove('border-transparent', 'text-slate-400');
      btn.classList.add('border-rose-500', 'text-rose-400');

      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.ir-tab-panel').forEach(panel => panel.classList.add('hidden'));
      const activePanel = document.getElementById(`subtab-content-${targetTab}`);
      if (activePanel) activePanel.classList.remove('hidden');
    });
  });

  // Modal event wiring
  const isolateModal = document.getElementById('modal-ir-isolate');
  const releaseModal = document.getElementById('modal-ir-release');
  const playbookModal = document.getElementById('modal-ir-playbook');

  document.getElementById('modal-isolate-cancel')?.addEventListener('click', () => isolateModal.classList.add('hidden'));
  document.getElementById('modal-release-cancel')?.addEventListener('click', () => releaseModal.classList.add('hidden'));
  document.getElementById('modal-pb-cancel')?.addEventListener('click', () => playbookModal.classList.add('hidden'));

  document.getElementById('btn-ir-new-playbook')?.addEventListener('click', () => {
    document.getElementById('modal-pb-name').value = '';
    document.getElementById('modal-pb-desc').value = '';
    playbookModal.classList.remove('hidden');
  });

  document.getElementById('btn-ir-refresh')?.addEventListener('click', () => loadAllIRData(api));

  // Confirm Isolate
  document.getElementById('modal-isolate-confirm')?.addEventListener('click', async () => {
    if (!targetDeviceId) return;
    const isolationType = document.getElementById('modal-isolate-type').value;
    const reason = document.getElementById('modal-isolate-reason').value || 'Manual operator containment';
    try {
      await api.post(`/api/v1/fleet/devices/${targetDeviceId}/contain`, {
        isolation_type: isolationType,
        reason: reason
      });
      if (window.showToast) window.showToast(`Host ${targetHostname} isolated successfully`, 'warning');
      isolateModal.classList.add('hidden');
      await loadAllIRData(api);
    } catch (err) {
      alert('Failed to isolate host: ' + err.message);
    }
  });

  // Confirm Release
  document.getElementById('modal-release-confirm')?.addEventListener('click', async () => {
    if (!targetDeviceId) return;
    try {
      await api.post(`/api/v1/fleet/devices/${targetDeviceId}/release`, {
        reason: 'Operator approved release'
      });
      if (window.showToast) window.showToast(`Host ${targetHostname} released from containment`, 'success');
      releaseModal.classList.add('hidden');
      await loadAllIRData(api);
    } catch (err) {
      alert('Failed to release host: ' + err.message);
    }
  });

  // Submit New Playbook
  document.getElementById('modal-pb-submit')?.addEventListener('click', async () => {
    const name = document.getElementById('modal-pb-name').value.trim();
    if (!name) return alert('Playbook name is required');
    const trigger = document.getElementById('modal-pb-trigger').value;
    const desc = document.getElementById('modal-pb-desc').value.trim();

    const actions = [];
    if (document.getElementById('modal-pb-act-isolate').checked) actions.push('ISOLATE_NETWORK');
    if (document.getElementById('modal-pb-act-triage').checked) actions.push('COLLECT_TRIAGE');
    if (document.getElementById('modal-pb-act-kill').checked) actions.push('KILL_PROCESS_TREE');
    if (document.getElementById('modal-pb-act-toast').checked) actions.push('DISPATCH_TOAST');

    try {
      await api.post('/api/v1/fleet/ir/playbooks', {
        name,
        description: desc,
        trigger_event_type: trigger,
        actions: JSON.stringify(actions),
        is_enabled: 1
      });
      if (window.showToast) window.showToast(`Playbook '${name}' created`, 'success');
      playbookModal.classList.add('hidden');
      await loadAllIRData(api);
    } catch (err) {
      alert('Failed to create playbook: ' + err.message);
    }
  });

  // Initial load
  await loadAllIRData(api);

  async function loadAllIRData(api) {
    try {
      // 1. Fetch KPI stats
      const stats = await api.get('/api/v1/fleet/ir/stats');
      if (stats) {
        document.getElementById('kpi-ir-contained').textContent = stats.contained_hosts || 0;
        document.getElementById('kpi-ir-playbooks').textContent = stats.active_playbooks || 0;
        document.getElementById('kpi-ir-triage').textContent = stats.triage_packages || 0;
      }

      // 2. Fetch Devices & Containment States
      const devRes = await api.get('/api/v1/fleet/devices');
      allDevices = (devRes && devRes.devices) ? devRes.devices : [];

      const contRes = await api.get('/api/v1/fleet/ir/containment');
      const containmentList = (contRes && contRes.containment_states) ? contRes.containment_states : [];
      const contMap = new Map();
      containmentList.forEach(c => contMap.set(c.device_id, c));

      // Populate Host Containment Table
      const tbody = document.getElementById('ir-containment-tbody');
      if (tbody) {
        if (allDevices.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No enrolled workstations found.</td></tr>';
        } else {
          tbody.innerHTML = allDevices.map(d => {
            const cont = contMap.get(d.id);
            const isContained = cont && cont.status === 'CONTAINED';
            return `
              <tr class="hover:bg-slate-800/40 transition">
                <td class="px-4 py-3">
                  <div class="font-bold text-white flex items-center gap-1.5">
                    <span>💻</span> ${escapeHtml(d.hostname)}
                  </div>
                  <div class="text-[11px] text-slate-500 font-mono">${escapeHtml(d.id.substring(0, 8))}... | ${escapeHtml(d.os_name || 'Windows')}</div>
                </td>
                <td class="px-4 py-3">
                  ${isContained 
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center gap-1 w-max">
                        <span class="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse"></span> CONTAINED
                       </span>`
                    : `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 w-max">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> UNCONTAINED
                       </span>`
                  }
                </td>
                <td class="px-4 py-3 text-slate-300">
                  ${isContained ? escapeHtml(cont.isolation_type || 'ALLOW_FLEET_MANAGEMENT_ONLY') : '<span class="text-slate-500">—</span>'}
                </td>
                <td class="px-4 py-3 text-slate-400 text-[11px]">
                  ${isContained && cont.isolated_at ? new Date(cont.isolated_at).toLocaleTimeString() : '<span class="text-slate-500">—</span>'}
                </td>
                <td class="px-4 py-3 text-slate-300 max-w-xs truncate" title="${isContained ? escapeHtml(cont.reason) : ''}">
                  ${isContained ? escapeHtml(cont.reason || 'Manual containment') : '<span class="text-slate-500">Normal Operations</span>'}
                </td>
                <td class="px-4 py-3 text-right">
                  ${isContained
                    ? `<button class="btn-release-host px-2.5 py-1 bg-emerald-700/80 hover:bg-emerald-600 text-emerald-100 rounded text-xs font-semibold transition" 
                        data-id="${d.id}" data-hostname="${escapeHtml(d.hostname)}">
                        🟢 Release
                       </button>`
                    : `<button class="btn-isolate-host px-2.5 py-1 bg-rose-700/80 hover:bg-rose-600 text-rose-100 rounded text-xs font-semibold transition"
                        data-id="${d.id}" data-hostname="${escapeHtml(d.hostname)}">
                        🔴 Isolate Host
                       </button>`
                  }
                </td>
              </tr>
            `;
          }).join('');

          // Bind Isolate/Release buttons
          tbody.querySelectorAll('.btn-isolate-host').forEach(btn => {
            btn.addEventListener('click', () => {
              targetDeviceId = btn.getAttribute('data-id');
              targetHostname = btn.getAttribute('data-hostname');
              document.getElementById('modal-isolate-host-label').textContent = `Target: ${targetHostname} (${targetDeviceId})`;
              isolateModal.classList.remove('hidden');
            });
          });

          tbody.querySelectorAll('.btn-release-host').forEach(btn => {
            btn.addEventListener('click', () => {
              targetDeviceId = btn.getAttribute('data-id');
              targetHostname = btn.getAttribute('data-hostname');
              document.getElementById('modal-release-host-label').textContent = `Target: ${targetHostname} (${targetDeviceId})`;
              releaseModal.classList.remove('hidden');
            });
          });
        }
      }

      // 3. Fetch Playbooks
      const pbRes = await api.get('/api/v1/fleet/ir/playbooks');
      const playbooks = (pbRes && pbRes.playbooks) ? pbRes.playbooks : [];
      const pbGrid = document.getElementById('ir-playbooks-grid');
      if (pbGrid) {
        if (playbooks.length === 0) {
          pbGrid.innerHTML = '<div class="col-span-full p-8 text-center text-slate-400">No playbooks configured.</div>';
        } else {
          pbGrid.innerHTML = playbooks.map(pb => {
            let acts = [];
            try { acts = JSON.parse(pb.actions); } catch(e) { acts = [pb.actions]; }
            return `
              <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow flex flex-col justify-between space-y-3">
                <div>
                  <div class="flex justify-between items-start mb-2">
                    <h4 class="font-bold text-white text-sm flex items-center gap-1.5">
                      <span>⚡</span> ${escapeHtml(pb.name)}
                    </h4>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${pb.is_enabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-700 text-slate-400'}">
                      ${pb.is_enabled ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </div>
                  <p class="text-xs text-slate-400 mb-3">${escapeHtml(pb.description || 'No description provided')}</p>
                  
                  <div class="text-[10px] text-slate-500 font-semibold uppercase mb-1">Trigger Alarm:</div>
                  <div class="text-xs font-mono text-cyan-300 bg-slate-900 px-2 py-1 rounded border border-slate-800 w-max mb-3">
                    ${escapeHtml(pb.trigger_event_type)}
                  </div>

                  <div class="text-[10px] text-slate-500 font-semibold uppercase mb-1">Automated Actions:</div>
                  <div class="flex flex-wrap gap-1">
                    ${acts.map(a => `<span class="px-1.5 py-0.5 bg-rose-900/40 text-rose-300 border border-rose-700/50 rounded text-[10px] font-semibold">${escapeHtml(a)}</span>`).join('')}
                  </div>
                </div>

                <div class="pt-3 border-t border-slate-700/40 flex justify-between items-center text-xs">
                  <span class="text-slate-500 text-[11px]">${pb.dual_custody_required ? '🔐 Dual-Custody' : '⚡ Autonomous'}</span>
                  <button class="btn-del-playbook text-rose-400 hover:text-rose-300 transition text-xs font-semibold" data-id="${pb.id}">
                    Delete
                  </button>
                </div>
              </div>
            `;
          }).join('');

          // Bind Delete Playbook
          pbGrid.querySelectorAll('.btn-del-playbook').forEach(btn => {
            btn.addEventListener('click', async () => {
              const pId = btn.getAttribute('data-id');
              if (confirm('Delete this automated incident response playbook?')) {
                try {
                  await api.delete(`/api/v1/fleet/ir/playbooks/${pId}`);
                  if (window.showToast) window.showToast('Playbook deleted', 'info');
                  await loadAllIRData(api);
                } catch(err) {
                  alert('Failed to delete playbook: ' + err.message);
                }
              }
            });
          });
        }
      }

      // 4. Fetch Triage Packages
      const triageRes = await api.get('/api/v1/fleet/ir/triage');
      const packages = (triageRes && triageRes.triage_packages) ? triageRes.triage_packages : [];
      const triageTbody = document.getElementById('ir-triage-tbody');
      if (triageTbody) {
        if (packages.length === 0) {
          triageTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No triage packages collected yet.</td></tr>';
        } else {
          triageTbody.innerHTML = packages.map(pkg => `
            <tr class="hover:bg-slate-800/40 transition">
              <td class="px-4 py-3">
                <div class="font-bold text-white flex items-center gap-1.5">
                  <span>📦</span> ${escapeHtml(pkg.package_name || pkg.id)}
                </div>
                <div class="text-[11px] text-slate-500 font-mono">Device: ${escapeHtml(pkg.device_id.substring(0, 8))}...</div>
              </td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${pkg.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}">
                  ${escapeHtml(pkg.status)}
                </span>
              </td>
              <td class="px-4 py-3 text-slate-300">${escapeHtml(pkg.trigger_source || 'ON_DEMAND')}</td>
              <td class="px-4 py-3 font-mono text-[11px] text-slate-400">
                <div>${(pkg.file_size_bytes / (1024 * 1024)).toFixed(2)} MB</div>
                <div class="text-[10px] text-slate-500 truncate w-36" title="${escapeHtml(pkg.sha256_hash || '')}">${escapeHtml(pkg.sha256_hash ? pkg.sha256_hash.substring(0, 16) + '...' : 'pending')}</div>
              </td>
              <td class="px-4 py-3 text-slate-400 text-[11px]">
                ${pkg.created_at ? new Date(pkg.created_at).toLocaleDateString() : '—'}
              </td>
              <td class="px-4 py-3 text-right">
                <button class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs transition" 
                  onclick="window.open('/api/v1/fleet/ir/triage/${pkg.id}/download', '_blank')">
                  📥 Download Zip
                </button>
              </td>
            </tr>
          `).join('');
        }
      }

    } catch (err) {
      console.error('Failed loading incident response data:', err);
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

window.IncidentResponseTable = {
  render: async function() {
    const container = document.getElementById('tab-incident-response');
    if (!container) return;
    container.innerHTML = renderIncidentResponseBlade();
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
    await initIncidentResponseBlade(client);
  }
};
