/**
 * LocalPilot Fleet — Zero-Trust Device Health Attestation & Microsegmentation Blade
 * Hardware Root-of-Trust, TPM 2.0 PCR Measured Boot, and Software-Defined Perimeter.
 */

function renderDeviceHealthAttestationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-indigo-500/20 text-indigo-400 rounded-lg text-2xl border border-indigo-500/30">🛡️</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Zero-Trust Device Health Attestation &amp; ZTNA
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">TPM 2.0 Measured Boot</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Hardware root-of-trust verification, PCR register validation, and dynamic WFP microsegmentation</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-dha-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-dha-new-policy" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-indigo-500/20">
            <span>📋</span> New Baseline Policy
          </button>
          <button id="btn-dha-new-rule" class="px-3.5 py-2 bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg text-sm font-semibold transition flex items-center gap-1.5 border border-slate-600">
            <span>🌐</span> New Microsegment Rule
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="dha-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">DHA Compliance Rate</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">✅</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-dha-compliance">100%</p>
          <p class="text-xs text-emerald-300 mt-1 flex items-center gap-1">Hardware Verified</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">VBS &amp; HVCI Enforced</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">🔒</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-dha-vbs">-</p>
          <p class="text-xs text-cyan-400 mt-1 flex items-center gap-1">Strict Isolation</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Bootkit / Tamper Detections</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-dha-tamper">0</p>
          <p class="text-xs text-rose-300 mt-1">PCR Hash Violations</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Microsegmentation Rules</p>
            <span class="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-md text-sm">🌐</span>
          </div>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-dha-rules">-</p>
          <p class="text-xs text-indigo-300 mt-1">Active Perimeter Filters</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="dha-subtab px-4 py-2 text-sm font-semibold border-b-2 border-indigo-500 text-indigo-400" data-tab="reports">
          🛡️ Device Health Attestation Ledger
        </button>
        <button class="dha-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="policies">
          📋 Attestation &amp; Measured Boot Policies
        </button>
        <button class="dha-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="microsegmentation">
          🌐 Zero-Trust Microsegmentation Rules
        </button>
      </div>

      <!-- Tab Content 1: Device Reports -->
      <div id="subtab-content-reports" class="dha-tab-panel space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🛡️</span> Workstation Hardware Health &amp; Measured Boot Posture
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Cryptographic verification of TPM 2.0 PCR registers, Secure Boot, BitLocker, VBS, and HVCI</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Workstation</th>
                <th class="px-4 py-3">Attestation Status</th>
                <th class="px-4 py-3">Hardware Protections</th>
                <th class="px-4 py-3">VBS / HVCI Posture</th>
                <th class="px-4 py-3">Verified At</th>
                <th class="px-4 py-3 text-right">Firewall Rules</th>
              </tr>
            </thead>
            <tbody id="dha-reports-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading attestation reports...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Content 2: Policies -->
      <div id="subtab-content-policies" class="dha-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>📋</span> Hardware Root-of-Trust Baseline Standards
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Configured baseline rules enforcing Secure Boot, BitLocker, VBS, HVCI, ELAM drivers, and golden PCR measurements</p>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" id="dha-policies-grid">
          <div class="col-span-full p-8 text-center text-slate-400">Loading baseline policies...</div>
        </div>
      </div>

      <!-- Tab Content 3: Microsegmentation -->
      <div id="subtab-content-microsegmentation" class="dha-tab-panel hidden space-y-4">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 bg-slate-800/40 p-4 rounded-xl border border-slate-700/50">
          <div>
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🌐</span> Software-Defined Perimeter &amp; ZTNA Access Rules
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Dynamically permit or quarantine network access based on device health attestation compliance</p>
          </div>
        </div>

        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <table class="w-full text-left text-xs text-slate-300">
            <thead class="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-700/50">
              <tr>
                <th class="px-4 py-3">Rule Name</th>
                <th class="px-4 py-3">Target Subnet / Destination</th>
                <th class="px-4 py-3">Ports &amp; Protocol</th>
                <th class="px-4 py-3">Zero-Trust Action</th>
                <th class="px-4 py-3">Mode</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="dha-msp-tbody" class="divide-y divide-slate-700/30 font-medium">
              <tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">Loading microsegmentation rules...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Modal: View WFP Firewall Rules -->
    <div id="modal-dha-wfp" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-2xl shadow-2xl space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="p-2 bg-indigo-500/20 text-indigo-400 rounded-lg text-xl border border-indigo-500/30">💻</span>
            <div>
              <h3 class="font-bold text-white text-base" id="modal-wfp-title">Synthesized WFP Microsegmentation Script</h3>
              <p class="text-xs text-slate-400" id="modal-wfp-subtitle">Endpoint Zero-Trust Network Rules</p>
            </div>
          </div>
          <button id="modal-wfp-close" class="text-slate-400 hover:text-white text-xl">&times;</button>
        </div>
        <div class="bg-slate-900 rounded-lg p-4 font-mono text-xs text-cyan-300 border border-slate-800 overflow-x-auto max-h-80 whitespace-pre" id="modal-wfp-code">
          Loading script...
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button id="modal-wfp-copy" class="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md">
            <span>📋</span> Copy PowerShell Script
          </button>
        </div>
      </div>
    </div>
  `;
}

async function initDeviceHealthAttestationBlade(api) {
  // Tab switching
  document.querySelectorAll('.dha-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.dha-subtab').forEach(b => {
        b.classList.remove('border-indigo-500', 'text-indigo-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.remove('border-transparent', 'text-slate-400');
      btn.classList.add('border-indigo-500', 'text-indigo-400');

      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.dha-tab-panel').forEach(panel => panel.classList.add('hidden'));
      const activePanel = document.getElementById(`subtab-content-${targetTab}`);
      if (activePanel) activePanel.classList.remove('hidden');
    });
  });

  const wfpModal = document.getElementById('modal-dha-wfp');
  document.getElementById('modal-wfp-close')?.addEventListener('click', () => wfpModal.classList.add('hidden'));
  document.getElementById('btn-dha-refresh')?.addEventListener('click', () => loadAllDhaData(api));

  document.getElementById('modal-wfp-copy')?.addEventListener('click', () => {
    const code = document.getElementById('modal-wfp-code').textContent;
    navigator.clipboard.writeText(code).then(() => {
      if (window.showToast) window.showToast('PowerShell WFP script copied to clipboard', 'info');
    });
  });

  await loadAllDhaData(api);

  async function loadAllDhaData(api) {
    try {
      // 1. Stats
      const stats = await api.get('/api/v1/fleet/dha/stats');
      if (stats) {
        document.getElementById('kpi-dha-compliance').textContent = `${stats.complianceRatePercent}%`;
        document.getElementById('kpi-dha-vbs').textContent = stats.vbsHvciActiveReports || 0;
        document.getElementById('kpi-dha-tamper').textContent = stats.tamperedReports || 0;
        document.getElementById('kpi-dha-rules').textContent = stats.activeMicrosegmentationRules || 0;
      }

      // 2. Reports
      const repRes = await api.get('/api/v1/fleet/dha/reports');
      const reports = (repRes && repRes.reports) ? repRes.reports : [];
      const repTbody = document.getElementById('dha-reports-tbody');
      if (repTbody) {
        if (reports.length === 0) {
          repTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No attestation reports collected yet.</td></tr>';
        } else {
          repTbody.innerHTML = reports.map(r => {
            const isCompliant = r.attestation_status === 'COMPLIANT';
            const isTampered = r.attestation_status === 'TAMPERED' || r.bootkit_detected;
            return `
              <tr class="hover:bg-slate-800/40 transition">
                <td class="px-4 py-3">
                  <div class="font-bold text-white flex items-center gap-1.5">
                    <span>💻</span> ${escapeHtml(r.hostname)}
                  </div>
                  <div class="text-[11px] text-slate-500 font-mono">${escapeHtml(r.device_id.substring(0, 8))}...</div>
                </td>
                <td class="px-4 py-3">
                  ${isTampered 
                    ? `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center gap-1 w-max">
                        <span class="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse"></span> TAMPERED
                       </span>`
                    : (isCompliant
                        ? `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1 w-max">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> COMPLIANT
                           </span>`
                        : `<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1 w-max">
                            <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> FAILED
                           </span>`
                      )
                  }
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-1.5">
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${r.secure_boot_enabled ? 'bg-emerald-900/40 text-emerald-300' : 'bg-rose-900/40 text-rose-300'}">
                      SecureBoot: ${r.secure_boot_enabled ? 'ON' : 'OFF'}
                    </span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-700 text-slate-300">
                      BitLocker: ${escapeHtml(r.bitlocker_status)}
                    </span>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <div class="text-[11px] text-slate-300">VBS: <span class="font-mono text-cyan-300">${escapeHtml(r.vbs_status)}</span></div>
                  <div class="text-[10px] text-slate-500">HVCI: ${escapeHtml(r.hvci_status)}</div>
                </td>
                <td class="px-4 py-3 text-slate-400 text-[11px]">
                  ${r.verified_at ? new Date(r.verified_at).toLocaleTimeString() : '—'}
                </td>
                <td class="px-4 py-3 text-right">
                  <button class="btn-view-wfp px-2.5 py-1 bg-indigo-700/80 hover:bg-indigo-600 text-indigo-100 rounded text-xs font-semibold transition"
                    data-id="${r.device_id}" data-hostname="${escapeHtml(r.hostname)}">
                    🛡️ View WFP Rules
                  </button>
                </td>
              </tr>
            `;
          }).join('');

          repTbody.querySelectorAll('.btn-view-wfp').forEach(btn => {
            btn.addEventListener('click', async () => {
              const dId = btn.getAttribute('data-id');
              const host = btn.getAttribute('data-hostname');
              try {
                const fw = await api.get(`/api/v1/fleet/devices/${dId}/dha/firewall-rules`);
                document.getElementById('modal-wfp-title').textContent = `WFP Microsegmentation: ${host}`;
                document.getElementById('modal-wfp-subtitle').textContent = `DHA Status: ${fw.is_dha_compliant ? 'COMPLIANT (Full Zero-Trust Access)' : 'NON-COMPLIANT (Quarantine Block Enforced)'}`;
                document.getElementById('modal-wfp-code').textContent = fw.powershell_script || 'No rules generated';
                wfpModal.classList.remove('hidden');
              } catch(e) {
                alert('Failed to load firewall rules: ' + e.message);
              }
            });
          });
        }
      }

      // 3. Policies
      const polRes = await api.get('/api/v1/fleet/dha/policies');
      const policies = (polRes && polRes.policies) ? polRes.policies : [];
      const polGrid = document.getElementById('dha-policies-grid');
      if (polGrid) {
        if (policies.length === 0) {
          polGrid.innerHTML = '<div class="col-span-full p-8 text-center text-slate-400">No DHA policies configured.</div>';
        } else {
          polGrid.innerHTML = policies.map(p => `
            <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow flex flex-col justify-between space-y-3">
              <div>
                <div class="flex justify-between items-start mb-2">
                  <h4 class="font-bold text-white text-sm flex items-center gap-1.5">
                    <span>📋</span> ${escapeHtml(p.name)}
                  </h4>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.is_enabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-700 text-slate-400'}">
                    ${p.is_enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
                <p class="text-xs text-slate-400 mb-3">${escapeHtml(p.description || 'No description provided')}</p>
                
                <div class="text-[10px] text-slate-500 font-semibold uppercase mb-1">Hardware Constraints:</div>
                <div class="grid grid-cols-2 gap-1 text-[11px] text-slate-300">
                  <div>SecureBoot: ${p.require_secure_boot ? '✅' : '❌'}</div>
                  <div>BitLocker: ${p.require_bitlocker ? '✅' : '❌'}</div>
                  <div>VBS Mode: ${p.require_virtualization_based_security ? '✅' : '❌'}</div>
                  <div>HVCI Guard: ${p.require_hypervisor_enforced_code_integrity ? '✅' : '❌'}</div>
                </div>
              </div>

              <div class="pt-3 border-t border-slate-700/40 text-[10px] text-slate-500 flex justify-between items-center">
                <span>Scope: ${escapeHtml(p.target_scope)}</span>
                <span class="font-mono text-cyan-400">TPM 2.0 PCR</span>
              </div>
            </div>
          `).join('');
        }
      }

      // 4. Microsegmentation Rules
      const mspRes = await api.get('/api/v1/fleet/dha/microsegmentation');
      const rules = (mspRes && mspRes.policies) ? mspRes.policies : [];
      const mspTbody = document.getElementById('dha-msp-tbody');
      if (mspTbody) {
        if (rules.length === 0) {
          mspTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400">No microsegmentation rules found.</td></tr>';
        } else {
          mspTbody.innerHTML = rules.map(rule => `
            <tr class="hover:bg-slate-800/40 transition">
              <td class="px-4 py-3">
                <div class="font-bold text-white flex items-center gap-1.5">
                  <span>🌐</span> ${escapeHtml(rule.name)}
                </div>
                <div class="text-[10px] text-slate-500">${escapeHtml(rule.description || '')}</div>
              </td>
              <td class="px-4 py-3 font-mono text-slate-300">${escapeHtml(rule.destination_cidr)}</td>
              <td class="px-4 py-3">
                <span class="font-mono text-cyan-300">${rule.allowed_ports.join(', ')}</span> 
                <span class="text-slate-500">(${escapeHtml(rule.protocol)})</span>
              </td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${rule.action === 'REQUIRE_DHA_COMPLIANCE' ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30' : 'bg-slate-700 text-slate-300'}">
                  ${escapeHtml(rule.action)}
                </span>
              </td>
              <td class="px-4 py-3">
                <span class="text-slate-400">${escapeHtml(rule.enforcement_mode)}</span>
              </td>
              <td class="px-4 py-3 text-right">
                <button class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs font-medium transition" onclick="alert('Rule ID: ' + '${rule.id}')">
                  Details
                </button>
              </td>
            </tr>
          `).join('');
        }
      }

    } catch (err) {
      console.error('Failed loading DHA blade data:', err);
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

window.DeviceHealthAttestationTable = {
  render: async function() {
    const container = document.getElementById('tab-dha');
    if (!container) return;
    container.innerHTML = renderDeviceHealthAttestationBlade();
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
    await initDeviceHealthAttestationBlade(client);
  }
};
