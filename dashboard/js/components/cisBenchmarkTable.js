/**
 * LocalPilot Fleet — Endpoint Configuration Drift & CIS Benchmark Compliance Blade
 * dashboard/js/components/cisBenchmarkTable.js
 *
 * Provides real-time Center for Internet Security (CIS) Level 1 & Level 2 benchmark auditing,
 * registry & GPO configuration drift monitoring, and 1-click surgical remediation scripts.
 */

function renderCisBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-cyan-500/20 text-cyan-400 rounded-lg text-2xl border border-cyan-500/30">📐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                CIS Benchmark Hardening &amp; Drift Governance
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">CIS Level 1 &amp; 2</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Continuous registry &amp; policy drift detection, compliance scoring (0–100%), and 1-click remediation scripts</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-cis-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-cis-new-rule" class="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-cyan-500/20">
            <span>➕</span> Add Rule
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="cis-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Benchmark Rules</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">📐</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-cis-rules">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mean Compliance</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🎯</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-cis-score">-%</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Drifted Endpoints</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-cis-drifted">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediation Scripts</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-cis-remediations">-</p>
        </div>
      </div>

      <!-- Section 1: CIS Hardening Benchmark Rules -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">CIS Hardening Benchmark Catalog</h3>
            <p class="text-xs text-slate-400 mt-0.5">Windows 11 &amp; Server 2025 security baseline rules and registry targets</p>
          </div>
          <div class="flex items-center gap-3">
            <select id="cis-profile-filter" class="px-2.5 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500">
              <option value="">All Profiles</option>
              <option value="LEVEL_1">Level 1 (Corporate Baseline)</option>
              <option value="LEVEL_2">Level 2 (High Security)</option>
              <option value="BITLOCKER_ADDON">BitLocker Addon</option>
            </select>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Section</th>
                <th class="px-4 py-3">Benchmark Title</th>
                <th class="px-4 py-3">Profile</th>
                <th class="px-4 py-3">Check Type</th>
                <th class="px-4 py-3">Target Path / Key</th>
                <th class="px-4 py-3">Expected</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="cis-rules-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">Loading benchmark rules...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Endpoint Compliance Audits -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Endpoint Compliance Scorecards</h3>
            <p class="text-xs text-slate-400 mt-0.5">Continuous evaluation results and configuration drift detection status</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="cis-audits-count">0 Audits</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Hostname</th>
                <th class="px-4 py-3">Benchmark Profile</th>
                <th class="px-4 py-3">Evaluated</th>
                <th class="px-4 py-3">Passed</th>
                <th class="px-4 py-3">Failed</th>
                <th class="px-4 py-3">Compliance Score</th>
                <th class="px-4 py-3">Drift Status</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="cis-audits-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-sans">Loading compliance audits...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Author Benchmark Rule Modal -->
      <div id="modal-cis-rule" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>📐</span> Author CIS Benchmark Rule
            </h3>
            <button id="modal-cis-rule-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Section ID</label>
                <input id="input-cis-rule-section" type="text" placeholder="18.9.4.2" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Profile Level</label>
                <select id="input-cis-rule-level" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="LEVEL_1">Level 1 (Corporate Baseline)</option>
                  <option value="LEVEL_2">Level 2 (High Security)</option>
                  <option value="BITLOCKER_ADDON">BitLocker Addon</option>
                </select>
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Benchmark Title</label>
              <input id="input-cis-rule-title" type="text" placeholder="Ensure Windows Defender Credential Guard is enabled" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Check Type</label>
                <select id="input-cis-rule-type" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono">
                  <option value="REGISTRY_VALUE">REGISTRY_VALUE</option>
                  <option value="AUDIT_POLICY">AUDIT_POLICY</option>
                  <option value="SECURITY_OPTION">SECURITY_OPTION</option>
                  <option value="POWERSHELL_QUERY">POWERSHELL_QUERY</option>
                </select>
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Expected Value</label>
                <input id="input-cis-rule-expected" type="text" placeholder="1" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Target Registry / GPO Path</label>
              <input id="input-cis-rule-path" type="text" placeholder="HKLM:\\Software\\Policies\\Microsoft\\Windows\\DeviceGuard" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Target Key / Property</label>
              <input id="input-cis-rule-key" type="text" placeholder="EnableVirtualizationBasedSecurity" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-cis-rule-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-cis-rule-submit" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold">Save Rule</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function initCisBlade() {
  const getFleetKey = () => localStorage.getItem('fleetKey') || '';

  async function loadCisStats() {
    try {
      const res = await fetch('/api/v1/fleet/cis/stats', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        const rulesEl = document.getElementById('kpi-cis-rules');
        const scoreEl = document.getElementById('kpi-cis-score');
        const driftedEl = document.getElementById('kpi-cis-drifted');
        const remediationsEl = document.getElementById('kpi-cis-remediations');
        if (rulesEl) rulesEl.textContent = data.stats.totalRules ?? 0;
        if (scoreEl) scoreEl.textContent = (data.stats.meanComplianceScore ?? 0) + '%';
        if (driftedEl) driftedEl.textContent = data.stats.driftedEndpointsCount ?? 0;
        if (remediationsEl) remediationsEl.textContent = data.stats.totalRemediationsAvailable ?? 0;
      }
    } catch (e) {
      console.error('Failed to load CIS stats:', e);
    }
  }

  async function loadRules() {
    try {
      const profile = document.getElementById('cis-profile-filter')?.value || '';
      const query = new URLSearchParams();
      if (profile) query.set('profile_level', profile);

      const res = await fetch(`/api/v1/fleet/cis/rules?${query.toString()}`, {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('cis-rules-tbody');
      if (!tbody) return;

      const rules = data.rules || [];
      if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No CIS benchmark rules found.</td></tr>';
        return;
      }

      tbody.innerHTML = rules.map(r => {
        const levelBadge = r.profile_level === 'LEVEL_1' ?
          '<span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-sans">Level 1</span>' :
          '<span class="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-sans">Level 2</span>';

        const remBtn = r.remediation ?
          `<button onclick="window.cisViewRemediation('${r.id}')" class="px-2.5 py-1 bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 rounded text-xs border border-cyan-500/30 transition font-sans">Remediate</button>` :
          '<span class="text-slate-500 font-sans">Manual</span>';

        const targetDisplay = r.target_key ? `${r.target_path}\\${r.target_key}` : r.target_path;

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-bold text-cyan-400">${r.section_id}</td>
            <td class="px-4 py-3 text-white font-sans max-w-sm truncate" title="${r.title}">${r.title}</td>
            <td class="px-4 py-3">${levelBadge}</td>
            <td class="px-4 py-3 text-slate-400">${r.check_type}</td>
            <td class="px-4 py-3 text-slate-300 max-w-xs truncate" title="${targetDisplay}">${targetDisplay}</td>
            <td class="px-4 py-3 text-emerald-400 font-bold">${r.expected_value}</td>
            <td class="px-4 py-3 text-right">${remBtn}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load rules:', e);
    }
  }

  async function loadAudits() {
    try {
      const res = await fetch('/api/v1/fleet/cis/audits', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('cis-audits-tbody');
      const countEl = document.getElementById('cis-audits-count');
      if (!tbody) return;

      const audits = data.audits || [];
      if (countEl) countEl.textContent = `${audits.length} Audits`;

      if (audits.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-sans">No compliance audits recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = audits.map(a => {
        const driftBadge = a.drift_detected === 1 ?
          '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold animate-pulse font-sans">DRIFT DETECTED</span>' :
          '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-sans">COMPLIANT</span>';

        const scoreColor = a.compliance_score_percent >= 90 ? 'text-emerald-400' :
                           a.compliance_score_percent >= 70 ? 'text-amber-400' :
                           'text-rose-400';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white font-sans">${a.hostname}</td>
            <td class="px-4 py-3 text-slate-300 font-sans">${a.benchmark_name}</td>
            <td class="px-4 py-3 text-slate-400">${a.total_rules_evaluated}</td>
            <td class="px-4 py-3 text-emerald-400 font-bold">${a.passed_rules_count}</td>
            <td class="px-4 py-3 text-rose-400 font-bold">${a.failed_rules_count}</td>
            <td class="px-4 py-3 font-bold ${scoreColor}">${a.compliance_score_percent.toFixed(1)}%</td>
            <td class="px-4 py-3">${driftBadge}</td>
            <td class="px-4 py-3 text-right font-sans">
              <button onclick="window.cisEvaluateDevice('${a.device_id}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs border border-slate-600 transition">Re-Audit</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load audits:', e);
    }
  }

  // Global window helpers
  window.cisViewRemediation = async (ruleId) => {
    try {
      const res = await fetch(`/api/v1/fleet/cis/remediations/${ruleId}`, {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (res.ok) {
        const data = await res.json();
        alert('Remediation Script (' + data.remediation.script_type + '):\n\n' + data.remediation.remediation_code);
      } else {
        alert('No remediation script found for this rule.');
      }
    } catch (e) {
      console.error(e);
    }
  };

  window.cisEvaluateDevice = async (deviceId) => {
    try {
      const res = await fetch(`/api/v1/fleet/cis/evaluate/${deviceId}`, {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' }
      });
      if (res.ok) {
        loadAudits();
        loadCisStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Event handlers
  document.getElementById('btn-cis-refresh')?.addEventListener('click', () => {
    loadCisStats();
    loadRules();
    loadAudits();
  });

  document.getElementById('cis-profile-filter')?.addEventListener('change', () => loadRules());

  // Modal: Author Rule
  document.getElementById('btn-cis-new-rule')?.addEventListener('click', () => {
    document.getElementById('modal-cis-rule').classList.remove('hidden');
  });
  document.getElementById('modal-cis-rule-close')?.addEventListener('click', () => {
    document.getElementById('modal-cis-rule').classList.add('hidden');
  });
  document.getElementById('modal-cis-rule-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-cis-rule').classList.add('hidden');
  });
  document.getElementById('modal-cis-rule-submit')?.addEventListener('click', async () => {
    const section_id = document.getElementById('input-cis-rule-section').value.trim();
    const profile_level = document.getElementById('input-cis-rule-level').value;
    const title = document.getElementById('input-cis-rule-title').value.trim();
    const check_type = document.getElementById('input-cis-rule-type').value;
    const expected_value = document.getElementById('input-cis-rule-expected').value.trim();
    const target_path = document.getElementById('input-cis-rule-path').value.trim();
    const target_key = document.getElementById('input-cis-rule-key').value.trim();

    if (!section_id || !title || !target_path || !expected_value) {
      alert('Section ID, Title, Target Path, and Expected Value are required');
      return;
    }

    try {
      const res = await fetch('/api/v1/fleet/cis/rules', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ section_id, profile_level, title, check_type, expected_value, target_path, target_key })
      });
      if (res.ok) {
        document.getElementById('modal-cis-rule').classList.add('hidden');
        loadRules();
        loadCisStats();
      } else {
        const err = await res.json();
        alert(err.message || 'Failed to save rule');
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadCisStats();
  loadRules();
  loadAudits();
}

window.renderCisBlade = renderCisBlade;
window.initCisBlade = initCisBlade;

window.CisBenchmarkTable = {
  async render() {
    const container = document.getElementById('tab-cis');
    if (!container) return;
    container.innerHTML = renderCisBlade();
    initCisBlade();
  }
};
