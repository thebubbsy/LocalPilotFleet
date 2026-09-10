/**
 * LocalPilot Fleet — Data Loss Prevention (DLP) Dashboard Blade
 * dashboard/js/components/dlpTable.js
 *
 * Provides real-time sensitive data discovery (PCI, PII, Secrets, HIPAA),
 * exfiltration guardrail monitoring (USB, Clipboard, Network shares),
 * and live text content inspection.
 */

function renderDlpBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-2xl border border-emerald-500/30">🔐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Data Loss Prevention &amp; Exfiltration Guardrails (DLP)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Microsoft Purview Parity</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated sensitive data classification, unencrypted disk exposures, and real-time USB/clipboard interception</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-dlp-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-dlp-new-rule" class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-emerald-500/20">
            <span>➕</span> New Rule
          </button>
          <button id="btn-dlp-test-scanner" class="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-blue-500/20">
            <span>🔍</span> Test Scanner
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="dlp-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Rules</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-dlp-rules">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Unencrypted Exposures</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-dlp-exposures">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Exposed Endpoints</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">💻</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-dlp-devices">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Blocked Exfiltrations</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">⛔</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-dlp-blocked">-</p>
        </div>
      </div>

      <!-- Section 1: Sensitive Data Classification Rules -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Data Classification Rules</h3>
            <p class="text-xs text-slate-400 mt-0.5">High-speed regex classifiers for PCI, PII, Cloud Secrets, and Private Keys</p>
          </div>
          <div class="flex items-center gap-3">
            <select id="dlp-category-filter" class="px-2.5 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500">
              <option value="">All Categories</option>
              <option value="FINANCIAL_PCI">Financial (PCI-DSS)</option>
              <option value="PERSONAL_PII">Personal PII (SSN)</option>
              <option value="SECRETS_CREDENTIALS">Secrets &amp; Credentials</option>
              <option value="HEALTH_HIPAA">Health &amp; Medical (HIPAA)</option>
              <option value="CUSTOM_REGEX">Custom Patterns</option>
            </select>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Rule Name</th>
                <th class="px-4 py-3">Category</th>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Pattern Regex</th>
                <th class="px-4 py-3">Confidence</th>
                <th class="px-4 py-3">Enforcement</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="dlp-rules-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">Loading classification rules...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Endpoint Sensitive File Exposures -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Endpoint File Exposures</h3>
            <p class="text-xs text-slate-400 mt-0.5">Unencrypted sensitive documents and keys discovered on endpoint storage</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="dlp-findings-count">0 Exposures</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Hostname</th>
                <th class="px-4 py-3">File Path</th>
                <th class="px-4 py-3">Matched Rule</th>
                <th class="px-4 py-3">Matches</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="dlp-findings-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">Loading endpoint file exposures...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 3: Exfiltration Interception Stream -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Exfiltration Interception Stream</h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time blocked and audited leaks via USB storage, clipboard copying, and web uploads</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="dlp-incidents-count">0 Incidents</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Channel</th>
                <th class="px-4 py-3">Hostname</th>
                <th class="px-4 py-3">User</th>
                <th class="px-4 py-3">File / Target</th>
                <th class="px-4 py-3">Violated Rule</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody id="dlp-incidents-tbody" class="divide-y divide-slate-700/40 text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-mono">Loading exfiltration stream...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Author Classification Rule Modal -->
      <div id="modal-dlp-rule" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🔐</span> Author DLP Classification Rule
            </h3>
            <button id="modal-dlp-rule-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Rule Name</label>
              <input id="input-dlp-rule-name" type="text" placeholder="Custom API Key Pattern" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Category</label>
                <select id="input-dlp-rule-category" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="FINANCIAL_PCI">Financial (PCI-DSS)</option>
                  <option value="PERSONAL_PII">Personal PII</option>
                  <option value="SECRETS_CREDENTIALS" selected>Secrets &amp; Credentials</option>
                  <option value="HEALTH_HIPAA">Health &amp; Medical (HIPAA)</option>
                  <option value="CUSTOM_REGEX">Custom Regex</option>
                </select>
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Severity</label>
                <select id="input-dlp-rule-severity" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH" selected>High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Regular Expression Pattern</label>
              <input id="input-dlp-rule-regex" type="text" placeholder="api_key_[a-zA-Z0-9]{32}" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Confidence Threshold (%)</label>
                <input id="input-dlp-rule-confidence" type="number" step="1" min="1" max="100" value="90" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Enforcement Action</label>
                <select id="input-dlp-rule-action" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="BLOCK" selected>Block Exfiltration</option>
                  <option value="AUDIT_ONLY">Audit Only</option>
                  <option value="ENCRYPT">Force Encryption</option>
                  <option value="QUARANTINE_FILE">Quarantine File</option>
                </select>
              </div>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-dlp-rule-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-dlp-rule-submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold">Save Rule</button>
          </div>
        </div>
      </div>

      <!-- Test Scanner Modal -->
      <div id="modal-dlp-scanner" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🔍</span> DLP Text Payload Scanner
            </h3>
            <button id="modal-dlp-scanner-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Paste Sample Text / Document Stream</label>
              <textarea id="input-dlp-test-text" rows="5" placeholder="Paste test content containing credit cards, SSNs, or keys to test regex matching..." class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono"></textarea>
            </div>
            <div id="dlp-scan-results" class="hidden p-3 bg-slate-900/90 rounded-lg border border-slate-700 space-y-2">
              <p class="font-bold text-slate-300">Scan Results:</p>
              <div id="dlp-scan-hits" class="space-y-1"></div>
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-dlp-scanner-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Close</button>
            <button id="modal-dlp-scanner-run" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold">Run Scan</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function initDlpBlade() {
  const getFleetKey = () => localStorage.getItem('fleetKey') || '';

  async function loadDlpStats() {
    try {
      const res = await fetch('/api/v1/fleet/dlp/stats', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        document.getElementById('kpi-dlp-rules').textContent = data.stats.activeRules ?? 0;
        document.getElementById('kpi-dlp-exposures').textContent = data.stats.unencryptedExposures ?? 0;
        document.getElementById('kpi-dlp-devices').textContent = data.stats.exposedDevices ?? 0;
        document.getElementById('kpi-dlp-blocked').textContent = data.stats.blockedExfiltrations ?? 0;
      }
    } catch (e) {
      console.error('Failed to load DLP stats:', e);
    }
  }

  async function loadRules() {
    try {
      const category = document.getElementById('dlp-category-filter')?.value || '';
      const query = new URLSearchParams();
      if (category) query.set('category', category);

      const res = await fetch(`/api/v1/fleet/dlp/rules?${query.toString()}`, {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('dlp-rules-tbody');
      if (!tbody) return;

      const rules = data.rules || [];
      if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No classification rules configured.</td></tr>';
        return;
      }

      tbody.innerHTML = rules.map(r => {
        const sevColor = r.severity === 'CRITICAL' ? 'bg-purple-500/20 text-purple-300 border-purple-500/30' :
                         r.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
                         'bg-amber-500/20 text-amber-300 border-amber-500/30';

        const actionColor = r.enforcement_action === 'BLOCK' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30 font-bold' :
                            r.enforcement_action === 'ENCRYPT' ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' :
                            'bg-slate-700/50 text-slate-300';

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white font-sans">${r.rule_name}</td>
            <td class="px-4 py-3 text-emerald-400 font-mono">${r.category}</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-xs border font-sans ${sevColor}">${r.severity}</span></td>
            <td class="px-4 py-3 text-slate-400 max-w-xs truncate" title="${r.pattern_regex}">${r.pattern_regex}</td>
            <td class="px-4 py-3 text-slate-300">${r.confidence_threshold.toFixed(0)}%</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-xs border ${actionColor}">${r.enforcement_action}</span></td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.dlpDeleteRule('${r.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-600/50 text-slate-400 hover:text-rose-200 rounded text-xs transition">Delete</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load rules:', e);
    }
  }

  async function loadFindings() {
    try {
      const res = await fetch('/api/v1/fleet/dlp/findings', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('dlp-findings-tbody');
      const countEl = document.getElementById('dlp-findings-count');
      if (!tbody) return;

      const findings = data.findings || [];
      if (countEl) countEl.textContent = `${findings.length} Exposures`;

      if (findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No unencrypted file exposures detected.</td></tr>';
        return;
      }

      tbody.innerHTML = findings.map(f => {
        const statusBadge = f.remediation_status === 'SECURED_ENCRYPTED' ?
          `<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ENCRYPTED</span>` :
          `<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">UNENCRYPTED EXPOSURE</span>`;

        const actionBtn = f.remediation_status !== 'SECURED_ENCRYPTED' ?
          `<button onclick="window.dlpSecureFinding('${f.id}')" class="px-2.5 py-1 bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 rounded text-xs border border-emerald-500/30 transition">Encrypt</button>` :
          `<span class="text-slate-500 text-xs font-sans">Secured</span>`;

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-white font-sans">${f.hostname}</td>
            <td class="px-4 py-3 text-slate-300 max-w-sm truncate" title="${f.file_path}">${f.file_path}</td>
            <td class="px-4 py-3 text-emerald-400 font-sans">${f.rule_name}</td>
            <td class="px-4 py-3 text-slate-300">${f.match_count}</td>
            <td class="px-4 py-3 font-sans">${statusBadge}</td>
            <td class="px-4 py-3 text-right font-sans">${actionBtn}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load findings:', e);
    }
  }

  async function loadIncidents() {
    try {
      const res = await fetch('/api/v1/fleet/dlp/incidents', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('dlp-incidents-tbody');
      const countEl = document.getElementById('dlp-incidents-count');
      if (!tbody) return;

      const incidents = data.incidents || [];
      if (countEl) countEl.textContent = `${incidents.length} Incidents`;

      if (incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No exfiltration incidents intercepted.</td></tr>';
        return;
      }

      tbody.innerHTML = incidents.map(i => {
        const channelBadge = i.channel === 'REMOVABLE_USB' ?
          `<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">💾 USB TRANSFER</span>` :
          i.channel === 'CLIPBOARD_PASTE' ?
          `<span class="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-mono">📋 CLIPBOARD</span>` :
          `<span class="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">${i.channel}</span>`;

        const actionBadge = i.action_taken === 'BLOCKED' ?
          `<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold">BLOCKED</span>` :
          `<span class="px-2 py-0.5 rounded-full bg-slate-700 text-slate-300 font-mono">${i.action_taken}</span>`;

        return `
          <tr class="hover:bg-slate-700/30 transition font-sans">
            <td class="px-4 py-3">${channelBadge}</td>
            <td class="px-4 py-3 font-semibold text-white font-mono">${i.hostname}</td>
            <td class="px-4 py-3 text-slate-300 font-mono">${i.user_account}</td>
            <td class="px-4 py-3 text-slate-400 font-mono max-w-xs truncate" title="${i.file_or_data_name}">${i.file_or_data_name}</td>
            <td class="px-4 py-3 text-emerald-400">${i.rule_name}</td>
            <td class="px-4 py-3 font-mono">${actionBadge}</td>
            <td class="px-4 py-3 text-slate-400 text-xs font-mono">${i.intercepted_at}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load incidents:', e);
    }
  }

  // Global window helpers
  window.dlpDeleteRule = async (id) => {
    if (!confirm('Are you sure you want to delete this DLP classification rule?')) return;
    try {
      const res = await fetch(`/api/v1/fleet/dlp/rules/${id}`, {
        method: 'DELETE',
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (res.ok) {
        loadRules();
        loadDlpStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  window.dlpSecureFinding = async (id) => {
    try {
      const res = await fetch(`/api/v1/fleet/dlp/findings/${id}`, {
        method: 'PUT',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'SECURED_ENCRYPTED' })
      });
      if (res.ok) {
        loadFindings();
        loadDlpStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Event handlers
  document.getElementById('btn-dlp-refresh')?.addEventListener('click', () => {
    loadDlpStats();
    loadRules();
    loadFindings();
    loadIncidents();
  });

  document.getElementById('dlp-category-filter')?.addEventListener('change', () => loadRules());

  // Modal: Author Rule
  document.getElementById('btn-dlp-new-rule')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-rule').classList.remove('hidden');
  });
  document.getElementById('modal-dlp-rule-close')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-rule').classList.add('hidden');
  });
  document.getElementById('modal-dlp-rule-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-rule').classList.add('hidden');
  });
  document.getElementById('modal-dlp-rule-submit')?.addEventListener('click', async () => {
    const rule_name = document.getElementById('input-dlp-rule-name').value.trim();
    const category = document.getElementById('input-dlp-rule-category').value;
    const severity = document.getElementById('input-dlp-rule-severity').value;
    const pattern_regex = document.getElementById('input-dlp-rule-regex').value.trim();
    const confidence_threshold = parseFloat(document.getElementById('input-dlp-rule-confidence').value) || 90;
    const enforcement_action = document.getElementById('input-dlp-rule-action').value;

    if (!rule_name || !pattern_regex) {
      alert('Rule Name and Pattern Regex are required');
      return;
    }

    try {
      const res = await fetch('/api/v1/fleet/dlp/rules', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_name, category, severity, pattern_regex, confidence_threshold, enforcement_action })
      });
      if (res.ok) {
        document.getElementById('modal-dlp-rule').classList.add('hidden');
        loadRules();
        loadDlpStats();
      } else {
        const err = await res.json();
        alert(err.message || 'Failed to create rule');
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Modal: Test Scanner
  document.getElementById('btn-dlp-test-scanner')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-scanner').classList.remove('hidden');
  });
  document.getElementById('modal-dlp-scanner-close')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-scanner').classList.add('hidden');
  });
  document.getElementById('modal-dlp-scanner-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-dlp-scanner').classList.add('hidden');
  });
  document.getElementById('modal-dlp-scanner-run')?.addEventListener('click', async () => {
    const text = document.getElementById('input-dlp-test-text').value;
    if (!text) return;

    try {
      const res = await fetch('/api/v1/fleet/dlp/scan-text', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      if (res.ok) {
        const data = await res.json();
        const resBox = document.getElementById('dlp-scan-results');
        const hitsBox = document.getElementById('dlp-scan-hits');
        resBox.classList.remove('hidden');
        if (data.matches && data.matches.length > 0) {
          hitsBox.innerHTML = data.matches.map(m => `
            <div class="p-2 bg-slate-800 rounded border border-rose-500/30 flex justify-between items-center text-xs">
              <div>
                <p class="font-bold text-rose-300">${m.rule_name} (${m.category})</p>
                <p class="text-slate-400">Hits: ${m.match_count} | Sample: ${m.sample_preview}</p>
              </div>
              <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">${m.enforcement_action}</span>
            </div>
          `).join('');
        } else {
          hitsBox.innerHTML = '<p class="text-emerald-400 text-xs">✅ Clean: No sensitive data patterns matched.</p>';
        }
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadDlpStats();
  loadRules();
  loadFindings();
  loadIncidents();
}

window.renderDlpBlade = renderDlpBlade;
window.initDlpBlade = initDlpBlade;

window.DlpTable = {
  async render() {
    const container = document.getElementById('tab-dlp');
    if (!container) return;
    container.innerHTML = renderDlpBlade();
    initDlpBlade();
  }
};
