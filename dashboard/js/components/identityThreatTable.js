/**
 * LocalPilot Fleet — Identity Threat Detection & Response (ITDR) Dashboard Blade
 * dashboard/js/components/identityThreatTable.js
 *
 * Provides real-time Active Directory & Entra ID credential defense,
 * Kerberoasting / DCSync / LSASS dump detection, honeytoken deception,
 * and automated account containment.
 */

function renderIdentityThreatBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-indigo-500/20 text-indigo-400 rounded-lg text-2xl border border-indigo-500/30">👤</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Identity Threat Detection &amp; Response (ITDR)
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">Defender Identity Parity</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Kerberoasting &amp; DCSync defense, LSASS scraping detection, honeytoken deception, and account containment</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-itdr-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-itdr-new-honeytoken" class="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-indigo-500/20">
            <span>🍯</span> Deploy Honeytoken
          </button>
          <button id="btn-itdr-contain" class="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-rose-500/20">
            <span>🔒</span> Contain Account
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="itdr-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Attacks</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-itdr-active">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Risk</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🔥</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-itdr-critical">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Deception Traps</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🍯</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-itdr-honeytokens">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Contained Accounts</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-itdr-contained">-</p>
        </div>
      </div>

      <!-- Section 1: Live Identity Threat Detections -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex flex-wrap items-center justify-between gap-3 bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Live Identity Threat Detections</h3>
            <p class="text-xs text-slate-400 mt-0.5">Real-time alerts for Kerberoasting, DCSync, LSASS dumps, and honeytoken triggers</p>
          </div>
          <div class="flex items-center gap-3">
            <select id="itdr-vector-filter" class="px-2.5 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-indigo-500">
              <option value="">All Vectors</option>
              <option value="KERBEROASTING">Kerberoasting</option>
              <option value="ASREP_ROASTING">AS-REP Roasting</option>
              <option value="DCSYNC">DCSync Replication</option>
              <option value="LSASS_MEMORY_DUMP">LSASS Memory Dump</option>
              <option value="HONEYTOKEN_TRIGGERED">Honeytoken Triggered</option>
              <option value="PASS_THE_HASH">Pass-The-Hash</option>
              <option value="GOLDEN_TICKET">Golden Ticket</option>
            </select>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Attack Vector</th>
                <th class="px-4 py-3">Target Account</th>
                <th class="px-4 py-3">Source Host</th>
                <th class="px-4 py-3">Risk</th>
                <th class="px-4 py-3">MITRE</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Detected At</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="itdr-detections-tbody" class="divide-y divide-slate-700/40 text-xs font-mono">
              <tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-sans">Loading identity detections...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Deception Honeytokens Catalog -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Deception Honeytokens Catalog</h3>
            <p class="text-xs text-slate-400 mt-0.5">Planted decoy accounts, fake SPN services, and memory traps acting as tripwires</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="itdr-honeytokens-count">0 Honeytokens</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Account / Trap Name</th>
                <th class="px-4 py-3">Deception Type</th>
                <th class="px-4 py-3">SPN / Service</th>
                <th class="px-4 py-3">Planted On Host</th>
                <th class="px-4 py-3">Triggers</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="itdr-honeytokens-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">Loading deception catalog...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 3: Identity Account Risk Directory -->
      <div class="bg-slate-800/80 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/60 flex items-center justify-between bg-slate-800/40">
          <div>
            <h3 class="text-md font-bold text-white tracking-wide">Identity Account Risk Directory</h3>
            <p class="text-xs text-slate-400 mt-0.5">Continuous identity risk scoring and automated containment state governance</p>
          </div>
          <span class="text-xs text-slate-400 font-mono" id="itdr-accounts-count">0 Accounts</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/60 text-xs uppercase text-slate-400 font-semibold border-b border-slate-700/60">
              <tr>
                <th class="px-4 py-3">Account Name</th>
                <th class="px-4 py-3">Type</th>
                <th class="px-4 py-3">Department</th>
                <th class="px-4 py-3">Risk Score</th>
                <th class="px-4 py-3">Risk Level</th>
                <th class="px-4 py-3">Anomalies</th>
                <th class="px-4 py-3">Containment</th>
                <th class="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="itdr-accounts-tbody" class="divide-y divide-slate-700/40 text-xs">
              <tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-mono">Loading account risk directory...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Deploy Honeytoken Modal -->
      <div id="modal-itdr-honeytoken" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🍯</span> Deploy Deception Honeytoken
            </h3>
            <button id="modal-itdr-honeytoken-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Account / Trap Name</label>
              <input id="input-itdr-ht-name" type="text" placeholder="DA_Honeytoken_Bravo" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-slate-400 mb-1">Deception Type</label>
                <select id="input-itdr-ht-type" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                  <option value="DECOY_USER_ACCOUNT">Decoy User Account</option>
                  <option value="FAKE_SPN_SERVICE">Fake SPN Service</option>
                  <option value="CREDENTIAL_MANAGER_BLOB">Credential Manager Blob</option>
                  <option value="REGISTRY_LSA_SECRET">Registry LSA Secret</option>
                </select>
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Domain</label>
                <input id="input-itdr-ht-domain" type="text" value="LOCALPILOT.CORP" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
              </div>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Service Principal Name (SPN, optional)</label>
              <input id="input-itdr-ht-spn" type="text" placeholder="MSSQLSvc/db-decoy.localpilot.corp" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Planted On Host</label>
              <input id="input-itdr-ht-host" type="text" placeholder="All Workstations or DC01" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Description / Strategy</label>
              <input id="input-itdr-ht-desc" type="text" value="Decoy administrative account to catch enumeration tools" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" />
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-itdr-honeytoken-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-itdr-honeytoken-submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold">Deploy Trap</button>
          </div>
        </div>
      </div>

      <!-- Contain Account Modal -->
      <div id="modal-itdr-contain" class="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-4">
          <div class="flex justify-between items-center pb-3 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🔒</span> Execute Account Containment
            </h3>
            <button id="modal-itdr-contain-close" class="text-slate-400 hover:text-white text-lg">✕</button>
          </div>
          <div class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Target Account Name</label>
              <input id="input-itdr-contain-account" type="text" placeholder="e.g. svc_sql_reporting" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Containment Action</label>
              <select id="input-itdr-contain-action" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                <option value="ACCOUNT_LOCKED">Lock Account Immediately</option>
                <option value="TOKENS_REVOKED">Revoke All OAuth / Kerberos Refresh Tokens</option>
                <option value="PASSWORD_RESET_REQUIRED">Force Immediate Password Reset</option>
                <option value="NORMAL">Restore to Normal (Remove Containment)</option>
              </select>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">SecOps Incident Notes</label>
              <input id="input-itdr-contain-notes" type="text" value="Emergency containment triggered by ITDR alert" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" />
            </div>
          </div>
          <div class="flex justify-end gap-3 pt-3 border-t border-slate-700">
            <button id="modal-itdr-contain-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold">Cancel</button>
            <button id="modal-itdr-contain-submit" class="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold">Execute Containment</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function initIdentityThreatBlade() {
  const getFleetKey = () => localStorage.getItem('fleetKey') || '';

  async function loadItdrStats() {
    try {
      const res = await fetch('/api/v1/fleet/itdr/stats', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        document.getElementById('kpi-itdr-active').textContent = data.stats.activeDetections ?? 0;
        document.getElementById('kpi-itdr-critical').textContent = data.stats.criticalRiskDetections ?? 0;
        document.getElementById('kpi-itdr-honeytokens').textContent = data.stats.activeHoneytokens ?? 0;
        document.getElementById('kpi-itdr-contained').textContent = data.stats.containedAccounts ?? 0;
      }
    } catch (e) {
      console.error('Failed to load ITDR stats:', e);
    }
  }

  async function loadDetections() {
    try {
      const vector = document.getElementById('itdr-vector-filter')?.value || '';
      const query = new URLSearchParams();
      if (vector) query.set('attack_vector', vector);

      const res = await fetch(`/api/v1/fleet/itdr/detections?${query.toString()}`, {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('itdr-detections-tbody');
      if (!tbody) return;

      const detections = data.detections || [];
      if (detections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-sans">No identity threat detections recorded.</td></tr>';
        return;
      }

      tbody.innerHTML = detections.map(d => {
        const vectorColor = d.attack_vector === 'HONEYTOKEN_TRIGGERED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                            d.attack_vector === 'DCSYNC' || d.attack_vector === 'LSASS_MEMORY_DUMP' ? 'bg-purple-500/20 text-purple-300 border-purple-500/30' :
                            'bg-rose-500/20 text-rose-300 border-rose-500/30';

        const riskColor = d.risk_score >= 90 ? 'text-purple-400 font-bold' :
                          d.risk_score >= 70 ? 'text-rose-400 font-semibold' :
                          'text-amber-400';

        const statusBadge = d.status === 'CONTAINED' ?
          `<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">CONTAINED</span>` :
          d.status === 'INVESTIGATING' ?
          `<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">INVESTIGATING</span>` :
          `<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">NEW ATTACK</span>`;

        const actionBtn = d.status !== 'CONTAINED' ?
          `<button onclick="window.itdrContainTarget('${d.target_account}')" class="px-2.5 py-1 bg-rose-600/30 hover:bg-rose-600/50 text-rose-300 rounded text-xs border border-rose-500/30 transition">Contain</button>` :
          `<span class="text-slate-500 text-xs">Secured</span>`;

        return `
          <tr class="hover:bg-slate-700/30 transition font-sans">
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-xs border font-mono ${vectorColor}">${d.attack_vector}</span></td>
            <td class="px-4 py-3 font-semibold text-white font-mono">${d.target_account}</td>
            <td class="px-4 py-3 text-slate-300 font-mono">${d.source_host}</td>
            <td class="px-4 py-3 font-mono ${riskColor}">${d.risk_score.toFixed(1)}</td>
            <td class="px-4 py-3 text-slate-400 font-mono text-xs">${d.mitre_technique}</td>
            <td class="px-4 py-3">${statusBadge}</td>
            <td class="px-4 py-3 text-slate-400 text-xs font-mono">${d.detected_at}</td>
            <td class="px-4 py-3 text-right">${actionBtn}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load detections:', e);
    }
  }

  async function loadHoneytokens() {
    try {
      const res = await fetch('/api/v1/fleet/itdr/honeytokens', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('itdr-honeytokens-tbody');
      const countEl = document.getElementById('itdr-honeytokens-count');
      if (!tbody) return;

      const tokens = data.honeytokens || [];
      if (countEl) countEl.textContent = `${tokens.length} Honeytokens`;

      if (tokens.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No deception honeytokens deployed.</td></tr>';
        return;
      }

      tbody.innerHTML = tokens.map(t => {
        const triggerBadge = t.trigger_count > 0 ?
          `<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold animate-pulse">TRIPPED (${t.trigger_count})</span>` :
          `<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ARMED</span>`;

        return `
          <tr class="hover:bg-slate-700/30 transition">
            <td class="px-4 py-3 font-semibold text-amber-400">${t.account_name}</td>
            <td class="px-4 py-3 text-slate-300 font-sans">${t.honeytoken_type}</td>
            <td class="px-4 py-3 text-slate-400">${t.spn || '-'}</td>
            <td class="px-4 py-3 text-slate-300">${t.planted_on_host || 'Global Domain'}</td>
            <td class="px-4 py-3">${triggerBadge}</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-xs bg-slate-700/50 text-slate-300">ACTIVE</span></td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.itdrTriggerTest('${t.id}')" class="px-2 py-1 bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 rounded text-xs border border-amber-500/30 transition">Test Tripwire</button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load honeytokens:', e);
    }
  }

  async function loadAccounts() {
    try {
      const res = await fetch('/api/v1/fleet/itdr/accounts', {
        headers: { 'x-fleet-key': getFleetKey() }
      });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('itdr-accounts-tbody');
      const countEl = document.getElementById('itdr-accounts-count');
      if (!tbody) return;

      const accounts = data.accounts || [];
      if (countEl) countEl.textContent = `${accounts.length} Accounts`;

      if (accounts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500 font-mono">No account risk profiles tracked.</td></tr>';
        return;
      }

      tbody.innerHTML = accounts.map(a => {
        const levelColor = a.risk_level === 'CRITICAL' ? 'bg-purple-500/20 text-purple-300 border-purple-500/30' :
                           a.risk_level === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
                           a.risk_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                           'bg-blue-500/20 text-blue-300 border-blue-500/30';

        const statusBadge = a.containment_status === 'ACCOUNT_LOCKED' ?
          `<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold">LOCKED</span>` :
          a.containment_status === 'TOKENS_REVOKED' ?
          `<span class="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">REVOKED</span>` :
          `<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">NORMAL</span>`;

        return `
          <tr class="hover:bg-slate-700/30 transition font-mono">
            <td class="px-4 py-3 font-semibold text-white">${a.account_name}</td>
            <td class="px-4 py-3 text-slate-400 font-sans">${a.account_type}</td>
            <td class="px-4 py-3 text-slate-300 font-sans">${a.department || '-'}</td>
            <td class="px-4 py-3 font-bold text-rose-400">${a.risk_score.toFixed(1)}</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-xs border font-sans ${levelColor}">${a.risk_level}</span></td>
            <td class="px-4 py-3 text-slate-300">${a.anomalous_logon_count}</td>
            <td class="px-4 py-3 font-sans">${statusBadge}</td>
            <td class="px-4 py-3 text-right">
              <button onclick="window.itdrContainTarget('${a.account_name}')" class="px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs border border-slate-600 transition font-sans">
                Manage
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Failed to load accounts:', e);
    }
  }

  // Global window helpers
  window.itdrContainTarget = (accountName) => {
    document.getElementById('input-itdr-contain-account').value = accountName;
    document.getElementById('modal-itdr-contain').classList.remove('hidden');
  };

  window.itdrTriggerTest = async (tokenId) => {
    try {
      const res = await fetch(`/api/v1/fleet/itdr/honeytokens/${tokenId}/trigger`, {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ trigger_host: 'ITDR-Console-Test', attacker_ip: '10.0.0.88' })
      });
      if (res.ok) {
        loadHoneytokens();
        loadDetections();
        loadItdrStats();
      }
    } catch (e) {
      console.error('Failed to trigger test:', e);
    }
  };

  // Event handlers
  document.getElementById('btn-itdr-refresh')?.addEventListener('click', () => {
    loadItdrStats();
    loadDetections();
    loadHoneytokens();
    loadAccounts();
  });

  document.getElementById('itdr-vector-filter')?.addEventListener('change', () => loadDetections());

  // Modal: Honeytoken
  document.getElementById('btn-itdr-new-honeytoken')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-honeytoken').classList.remove('hidden');
  });
  document.getElementById('modal-itdr-honeytoken-close')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-honeytoken').classList.add('hidden');
  });
  document.getElementById('modal-itdr-honeytoken-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-honeytoken').classList.add('hidden');
  });
  document.getElementById('modal-itdr-honeytoken-submit')?.addEventListener('click', async () => {
    const account_name = document.getElementById('input-itdr-ht-name').value.trim();
    const honeytoken_type = document.getElementById('input-itdr-ht-type').value;
    const domain_name = document.getElementById('input-itdr-ht-domain').value.trim();
    const spn = document.getElementById('input-itdr-ht-spn').value.trim();
    const planted_on_host = document.getElementById('input-itdr-ht-host').value.trim();
    const description = document.getElementById('input-itdr-ht-desc').value.trim();

    if (!account_name) {
      alert('Account Name is required');
      return;
    }

    try {
      const res = await fetch('/api/v1/fleet/itdr/honeytokens', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_name, honeytoken_type, domain_name, spn, planted_on_host, description })
      });
      if (res.ok) {
        document.getElementById('modal-itdr-honeytoken').classList.add('hidden');
        loadHoneytokens();
        loadItdrStats();
      } else {
        const err = await res.json();
        alert(err.message || 'Failed to deploy honeytoken');
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Modal: Contain Account
  document.getElementById('btn-itdr-contain')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-contain').classList.remove('hidden');
  });
  document.getElementById('modal-itdr-contain-close')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-contain').classList.add('hidden');
  });
  document.getElementById('modal-itdr-contain-cancel')?.addEventListener('click', () => {
    document.getElementById('modal-itdr-contain').classList.add('hidden');
  });
  document.getElementById('modal-itdr-contain-submit')?.addEventListener('click', async () => {
    const account_name = document.getElementById('input-itdr-contain-account').value.trim();
    const action = document.getElementById('input-itdr-contain-action').value;
    const notes = document.getElementById('input-itdr-contain-notes').value.trim();

    if (!account_name) {
      alert('Target Account Name is required');
      return;
    }

    try {
      const res = await fetch('/api/v1/fleet/itdr/contain-account', {
        method: 'POST',
        headers: { 'x-fleet-key': getFleetKey(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_name, action, notes })
      });
      if (res.ok) {
        document.getElementById('modal-itdr-contain').classList.add('hidden');
        loadAccounts();
        loadDetections();
        loadItdrStats();
      } else {
        const err = await res.json();
        alert(err.message || 'Failed to contain account');
      }
    } catch (e) {
      console.error(e);
    }
  });

  // Initial load
  loadItdrStats();
  loadDetections();
  loadHoneytokens();
  loadAccounts();
}

window.renderIdentityThreatBlade = renderIdentityThreatBlade;
window.initIdentityThreatBlade = initIdentityThreatBlade;

window.IdentityThreatTable = {
  async render() {
    const container = document.getElementById('tab-itdr');
    if (!container) return;
    container.innerHTML = renderIdentityThreatBlade();
    initIdentityThreatBlade();
  }
};
