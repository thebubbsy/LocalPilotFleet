/**
 * LocalPilot Fleet — Enterprise Secrets Vault & OpenAPI Explorer Blade
 * Hardware / DPAPI-NG / AES-256-GCM Credential Escrow & API Documentation
 */

export function renderVaultSecretsBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-amber-500/20 text-amber-400 rounded-lg text-2xl border border-amber-500/30">🔐</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Enterprise Secrets Vault & DPAPI-NG Escrow
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">FIPS 140-3 Ready</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Zero-plaintext envelope encryption for BitLocker recovery keys, LAPS passwords & mTLS credentials</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <a href="/api/v1/docs" target="_blank" class="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-2 shadow-md hover:shadow-sky-500/20">
            <span>📖</span> Interactive OpenAPI 3.0 Docs
          </a>
          <button id="btn-vault-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="vault-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Vault Secrets</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🔑</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-vault-total">-</p>
          <p class="text-xs text-blue-400 mt-1 flex items-center gap-1">Escrowed Across Fleet</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Credentials</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-vault-active">-</p>
          <p class="text-xs text-emerald-400 mt-1 flex items-center gap-1">Rotatable & Compliant</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Zero-Plaintext Storage</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">🔒</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2">100%</p>
          <p class="text-xs text-purple-300 mt-1">AES-256-GCM + DPAPI-NG</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Immutable Audits</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">📜</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-vault-audits">-</p>
          <p class="text-xs text-amber-300 mt-1">Non-Repudiation Ledger</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="flex border-b border-slate-700/80 gap-2">
        <button class="vault-subtab px-4 py-2 text-sm font-semibold border-b-2 border-amber-500 text-amber-400" data-tab="secrets">
          🔑 Escrowed Secrets
        </button>
        <button class="vault-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="audits">
          📜 Access & Decrypt Audits
        </button>
        <button class="vault-subtab px-4 py-2 text-sm font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200" data-tab="openapi">
          📖 OpenAPI 3.0 & DPAPI Scripts
        </button>
      </div>

      <!-- Tab 1: Secrets List -->
      <div id="vault-tab-secrets" class="vault-tab-content space-y-4">
        <div class="bg-slate-800/40 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-800/80 text-xs font-semibold text-slate-400 uppercase border-b border-slate-700">
                <tr>
                  <th class="px-4 py-3">Secret ID & Name</th>
                  <th class="px-4 py-3">Scope</th>
                  <th class="px-4 py-3">Device ID</th>
                  <th class="px-4 py-3">Encryption Scheme</th>
                  <th class="px-4 py-3">Rotation Days</th>
                  <th class="px-4 py-3">Last Rotated</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="vault-secrets-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading enterprise vault secrets...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 2: Audits List -->
      <div id="vault-tab-audits" class="vault-tab-content hidden space-y-4">
        <div class="bg-slate-800/40 rounded-xl border border-slate-700/50 overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-800/80 text-xs font-semibold text-slate-400 uppercase border-b border-slate-700">
                <tr>
                  <th class="px-4 py-3">Timestamp</th>
                  <th class="px-4 py-3">Secret ID</th>
                  <th class="px-4 py-3">Action</th>
                  <th class="px-4 py-3">Actor Identity</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Dual-Custody Ref</th>
                </tr>
              </thead>
              <tbody id="vault-audits-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading audit ledger...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 3: OpenAPI & Scripts -->
      <div id="vault-tab-openapi" class="vault-tab-content hidden space-y-4">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <!-- OpenAPI Card -->
          <div class="bg-slate-800/50 p-5 rounded-xl border border-slate-700/60 shadow">
            <h3 class="text-base font-bold text-white flex items-center gap-2 mb-2">
              <span>📖</span> OpenAPI 3.0.3 Contract
            </h3>
            <p class="text-xs text-slate-400 mb-4">Complete API schema, security scopes (FleetKeyAuth, BearerAuth, MtlsCertAuth), and endpoint catalog.</p>
            <div class="space-y-3">
              <a href="/api/v1/docs" target="_blank" class="block w-full text-center py-2.5 bg-sky-600 hover:bg-sky-500 text-white font-semibold rounded-lg text-xs transition">
                Open Swagger UI Interactive Console ↗
              </a>
              <a href="/api/v1/openapi.json" target="_blank" class="block w-full text-center py-2.5 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg text-xs transition border border-slate-600">
                Download Raw openapi.json Specification ↗
              </a>
            </div>
          </div>

          <!-- DPAPI PowerShell Script Card -->
          <div class="bg-slate-800/50 p-5 rounded-xl border border-slate-700/60 shadow">
            <h3 class="text-base font-bold text-white flex items-center gap-2 mb-2">
              <span>🛡️</span> DPAPI-NG Machine Escrow Script
            </h3>
            <p class="text-xs text-slate-400 mb-2">Native Windows PowerShell snippet for hardware-rooted local credential escrow.</p>
            <pre class="bg-slate-900 p-3 rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-48 border border-slate-800" id="dpapi-snippet-pre">Loading snippet...</pre>
          </div>
        </div>
      </div>
    </div>
  `;
}

export async function initVaultSecretsBlade(api) {
  const refreshBtn = document.getElementById('btn-vault-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => loadVaultData(api));
  }

  // Subtab switching
  document.querySelectorAll('.vault-subtab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.vault-subtab').forEach(b => {
        b.classList.remove('border-amber-500', 'text-amber-400');
        b.classList.add('border-transparent', 'text-slate-400');
      });
      btn.classList.add('border-amber-500', 'text-amber-400');
      btn.classList.remove('border-transparent', 'text-slate-400');

      document.querySelectorAll('.vault-tab-content').forEach(c => c.classList.add('hidden'));
      const tabId = `vault-tab-${btn.getAttribute('data-tab')}`;
      const target = document.getElementById(tabId);
      if (target) target.classList.remove('hidden');
    });
  });

  await loadVaultData(api);
}

async function loadVaultData(api) {
  try {
    const statsRes = await api.get('/api/v1/fleet/vault/stats');
    if (statsRes) {
      document.getElementById('kpi-vault-total').textContent = statsRes.totalSecrets || 0;
      document.getElementById('kpi-vault-active').textContent = statsRes.activeSecrets || 0;
      document.getElementById('kpi-vault-audits').textContent = statsRes.totalAudits || 0;
    }

    const secretsRes = await api.get('/api/v1/fleet/vault/secrets');
    const tbody = document.getElementById('vault-secrets-tbody');
    if (tbody && secretsRes && secretsRes.secrets) {
      if (secretsRes.secrets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No escrowed credentials in vault.</td></tr>';
      } else {
        tbody.innerHTML = secretsRes.secrets.map(s => `
          <tr class="hover:bg-slate-800/50 transition">
            <td class="px-4 py-3">
              <div class="font-bold text-slate-100">${escapeHtml(s.secret_name)}</div>
              <div class="text-[10px] text-slate-400 font-mono">${escapeHtml(s.secret_id)}</div>
            </td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                ${escapeHtml(s.secret_scope)}
              </span>
            </td>
            <td class="px-4 py-3 text-slate-300 font-mono">${escapeHtml(s.device_id || 'Global / Fleet')}</td>
            <td class="px-4 py-3">
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${s.encryption_scheme.includes('DPAPI') ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'} border">
                ${escapeHtml(s.encryption_scheme)}
              </span>
            </td>
            <td class="px-4 py-3 text-slate-400">${s.rotation_interval_days} days</td>
            <td class="px-4 py-3 text-slate-400">${s.last_rotated_at || 'Never'}</td>
            <td class="px-4 py-3 text-right">
              <button class="px-2.5 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded text-[11px] font-semibold transition" onclick="alert('Dual-Custody 4-Eyes authorization required to decrypt secret: ' + '${s.secret_id}')">
                👁️ Decrypt
              </button>
            </td>
          </tr>
        `).join('');
      }
    }

    const auditsRes = await api.get('/api/v1/fleet/vault/audits?limit=20');
    const auditsTbody = document.getElementById('vault-audits-tbody');
    if (auditsTbody && auditsRes && auditsRes.audits) {
      if (auditsRes.audits.length === 0) {
        auditsTbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No vault audit events recorded.</td></tr>';
      } else {
        auditsTbody.innerHTML = auditsRes.audits.map(a => `
          <tr class="hover:bg-slate-800/50 transition">
            <td class="px-4 py-2.5 text-slate-400">${escapeHtml(a.created_at)}</td>
            <td class="px-4 py-2.5 text-slate-200 font-mono">${escapeHtml(a.secret_id)}</td>
            <td class="px-4 py-2.5">
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${a.action === 'ACCESS_DENIED' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'}">
                ${escapeHtml(a.action)}
              </span>
            </td>
            <td class="px-4 py-2.5 text-slate-300 font-mono">${escapeHtml(a.actor)}</td>
            <td class="px-4 py-2.5">
              <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${a.status === 'SUCCESS' ? 'text-emerald-400' : 'text-rose-400'}">
                ${escapeHtml(a.status)}
              </span>
            </td>
            <td class="px-4 py-2.5 text-slate-400 font-mono">${escapeHtml(a.dual_custody_ref_id || '—')}</td>
          </tr>
        `).join('');
      }
    }

    // Load snippet
    const snippetPre = document.getElementById('dpapi-snippet-pre');
    if (snippetPre) {
      snippetPre.textContent = `# LocalPilot Enterprise DPAPI-NG Machine Credential Escrow
Add-Type -AssemblyName System.Security

function Protect-LocalSecret {
    param([string]$Plaintext)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
    $entropy = [System.Text.Encoding]::UTF8.GetBytes("LocalPilot-Fleet-Entropy-2026")
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($encrypted)
}`;
    }
  } catch (err) {
    console.error('Failed loading vault data:', err);
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
