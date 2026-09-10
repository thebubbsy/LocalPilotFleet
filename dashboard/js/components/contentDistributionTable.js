/**
 * LocalPilot Fleet — Content Distribution, BITS, P2P Mesh & Hardware TPM mTLS Blade
 * dashboard/js/components/contentDistributionTable.js
 *
 * Dimension 4: Content Distribution & Bandwidth Management
 * Dimension 3: Cryptographic Identity, Zero Trust & Supply Chain Security
 */

import { api } from '../api.js';

export function renderContentDistributionBlade() {
  const container = document.getElementById('tab-content-distribution');
  if (!container) return;

  container.innerHTML = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <span class="text-indigo-400">🌐</span> Content Distribution, BITS & TPM 2.0 mTLS
          </h2>
          <p class="text-sm text-slate-400 mt-1">
            Background Intelligent Transfer Service (BITS), P2P LAN Mesh peer caching, and Hardware TPM 2.0 client mTLS authentication.
          </p>
        </div>
        <div class="flex items-center gap-2">
          <button id="btn-refresh-dist" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-sm font-medium transition flex items-center gap-1.5 border border-slate-700">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-create-bits-job" class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-sm font-medium transition flex items-center gap-1.5 shadow">
            <span>➕</span> New BITS Job
          </button>
          <button id="btn-enroll-tpm-cert" class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-medium transition flex items-center gap-1.5 shadow">
            <span>🛡️</span> Enroll TPM mTLS
          </button>
        </div>
      </div>

      <!-- KPI Cards Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active BITS Transfers</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-dist-active-bits" class="text-2xl font-bold text-indigo-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">Idle Throttled</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-dist-total-transferred">Total: 0 MB</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">P2P LAN Cache Seeds</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-dist-p2p-seeds" class="text-2xl font-bold text-sky-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">Subnet Mesh</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-dist-p2p-bytes">Served: 0 MB</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">P2P WAN Bandwidth Offload</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-dist-offload-rate" class="text-2xl font-bold text-emerald-400">--%</span>
            <span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">Link Protection</span>
          </div>
          <div class="text-xs text-slate-500 mt-1">Zero-Cloud P2P Mesh</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hardware TPM 2.0 mTLS</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-dist-tpm-certs" class="text-2xl font-bold text-purple-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">Zero Trust PKI</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-dist-enrolled-devs">0 Enrolled Nodes</div>
        </div>
      </div>

      <!-- Navigation Sub-Tabs -->
      <div class="border-b border-slate-800 flex gap-4 text-sm font-medium">
        <button id="subtab-btn-bits" class="pb-2 border-b-2 border-indigo-500 text-indigo-400 transition flex items-center gap-1.5">
          <span>🚀</span> BITS Transfer Queue
        </button>
        <button id="subtab-btn-p2p" class="pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5">
          <span>🌐</span> P2P LAN Mesh & Subnet Cache
        </button>
        <button id="subtab-btn-mtls" class="pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5">
          <span>🛡️</span> Hardware TPM 2.0 & mTLS Certificates
        </button>
      </div>

      <!-- Subtab 1: BITS Transfer Queue -->
      <div id="subtab-pane-bits" class="space-y-4">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Job Name</th>
                  <th class="px-4 py-3">Target Device</th>
                  <th class="px-4 py-3">Priority</th>
                  <th class="px-4 py-3">Transfer Progress</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Peer Caching</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="bits-jobs-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading BITS transfer queue...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Subtab 2: P2P LAN Mesh & Subnet Cache -->
      <div id="subtab-pane-p2p" class="space-y-4 hidden">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Payload Name</th>
                  <th class="px-4 py-3">Content SHA-256</th>
                  <th class="px-4 py-3">Size</th>
                  <th class="px-4 py-3">Seeding Device</th>
                  <th class="px-4 py-3">Subnet & LAN Endpoint</th>
                  <th class="px-4 py-3">P2P Offloaded</th>
                  <th class="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody id="p2p-seeds-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading P2P subnet seeds...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Subtab 3: Hardware TPM 2.0 & mTLS Certificates -->
      <div id="subtab-pane-mtls" class="space-y-4 hidden">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Certificate Subject (CN)</th>
                  <th class="px-4 py-3">Thumbprint</th>
                  <th class="px-4 py-3">Device</th>
                  <th class="px-4 py-3">Hardware Root</th>
                  <th class="px-4 py-3">Algorithm</th>
                  <th class="px-4 py-3">Validity</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="mtls-certs-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="8" class="px-4 py-8 text-center text-slate-500">Loading mTLS certificates...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Script Modal Container -->
    <div id="modal-dist-script" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
      <div class="bg-slate-900 border border-slate-800 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        <div class="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-950">
          <h3 class="text-sm font-semibold text-white flex items-center gap-2">
            <span class="text-indigo-400">📜</span> Native BITS PowerShell Transfer Script
          </h3>
          <button id="modal-dist-script-close" class="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
        </div>
        <div class="p-4 overflow-y-auto flex-1 bg-slate-950">
          <pre id="modal-dist-script-content" class="text-xs font-mono text-indigo-300 whitespace-pre-wrap break-all select-all"></pre>
        </div>
        <div class="p-3 border-t border-slate-800 flex justify-end gap-2 bg-slate-900">
          <button id="modal-dist-script-copy" class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-medium transition">
            📋 Copy Script
          </button>
        </div>
      </div>
    </div>
  `;

  setupContentDistEvents();
  loadContentDistData();
}

function setupContentDistEvents() {
  document.getElementById('btn-refresh-dist')?.addEventListener('click', loadContentDistData);

  const subtabs = [
    { btn: 'subtab-btn-bits', pane: 'subtab-pane-bits' },
    { btn: 'subtab-btn-p2p', pane: 'subtab-pane-p2p' },
    { btn: 'subtab-btn-mtls', pane: 'subtab-pane-mtls' }
  ];

  subtabs.forEach(tab => {
    document.getElementById(tab.btn)?.addEventListener('click', () => {
      subtabs.forEach(t => {
        const b = document.getElementById(t.btn);
        const p = document.getElementById(t.pane);
        if (t.btn === tab.btn) {
          b.className = 'pb-2 border-b-2 border-indigo-500 text-indigo-400 transition flex items-center gap-1.5';
          p.classList.remove('hidden');
        } else {
          b.className = 'pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5';
          p.classList.add('hidden');
        }
      });
    });
  });

  document.getElementById('modal-dist-script-close')?.addEventListener('click', () => {
    document.getElementById('modal-dist-script')?.classList.add('hidden');
  });

  document.getElementById('modal-dist-script-copy')?.addEventListener('click', () => {
    const code = document.getElementById('modal-dist-script-content')?.innerText;
    if (code) {
      navigator.clipboard.writeText(code);
      const copyBtn = document.getElementById('modal-dist-script-copy');
      const orig = copyBtn.innerText;
      copyBtn.innerText = '✅ Copied!';
      setTimeout(() => { copyBtn.innerText = orig; }, 2000);
    }
  });
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function loadContentDistData() {
  try {
    const stats = await api.getContentDistributionStats();
    if (stats) {
      document.getElementById('kpi-dist-active-bits').innerText = stats.activeBitsTransfers;
      document.getElementById('kpi-dist-total-transferred').innerText = `Total: ${formatBytes(stats.totalTransferredBytes)}`;
      document.getElementById('kpi-dist-p2p-seeds').innerText = stats.p2pActiveSeeds;
      document.getElementById('kpi-dist-p2p-bytes').innerText = `Served: ${formatBytes(stats.totalP2pBytesServed)}`;
      document.getElementById('kpi-dist-offload-rate').innerText = `${stats.p2pOffloadRate}%`;
      document.getElementById('kpi-dist-tpm-certs').innerText = stats.tpmBackedCerts;
      document.getElementById('kpi-dist-enrolled-devs').innerText = `${stats.enrolledMtlsDevices} Enrolled Nodes`;
    }

    // Load BITS Jobs
    const bitsRes = await api.getBitsJobs();
    renderBitsJobs(bitsRes?.jobs || []);

    // Load P2P Seeds
    const p2pRes = await api.getP2pSeeds();
    renderP2pSeeds(p2pRes?.seeds || []);

    // Load mTLS Certs
    const mtlsRes = await api.getMtlsCertificates();
    renderMtlsCerts(mtlsRes?.certificates || []);

  } catch (err) {
    console.error('Failed to load content distribution data:', err);
  }
}

function renderBitsJobs(jobs) {
  const tbody = document.getElementById('bits-jobs-table-body');
  if (!tbody) return;

  if (jobs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No BITS jobs in queue.</td></tr>`;
    return;
  }

  tbody.innerHTML = jobs.map(job => {
    const pct = job.total_bytes > 0 ? Math.min(100, Math.round((job.transferred_bytes / job.total_bytes) * 100)) : 0;
    
    let priorityBadge = 'bg-slate-800 text-slate-300';
    if (job.priority === 'HIGH') priorityBadge = 'bg-amber-950 text-amber-300 border border-amber-800';
    if (job.priority === 'FOREGROUND') priorityBadge = 'bg-rose-950 text-rose-300 border border-rose-800';
    if (job.priority === 'NORMAL') priorityBadge = 'bg-indigo-950 text-indigo-300 border border-indigo-800';

    let statusBadge = 'bg-slate-800 text-slate-300';
    if (job.status === 'TRANSFERRING') statusBadge = 'bg-sky-950 text-sky-300 border border-sky-800 animate-pulse';
    if (job.status === 'TRANSFERRED' || job.status === 'ACKNOWLEDGED') statusBadge = 'bg-emerald-950 text-emerald-300 border border-emerald-800';
    if (job.status === 'CANCELLED') statusBadge = 'bg-slate-800 text-slate-400 border border-slate-700';
    if (job.status === 'ERROR') statusBadge = 'bg-rose-950 text-rose-300 border border-rose-800';

    return `
      <tr class="hover:bg-slate-800/50 transition">
        <td class="px-4 py-3">
          <div class="font-medium text-white">${job.job_name}</div>
          <div class="text-[11px] font-mono text-slate-500 truncate max-w-xs">${job.source_url}</div>
        </td>
        <td class="px-4 py-3">
          <span class="font-mono text-slate-300">${job.device_hostname || job.device_name || job.device_id}</span>
        </td>
        <td class="px-4 py-3">
          <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${priorityBadge}">${job.priority}</span>
        </td>
        <td class="px-4 py-3 min-w-[160px]">
          <div class="flex justify-between text-[11px] text-slate-400 mb-1">
            <span>${pct}%</span>
            <span>${formatBytes(job.transferred_bytes)} / ${formatBytes(job.total_bytes)}</span>
          </div>
          <div class="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div class="bg-indigo-500 h-full rounded-full transition-all duration-300" style="width: ${pct}%"></div>
          </div>
        </td>
        <td class="px-4 py-3">
          <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${statusBadge}">${job.status}</span>
        </td>
        <td class="px-4 py-3">
          <span class="text-[11px] ${job.peer_caching_enabled ? 'text-emerald-400' : 'text-slate-500'}">
            ${job.peer_caching_enabled ? '⚡ Enabled' : 'Disabled'}
          </span>
        </td>
        <td class="px-4 py-3 text-right">
          <div class="flex items-center justify-end gap-1.5">
            <button onclick="window.viewBitsScript('${job.id}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-indigo-400 rounded text-xs border border-slate-700">
              📜 Script
            </button>
            ${['QUEUED', 'CONNECTING', 'TRANSFERRING'].includes(job.status) ? `
              <button onclick="window.cancelBitsJob('${job.id}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 rounded text-xs border border-rose-800">
                Cancel
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function renderP2pSeeds(seeds) {
  const tbody = document.getElementById('p2p-seeds-table-body');
  if (!tbody) return;

  if (seeds.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No active P2P cache seeds.</td></tr>`;
    return;
  }

  tbody.innerHTML = seeds.map(seed => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="px-4 py-3 font-medium text-white">${seed.payload_name}</td>
      <td class="px-4 py-3 font-mono text-[11px] text-slate-400 truncate max-w-xs" title="${seed.content_sha256}">
        ${seed.content_sha256.substring(0, 16)}...
      </td>
      <td class="px-4 py-3 text-slate-300">${formatBytes(seed.total_size_bytes)}</td>
      <td class="px-4 py-3 font-mono text-slate-300">${seed.device_hostname || seed.device_name || seed.device_id}</td>
      <td class="px-4 py-3">
        <span class="text-sky-400 font-mono text-xs">${seed.lan_ip}:${seed.p2p_port}</span>
        <span class="text-[10px] text-slate-500 block">(${seed.subnet_cidr})</span>
      </td>
      <td class="px-4 py-3 text-emerald-400 font-semibold">${formatBytes(seed.bytes_served_p2p)}</td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${seed.is_active ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-500'}">
          ${seed.is_active ? 'SEEDING' : 'INACTIVE'}
        </span>
      </td>
    </tr>
  `).join('');
}

function renderMtlsCerts(certs) {
  const tbody = document.getElementById('mtls-certs-table-body');
  if (!tbody) return;

  if (certs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-8 text-center text-slate-500">No mTLS client certificates enrolled.</td></tr>`;
    return;
  }

  tbody.innerHTML = certs.map(c => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="px-4 py-3">
        <div class="font-medium text-white">${c.subject_cn}</div>
        <div class="text-[10px] text-slate-500">Issuer: ${c.issuer_cn}</div>
      </td>
      <td class="px-4 py-3 font-mono text-[11px] text-purple-300" title="${c.cert_thumbprint}">
        ${c.cert_thumbprint.substring(0, 16)}...
      </td>
      <td class="px-4 py-3 font-mono text-slate-300">${c.device_hostname || c.device_name || c.device_id}</td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold ${c.tpm_backed ? 'bg-purple-950 text-purple-300 border border-purple-800' : 'bg-slate-800 text-slate-400'}">
          ${c.tpm_backed ? '🛡️ TPM 2.0 EK' : 'Software'}
        </span>
      </td>
      <td class="px-4 py-3 font-mono text-xs text-slate-300">${c.key_algorithm}</td>
      <td class="px-4 py-3 text-[11px] text-slate-400">
        <div>Valid To: ${new Date(c.valid_to).toLocaleDateString()}</div>
        <div class="text-[10px] text-slate-500">${c.scep_transaction_id || ''}</div>
      </td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${c.revocation_status === 'ACTIVE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'}">
          ${c.revocation_status}
        </span>
      </td>
      <td class="px-4 py-3 text-right">
        <div class="flex items-center justify-end gap-1.5">
          <button onclick="window.verifyMtlsCert('${c.cert_thumbprint}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-purple-400 rounded text-xs border border-slate-700">
            Verify
          </button>
          ${c.revocation_status === 'ACTIVE' ? `
            <button onclick="window.revokeMtlsCert('${c.cert_thumbprint}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 rounded text-xs border border-rose-800">
              Revoke
            </button>
          ` : ''}
        </div>
      </td>
    </tr>
  `).join('');
}

// Global UI helper hooks
window.viewBitsScript = async function(jobId) {
  try {
    const res = await api.getBitsJobScript(jobId);
    if (res) {
      document.getElementById('modal-dist-script-content').innerText = typeof res === 'string' ? res : (res.script || JSON.stringify(res, null, 2));
      document.getElementById('modal-dist-script')?.classList.remove('hidden');
    }
  } catch (err) {
    alert(`Failed to fetch BITS script: ${err.message}`);
  }
};

window.cancelBitsJob = async function(jobId) {
  if (!confirm(`Are you sure you want to cancel BITS transfer job '${jobId}'?`)) return;
  try {
    await api.cancelBitsJob(jobId);
    loadContentDistData();
  } catch (err) {
    alert(`Failed to cancel job: ${err.message}`);
  }
};

window.verifyMtlsCert = async function(thumbprint) {
  try {
    const res = await api.verifyMtlsCertificate({ cert_thumbprint: thumbprint });
    if (res.valid) {
      alert(`[+] Mutual TLS Certificate Validated!\nThumbprint: ${thumbprint}\nStatus: Active & TPM 2.0 Protected`);
    } else {
      alert(`[-] Mutual TLS Certificate Verification Failed!\nReason: ${res.reason}`);
    }
  } catch (err) {
    alert(`Verification error: ${err.message}`);
  }
};

window.revokeMtlsCert = async function(thumbprint) {
  const reason = prompt('Enter revocation reason (e.g. KEY_COMPROMISE, SUPERSEDED, RETIRED):', 'KEY_COMPROMISE');
  if (!reason) return;
  try {
    await api.revokeMtlsCertificate({ cert_thumbprint: thumbprint, reason });
    loadContentDistData();
  } catch (err) {
    alert(`Revocation error: ${err.message}`);
  }
};

window.ContentDistributionTable = {
  render: renderContentDistributionBlade
};
