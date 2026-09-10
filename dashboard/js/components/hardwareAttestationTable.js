/**
 * LocalPilot Fleet — Hardware Supply Chain & TPM 2.0 Measured Boot Attestation Blade
 * dashboard/js/components/hardwareAttestationTable.js
 *
 * Provides real-time hardware component auditing, TPM 2.0 PCR validation,
 * UEFI boot-chain integrity monitoring, and zero-trust supply chain defense.
 */

function renderHardwareAttestationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-cyan-500/20 text-cyan-400 rounded-lg text-2xl border border-cyan-500/30">🔒</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Hardware Supply Chain &amp; TPM 2.0 Measured Boot
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">Root of Trust</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Cryptographic hardware root-of-trust, TPM 2.0 PCR hash validation, and component serial tamper defense</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-attestation-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-attestation-new" class="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-cyan-500/20">
            <span>➕</span> Enroll Hardware Baseline
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="attest-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Attested Fleet</p>
            <span class="p-1.5 bg-cyan-500/20 text-cyan-400 rounded-md text-sm">💻</span>
          </div>
          <p class="text-2xl font-bold text-cyan-400 mt-2" id="kpi-attest-total">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Verified</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">✅</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-attest-verified">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mismatches</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-attest-mismatches">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Secure Boot</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-attest-secureboot">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">DMA / HVCI</p>
            <span class="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-md text-sm">⚡</span>
          </div>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-attest-dma">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">PCR Drifts</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚨</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-attest-pcr-drifts">-</p>
        </div>
      </div>

      <!-- Main Layout: Stacked Cards -->
      <div class="grid grid-cols-1 gap-6">
        <!-- Hardware Baselines Catalog Card -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">⚙️</span>
              <h3 class="font-semibold text-slate-200">Hardware Supply Chain Baselines</h3>
            </div>
            <div class="flex items-center gap-2">
              <input type="text" id="filter-attest-search" placeholder="Search device or manufacturer..." class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500">
              <select id="filter-attest-status" class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500">
                <option value="">All Verification Statuses</option>
                <option value="VERIFIED">VERIFIED</option>
                <option value="COMPONENT_MISMATCH">COMPONENT_MISMATCH</option>
                <option value="TAMPER_ALERT">TAMPER_ALERT</option>
              </select>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Device / Host</th>
                  <th class="px-4 py-3">TPM Manufacturer</th>
                  <th class="px-4 py-3">Motherboard Serial</th>
                  <th class="px-4 py-3">Chassis Serial</th>
                  <th class="px-4 py-3">Hardware Root-of-Trust</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Last Verified</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="attest-baselines-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading hardware supply chain baselines...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- TPM Measured Boot Logs & PCR Verification Stream -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">📜</span>
              <h3 class="font-semibold text-slate-200">TPM 2.0 Measured Boot &amp; PCR Attestation Stream</h3>
            </div>
            <div class="text-xs text-slate-400">
              Platform Configuration Register cryptographic hashes (PCR 0, 4, 7, 11)
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Boot Session</th>
                  <th class="px-4 py-3">Device / Host</th>
                  <th class="px-4 py-3">PCR 0 (BIOS)</th>
                  <th class="px-4 py-3">PCR 4 (BootMgr)</th>
                  <th class="px-4 py-3">PCR 7 (SecureBoot)</th>
                  <th class="px-4 py-3">PCR 11 (BitLocker)</th>
                  <th class="px-4 py-3">Result</th>
                  <th class="px-4 py-3">Recorded At</th>
                </tr>
              </thead>
              <tbody id="attest-bootlogs-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading TPM measured boot logs...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Enroll Hardware Baseline Modal -->
      <div id="modal-attestation-new" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full p-6 text-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>🔒</span> Enroll Hardware Supply Chain Baseline
            </h3>
            <button id="modal-attest-close" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>
          <form id="form-attest-baseline" class="space-y-4 mt-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Target Device ID</label>
              <input type="text" id="input-attest-device-id" required placeholder="e.g. dev-01" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500">
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Hostname</label>
                <input type="text" id="input-attest-hostname" required placeholder="e.g. DESKTOP-CORP-01" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">TPM Manufacturer</label>
                <input type="text" id="input-attest-tpm" required value="Infineon Technologies AG" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500">
              </div>
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Motherboard Serial</label>
                <input type="text" id="input-attest-mb" required placeholder="e.g. MB-LPT-998234-A" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Chassis Serial</label>
                <input type="text" id="input-attest-chassis" placeholder="e.g. CHS-CORP-01" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500">
              </div>
            </div>
            <div class="grid grid-cols-3 gap-3 pt-2">
              <label class="flex items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" id="check-attest-secureboot" checked class="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0">
                Secure Boot
              </label>
              <label class="flex items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" id="check-attest-dma" checked class="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0">
                Kernel DMA
              </label>
              <label class="flex items-center gap-2 text-xs text-slate-300">
                <input type="checkbox" id="check-attest-hvci" checked class="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0">
                HVCI Integrity
              </label>
            </div>
            <div class="flex justify-end gap-3 pt-4 border-t border-slate-700">
              <button type="button" id="modal-attest-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold">Save Baseline</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  `;
}

function truncateHash(hash) {
  if (!hash) return '-';
  return hash.substring(0, 10) + '...';
}

window.HardwareAttestationTable = {
  getHeaders: function() {
    const key = localStorage.getItem('fleetKey') || '';
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': key
    };
  },

  render: async function() {
    const container = document.getElementById('attestation-container');
    if (!container) return;
    container.innerHTML = renderHardwareAttestationBlade();

    this.bindEvents();
    await this.loadAll();
  },

  bindEvents: function() {
    document.getElementById('btn-attestation-refresh')?.addEventListener('click', () => this.loadAll());

    const modal = document.getElementById('modal-attestation-new');
    document.getElementById('btn-attestation-new')?.addEventListener('click', () => modal?.classList.remove('hidden'));
    document.getElementById('modal-attest-close')?.addEventListener('click', () => modal?.classList.add('hidden'));
    document.getElementById('modal-attest-cancel')?.addEventListener('click', () => modal?.classList.add('hidden'));

    document.getElementById('form-attest-baseline')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        device_id: document.getElementById('input-attest-device-id').value.trim(),
        hostname: document.getElementById('input-attest-hostname').value.trim(),
        tpm_manufacturer: document.getElementById('input-attest-tpm').value.trim(),
        motherboard_serial: document.getElementById('input-attest-mb').value.trim(),
        chassis_serial: document.getElementById('input-attest-chassis').value.trim() || null,
        secure_boot_enabled: document.getElementById('check-attest-secureboot').checked ? 1 : 0,
        dma_guard_enabled: document.getElementById('check-attest-dma').checked ? 1 : 0,
        hvci_code_integrity: document.getElementById('check-attest-hvci').checked ? 1 : 0
      };

      try {
        const res = await fetch('/api/v1/fleet/hardware-attestation/baselines', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          modal?.classList.add('hidden');
          document.getElementById('form-attest-baseline').reset();
          await this.loadAll();
        } else {
          alert('Failed to save hardware baseline');
        }
      } catch (err) {
        console.error('Error saving baseline:', err);
      }
    });

    document.getElementById('filter-attest-search')?.addEventListener('input', () => this.filterBaselines());
    document.getElementById('filter-attest-status')?.addEventListener('change', () => this.filterBaselines());
  },

  baselinesData: [],

  loadAll: async function() {
    await Promise.all([
      this.loadStats(),
      this.loadBaselines(),
      this.loadBootLogs()
    ]);
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/hardware-attestation/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || data;

      document.getElementById('kpi-attest-total').textContent = stats.totalAttestedDevices || 0;
      document.getElementById('kpi-attest-verified').textContent = stats.verifiedDevices || 0;
      document.getElementById('kpi-attest-mismatches').textContent = stats.componentMismatches || 0;
      document.getElementById('kpi-attest-secureboot').textContent = (stats.secureBootCompliancePct || 0) + '%';
      document.getElementById('kpi-attest-dma').textContent = (stats.dmaGuardCompliancePct || 0) + '%';
      document.getElementById('kpi-attest-pcr-drifts').textContent = stats.pcrDriftsDetected || 0;
    } catch (err) {
      console.error('Failed to load attestation stats:', err);
    }
  },

  loadBaselines: async function() {
    try {
      const res = await fetch('/api/v1/fleet/hardware-attestation/baselines', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.baselinesData = data.baselines || data;
      this.renderBaselines(this.baselinesData);
    } catch (err) {
      console.error('Failed to load baselines:', err);
    }
  },

  filterBaselines: function() {
    const search = (document.getElementById('filter-attest-search')?.value || '').toLowerCase();
    const status = document.getElementById('filter-attest-status')?.value || '';

    const filtered = (this.baselinesData || []).filter(b => {
      const matchesSearch = !search ||
        (b.hostname && b.hostname.toLowerCase().includes(search)) ||
        (b.tpm_manufacturer && b.tpm_manufacturer.toLowerCase().includes(search));
      const matchesStatus = !status || b.verified_status === status;
      return matchesSearch && matchesStatus;
    });

    this.renderBaselines(filtered);
  },

  renderBaselines: function(baselines) {
    const tbody = document.getElementById('attest-baselines-tbody');
    if (!tbody) return;

    if (!baselines || baselines.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No hardware baselines enrolled.</td></tr>';
      return;
    }

    tbody.innerHTML = baselines.map(b => {
      let statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">VERIFIED</span>';
      if (b.verified_status === 'COMPONENT_MISMATCH') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">MISMATCH</span>';
      } else if (b.verified_status === 'TAMPER_ALERT') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">TAMPER ALERT</span>';
      }

      const securityPills = [
        b.secure_boot_enabled ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-300">SB</span>' : '',
        b.dma_guard_enabled ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-indigo-500/20 text-indigo-300">DMA</span>' : '',
        b.hvci_code_integrity ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300">HVCI</span>' : ''
      ].filter(Boolean).join(' ');

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 font-semibold text-slate-200">${b.hostname}</td>
          <td class="px-4 py-3 text-slate-400 font-sans">${b.tpm_manufacturer} (v${b.tpm_spec_version})</td>
          <td class="px-4 py-3 text-slate-300 font-mono text-xs">${b.motherboard_serial || '-'}</td>
          <td class="px-4 py-3 text-slate-400 font-mono text-xs">${b.chassis_serial || '-'}</td>
          <td class="px-4 py-3"><div class="flex items-center gap-1">${securityPills}</div></td>
          <td class="px-4 py-3">${statusBadge}</td>
          <td class="px-4 py-3 text-slate-400">${b.updated_at || b.created_at}</td>
          <td class="px-4 py-3 text-right">
            <button onclick="window.HardwareAttestationTable.deleteBaseline('${b.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-700 text-slate-300 hover:text-white rounded text-xs transition">
              Delete
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  deleteBaseline: async function(id) {
    if (!confirm(`Are you sure you want to delete hardware baseline ${id}?`)) return;
    try {
      const res = await fetch(`/api/v1/fleet/hardware-attestation/baselines/${id}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        await this.loadAll();
      } else {
        alert('Failed to delete baseline');
      }
    } catch (err) {
      console.error('Error deleting baseline:', err);
    }
  },

  loadBootLogs: async function() {
    try {
      const res = await fetch('/api/v1/fleet/hardware-attestation/boot-logs', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.renderBootLogs(data.logs || data);
    } catch (err) {
      console.error('Failed to load boot logs:', err);
    }
  },

  renderBootLogs: function(logs) {
    const tbody = document.getElementById('attest-bootlogs-tbody');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No TPM measured boot logs captured.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(l => {
      let resultBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">PASSED</span>';
      if (l.attestation_result === 'PCR_DRIFT_DETECTED') {
        resultBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">PCR DRIFT</span>';
      }

      return `
        <tr class="hover:bg-slate-800/50 transition font-mono text-xs">
          <td class="px-4 py-3 text-slate-300 font-sans">${l.boot_session_id}</td>
          <td class="px-4 py-3 font-semibold text-slate-200 font-sans">${l.hostname}</td>
          <td class="px-4 py-3 text-cyan-400" title="${l.pcr_0_bios_sha256}">${truncateHash(l.pcr_0_bios_sha256)}</td>
          <td class="px-4 py-3 text-slate-400" title="${l.pcr_4_bootmgr_sha256}">${truncateHash(l.pcr_4_bootmgr_sha256)}</td>
          <td class="px-4 py-3 text-blue-400" title="${l.pcr_7_secureboot_sha256}">${truncateHash(l.pcr_7_secureboot_sha256)}</td>
          <td class="px-4 py-3 text-slate-400" title="${l.pcr_11_bitlocker_sha256}">${truncateHash(l.pcr_11_bitlocker_sha256)}</td>
          <td class="px-4 py-3">${resultBadge}</td>
          <td class="px-4 py-3 text-slate-400 font-sans">${l.recorded_at}</td>
        </tr>
      `;
    }).join('');
  }
};
