/**
 * LocalPilot Fleet — Software License Optimization & Enterprise Metering Blade
 * dashboard/js/components/licenseOptimizationTable.js
 *
 * Provides real-time SAM analytics, SaaS/Desktop FinOps metrics, seat allocation management,
 * foreground process runtime metering, and automated shelfware reclamation.
 */

function renderLicenseOptimizationBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-2xl border border-emerald-500/30">💳</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                Software License Optimization &amp; Metering
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">SAM &amp; FinOps</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Automated software asset management, seat entitlement tracking, process foreground metering, and shelfware cost recovery</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-sam-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-sam-shelfware" class="px-3 py-2 bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-amber-500/40">
            <span>🧹</span> Scan Shelfware
          </button>
          <button id="btn-sam-new-license" class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-emerald-500/20">
            <span>➕</span> Add License
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4" id="sam-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Licenses</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">📑</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-sam-total-licenses">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Seats</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">👥</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-sam-total-seats">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Utilization</p>
            <span class="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-md text-sm">📊</span>
          </div>
          <p class="text-2xl font-bold text-indigo-400 mt-2" id="kpi-sam-utilization">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Annual Spend</p>
            <span class="p-1.5 bg-purple-500/20 text-purple-400 rounded-md text-sm">💵</span>
          </div>
          <p class="text-2xl font-bold text-purple-400 mt-2" id="kpi-sam-annual-spend">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Shelfware Recovery</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">💰</span>
          </div>
          <p class="text-2xl font-bold text-amber-400 mt-2" id="kpi-sam-savings">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Shelfware Flags</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">⚠️</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-sam-shelfware-count">-</p>
        </div>
      </div>

      <!-- Main Layout: Stacked Cards -->
      <div class="grid grid-cols-1 gap-6">
        <!-- Software Licenses Catalog Card -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">📦</span>
              <h3 class="font-semibold text-slate-200">Software Licenses &amp; Entitlements Catalog</h3>
            </div>
            <div class="flex items-center gap-2">
              <input type="text" id="filter-sam-search" placeholder="Search product or vendor..." class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
              <select id="filter-sam-type" class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
                <option value="">All Types</option>
                <option value="SUBSCRIPTION">SUBSCRIPTION</option>
                <option value="PER_SEAT">PER_SEAT</option>
                <option value="PERPETUAL">PERPETUAL</option>
                <option value="CONCURRENT">CONCURRENT</option>
                <option value="SITE_LICENSE">SITE_LICENSE</option>
              </select>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Product Name</th>
                  <th class="px-4 py-3">Vendor</th>
                  <th class="px-4 py-3">License Type</th>
                  <th class="px-4 py-3">Seat Utilization</th>
                  <th class="px-4 py-3">Cost / Seat</th>
                  <th class="px-4 py-3">Billing</th>
                  <th class="px-4 py-3">Expiration</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="sam-licenses-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading software license entitlements...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Seat Allocations & Shelfware Recovery Table -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">👥</span>
              <h3 class="font-semibold text-slate-200">Device Seat Allocations &amp; Shelfware Reclamation</h3>
            </div>
            <div class="flex items-center gap-2">
              <select id="filter-sam-alloc-status" class="px-3 py-1.5 bg-slate-900/60 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
                <option value="">All Allocation Statuses</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="FLAGGED_SHELFWARE">FLAGGED_SHELFWARE</option>
                <option value="RECLAIMED">RECLAIMED</option>
              </select>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Allocation ID</th>
                  <th class="px-4 py-3">Licensed Product</th>
                  <th class="px-4 py-3">Assigned Hostname</th>
                  <th class="px-4 py-3">Assigned User</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Last Active</th>
                  <th class="px-4 py-3">Reclamation Note</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="sam-allocations-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading seat allocations...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Software Usage Metering Telemetry -->
        <div class="bg-slate-800/70 rounded-xl border border-slate-700/60 shadow-lg overflow-hidden">
          <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-800/40">
            <div class="flex items-center gap-2">
              <span class="text-lg">⏱️</span>
              <h3 class="font-semibold text-slate-200">Process Usage &amp; Foreground Metering Telemetry</h3>
            </div>
            <div class="text-xs text-slate-400">
              Live telemetry tracking active vs idle desktop application time
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-900/60 text-slate-400 border-b border-slate-700/60">
                <tr>
                  <th class="px-4 py-3">Process Name</th>
                  <th class="px-4 py-3">Product Name</th>
                  <th class="px-4 py-3">Device / Host</th>
                  <th class="px-4 py-3">Total Runtime</th>
                  <th class="px-4 py-3">Foreground Usage</th>
                  <th class="px-4 py-3">Launch Count</th>
                  <th class="px-4 py-3">Last Launched</th>
                  <th class="px-4 py-3">Shelfware Risk</th>
                </tr>
              </thead>
              <tbody id="sam-metering-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr>
                  <td colspan="8" class="text-center py-8 text-slate-500">Loading process usage telemetry...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Add License Modal -->
      <div id="modal-sam-license-new" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full p-6 text-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>💳</span> Register Software License Entitlement
            </h3>
            <button id="modal-sam-close" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>
          <form id="form-sam-license" class="space-y-4 mt-4">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Product Name</label>
              <input type="text" id="input-sam-product" required placeholder="e.g. AutoCAD 2026 Commercial" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Vendor</label>
                <input type="text" id="input-sam-vendor" required placeholder="e.g. Autodesk" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">License Type</label>
                <select id="select-sam-type" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
                  <option value="SUBSCRIPTION">SUBSCRIPTION</option>
                  <option value="PER_SEAT">PER_SEAT</option>
                  <option value="PERPETUAL">PERPETUAL</option>
                  <option value="CONCURRENT">CONCURRENT</option>
                  <option value="SITE_LICENSE">SITE_LICENSE</option>
                </select>
              </div>
            </div>
            <div class="grid grid-cols-3 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Total Seats</label>
                <input type="number" id="input-sam-seats" required value="10" min="1" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Cost / Seat ($)</label>
                <input type="number" step="0.01" id="input-sam-cost" required value="499.00" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Billing</label>
                <select id="select-sam-billing" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
                  <option value="ANNUAL">ANNUAL</option>
                  <option value="MONTHLY">MONTHLY</option>
                  <option value="PERPETUAL">PERPETUAL</option>
                </select>
              </div>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">License / Activation Key</label>
              <input type="text" id="input-sam-key" placeholder="e.g. XXXX-XXXX-XXXX-XXXX" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Expiration Date</label>
              <input type="date" id="input-sam-exp" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
            </div>
            <div class="flex justify-end gap-3 pt-4 border-t border-slate-700">
              <button type="button" id="modal-sam-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold">Save Entitlement</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Allocate Seat Modal -->
      <div id="modal-sam-allocate" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center hidden">
        <div class="bg-slate-800 border border-slate-700 rounded-xl shadow-2xl max-w-md w-full p-6 text-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-700">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>👥</span> Allocate Software Seat
            </h3>
            <button id="modal-alloc-close" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>
          <form id="form-sam-allocate" class="space-y-4 mt-4">
            <input type="hidden" id="input-alloc-license-id">
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Target Product</label>
              <input type="text" id="input-alloc-product-name" readonly class="w-full px-3 py-2 bg-slate-900/60 border border-slate-700 rounded-lg text-sm text-slate-300 cursor-not-allowed">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Device ID / Hostname</label>
              <input type="text" id="input-alloc-device-id" required placeholder="e.g. dev-01 or hostname" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Assigned User Principal</label>
              <input type="email" id="input-alloc-user" placeholder="e.g. user@localpilot.corp" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500">
            </div>
            <div class="flex justify-end gap-3 pt-4 border-t border-slate-700">
              <button type="button" id="modal-alloc-cancel" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold">Confirm Allocation</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  `;
}

function formatHours(seconds) {
  if (!seconds || seconds === 0) return '0.0h';
  return (seconds / 3600).toFixed(1) + 'h';
}

window.LicenseOptimizationTable = {
  getHeaders: function() {
    const key = localStorage.getItem('fleetKey') || '';
    return {
      'Content-Type': 'application/json',
      'x-fleet-key': key
    };
  },

  render: async function() {
    const container = document.getElementById('sam-container');
    if (!container) return;
    container.innerHTML = renderLicenseOptimizationBlade();

    this.bindEvents();
    await this.loadAll();
  },

  bindEvents: function() {
    document.getElementById('btn-sam-refresh')?.addEventListener('click', () => this.loadAll());

    const modalLic = document.getElementById('modal-sam-license-new');
    document.getElementById('btn-sam-new-license')?.addEventListener('click', () => modalLic?.classList.remove('hidden'));
    document.getElementById('modal-sam-close')?.addEventListener('click', () => modalLic?.classList.add('hidden'));
    document.getElementById('modal-sam-cancel')?.addEventListener('click', () => modalLic?.classList.add('hidden'));

    const modalAlloc = document.getElementById('modal-sam-allocate');
    document.getElementById('modal-alloc-close')?.addEventListener('click', () => modalAlloc?.classList.add('hidden'));
    document.getElementById('modal-alloc-cancel')?.addEventListener('click', () => modalAlloc?.classList.add('hidden'));

    document.getElementById('btn-sam-shelfware')?.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/v1/fleet/sam/reclaim-shelfware', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify({ inactive_days_threshold: 30 })
        });
        if (res.ok) {
          const data = await res.json();
          alert(`Shelfware scan complete! Flagged ${data.result.flaggedCount} unused allocations with $${data.result.potentialSavingsUsd} potential savings.`);
          await this.loadAll();
        }
      } catch (err) {
        console.error('Error scanning shelfware:', err);
      }
    });

    document.getElementById('form-sam-license')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        product_name: document.getElementById('input-sam-product').value.trim(),
        vendor: document.getElementById('input-sam-vendor').value.trim(),
        license_type: document.getElementById('select-sam-type').value,
        total_seats: parseInt(document.getElementById('input-sam-seats').value, 10) || 1,
        cost_per_seat_usd: parseFloat(document.getElementById('input-sam-cost').value) || 0,
        billing_cycle: document.getElementById('select-sam-billing').value,
        license_key: document.getElementById('input-sam-key').value.trim() || null,
        expiration_date: document.getElementById('input-sam-exp').value || null
      };

      try {
        const res = await fetch('/api/v1/fleet/sam/licenses', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          modalLic?.classList.add('hidden');
          document.getElementById('form-sam-license').reset();
          await this.loadAll();
        } else {
          alert('Failed to register license entitlement');
        }
      } catch (err) {
        console.error('Error saving license:', err);
      }
    });

    document.getElementById('form-sam-allocate')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        license_id: document.getElementById('input-alloc-license-id').value,
        device_id: document.getElementById('input-alloc-device-id').value.trim(),
        assigned_user: document.getElementById('input-alloc-user').value.trim() || null
      };

      try {
        const res = await fetch('/api/v1/fleet/sam/allocations', {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          modalAlloc?.classList.add('hidden');
          document.getElementById('form-sam-allocate').reset();
          await this.loadAll();
        } else {
          alert('Failed to allocate seat: ' + res.statusText);
        }
      } catch (err) {
        console.error('Error allocating seat:', err);
      }
    });

    document.getElementById('filter-sam-search')?.addEventListener('input', () => this.filterLicenses());
    document.getElementById('filter-sam-type')?.addEventListener('change', () => this.filterLicenses());
    document.getElementById('filter-sam-alloc-status')?.addEventListener('change', () => this.filterAllocations());
  },

  licensesData: [],
  allocationsData: [],

  loadAll: async function() {
    await Promise.all([
      this.loadStats(),
      this.loadLicenses(),
      this.loadAllocations(),
      this.loadMetering()
    ]);
  },

  loadStats: async function() {
    try {
      const res = await fetch('/api/v1/fleet/sam/stats', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      const stats = data.stats || data;

      document.getElementById('kpi-sam-total-licenses').textContent = stats.totalLicenses || 0;
      document.getElementById('kpi-sam-total-seats').textContent = stats.totalSeats || 0;
      document.getElementById('kpi-sam-utilization').textContent = (stats.seatUtilizationPct || 0) + '%';
      document.getElementById('kpi-sam-annual-spend').textContent = '$' + (stats.totalAnnualSpendUsd || 0).toLocaleString();
      document.getElementById('kpi-sam-savings').textContent = '$' + (stats.potentialShelfwareSavingsUsd || 0).toLocaleString();
      document.getElementById('kpi-sam-shelfware-count').textContent = stats.shelfwareCount || 0;
    } catch (err) {
      console.error('Failed to load SAM stats:', err);
    }
  },

  loadLicenses: async function() {
    try {
      const res = await fetch('/api/v1/fleet/sam/licenses', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.licensesData = data.licenses || data;
      this.renderLicenses(this.licensesData);
    } catch (err) {
      console.error('Failed to load licenses:', err);
    }
  },

  filterLicenses: function() {
    const search = (document.getElementById('filter-sam-search')?.value || '').toLowerCase();
    const type = document.getElementById('filter-sam-type')?.value || '';

    const filtered = (this.licensesData || []).filter(l => {
      const matchesSearch = !search ||
        (l.product_name && l.product_name.toLowerCase().includes(search)) ||
        (l.vendor && l.vendor.toLowerCase().includes(search));
      const matchesType = !type || l.license_type === type;
      return matchesSearch && matchesType;
    });

    this.renderLicenses(filtered);
  },

  renderLicenses: function(licenses) {
    const tbody = document.getElementById('sam-licenses-tbody');
    if (!tbody) return;

    if (!licenses || licenses.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No software licenses match filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = licenses.map(l => {
      const util = l.utilization_pct || 0;
      let barColor = 'bg-emerald-500';
      if (util >= 95) barColor = 'bg-rose-500';
      else if (util >= 80) barColor = 'bg-amber-500';

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 font-medium text-slate-200">${l.product_name}</td>
          <td class="px-4 py-3 text-slate-400 font-sans">${l.vendor}</td>
          <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-xs bg-slate-700 text-slate-300 font-semibold">${l.license_type}</span></td>
          <td class="px-4 py-3">
            <div class="flex items-center gap-2">
              <span class="text-xs text-slate-300 w-16">${l.allocated_seats} / ${l.total_seats}</span>
              <div class="w-20 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                <div class="${barColor} h-1.5 rounded-full" style="width: ${Math.min(100, util)}%"></div>
              </div>
              <span class="text-xs text-slate-400">${util}%</span>
            </div>
          </td>
          <td class="px-4 py-3 text-emerald-400 font-semibold">$${l.cost_per_seat_usd ? l.cost_per_seat_usd.toFixed(2) : '0.00'}</td>
          <td class="px-4 py-3 text-slate-400">${l.billing_cycle}</td>
          <td class="px-4 py-3 text-slate-400">${l.expiration_date ? l.expiration_date.split('T')[0] : 'Perpetual'}</td>
          <td class="px-4 py-3 text-right">
            <div class="flex items-center justify-end gap-1.5">
              <button onclick="window.LicenseOptimizationTable.openAllocate('${l.id}', '${encodeURIComponent(l.product_name)}')" class="px-2 py-1 bg-emerald-600/30 hover:bg-emerald-600 text-emerald-300 hover:text-white rounded text-xs transition">
                + Seat
              </button>
              <button onclick="window.LicenseOptimizationTable.deleteLicense('${l.id}')" class="px-2 py-1 bg-slate-700 hover:bg-rose-700 text-slate-300 hover:text-white rounded text-xs transition">
                Delete
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  },

  openAllocate: function(licenseId, productNameEnc) {
    const productName = decodeURIComponent(productNameEnc);
    document.getElementById('input-alloc-license-id').value = licenseId;
    document.getElementById('input-alloc-product-name').value = productName;
    document.getElementById('modal-sam-allocate')?.classList.remove('hidden');
  },

  deleteLicense: async function(id) {
    if (!confirm(`Are you sure you want to delete license ${id} and revoke all seat allocations?`)) return;
    try {
      const res = await fetch(`/api/v1/fleet/sam/licenses/${id}`, {
        method: 'DELETE',
        headers: this.getHeaders()
      });
      if (res.ok) {
        await this.loadAll();
      } else {
        alert('Failed to delete license entitlement');
      }
    } catch (err) {
      console.error('Error deleting license:', err);
    }
  },

  loadAllocations: async function() {
    try {
      const res = await fetch('/api/v1/fleet/sam/allocations', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.allocationsData = data.allocations || data;
      this.renderAllocations(this.allocationsData);
    } catch (err) {
      console.error('Failed to load allocations:', err);
    }
  },

  filterAllocations: function() {
    const status = document.getElementById('filter-sam-alloc-status')?.value || '';
    const filtered = (this.allocationsData || []).filter(a => !status || a.status === status);
    this.renderAllocations(filtered);
  },

  renderAllocations: function(allocations) {
    const tbody = document.getElementById('sam-allocations-tbody');
    if (!tbody) return;

    if (!allocations || allocations.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No seat allocations found.</td></tr>';
      return;
    }

    tbody.innerHTML = allocations.map(a => {
      let statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ACTIVE</span>';
      if (a.status === 'FLAGGED_SHELFWARE') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">SHELFWARE</span>';
      } else if (a.status === 'RECLAIMED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-400">RECLAIMED</span>';
      }

      const isReclaimable = a.status !== 'RECLAIMED';

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 text-slate-400">${a.id}</td>
          <td class="px-4 py-3 font-medium text-slate-200">${a.product_name || a.license_id}</td>
          <td class="px-4 py-3 text-slate-300 font-semibold">${a.hostname}</td>
          <td class="px-4 py-3 text-slate-400">${a.assigned_user || 'Unassigned'}</td>
          <td class="px-4 py-3">${statusBadge}</td>
          <td class="px-4 py-3 text-slate-400">${a.last_used_at || 'Never'}</td>
          <td class="px-4 py-3 text-slate-400 font-sans text-xs">${a.reclamation_reason || '-'}</td>
          <td class="px-4 py-3 text-right">
            ${isReclaimable ? `
              <button onclick="window.LicenseOptimizationTable.reclaimSeat('${a.id}')" class="px-2.5 py-1 bg-amber-600/30 hover:bg-amber-600 text-amber-300 hover:text-white rounded text-xs transition">
                Reclaim
              </button>
            ` : '<span class="text-xs text-slate-500 font-sans">Done</span>'}
          </td>
        </tr>
      `;
    }).join('');
  },

  reclaimSeat: async function(allocationId) {
    if (!confirm(`Reclaim this license seat and free entitlement quota?`)) return;
    try {
      const res = await fetch(`/api/v1/fleet/sam/allocations/${allocationId}/reclaim`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ reason: 'Admin Reclaimed from Console' })
      });
      if (res.ok) {
        await this.loadAll();
      } else {
        alert('Failed to reclaim seat');
      }
    } catch (err) {
      console.error('Error reclaiming seat:', err);
    }
  },

  loadMetering: async function() {
    try {
      const res = await fetch('/api/v1/fleet/sam/metering', { headers: this.getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      this.renderMetering(data.metering || data);
    } catch (err) {
      console.error('Failed to load metering:', err);
    }
  },

  renderMetering: function(metering) {
    const tbody = document.getElementById('sam-metering-tbody');
    if (!tbody) return;

    if (!metering || metering.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-6 text-slate-500">No process runtime metering telemetry captured.</td></tr>';
      return;
    }

    tbody.innerHTML = metering.map(m => {
      const shelfwareBadge = m.is_shelfware ?
        '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-400">HIGH RISK</span>' :
        '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400">NORMAL</span>';

      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="px-4 py-3 font-semibold text-emerald-400">${m.process_name}</td>
          <td class="px-4 py-3 font-medium text-slate-200">${m.product_name || '-'}</td>
          <td class="px-4 py-3 text-slate-300">${m.hostname}</td>
          <td class="px-4 py-3 text-slate-300">${formatHours(m.total_runtime_seconds)}</td>
          <td class="px-4 py-3 text-indigo-300 font-semibold">${formatHours(m.foreground_seconds)}</td>
          <td class="px-4 py-3 text-slate-400">${m.launch_count}</td>
          <td class="px-4 py-3 text-slate-400">${m.last_launched_at}</td>
          <td class="px-4 py-3">${shelfwareBadge}</td>
        </tr>
      `;
    }).join('');
  }
};
