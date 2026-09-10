/**
 * LocalPilot Fleet — Multi-Tenancy (MSP Organizations, Sites & Collections) & Database HA Blade
 * dashboard/js/components/multiTenancyTable.js
 *
 * Dimension 6: Enterprise Governance, RBAC & Multi-Tenancy
 * Section 2: Transport Protocol, Real-Time Push & Scale (P4 Database HA)
 */

import { api } from '../api.js';

export function renderMultiTenancyBlade() {
  const container = document.getElementById('tab-tenancy');
  if (!container) return;

  container.innerHTML = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <span class="text-amber-400">🏢</span> Multi-Tenancy, MSP Scopes & Database HA
          </h2>
          <p class="text-sm text-slate-400 mt-1">
            Logical boundary separation of Organizations, Branch Office Sites, and Scoped Device Collections with PostgreSQL high-concurrency HA readiness.
          </p>
        </div>
        <div class="flex items-center gap-2">
          <button id="btn-refresh-tenancy" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-sm font-medium transition flex items-center gap-1.5 border border-slate-700">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-create-org" class="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-sm font-medium transition flex items-center gap-1.5 shadow">
            <span>➕</span> New Organization
          </button>
          <button id="btn-create-site" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-sm font-medium transition flex items-center gap-1.5 border border-slate-700">
            <span>📍</span> Add Site
          </button>
        </div>
      </div>

      <!-- KPI Cards Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Organizations</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-tenancy-active-orgs" class="text-2xl font-bold text-amber-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">MSP Isolated</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-tenancy-seats">Allocated Seats: --</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Branch Offices & Sites</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-tenancy-total-sites" class="text-2xl font-bold text-sky-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">Subnet Scoped</span>
          </div>
          <div class="text-xs text-slate-500 mt-1">Bandwidth Throttled</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scoped Collections</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-tenancy-total-cols" class="text-2xl font-bold text-emerald-400">--</span>
            <span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">Ensembles</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-tenancy-dynamic-cols">Dynamic Rules: --</div>
        </div>

        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow">
          <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Database HA Architecture</div>
          <div class="mt-2 flex items-baseline justify-between">
            <span id="kpi-tenancy-db-dialect" class="text-2xl font-bold text-purple-400">SQLite / PG</span>
            <span class="text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">HA Ready</span>
          </div>
          <div class="text-xs text-slate-500 mt-1" id="kpi-tenancy-concurrency">100,000+ Nodes Support</div>
        </div>
      </div>

      <!-- Navigation Sub-Tabs -->
      <div class="border-b border-slate-800 flex gap-4 text-sm font-medium">
        <button id="subtab-btn-orgs" class="pb-2 border-b-2 border-amber-500 text-amber-400 transition flex items-center gap-1.5">
          <span>🏢</span> Organizations (Tenants)
        </button>
        <button id="subtab-btn-sites" class="pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5">
          <span>📍</span> Sites & Branch Offices
        </button>
        <button id="subtab-btn-cols" class="pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5">
          <span>🏷️</span> Scoped Device Collections
        </button>
        <button id="subtab-btn-dbha" class="pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5">
          <span>⚡</span> Database HA & Engine Health
        </button>
      </div>

      <!-- Subtab 1: Organizations -->
      <div id="subtab-pane-orgs" class="space-y-4">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Organization Name</th>
                  <th class="px-4 py-3">Tenant Slug</th>
                  <th class="px-4 py-3">Primary Domain</th>
                  <th class="px-4 py-3">License Tier</th>
                  <th class="px-4 py-3">Seat Quota</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="orgs-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="7" class="px-4 py-8 text-center text-slate-500">Loading organizations...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Subtab 2: Sites -->
      <div id="subtab-pane-sites" class="space-y-4 hidden">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Site / Branch Name</th>
                  <th class="px-4 py-3">Organization</th>
                  <th class="px-4 py-3">Location</th>
                  <th class="px-4 py-3">Subnet Boundaries</th>
                  <th class="px-4 py-3">Bandwidth Cap</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="sites-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading sites...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Subtab 3: Scoped Collections -->
      <div id="subtab-pane-cols" class="space-y-4 hidden">
        <div class="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th class="px-4 py-3">Collection Name</th>
                  <th class="px-4 py-3">Organization</th>
                  <th class="px-4 py-3">Assigned Site</th>
                  <th class="px-4 py-3">Type</th>
                  <th class="px-4 py-3">Dynamic Rule</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="collections-table-body" class="divide-y divide-slate-800">
                <tr>
                  <td colspan="6" class="px-4 py-8 text-center text-slate-500">Loading scoped collections...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Subtab 4: Database HA & Engine Health -->
      <div id="subtab-pane-dbha" class="space-y-4 hidden">
        <div class="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow space-y-6">
          <div class="border-b border-slate-800 pb-4">
            <h3 class="text-base font-bold text-white flex items-center gap-2">
              <span class="text-purple-400">⚡</span> Database High-Availability Engine Posture
            </h3>
            <p class="text-xs text-slate-400 mt-1">
              Architecture abstraction layer allowing LocalPilot Fleet to operate seamlessly across on-premises native SQLite and enterprise PostgreSQL Always-On clusters.
            </p>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div class="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
              <div class="text-slate-500 uppercase font-bold">Driver Dialect</div>
              <div id="dbha-dialect" class="text-sm font-bold text-white">node:sqlite (WAL Mode)</div>
              <div class="text-[11px] text-slate-400">PG Adapter: Translation Layer Active</div>
            </div>

            <div class="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
              <div class="text-slate-500 uppercase font-bold">Query Ping Latency</div>
              <div id="dbha-latency" class="text-sm font-bold text-emerald-400">&lt; 1 ms</div>
              <div class="text-[11px] text-slate-400">In-Process Fast Memory Bus</div>
            </div>

            <div class="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
              <div class="text-slate-500 uppercase font-bold">Connection Pool Health</div>
              <div id="dbha-pool" class="text-sm font-bold text-indigo-400">1 Active / 4 Idle</div>
              <div class="text-[11px] text-slate-400">Stateless Gateway Scalable</div>
            </div>
          </div>

          <div class="bg-slate-950 p-4 rounded border border-slate-800">
            <div class="text-xs font-semibold text-slate-300 mb-2">Automated Dialect Translation Example (SQLite $\to$ PostgreSQL)</div>
            <pre class="text-[11px] font-mono text-purple-300 bg-slate-900 p-3 rounded overflow-x-auto">
-- Source SQLite:
INSERT INTO events (id, created_at) VALUES ('ev-1', DATETIME('now'));

-- Translated PostgreSQL (ANSI SQL):
INSERT INTO events (id, created_at) VALUES ('ev-1', NOW());</pre>
          </div>
        </div>
      </div>
    </div>
  `;

  setupMultiTenancyEvents();
  loadMultiTenancyData();
}

function setupMultiTenancyEvents() {
  document.getElementById('btn-refresh-tenancy')?.addEventListener('click', loadMultiTenancyData);

  const subtabs = [
    { btn: 'subtab-btn-orgs', pane: 'subtab-pane-orgs' },
    { btn: 'subtab-btn-sites', pane: 'subtab-pane-sites' },
    { btn: 'subtab-btn-cols', pane: 'subtab-pane-cols' },
    { btn: 'subtab-btn-dbha', pane: 'subtab-pane-dbha' }
  ];

  subtabs.forEach(tab => {
    document.getElementById(tab.btn)?.addEventListener('click', () => {
      subtabs.forEach(t => {
        const b = document.getElementById(t.btn);
        const p = document.getElementById(t.pane);
        if (t.btn === tab.btn) {
          b.className = 'pb-2 border-b-2 border-amber-500 text-amber-400 transition flex items-center gap-1.5';
          p.classList.remove('hidden');
        } else {
          b.className = 'pb-2 border-b-2 border-transparent text-slate-400 hover:text-slate-300 transition flex items-center gap-1.5';
          p.classList.add('hidden');
        }
      });
    });
  });
}

async function loadMultiTenancyData() {
  try {
    const stats = await api.getMultiTenancyStats();
    if (stats) {
      document.getElementById('kpi-tenancy-active-orgs').innerText = stats.activeOrganizations;
      document.getElementById('kpi-tenancy-seats').innerText = `Allocated Seats: ${stats.totalAllocatedSeats.toLocaleString()}`;
      document.getElementById('kpi-tenancy-total-sites').innerText = stats.totalSites;
      document.getElementById('kpi-tenancy-total-cols').innerText = stats.totalScopedCollections;
      document.getElementById('kpi-tenancy-dynamic-cols').innerText = `Dynamic Rules: ${stats.dynamicCollections}`;
    }

    const orgsRes = await api.getOrganizations();
    renderOrgsTable(orgsRes?.organizations || []);

    const sitesRes = await api.getSites();
    renderSitesTable(sitesRes?.sites || []);

    const colsRes = await api.getScopedCollections();
    renderCollectionsTable(colsRes?.collections || []);

    const health = await api.getDatabaseHealth();
    if (health) {
      document.getElementById('dbha-dialect').innerText = `${health.dialect.toUpperCase()} (Dialect Adapter Active)`;
      document.getElementById('dbha-latency').innerText = `${health.latencyMs} ms`;
      document.getElementById('dbha-pool').innerText = `${health.pool.active} Active / ${health.pool.idle} Idle (Max: ${health.pool.max})`;
    }
  } catch (err) {
    console.error('Failed to load multi-tenancy data:', err);
  }
}

function renderOrgsTable(orgs) {
  const tbody = document.getElementById('orgs-table-body');
  if (!tbody) return;

  if (orgs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500">No organizations found.</td></tr>`;
    return;
  }

  tbody.innerHTML = orgs.map(org => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="px-4 py-3 font-semibold text-white">${org.name}</td>
      <td class="px-4 py-3 font-mono text-amber-400 text-xs">${org.slug}</td>
      <td class="px-4 py-3 text-slate-400 text-xs">${org.domain || 'N/A'}</td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${org.license_tier === 'ENTERPRISE' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-slate-800 text-slate-300'}">
          ${org.license_tier}
        </span>
      </td>
      <td class="px-4 py-3 text-slate-300">${org.max_devices} nodes</td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold uppercase ${org.is_active ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-500'}">
          ${org.is_active ? 'ACTIVE' : 'SUSPENDED'}
        </span>
      </td>
      <td class="px-4 py-3 text-right">
        ${org.slug !== 'default' ? `
          <button onclick="window.deleteOrg('${org.id}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 rounded text-xs border border-rose-800">
            Delete
          </button>
        ` : '<span class="text-[10px] text-slate-500 font-mono">System Default</span>'}
      </td>
    </tr>
  `).join('');
}

function renderSitesTable(sites) {
  const tbody = document.getElementById('sites-table-body');
  if (!tbody) return;

  if (sites.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No sites configured.</td></tr>`;
    return;
  }

  tbody.innerHTML = sites.map(s => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="px-4 py-3 font-semibold text-white">${s.name}</td>
      <td class="px-4 py-3 text-amber-400 text-xs font-mono">${s.org_name || s.org_id}</td>
      <td class="px-4 py-3 text-slate-300 text-xs">${s.city || 'N/A'}, ${s.country}</td>
      <td class="px-4 py-3 font-mono text-[11px] text-sky-300">
        ${(s.subnet_cidrs || []).join(', ') || 'Global'}
      </td>
      <td class="px-4 py-3 text-slate-400 text-xs">${s.bandwidth_cap_mbps} Mbps</td>
      <td class="px-4 py-3 text-right">
        <button onclick="window.deleteSite('${s.id}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 rounded text-xs border border-rose-800">
          Delete
        </button>
      </td>
    </tr>
  `).join('');
}

function renderCollectionsTable(cols) {
  const tbody = document.getElementById('collections-table-body');
  if (!tbody) return;

  if (cols.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No scoped collections found.</td></tr>`;
    return;
  }

  tbody.innerHTML = cols.map(c => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="px-4 py-3 font-semibold text-white">
        <div>${c.name}</div>
        <div class="text-[10px] text-slate-500">${c.description || ''}</div>
      </td>
      <td class="px-4 py-3 text-amber-400 text-xs font-mono">${c.org_name || c.org_id}</td>
      <td class="px-4 py-3 text-slate-400 text-xs">${c.site_name || 'All Sites'}</td>
      <td class="px-4 py-3">
        <span class="text-[10px] px-2 py-0.5 rounded font-bold ${c.is_dynamic ? 'bg-purple-950 text-purple-300 border border-purple-800' : 'bg-slate-800 text-slate-400'}">
          ${c.is_dynamic ? 'DYNAMIC' : 'STATIC'}
        </span>
      </td>
      <td class="px-4 py-3 font-mono text-[11px] text-emerald-300">${c.membership_rule || 'Static Membership'}</td>
      <td class="px-4 py-3 text-right">
        <button onclick="window.deleteScopedCollection('${c.id}')" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 rounded text-xs border border-rose-800">
          Delete
        </button>
      </td>
    </tr>
  `).join('');
}

window.deleteOrg = async function(id) {
  if (!confirm(`Are you sure you want to delete organization '${id}'?`)) return;
  try {
    await api.deleteOrganization(id);
    loadMultiTenancyData();
  } catch (err) {
    alert(`Failed to delete organization: ${err.message}`);
  }
};

window.deleteSite = async function(id) {
  if (!confirm(`Are you sure you want to delete site '${id}'?`)) return;
  try {
    await api.deleteSite(id);
    loadMultiTenancyData();
  } catch (err) {
    alert(`Failed to delete site: ${err.message}`);
  }
};

window.deleteScopedCollection = async function(id) {
  if (!confirm(`Are you sure you want to delete scoped collection '${id}'?`)) return;
  try {
    await api.deleteScopedCollection(id);
    loadMultiTenancyData();
  } catch (err) {
    alert(`Failed to delete scoped collection: ${err.message}`);
  }
};

window.MultiTenancyTable = {
  render: renderMultiTenancyBlade
};
