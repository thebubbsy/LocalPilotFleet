/**
 * LocalPilot Fleet — Microsoft Intune Suite Enterprise Application Management & Company Portal Blade
 * dashboard/js/components/companyPortalTable.js
 */

(function () {
  'use strict';

  let currentSubTab = 'catalog'; // 'catalog' | 'requests' | 'licenses'
  let cachedStats = null;
  let cachedApps = [];
  let cachedRequests = [];
  let cachedLicenses = [];
  let searchQuery = '';
  let selectedCategory = '';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getStatusBadge(status) {
    const s = String(status || 'PENDING_APPROVAL').toUpperCase();
    if (s === 'COMPLETED' || s === 'ACTIVE') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ ' + esc(s) + '</span>';
    } else if (s === 'APPROVED' || s === 'QUEUED' || s === 'INSTALLING') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;font-weight:700;">🔄 ' + esc(s) + '</span>';
    } else if (s === 'PENDING_APPROVAL') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⏳ PENDING REVIEW</span>';
    } else if (s === 'REJECTED' || s === 'FAILED' || s === 'REVOKED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">❌ ' + esc(s) + '</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9CA3AF;">' + esc(s) + '</span>';
  }

  function getLicenseBadge(type, available) {
    if (type === 'FREE' || type === 'OPEN_SOURCE') {
      return '<span class="badge" style="background:rgba(16,185,129,0.12);color:#10B981;font-size:11px;">🆓 ' + esc(type) + '</span>';
    }
    const availText = available === 'UNLIMITED' ? 'Unlimited' : available + ' seats left';
    return '<span class="badge" style="background:rgba(139,92,246,0.12);color:#8B5CF6;font-size:11px;">🔑 ' + esc(type) + ' (' + availText + ')</span>';
  }

  async function loadData() {
    try {
      const [stats, catalogData, requestsData, licensesData] = await Promise.all([
        window.FleetAPI.getEamStats().catch(() => ({})),
        window.FleetAPI.getEamCatalog().catch(() => ({ apps: [] })),
        window.FleetAPI.getEamRequests().catch(() => ({ requests: [] })),
        window.FleetAPI.getEamLicenses().catch(() => ({ licenses: [] }))
      ]);

      cachedStats = stats;
      cachedApps = catalogData.apps || [];
      cachedRequests = requestsData.requests || [];
      cachedLicenses = licensesData.licenses || [];
    } catch (e) {
      console.error('Failed to load Enterprise App data:', e);
    }
  }

  async function render(container) {
    if (!container) {
      container = document.getElementById('tab-companyportal');
    }
    if (!container) return;

    container.innerHTML = '<div style="padding:2rem;text-align:center;color:#94a3b8;"><div class="spinner"></div> Loading Enterprise Application Catalog...</div>';

    await loadData();

    const stats = cachedStats || {};
    const totalApps = stats.total_apps || cachedApps.length || 0;
    const selfServiceApps = stats.self_service_apps || 0;
    const allocatedLicenses = stats.allocated_licenses || 0;
    const totalLicenses = stats.total_licenses || 0;
    const pendingRequests = stats.pending_requests || 0;

    let html = `
      <div class="blade-header" style="margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
          <div>
            <h1 style="font-size:1.5rem;font-weight:700;color:#f8fafc;margin:0 0 0.25rem 0;display:flex;align-items:center;gap:0.5rem;">
              <span>📦</span> Enterprise App Management & Company Portal
            </h1>
            <p style="color:#94a3b8;margin:0;font-size:0.875rem;">
              Curated enterprise application catalog, private WinGet repository, self-service software portal requests, and software license seat governance.
            </p>
          </div>
          <div style="display:flex;gap:0.75rem;">
            <button class="btn btn-secondary" id="btn-refresh-portal" style="display:flex;align-items:center;gap:0.4rem;">
              <span>🔄</span> Refresh
            </button>
            <button class="btn btn-primary" id="btn-add-app" style="display:flex;align-items:center;gap:0.4rem;background:#3B82F6;">
              <span>➕</span> Add Enterprise App
            </button>
          </div>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:1.5rem;">
        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Enterprise Catalog Apps</div>
          <div style="font-size:1.8rem;font-weight:700;color:#38bdf8;">${totalApps}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">WinGet & Private Packages</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Self-Service Portal Apps</div>
          <div style="font-size:1.8rem;font-weight:700;color:#10b981;">${selfServiceApps}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Available in Company Portal</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Active License Allocations</div>
          <div style="font-size:1.8rem;font-weight:700;color:#a855f7;">${allocatedLicenses} <span style="font-size:1rem;color:#64748b;">/ ${totalLicenses > 0 ? totalLicenses : '∞'}</span></div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Assigned workstation seats</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Pending Elevation Requests</div>
          <div style="font-size:1.8rem;font-weight:700;color:${pendingRequests > 0 ? '#f59e0b' : '#10b981'};">${pendingRequests}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Awaiting IT Administrator Review</div>
        </div>
      </div>

      <!-- Navigation Subtabs -->
      <div style="display:flex;gap:0.5rem;border-bottom:1px solid #334155;margin-bottom:1.5rem;padding-bottom:0.5rem;">
        <button class="btn btn-subtab ${currentSubTab === 'catalog' ? 'active' : ''}" data-subtab="catalog" style="background:${currentSubTab === 'catalog' ? '#334155' : 'transparent'};color:${currentSubTab === 'catalog' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>📱</span> Enterprise App Catalog (${cachedApps.length})
        </button>
        <button class="btn btn-subtab ${currentSubTab === 'requests' ? 'active' : ''}" data-subtab="requests" style="background:${currentSubTab === 'requests' ? '#334155' : 'transparent'};color:${currentSubTab === 'requests' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>🙋</span> Company Portal Requests (${cachedRequests.length}) ${pendingRequests > 0 ? '<span class="badge badge-warning" style="background:#f59e0b;color:#000;border-radius:999px;padding:1px 6px;font-size:11px;font-weight:700;">' + pendingRequests + '</span>' : ''}
        </button>
        <button class="btn btn-subtab ${currentSubTab === 'licenses' ? 'active' : ''}" data-subtab="licenses" style="background:${currentSubTab === 'licenses' ? '#334155' : 'transparent'};color:${currentSubTab === 'licenses' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>🔑</span> License Seat Allocations (${cachedLicenses.length})
        </button>
      </div>

      <!-- Subtab Container -->
      <div id="eam-subtab-content">
    `;

    if (currentSubTab === 'catalog') {
      html += renderCatalogSubtab();
    } else if (currentSubTab === 'requests') {
      html += renderRequestsSubtab();
    } else {
      html += renderLicensesSubtab();
    }

    html += '</div>';

    container.innerHTML = html;
    attachEvents(container);
  }

  function renderCatalogSubtab() {
    let filtered = cachedApps.slice();
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(a =>
        (a.name && a.name.toLowerCase().includes(q)) ||
        (a.publisher && a.publisher.toLowerCase().includes(q)) ||
        (a.package_identifier && a.package_identifier.toLowerCase().includes(q))
      );
    }
    if (selectedCategory) {
      filtered = filtered.filter(a => a.category === selectedCategory);
    }

    const categories = Array.from(new Set(cachedApps.map(a => a.category).filter(Boolean))).sort();

    let out = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;gap:1rem;flex-wrap:wrap;">
        <div style="display:flex;gap:0.75rem;flex:1;max-width:600px;">
          <input type="text" id="eam-search-input" class="form-control" placeholder="Search enterprise packages by name, publisher, WinGet ID..." value="${esc(searchQuery)}" style="background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem 0.75rem;border-radius:6px;flex:1;">
          <select id="eam-cat-select" class="form-control" style="background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem 0.75rem;border-radius:6px;width:180px;">
            <option value="">All Categories</option>
            ${categories.map(c => `<option value="${esc(c)}" ${selectedCategory === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}
          </select>
        </div>
        <div style="color:#94a3b8;font-size:0.85rem;">Showing ${filtered.length} of ${cachedApps.length} packages</div>
      </div>

      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.875rem;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:#0f172a;color:#94a3b8;">
              <th style="padding:0.75rem 1rem;">Application</th>
              <th style="padding:0.75rem 1rem;">Publisher</th>
              <th style="padding:0.75rem 1rem;">Package ID</th>
              <th style="padding:0.75rem 1rem;">Version</th>
              <th style="padding:0.75rem 1rem;">Licensing & Seats</th>
              <th style="padding:0.75rem 1rem;">Self-Service</th>
              <th style="padding:0.75rem 1rem;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    if (filtered.length === 0) {
      out += `
        <tr>
          <td colspan="7" style="padding:3rem;text-align:center;color:#64748b;">
            No enterprise applications found matching query. Click "Add Enterprise App" to create one.
          </td>
        </tr>
      `;
    } else {
      filtered.forEach(app => {
        out += `
          <tr style="border-bottom:1px solid #334155;transition:background 0.15s;" onmouseover="this.style.background='rgba(51,65,85,0.4)'" onmouseout="this.style.background='transparent'">
            <td style="padding:0.75rem 1rem;font-weight:600;color:#f8fafc;">
              <div style="display:flex;align-items:center;gap:0.6rem;">
                ${app.icon_url ? `<img src="${esc(app.icon_url)}" style="width:20px;height:20px;object-fit:contain;border-radius:3px;" onerror="this.style.display='none'"/>` : '📦'}
                <div>
                  <div>${esc(app.name)} ${app.featured ? '<span style="color:#f59e0b;font-size:11px;" title="Featured App">⭐</span>' : ''}</div>
                  <div style="font-size:0.75rem;color:#64748b;font-weight:normal;">${esc(app.category)}</div>
                </div>
              </div>
            </td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">${esc(app.publisher)}</td>
            <td style="padding:0.75rem 1rem;font-family:monospace;color:#38bdf8;font-size:0.8rem;">${esc(app.package_identifier)}</td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">${esc(app.version)}</td>
            <td style="padding:0.75rem 1rem;">${getLicenseBadge(app.license_type, app.available_licenses)}</td>
            <td style="padding:0.75rem 1rem;">
              ${app.self_service_enabled ? '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-size:11px;">Company Portal</span>' : '<span style="color:#64748b;font-size:11px;">IT Managed Only</span>'}
            </td>
            <td style="padding:0.75rem 1rem;text-align:right;">
              <div style="display:flex;gap:0.4rem;justify-content:flex-end;">
                <button class="btn btn-xs btn-script" data-app-id="${esc(app.id)}" style="background:#334155;color:#38bdf8;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;" title="Generate WinGet Script">
                  📜 Script
                </button>
                <button class="btn btn-xs btn-delete-app" data-app-id="${esc(app.id)}" style="background:rgba(239,68,68,0.15);color:#ef4444;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;" title="Delete App">
                  🗑️
                </button>
              </div>
            </td>
          </tr>
        `;
      });
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderRequestsSubtab() {
    let out = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.875rem;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:#0f172a;color:#94a3b8;">
              <th style="padding:0.75rem 1rem;">Application</th>
              <th style="padding:0.75rem 1rem;">Client Hostname</th>
              <th style="padding:0.75rem 1rem;">Requester</th>
              <th style="padding:0.75rem 1rem;">Type</th>
              <th style="padding:0.75rem 1rem;">Status</th>
              <th style="padding:0.75rem 1rem;">Justification</th>
              <th style="padding:0.75rem 1rem;text-align:right;">Admin Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    if (cachedRequests.length === 0) {
      out += `
        <tr>
          <td colspan="7" style="padding:3rem;text-align:center;color:#64748b;">
            No self-service Company Portal installation requests submitted yet.
          </td>
        </tr>
      `;
    } else {
      cachedRequests.forEach(req => {
        out += `
          <tr style="border-bottom:1px solid #334155;">
            <td style="padding:0.75rem 1rem;font-weight:600;color:#f8fafc;">
              <div style="display:flex;align-items:center;gap:0.5rem;">
                <span>📦</span>
                <div>
                  <div>${esc(req.app_name)}</div>
                  <div style="font-size:0.75rem;color:#64748b;font-family:monospace;">${esc(req.package_identifier)}</div>
                </div>
              </div>
            </td>
            <td style="padding:0.75rem 1rem;color:#38bdf8;font-weight:500;">${esc(req.hostname || 'Unknown')}</td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">${esc(req.user_name)}</td>
            <td style="padding:0.75rem 1rem;color:#94a3b8;"><span class="badge" style="background:#334155;color:#e2e8f0;font-size:11px;">${esc(req.request_type)}</span></td>
            <td style="padding:0.75rem 1rem;">${getStatusBadge(req.status)}</td>
            <td style="padding:0.75rem 1rem;color:#94a3b8;font-size:0.8rem;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
              ${esc(req.justification || '(No justification provided)')}
            </td>
            <td style="padding:0.75rem 1rem;text-align:right;">
              ${req.status === 'PENDING_APPROVAL' ? `
                <div style="display:flex;gap:0.4rem;justify-content:flex-end;">
                  <button class="btn btn-xs btn-approve-req" data-req-id="${esc(req.id)}" style="background:#10b981;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;">
                    ✓ Approve
                  </button>
                  <button class="btn btn-xs btn-reject-req" data-req-id="${esc(req.id)}" style="background:#ef4444;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;">
                    ✗ Reject
                  </button>
                </div>
              ` : `
                <span style="color:#64748b;font-size:11px;">${req.approver_user ? 'Reviewed by ' + esc(req.approver_user) : 'Auto-Processed'}</span>
              `}
            </td>
          </tr>
        `;
      });
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderLicensesSubtab() {
    let out = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.875rem;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:#0f172a;color:#94a3b8;">
              <th style="padding:0.75rem 1rem;">Application</th>
              <th style="padding:0.75rem 1rem;">Device Hostname</th>
              <th style="padding:0.75rem 1rem;">Assigned User</th>
              <th style="padding:0.75rem 1rem;">License Key</th>
              <th style="padding:0.75rem 1rem;">License Type</th>
              <th style="padding:0.75rem 1rem;">Status</th>
              <th style="padding:0.75rem 1rem;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    if (cachedLicenses.length === 0) {
      out += `
        <tr>
          <td colspan="7" style="padding:3rem;text-align:center;color:#64748b;">
            No enterprise software licenses currently allocated.
          </td>
        </tr>
      `;
    } else {
      cachedLicenses.forEach(lic => {
        out += `
          <tr style="border-bottom:1px solid #334155;">
            <td style="padding:0.75rem 1rem;font-weight:600;color:#f8fafc;">${esc(lic.app_name)}</td>
            <td style="padding:0.75rem 1rem;color:#38bdf8;">${esc(lic.hostname || 'Unknown')}</td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">${esc(lic.user_name)}</td>
            <td style="padding:0.75rem 1rem;font-family:monospace;color:#a855f7;font-size:0.8rem;">${esc(lic.license_key)}</td>
            <td style="padding:0.75rem 1rem;color:#94a3b8;"><span class="badge" style="background:#334155;color:#cbd5e1;font-size:11px;">${esc(lic.license_type)}</span></td>
            <td style="padding:0.75rem 1rem;">${getStatusBadge(lic.status)}</td>
            <td style="padding:0.75rem 1rem;text-align:right;">
              ${lic.status === 'ACTIVE' ? `
                <button class="btn btn-xs btn-revoke-lic" data-lic-id="${esc(lic.id)}" style="background:rgba(239,68,68,0.15);color:#ef4444;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;" title="Revoke Seat">
                  Revoke Seat
                </button>
              ` : '<span style="color:#64748b;font-size:11px;">Revoked</span>'}
            </td>
          </tr>
        `;
      });
    }

    out += '</tbody></table></div>';
    return out;
  }

  function attachEvents(container) {
    // Refresh
    const refreshBtn = container.querySelector('#btn-refresh-portal');
    if (refreshBtn) {
      refreshBtn.onclick = () => render(container);
    }

    // Subtab switching
    container.querySelectorAll('.btn-subtab').forEach(btn => {
      btn.onclick = () => {
        currentSubTab = btn.getAttribute('data-subtab');
        render(container);
      };
    });

    // Search and filter
    const searchInput = container.querySelector('#eam-search-input');
    if (searchInput) {
      searchInput.oninput = (e) => {
        searchQuery = e.target.value;
        const subContainer = container.querySelector('#eam-subtab-content');
        if (subContainer) subContainer.innerHTML = renderCatalogSubtab();
        attachSubtabEvents(container);
      };
    }

    const catSelect = container.querySelector('#eam-cat-select');
    if (catSelect) {
      catSelect.onchange = (e) => {
        selectedCategory = e.target.value;
        const subContainer = container.querySelector('#eam-subtab-content');
        if (subContainer) subContainer.innerHTML = renderCatalogSubtab();
        attachSubtabEvents(container);
      };
    }

    // Add App button
    const addAppBtn = container.querySelector('#btn-add-app');
    if (addAppBtn) {
      addAppBtn.onclick = () => showAddAppModal(container);
    }

    attachSubtabEvents(container);
  }

  function attachSubtabEvents(container) {
    // Script view
    container.querySelectorAll('.btn-script').forEach(btn => {
      btn.onclick = () => {
        const appId = btn.getAttribute('data-app-id');
        const app = cachedApps.find(a => a.id === appId);
        if (app) showScriptModal(app);
      };
    });

    // Delete app
    container.querySelectorAll('.btn-delete-app').forEach(btn => {
      btn.onclick = async () => {
        const appId = btn.getAttribute('data-app-id');
        if (confirm('Are you sure you want to remove this enterprise application and its requests?')) {
          try {
            await window.FleetAPI.deleteEamCatalogApp(appId);
            render(container);
          } catch (e) {
            alert('Failed to delete app: ' + e.message);
          }
        }
      };
    });

    // Approve request
    container.querySelectorAll('.btn-approve-req').forEach(btn => {
      btn.onclick = async () => {
        const reqId = btn.getAttribute('data-req-id');
        try {
          await window.FleetAPI.reviewEamRequest(reqId, {
            action: 'APPROVE',
            approver_user: 'IT Administrator'
          });
          render(container);
        } catch (e) {
          alert('Failed to approve request: ' + e.message);
        }
      };
    });

    // Reject request
    container.querySelectorAll('.btn-reject-req').forEach(btn => {
      btn.onclick = async () => {
        const reqId = btn.getAttribute('data-req-id');
        const notes = prompt('Enter rejection reason for employee:');
        if (notes !== null) {
          try {
            await window.FleetAPI.reviewEamRequest(reqId, {
              action: 'REJECT',
              approver_user: 'IT Administrator',
              notes
            });
            render(container);
          } catch (e) {
            alert('Failed to reject request: ' + e.message);
          }
        }
      };
    });

    // Revoke license
    container.querySelectorAll('.btn-revoke-lic').forEach(btn => {
      btn.onclick = async () => {
        const licId = btn.getAttribute('data-lic-id');
        if (confirm('Revoke this workstation license seat?')) {
          try {
            await window.FleetAPI.revokeEamLicense(licId);
            render(container);
          } catch (e) {
            alert('Failed to revoke license: ' + e.message);
          }
        }
      };
    });
  }

  function showScriptModal(app) {
    const modalId = 'modal-eam-script';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const scriptText = `# Automated Silent Installation Script for ${app.name}
$ErrorActionPreference = 'Stop'
Write-Host "Installing ${app.name} (${app.package_identifier})..." -ForegroundColor Cyan

winget install --id "${app.package_identifier}" ${app.silent_install_args || '--silent --accept-package-agreements --accept-source-agreements'}
if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2316632065) {
    Write-Host "Successfully installed ${app.name}." -ForegroundColor Green
} else {
    Write-Error "Installation failed with exit code $LASTEXITCODE"
}
`;

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'modal-overlay';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:650px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.1rem;display:flex;align-items:center;gap:0.5rem;">
            <span>📜</span> WinGet PowerShell Execution Payload — ${esc(app.name)}
          </h3>
          <button id="modal-close-script" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>
        <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:1rem;">
          This PowerShell script is dispatched automatically by the LocalPilot Agent to silently install the package without user prompts.
        </p>
        <pre style="background:#0f172a;border:1px solid #334155;border-radius:6px;padding:1rem;color:#38bdf8;font-size:0.8rem;overflow-x:auto;max-height:300px;">${esc(scriptText)}</pre>
        <div style="display:flex;justify-content:flex-end;gap:0.5rem;margin-top:1.2rem;">
          <button id="modal-copy-script" class="btn btn-secondary" style="background:#334155;color:#f8fafc;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">
            📋 Copy Script
          </button>
          <button id="modal-done-script" class="btn btn-primary" style="background:#3b82f6;color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">
            Done
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector('#modal-close-script').onclick = () => modal.remove();
    modal.querySelector('#modal-done-script').onclick = () => modal.remove();
    modal.querySelector('#modal-copy-script').onclick = () => {
      navigator.clipboard.writeText(scriptText);
      alert('Copied PowerShell script to clipboard!');
    };
  }

  function showAddAppModal(container) {
    const modalId = 'modal-add-app';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'modal-overlay';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:600px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);max-height:90vh;overflow-y:auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.1rem;display:flex;align-items:center;gap:0.5rem;">
            <span>➕</span> Add Enterprise Application to Catalog
          </h3>
          <button id="modal-close-add" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>

        <form id="form-add-app" style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
          <div style="grid-column:span 2;">
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Application Name *</label>
            <input type="text" id="add-app-name" required class="form-control" placeholder="e.g. Sublime Text" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Publisher *</label>
            <input type="text" id="add-app-pub" required class="form-control" placeholder="e.g. Sublime HQ Pty Ltd" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Category</label>
            <input type="text" id="add-app-cat" class="form-control" placeholder="e.g. Developer Tools" value="Developer Tools" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">WinGet Package ID *</label>
            <input type="text" id="add-app-pkg" required class="form-control" placeholder="e.g. SublimeHQ.SublimeText.4" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Version *</label>
            <input type="text" id="add-app-ver" required class="form-control" placeholder="e.g. 4.1.80" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">License Model</label>
            <select id="add-app-lic" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
              <option value="FREE">FREE / Unlicensed</option>
              <option value="OPEN_SOURCE">OPEN_SOURCE</option>
              <option value="PER_USER">PER_USER (Requires Seat)</option>
              <option value="PER_DEVICE">PER_DEVICE (Requires Seat)</option>
              <option value="ENTERPRISE_SUBSCRIPTION">ENTERPRISE_SUBSCRIPTION</option>
            </select>
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Total License Seats (0 = Unlimited)</label>
            <input type="number" id="add-app-seats" min="0" value="0" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div style="grid-column:span 2;display:flex;gap:1.5rem;margin-top:0.5rem;">
            <label style="color:#f8fafc;font-size:0.85rem;display:flex;align-items:center;gap:0.4rem;cursor:pointer;">
              <input type="checkbox" id="add-app-selfservice" checked> Enable in Self-Service Company Portal
            </label>
            <label style="color:#f8fafc;font-size:0.85rem;display:flex;align-items:center;gap:0.4rem;cursor:pointer;">
              <input type="checkbox" id="add-app-featured"> Featured App ⭐
            </label>
          </div>

          <div style="grid-column:span 2;display:flex;justify-content:flex-end;gap:0.5rem;margin-top:1rem;">
            <button type="button" id="modal-cancel-add" class="btn btn-secondary" style="background:#334155;color:#f8fafc;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary" style="background:#3b82f6;color:#fff;border:none;padding:0.5rem 1.2rem;border-radius:6px;cursor:pointer;font-weight:600;">
              Add Package
            </button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector('#modal-close-add').onclick = () => modal.remove();
    modal.querySelector('#modal-cancel-add').onclick = () => modal.remove();

    modal.querySelector('#form-add-app').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('add-app-name').value,
        publisher: document.getElementById('add-app-pub').value,
        category: document.getElementById('add-app-cat').value,
        package_identifier: document.getElementById('add-app-pkg').value,
        version: document.getElementById('add-app-ver').value,
        license_type: document.getElementById('add-app-lic').value,
        total_licenses: parseInt(document.getElementById('add-app-seats').value, 10) || 0,
        self_service_enabled: document.getElementById('add-app-selfservice').checked,
        featured: document.getElementById('add-app-featured').checked
      };

      try {
        await window.FleetAPI.createEamCatalogApp(payload);
        modal.remove();
        render(container);
      } catch (err) {
        alert('Failed to add application: ' + err.message);
      }
    };
  }

  // Export
  window.CompanyPortalTable = {
    render,
    init: render
  };
})();
