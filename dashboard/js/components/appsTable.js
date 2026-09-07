/**
 * LocalPilot Fleet — Microsoft Intune Application Management & Packaging Component
 * dashboard/js/components/appsTable.js
 */

(function() {
  'use strict';

  let _apps = [];
  let _stats = null;
  let _groups = [];
  let _searchTerm = '';
  let _filterType = 'all';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function loadData() {
    const container = document.getElementById('view-apps');
    if (!container) return;

    try {
      const [appsData, statsData, groupsData] = await Promise.all([
        window.FleetAPI.getApps(),
        window.FleetAPI.getAppStats(),
        window.FleetAPI.getGroups()
      ]);

      _apps = Array.isArray(appsData) ? appsData : [];
      _stats = statsData || {};
      _groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      render();
    } catch (err) {
      container.innerHTML = `
        <div class="intune-empty-state">
          <div class="empty-icon">⚠️</div>
          <div class="empty-title">Failed to load Intune Applications</div>
          <div class="empty-sub">${esc(err.message)}</div>
        </div>
      `;
    }
  }

  function render() {
    const container = document.getElementById('view-apps');
    if (!container) return;

    let filtered = _apps;
    if (_searchTerm) {
      const term = _searchTerm.toLowerCase();
      filtered = filtered.filter(a =>
        (a.name && a.name.toLowerCase().includes(term)) ||
        (a.publisher && a.publisher.toLowerCase().includes(term)) ||
        (a.package_identifier && a.package_identifier.toLowerCase().includes(term))
      );
    }
    if (_filterType !== 'all') {
      filtered = filtered.filter(a => a.app_type === _filterType);
    }

    container.innerHTML = `
      <!-- ── KPI Cards ── -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-title">Managed Apps</span>
            <span class="kpi-icon">📦</span>
          </div>
          <div class="kpi-value">${_stats?.total_apps ?? _apps.length}</div>
          <div class="kpi-footer">Enterprise catalog packages</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-title">Install Success Rate</span>
            <span class="kpi-icon">🎯</span>
          </div>
          <div class="kpi-value" style="color:var(--status-online);">${_stats?.fleet_install_rate_percent ?? 100}%</div>
          <div class="kpi-footer">${_stats?.total_installed ?? 0} successful installs across fleet</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-title">Pending Installs</span>
            <span class="kpi-icon">⏳</span>
          </div>
          <div class="kpi-value" style="color:#f59e0b;">${_stats?.total_pending ?? 0}</div>
          <div class="kpi-footer">Awaiting node agent synchronization</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-title">Failed Installs</span>
            <span class="kpi-icon">⚠️</span>
          </div>
          <div class="kpi-value" style="color:${(_stats?.total_failed ?? 0) > 0 ? '#ef4444' : 'var(--text-muted)'};">${_stats?.total_failed ?? 0}</div>
          <div class="kpi-footer">Requires administrator intervention</div>
        </div>
      </div>

      <!-- ── Toolbar ── -->
      <div class="intune-toolbar">
        <div class="toolbar-left">
          <div class="search-wrap">
            <input type="text" class="intune-input" id="apps-search" placeholder="Search application catalog..." value="${esc(_searchTerm)}">
          </div>
          <select class="intune-select" id="apps-type-filter">
            <option value="all" ${_filterType === 'all' ? 'selected' : ''}>All Types</option>
            <option value="WINGET" ${_filterType === 'WINGET' ? 'selected' : ''}>Winget Packages</option>
            <option value="WIN32" ${_filterType === 'WIN32' ? 'selected' : ''}>Win32 / Custom</option>
            <option value="MSI" ${_filterType === 'MSI' ? 'selected' : ''}>MSI Packages</option>
            <option value="SCRIPT" ${_filterType === 'SCRIPT' ? 'selected' : ''}>Script Installers</option>
          </select>
        </div>
        <div class="toolbar-right">
          <button class="intune-btn primary" id="btn-add-app">
            <span class="act-icon">➕</span> Add application
          </button>
        </div>
      </div>

      <!-- ── Applications Table ── -->
      <div class="intune-table-wrap">
        <table class="intune-table">
          <thead>
            <tr>
              <th>Application Name</th>
              <th>Publisher</th>
              <th>Version</th>
              <th>Type</th>
              <th>Assignment</th>
              <th>Target Group</th>
              <th>Install Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.length === 0 ? `
              <tr>
                <td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted);">
                  No applications found matching query.
                </td>
              </tr>
            ` : filtered.map(app => {
              const stats = app.stats || {};
              const rate = stats.install_rate_percent ?? 0;
              const installed = stats.installed_count ?? 0;
              const failed = stats.failed_count ?? 0;
              const pending = stats.pending_count ?? 0;
              const total = stats.total_targeted ?? 0;

              return `
                <tr>
                  <td>
                    <div style="display:flex;align-items:center;gap:8px;">
                      <span style="font-size:16px;">${app.app_type === 'WINGET' ? '📦' : '💻'}</span>
                      <div>
                        <div style="font-weight:600;color:var(--text-bright);">${esc(app.name)}</div>
                        <div style="font-size:11px;color:var(--text-muted);">${esc(app.package_identifier || app.id)}</div>
                      </div>
                    </div>
                  </td>
                  <td>${esc(app.publisher || '—')}</td>
                  <td><span class="mono">${esc(app.version || 'Latest')}</span></td>
                  <td>
                    <span class="badge" style="background:#1e293b;border:1px solid #334155;color:#94a3b8;">
                      ${esc(app.app_type)}
                    </span>
                  </td>
                  <td>
                    <span class="badge ${app.assignment_intent === 'REQUIRED' ? 'badge-online' : 'badge-offline'}">
                      ${esc(app.assignment_intent)}
                    </span>
                  </td>
                  <td>
                    <span class="badge" style="background:#3b82f622;border:1px solid #3b82f655;color:#60a5fa;">
                      ${esc(app.target_group_name || app.target_group_id || 'grp-all')}
                    </span>
                  </td>
                  <td style="min-width:140px;">
                    <div style="font-size:11px;display:flex;justify-content:space-between;margin-bottom:2px;">
                      <span style="color:#10b981;">${installed} installed</span>
                      <span style="color:${failed > 0 ? '#ef4444' : 'var(--text-muted)'};">${failed > 0 ? failed + ' failed' : (pending > 0 ? pending + ' pending' : '')}</span>
                    </div>
                    <div style="height:6px;background:#334155;border-radius:3px;overflow:hidden;display:flex;">
                      <div style="width:${rate}%;background:#10b981;height:100%;"></div>
                      <div style="width:${total > 0 ? (failed / total) * 100 : 0}%;background:#ef4444;height:100%;"></div>
                    </div>
                  </td>
                  <td>
                    <div style="display:flex;gap:6px;">
                      <button class="intune-btn small primary btn-inspect-app" data-id="${esc(app.id)}">
                        Inspect
                      </button>
                      <button class="intune-btn small delete btn-delete-app" data-id="${esc(app.id)}">
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;

    bindEvents(container);
  }

  function bindEvents(container) {
    const searchInput = container.querySelector('#apps-search');
    searchInput?.addEventListener('input', (e) => {
      _searchTerm = e.target.value;
      render();
    });

    const typeFilter = container.querySelector('#apps-type-filter');
    typeFilter?.addEventListener('change', (e) => {
      _filterType = e.target.value;
      render();
    });

    const addBtn = container.querySelector('#btn-add-app');
    addBtn?.addEventListener('click', openAddModal);

    container.querySelectorAll('.btn-inspect-app').forEach(btn => {
      btn.addEventListener('click', () => openInspectModal(btn.dataset.id));
    });

    container.querySelectorAll('.btn-delete-app').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (!confirm(`Delete application package '${id}'? This will remove it from all managed nodes.`)) return;
        try {
          await window.FleetAPI.deleteApp(id);
          if (typeof showToast === 'function') showToast('App Deleted', 'Application package removed from catalog.', 'info');
          loadData();
        } catch (err) {
          if (typeof showToast === 'function') showToast('Delete Failed', err.message, 'critical');
        }
      });
    });
  }

  function openAddModal() {
    let modal = document.getElementById('modal-add-app');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'modal-add-app';
      modal.className = 'intune-modal-overlay';
      document.body.appendChild(modal);
    }

    const groupOptions = _groups.map(g =>
      `<option value="${esc(g.id)}">${esc(g.name)} (${esc(g.id)})</option>`
    ).join('');

    modal.innerHTML = `
      <div class="intune-modal-card" style="max-width:680px;">
        <div class="intune-modal-header">
          <h2>Add Application Package</h2>
          <button class="modal-close" id="btn-close-add-app">&times;</button>
        </div>
        <div class="intune-modal-body">
          <p style="color:var(--text-muted);font-size:13px;margin-bottom:12px;">
            Deploy software across your fleet using Windows Package Manager (Winget) or custom Win32 installers.
          </p>

          <!-- Quick Presets -->
          <div style="margin-bottom:16px;">
            <label class="intune-label">⚡ Quick Enterprise Presets</label>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:8px;margin-top:6px;">
              <button class="intune-btn small preset-btn" data-preset="vscode">💻 VS Code</button>
              <button class="intune-btn small preset-btn" data-preset="git">🐙 Git</button>
              <button class="intune-btn small preset-btn" data-preset="7zip">🗜️ 7-Zip</button>
              <button class="intune-btn small preset-btn" data-preset="chrome">🌐 Chrome</button>
              <button class="intune-btn small preset-btn" data-preset="sysinternals">🛡️ Sysinternals</button>
              <button class="intune-btn small preset-btn" data-preset="docker">🐳 Docker</button>
            </div>
          </div>

          <form id="form-create-app" style="display:flex;flex-direction:column;gap:12px;">
            <div class="intune-form-group">
              <label class="intune-label">Application Name *</label>
              <input type="text" class="intune-input" id="app-name" required placeholder="e.g. Visual Studio Code">
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Publisher</label>
                <input type="text" class="intune-input" id="app-publisher" placeholder="e.g. Microsoft">
              </div>
              <div class="intune-form-group">
                <label class="intune-label">Version</label>
                <input type="text" class="intune-input" id="app-version" placeholder="e.g. 1.98.0 or Latest">
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Package Type</label>
                <select class="intune-select" id="app-type">
                  <option value="WINGET">Winget (Windows Package Manager)</option>
                  <option value="WIN32">Win32 Executable (.exe / .bat)</option>
                  <option value="MSI">MSI Installer</option>
                  <option value="SCRIPT">Custom PowerShell Script</option>
                </select>
              </div>
              <div class="intune-form-group">
                <label class="intune-label">Package Identifier (Winget ID)</label>
                <input type="text" class="intune-input" id="app-pkg-id" placeholder="e.g. Microsoft.VisualStudioCode">
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Assignment Intent</label>
                <select class="intune-select" id="app-intent">
                  <option value="REQUIRED">Required (Mandatory fleet installation)</option>
                  <option value="AVAILABLE">Available (Self-service catalog)</option>
                  <option value="UNINSTALL">Uninstall (Remove if installed)</option>
                </select>
              </div>
              <div class="intune-form-group">
                <label class="intune-label">Target Dynamic Group</label>
                <select class="intune-select" id="app-target-group">
                  <option value="grp-all">All Devices (grp-all)</option>
                  ${groupOptions}
                </select>
              </div>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Install Command</label>
              <input type="text" class="intune-input mono" id="app-install-cmd" placeholder="winget install --id Microsoft.VisualStudioCode --exact --silent --accept-source-agreements --accept-package-agreements">
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Uninstall Command</label>
              <input type="text" class="intune-input mono" id="app-uninstall-cmd" placeholder="winget uninstall --id Microsoft.VisualStudioCode --exact --silent">
            </div>

            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:8px;">
              <button type="button" class="intune-btn" id="btn-cancel-add-app">Cancel</button>
              <button type="submit" class="intune-btn primary">Save Application</button>
            </div>
          </form>
        </div>
      </div>
    `;

    modal.style.display = 'flex';

    // Preset handler
    const presets = {
      vscode: {
        name: 'Visual Studio Code',
        publisher: 'Microsoft',
        version: '1.98.0',
        type: 'WINGET',
        pkgId: 'Microsoft.VisualStudioCode',
        intent: 'REQUIRED',
        installCmd: 'winget install --id Microsoft.VisualStudioCode --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id Microsoft.VisualStudioCode --exact --silent'
      },
      git: {
        name: 'Git for Windows',
        publisher: 'Git for Windows Project',
        version: '2.44.0',
        type: 'WINGET',
        pkgId: 'Git.Git',
        intent: 'REQUIRED',
        installCmd: 'winget install --id Git.Git --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id Git.Git --exact --silent'
      },
      '7zip': {
        name: '7-Zip File Archiver',
        publisher: 'Igor Pavlov',
        version: '24.09',
        type: 'WINGET',
        pkgId: '7zip.7zip',
        intent: 'REQUIRED',
        installCmd: 'winget install --id 7zip.7zip --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id 7zip.7zip --exact --silent'
      },
      chrome: {
        name: 'Google Chrome Enterprise',
        publisher: 'Google LLC',
        version: '122.0.6261.95',
        type: 'WINGET',
        pkgId: 'Google.Chrome',
        intent: 'REQUIRED',
        installCmd: 'winget install --id Google.Chrome --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id Google.Chrome --exact --silent'
      },
      sysinternals: {
        name: 'Sysinternals Suite',
        publisher: 'Microsoft',
        version: '2025.1',
        type: 'WINGET',
        pkgId: 'Microsoft.Sysinternals.Suite',
        intent: 'AVAILABLE',
        installCmd: 'winget install --id Microsoft.Sysinternals.Suite --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id Microsoft.Sysinternals.Suite --exact --silent'
      },
      docker: {
        name: 'Docker Desktop',
        publisher: 'Docker Inc.',
        version: '4.35.0',
        type: 'WINGET',
        pkgId: 'Docker.DockerDesktop',
        intent: 'REQUIRED',
        installCmd: 'winget install --id Docker.DockerDesktop --exact --silent --accept-source-agreements --accept-package-agreements',
        uninstallCmd: 'winget uninstall --id Docker.DockerDesktop --exact --silent'
      }
    };

    modal.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const p = presets[btn.dataset.preset];
        if (!p) return;
        modal.querySelector('#app-name').value = p.name;
        modal.querySelector('#app-publisher').value = p.publisher;
        modal.querySelector('#app-version').value = p.version;
        modal.querySelector('#app-type').value = p.type;
        modal.querySelector('#app-pkg-id').value = p.pkgId;
        modal.querySelector('#app-intent').value = p.intent;
        modal.querySelector('#app-install-cmd').value = p.installCmd;
        modal.querySelector('#app-uninstall-cmd').value = p.uninstallCmd;
      });
    });

    const close = () => { modal.style.display = 'none'; };
    modal.querySelector('#btn-close-add-app').onclick = close;
    modal.querySelector('#btn-cancel-add-app').onclick = close;

    modal.querySelector('#form-create-app').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        name: modal.querySelector('#app-name').value.trim(),
        publisher: modal.querySelector('#app-publisher').value.trim(),
        version: modal.querySelector('#app-version').value.trim(),
        app_type: modal.querySelector('#app-type').value,
        package_identifier: modal.querySelector('#app-pkg-id').value.trim(),
        assignment_intent: modal.querySelector('#app-intent').value,
        target_group_id: modal.querySelector('#app-target-group').value,
        install_command: modal.querySelector('#app-install-cmd').value.trim(),
        uninstall_command: modal.querySelector('#app-uninstall-cmd').value.trim(),
        detection_rules: [
          { type: 'WINGET', package_id: modal.querySelector('#app-pkg-id').value.trim() }
        ]
      };

      try {
        await window.FleetAPI.createApp(payload);
        close();
        if (typeof showToast === 'function') showToast('App Added', 'Application successfully added to catalog.', 'success');
        loadData();
      } catch (err) {
        alert('Failed to save application: ' + err.message);
      }
    };
  }

  async function openInspectModal(appId) {
    let modal = document.getElementById('modal-inspect-app');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'modal-inspect-app';
      modal.className = 'intune-modal-overlay';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="intune-modal-card" style="max-width:760px;">
        <div class="intune-modal-header">
          <h2>Application Deployment Posture</h2>
          <button class="modal-close" id="btn-close-inspect-app">&times;</button>
        </div>
        <div class="intune-modal-body" id="inspect-app-body">
          <div style="text-align:center;padding:20px;color:var(--text-muted);">⏳ Loading application telemetry…</div>
        </div>
      </div>
    `;
    modal.style.display = 'flex';
    modal.querySelector('#btn-close-inspect-app').onclick = () => { modal.style.display = 'none'; };

    try {
      const app = await window.FleetAPI.getApp(appId);
      const body = modal.querySelector('#inspect-app-body');
      const stats = app.stats || {};
      const devices = app.device_statuses || [];

      body.innerHTML = `
        <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px 16px;margin-bottom:16px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <div style="font-size:16px;font-weight:700;color:var(--text-bright);">${esc(app.name)}</div>
              <div style="font-size:12px;color:var(--text-muted);">${esc(app.publisher || 'Unknown')} | ${esc(app.version || 'Latest')} | ${esc(app.app_type)}</div>
            </div>
            <span class="badge ${app.assignment_intent === 'REQUIRED' ? 'badge-online' : 'badge-offline'}">
              ${esc(app.assignment_intent)}
            </span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:8px;margin-top:12px;border-top:1px solid #334155;padding-top:8px;text-align:center;">
            <div>
              <div style="font-size:11px;color:var(--text-muted);">Targeted</div>
              <div style="font-weight:700;color:var(--text-bright);font-size:15px;">${stats.total_targeted ?? 0}</div>
            </div>
            <div>
              <div style="font-size:11px;color:var(--text-muted);">Installed</div>
              <div style="font-weight:700;color:#10b981;font-size:15px;">${stats.installed_count ?? 0}</div>
            </div>
            <div>
              <div style="font-size:11px;color:var(--text-muted);">Pending</div>
              <div style="font-weight:700;color:#f59e0b;font-size:15px;">${stats.pending_count ?? 0}</div>
            </div>
            <div>
              <div style="font-size:11px;color:var(--text-muted);">Failed</div>
              <div style="font-weight:700;color:#ef4444;font-size:15px;">${stats.failed_count ?? 0}</div>
            </div>
          </div>
        </div>

        <h3 style="font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);margin-bottom:8px;">
          Device Installation Posture
        </h3>

        <table class="intune-table" style="font-size:12px;">
          <thead>
            <tr>
              <th>Device</th>
              <th>Status</th>
              <th>Detected Version</th>
              <th>Last Attempt</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${devices.length === 0 ? `
              <tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-muted);">No devices targeted or reporting yet.</td></tr>
            ` : devices.map(d => {
              const isInst = d.install_status === 'INSTALLED';
              const isFail = d.install_status === 'FAILED';
              const color = isInst ? '#10b981' : (isFail ? '#ef4444' : '#f59e0b');

              return `
                <tr>
                  <td>
                    <div style="font-weight:600;color:var(--text-bright);">${esc(d.hostname)}</div>
                    <div style="font-size:10px;color:var(--text-muted);">${esc(d.primary_user || 'No user')} | OS: ${esc(d.os_build || 'Unknown')}</div>
                  </td>
                  <td>
                    <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;">
                      ${esc(d.install_status)}
                    </span>
                    ${d.error_message ? `<div style="font-size:10px;color:#ef4444;margin-top:2px;">${esc(d.error_message)}</div>` : ''}
                  </td>
                  <td><span class="mono">${esc(d.installed_version || '—')}</span></td>
                  <td>${d.last_attempt_at ? new Date(d.last_attempt_at).toLocaleTimeString() : '—'}</td>
                  <td>
                    <button class="intune-btn small primary btn-install-node" data-dev="${esc(d.device_id)}" data-app="${esc(app.id)}">
                      ⚡ Deploy Now
                    </button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;

      body.querySelectorAll('.btn-install-node').forEach(btn => {
        btn.addEventListener('click', async () => {
          const devId = btn.dataset.dev;
          const aId = btn.dataset.app;
          try {
            await window.FleetAPI.installDeviceApp(devId, aId);
            if (typeof showToast === 'function') showToast('Deploy Dispatched', 'Deployment command queued on node.', 'info');
            openInspectModal(aId);
          } catch (err) {
            if (typeof showToast === 'function') showToast('Deploy Failed', err.message, 'critical');
          }
        });
      });
    } catch (err) {
      modal.querySelector('#inspect-app-body').innerHTML = `
        <div style="color:#ef4444;padding:20px;text-align:center;">Failed to load application: ${esc(err.message)}</div>
      `;
    }
  }

  window.AppsTable = {
    loadData
  };
})();
