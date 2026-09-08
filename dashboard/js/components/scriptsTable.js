/**
 * LocalPilot Fleet — Microsoft Intune Windows PowerShell Scripts UI Component
 * dashboard/js/components/scriptsTable.js
 *
 * Implements Devices > Scripts (Windows 10/11 PowerShell Scripts) blade with:
 * - Enterprise script catalog management
 * - Dynamic group scoping & run frequencies (ONCE, SCHEDULED, ON_DEMAND)
 * - Execution context (SYSTEM vs USER, 32-bit vs 64-bit)
 * - Fleet-wide on-demand execution dispatch
 * - Execution run history with stdout, stderr, and exit codes
 * - Direct integration with Cloud Shell terminal
 */

(function () {
  'use strict';

  let _scripts = [];
  let _scriptRuns = [];
  let _stats = null;
  let _groups = [];
  let _activeTab = 'catalog'; // 'catalog' | 'runs'
  let _searchQuery = '';
  let _statusFilter = 'ALL';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  const PRESETS = [
    {
      name: 'Audit Local Administrators',
      desc: 'Enumerate all members of the local Administrators group and flag unauthorized accounts.',
      freq: 'SCHEDULED',
      context: 'SYSTEM',
      is32: false,
      script: `# Audit Local Administrators
$admins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
Write-Host "Local Administrators Count: $($admins.Count)"
$admins | Format-Table -AutoSize | Out-String | Write-Host
exit 0`
    },
    {
      name: 'Audit Expiring TLS Certificates',
      desc: 'Scan LocalMachine My store for certificates expiring within 30 days.',
      freq: 'SCHEDULED',
      context: 'SYSTEM',
      is32: false,
      script: `# Audit Expiring TLS Certificates
$threshold = (Get-Date).AddDays(30)
$expiring = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.NotAfter -le $threshold }
if ($expiring) {
    Write-Warning "Found $($expiring.Count) certificate(s) expiring within 30 days!"
    $expiring | Select-Object Subject, Thumbprint, NotAfter | Format-Table -AutoSize | Out-String | Write-Host
    exit 1
}
Write-Host "All LocalMachine certificates are valid beyond 30 days."
exit 0`
    },
    {
      name: 'Flush DNS & Reset TCP/IP Stack',
      desc: 'Flush resolver cache, register DNS, and restart network adapter IP configuration.',
      freq: 'ON_DEMAND',
      context: 'SYSTEM',
      is32: false,
      script: `# Network DNS & Stack Refresh
Clear-DnsClientCache
Register-DnsClient
Write-Host "DNS resolver cache successfully cleared and client re-registered."
exit 0`
    },
    {
      name: 'Windows Temp & Component Store Cleanup',
      desc: 'Purge Windows temporary files and invoke DISM StartComponentCleanup.',
      freq: 'SCHEDULED',
      context: 'SYSTEM',
      is32: false,
      script: `# Disk & DISM Cleanup
Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Temporary directories cleared."
dism.exe /online /cleanup-image /startcomponentcleanup /quiet /norestart
Write-Host "DISM component store cleanup completed with exit code $LASTEXITCODE."
exit 0`
    },
    {
      name: 'Reset Windows Update Agent & Cache',
      desc: 'Stop WUA services, clear SoftwareDistribution cache, and restart update services.',
      freq: 'ON_DEMAND',
      context: 'SYSTEM',
      is32: false,
      script: `# Reset Windows Update Agent
Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\\Windows\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name bits, cryptSvc, wuauserv -ErrorAction SilentlyContinue
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
Write-Host "Windows Update Agent reset and search cycle initiated."
exit 0`
    }
  ];

  async function loadData() {
    try {
      const [statsRes, scriptsRes, runsRes, groupsRes] = await Promise.all([
        window.FleetAPI.getScriptStats ? window.FleetAPI.getScriptStats() : Promise.resolve(null),
        window.FleetAPI.getScripts ? window.FleetAPI.getScripts() : Promise.resolve({ scripts: [] }),
        window.FleetAPI.getScriptRuns ? window.FleetAPI.getScriptRuns({ limit: 50 }) : Promise.resolve({ runs: [] }),
        window.FleetAPI.getGroups ? window.FleetAPI.getGroups() : Promise.resolve({ groups: [] })
      ]);

      _stats = statsRes;
      _scripts = scriptsRes.scripts || [];
      _scriptRuns = runsRes.runs || [];
      _groups = groupsRes.groups || [];
      render();
    } catch (err) {
      console.error('Failed to load PowerShell scripts data:', err);
    }
  }

  function renderKpiCards() {
    const s = _stats || {
      total_scripts: _scripts.length,
      active_scripts: _scripts.filter(x => x.enabled).length,
      success_rate_pct: 100,
      devices_covered: 1,
      total_runs: _scriptRuns.length
    };

    return `
      <div class="kpi-grid" style="margin-bottom: 20px;">
        <div class="kpi-card">
          <div class="kpi-label">Script Catalog</div>
          <div class="kpi-value">${s.total_scripts}</div>
          <div class="kpi-sub">Enterprise scripts defined</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Active Policies</div>
          <div class="kpi-value" style="color: #10B981;">${s.active_scripts}</div>
          <div class="kpi-sub">Enforced / available</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Success Rate</div>
          <div class="kpi-value" style="color: ${s.success_rate_pct >= 90 ? '#10B981' : '#F59E0B'};">${s.success_rate_pct}%</div>
          <div class="kpi-sub">${s.total_runs || 0} total executions</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Covered Nodes</div>
          <div class="kpi-value" style="color: #3B82F6;">${s.devices_covered}</div>
          <div class="kpi-sub">Targeted endpoint nodes</div>
        </div>
      </div>
    `;
  }

  function renderSubTabs() {
    return `
      <div style="display: flex; gap: 8px; border-bottom: 1px solid var(--border-color); margin-bottom: 16px;">
        <button class="tab-btn ${_activeTab === 'catalog' ? 'active' : ''}" id="tab-btn-catalog" style="padding: 8px 16px; border: none; background: none; border-bottom: 2px solid ${_activeTab === 'catalog' ? 'var(--primary-color)' : 'transparent'}; color: ${_activeTab === 'catalog' ? 'var(--primary-color)' : 'var(--text-muted)'}; font-weight: 600; cursor: pointer;">
          📜 PowerShell scripts (${_scripts.length})
        </button>
        <button class="tab-btn ${_activeTab === 'runs' ? 'active' : ''}" id="tab-btn-runs" style="padding: 8px 16px; border: none; background: none; border-bottom: 2px solid ${_activeTab === 'runs' ? 'var(--primary-color)' : 'transparent'}; color: ${_activeTab === 'runs' ? 'var(--primary-color)' : 'var(--text-muted)'}; font-weight: 600; cursor: pointer;">
          📋 Execution run history (${_scriptRuns.length})
        </button>
      </div>
    `;
  }

  function renderCatalogTable() {
    const q = _searchQuery.toLowerCase();
    const filtered = _scripts.filter(s => {
      const matchText = s.name.toLowerCase().includes(q) ||
        (s.description || '').toLowerCase().includes(q) ||
        (s.target_group_name || '').toLowerCase().includes(q);
      if (!matchText) return false;
      if (_statusFilter === 'ACTIVE') return Boolean(s.enabled);
      if (_statusFilter === 'DISABLED') return !s.enabled;
      return true;
    });

    if (filtered.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">📜</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No PowerShell Scripts Found</div>
          <p>Add a new script or choose from pre-built enterprise templates.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Script Name</th>
            <th>Target Scope</th>
            <th>Run Context</th>
            <th>Frequency</th>
            <th>Runs / Success</th>
            <th>Status</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(s => {
            const successRate = s.total_runs > 0 ? Math.round((s.success_runs / s.total_runs) * 100) : 100;
            return `
              <tr class="script-row" data-id="${esc(s.id)}" style="cursor: pointer;">
                <td>
                  <div style="font-weight: 600; color: var(--text-primary);">${esc(s.name)}</div>
                  <div style="font-size: 12px; color: var(--text-muted); max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    ${esc(s.description || 'No description provided')}
                  </div>
                </td>
                <td>
                  <span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #60A5FA;">
                    ${esc(s.target_group_name || s.target_group_id || 'All Enrolled Devices')}
                  </span>
                </td>
                <td>
                  <span class="badge" style="background: rgba(107, 114, 128, 0.15); color: var(--text-muted);">
                    ${esc(s.run_as_account)} (${s.run_as_32bit ? '32-bit' : '64-bit'})
                  </span>
                </td>
                <td>
                  <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34D399;">
                    ${esc(s.run_frequency)}
                  </span>
                </td>
                <td>
                  <div style="font-weight: 600;">${s.total_runs} runs</div>
                  <div style="font-size: 11px; color: ${successRate >= 90 ? '#10B981' : '#F59E0B'};">
                    ${successRate}% success (${s.success_runs} ok, ${s.failed_runs} fail)
                  </div>
                </td>
                <td>
                  <span class="status-pill ${s.enabled ? 'status-online' : 'status-offline'}">
                    ${s.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td style="text-align: right;" onclick="event.stopPropagation();">
                  <div style="display: flex; gap: 6px; justify-content: flex-end;">
                    <button class="btn-action-sm btn-run-script" data-id="${esc(s.id)}" title="Run immediately across fleet">⚡ Run</button>
                    <button class="btn-action-sm btn-edit-script" data-id="${esc(s.id)}" title="Edit script policy">✏ Edit</button>
                    <button class="btn-action-sm btn-del-script" data-id="${esc(s.id)}" style="color: #ef4444;" title="Delete script">🗑</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function renderRunsTable() {
    if (_scriptRuns.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">📋</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No Execution Runs Logged</div>
          <p>Execution results will stream here as nodes poll heartbeats or execute on-demand scripts.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Executed At</th>
            <th>Node Hostname</th>
            <th>Script Name</th>
            <th>Mode</th>
            <th>Status</th>
            <th>Exit Code</th>
            <th>Duration</th>
            <th style="text-align: right;">Output</th>
          </tr>
        </thead>
        <tbody>
          ${_scriptRuns.map(r => {
            const isOk = r.status === 'SUCCESS';
            const timeStr = r.executed_at ? new Date(r.executed_at).toLocaleString() : 'Just now';
            return `
              <tr>
                <td style="font-size: 12px; color: var(--text-muted);">${esc(timeStr)}</td>
                <td style="font-weight: 600;">${esc(r.hostname || r.device_id)}</td>
                <td>${esc(r.script_name || r.script_id)}</td>
                <td><span class="badge" style="background: rgba(107, 114, 128, 0.15);">${esc(r.run_mode)}</span></td>
                <td>
                  <span class="status-pill ${isOk ? 'status-online' : 'status-error'}">
                    ${esc(r.status)}
                  </span>
                </td>
                <td><code>${r.exit_code !== null ? r.exit_code : 0}</code></td>
                <td>${r.execution_time_ms ? `${r.execution_time_ms} ms` : '—'}</td>
                <td style="text-align: right;">
                  <button class="btn-action-sm btn-view-output" data-run-id="${esc(r.id)}">👁 Logs</button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function render() {
    const container = document.getElementById('view-scripts');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header-row" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <h2 class="view-title" style="margin: 0;">📜 PowerShell scripts</h2>
          <div class="view-subtitle" style="color: var(--text-muted); font-size: 13px;">
            Deploy, schedule, and execute native Windows 10/11 PowerShell management scripts (Microsoft Intune Devices &gt; Scripts).
          </div>
        </div>
        <div style="display: flex; gap: 10px;">
          <button class="btn btn-secondary" id="btn-refresh-scripts">↻ Refresh</button>
          <button class="btn btn-secondary" id="btn-open-terminal" style="background: rgba(59, 130, 246, 0.15); color: #60A5FA; border-color: rgba(59, 130, 246, 0.3);">💻 Open Cloud Shell</button>
          <button class="btn btn-primary" id="btn-create-script">+ Add script</button>
        </div>
      </div>

      ${renderKpiCards()}
      ${renderSubTabs()}

      <div class="table-controls-bar" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <div style="display: flex; gap: 10px; width: 50%;">
          <input
            type="text"
            id="script-search-input"
            class="search-input"
            placeholder="🔍 Filter scripts by name, description, group…"
            value="${esc(_searchQuery)}"
            style="width: 100%;"
          />
          <select id="script-status-filter" class="form-control" style="width: 140px;">
            <option value="ALL" ${_statusFilter === 'ALL' ? 'selected' : ''}>All Status</option>
            <option value="ACTIVE" ${_statusFilter === 'ACTIVE' ? 'selected' : ''}>Enabled Only</option>
            <option value="DISABLED" ${_statusFilter === 'DISABLED' ? 'selected' : ''}>Disabled Only</option>
          </select>
        </div>
        <div style="font-size: 13px; color: var(--text-muted);">
          Total: <strong style="color: var(--text-primary);">${_scripts.length}</strong> scripts
        </div>
      </div>

      <div class="table-container" style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px;">
        ${_activeTab === 'catalog' ? renderCatalogTable() : renderRunsTable()}
      </div>
    `;

    bindEvents(container);
  }

  function bindEvents(container) {
    container.querySelector('#tab-btn-catalog')?.addEventListener('click', () => {
      _activeTab = 'catalog';
      render();
    });

    container.querySelector('#tab-btn-runs')?.addEventListener('click', () => {
      _activeTab = 'runs';
      render();
    });

    container.querySelector('#btn-refresh-scripts')?.addEventListener('click', () => {
      loadData();
    });

    container.querySelector('#btn-open-terminal')?.addEventListener('click', () => {
      if (window.RemoteTerminal) {
        window.RemoteTerminal.open();
      }
    });

    container.querySelector('#btn-create-script')?.addEventListener('click', () => {
      openScriptModal(null);
    });

    const searchInput = container.querySelector('#script-search-input');
    searchInput?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      const tc = container.querySelector('.table-container');
      if (tc) tc.innerHTML = _activeTab === 'catalog' ? renderCatalogTable() : renderRunsTable();
      bindTableActions(container);
    });

    const statusFilter = container.querySelector('#script-status-filter');
    statusFilter?.addEventListener('change', (e) => {
      _statusFilter = e.target.value;
      const tc = container.querySelector('.table-container');
      if (tc) tc.innerHTML = _activeTab === 'catalog' ? renderCatalogTable() : renderRunsTable();
      bindTableActions(container);
    });

    bindTableActions(container);
  }

  function bindTableActions(container) {
    container.querySelectorAll('.script-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-id');
        const script = _scripts.find(s => s.id === id);
        if (script) openScriptModal(script);
      });
    });

    container.querySelectorAll('.btn-run-script').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const script = _scripts.find(s => s.id === id);
        if (!confirm(`Dispatch script "${script?.name || id}" to all eligible fleet devices now?`)) return;
        try {
          btn.disabled = true;
          btn.textContent = '⏳';
          await window.FleetAPI.dispatchScriptRun(id);
          alert('Script successfully queued for dispatch across the fleet!');
          await loadData();
        } catch (err) {
          alert(`Failed to dispatch script: ${err.message}`);
          btn.disabled = false;
          btn.textContent = '⚡ Run';
        }
      });
    });

    container.querySelectorAll('.btn-edit-script').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const script = _scripts.find(s => s.id === id);
        if (script) openScriptModal(script);
      });
    });

    container.querySelectorAll('.btn-del-script').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const script = _scripts.find(s => s.id === id);
        if (!confirm(`Are you sure you want to delete script policy "${script?.name || id}"?`)) return;
        try {
          await window.FleetAPI.deleteScript(id);
          await loadData();
        } catch (err) {
          alert(`Delete failed: ${err.message}`);
        }
      });
    });

    container.querySelectorAll('.btn-view-output').forEach(btn => {
      btn.addEventListener('click', () => {
        const runId = btn.getAttribute('data-run-id');
        const run = _scriptRuns.find(r => r.id === runId);
        if (run) openOutputModal(run);
      });
    });
  }

  function openOutputModal(run) {
    let modal = document.getElementById('script-output-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'script-output-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }

    const isOk = run.status === 'SUCCESS';
    modal.innerHTML = `
      <div class="modal-dialog" style="max-width: 750px; width: 90%;">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center;">
          <h3 style="margin: 0;">📜 Execution Output: ${esc(run.script_name || run.script_id)}</h3>
          <button class="btn-close" id="btn-close-output-modal">✕</button>
        </div>
        <div class="modal-body" style="padding: 16px;">
          <div style="display: flex; gap: 12px; margin-bottom: 12px; font-size: 13px;">
            <div>Node: <strong>${esc(run.hostname || run.device_id)}</strong></div>
            <div>Status: <span class="status-pill ${isOk ? 'status-online' : 'status-error'}">${esc(run.status)}</span></div>
            <div>Exit Code: <code>${run.exit_code !== null ? run.exit_code : 0}</code></div>
            <div>Duration: <strong>${run.execution_time_ms || 0} ms</strong></div>
          </div>
          <div style="margin-bottom: 8px; font-weight: 600; font-size: 13px;">Standard Output:</div>
          <pre style="background: #0d1117; color: #58a6ff; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 240px; overflow: auto;">${esc(run.stdout || '[No standard output]')}</pre>
          ${run.stderr ? `
            <div style="margin: 12px 0 8px; font-weight: 600; font-size: 13px; color: #ef4444;">Standard Error:</div>
            <pre style="background: #1f1215; color: #f87171; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 150px; overflow: auto;">${esc(run.stderr)}</pre>
          ` : ''}
        </div>
        <div class="modal-footer" style="padding: 12px 16px; display: flex; justify-content: flex-end;">
          <button class="btn btn-secondary" id="btn-dismiss-output-modal">Close</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';
    const close = () => { modal.style.display = 'none'; };
    modal.querySelector('#btn-close-output-modal')?.addEventListener('click', close);
    modal.querySelector('#btn-dismiss-output-modal')?.addEventListener('click', close);
  }

  function openScriptModal(script = null) {
    let modal = document.getElementById('script-editor-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'script-editor-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }

    const isEdit = Boolean(script);
    const s = script || {
      id: '',
      name: '',
      description: '',
      script_content: '# Enterprise PowerShell Script\nWrite-Host "LocalPilot Fleet Script Initiated"\nexit 0',
      run_as_account: 'SYSTEM',
      run_as_32bit: false,
      enforce_signature_check: false,
      timeout_seconds: 300,
      target_group_id: 'grp-all',
      assignment_intent: 'ASSIGNED',
      run_frequency: 'ONCE',
      enabled: true
    };

    modal.innerHTML = `
      <div class="modal-dialog" style="max-width: 800px; width: 90%;">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center;">
          <h3 style="margin: 0;">${isEdit ? '✏ Edit PowerShell Script' : '➕ Add PowerShell Script'}</h3>
          <button class="btn-close" id="btn-close-editor-modal">✕</button>
        </div>
        <div class="modal-body" style="padding: 16px; max-height: 75vh; overflow-y: auto;">
          ${!isEdit ? `
            <div style="margin-bottom: 16px; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 6px; padding: 10px;">
              <div style="font-weight: 600; font-size: 12px; margin-bottom: 6px; color: #60A5FA;">⚡ Load Enterprise Preset Template:</div>
              <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                ${PRESETS.map((p, idx) => `
                  <button type="button" class="btn-action-sm btn-load-preset" data-idx="${idx}" style="font-size: 11px;">
                    ${esc(p.name)}
                  </button>
                `).join('')}
              </div>
            </div>
          ` : ''}

          <div class="form-group" style="margin-bottom: 12px;">
            <label style="font-weight: 600; font-size: 13px;">Script Name *</label>
            <input type="text" id="script-name-input" class="form-control" value="${esc(s.name)}" placeholder="e.g. Audit Local Administrators" style="width: 100%;" />
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label style="font-weight: 600; font-size: 13px;">Description</label>
            <input type="text" id="script-desc-input" class="form-control" value="${esc(s.description)}" placeholder="Purpose of this script policy" style="width: 100%;" />
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 12px;">
            <div class="form-group">
              <label style="font-weight: 600; font-size: 13px;">Target Group</label>
              <select id="script-group-select" class="form-control" style="width: 100%;">
                <option value="grp-all" ${s.target_group_id === 'grp-all' ? 'selected' : ''}>All Enrolled Devices</option>
                ${_groups.map(g => `
                  <option value="${esc(g.id)}" ${s.target_group_id === g.id ? 'selected' : ''}>${esc(g.name)}</option>
                `).join('')}
              </select>
            </div>

            <div class="form-group">
              <label style="font-weight: 600; font-size: 13px;">Run Frequency</label>
              <select id="script-freq-select" class="form-control" style="width: 100%;">
                <option value="ONCE" ${s.run_frequency === 'ONCE' ? 'selected' : ''}>Run Once (Policy)</option>
                <option value="SCHEDULED" ${s.run_frequency === 'SCHEDULED' ? 'selected' : ''}>Scheduled (Periodic)</option>
                <option value="ON_DEMAND" ${s.run_frequency === 'ON_DEMAND' ? 'selected' : ''}>On Demand Only</option>
              </select>
            </div>

            <div class="form-group">
              <label style="font-weight: 600; font-size: 13px;">Run As Context</label>
              <select id="script-context-select" class="form-control" style="width: 100%;">
                <option value="SYSTEM" ${s.run_as_account === 'SYSTEM' ? 'selected' : ''}>SYSTEM (Elevated)</option>
                <option value="USER" ${s.run_as_account === 'USER' ? 'selected' : ''}>User (Logged-on)</option>
              </select>
            </div>
          </div>

          <div style="display: flex; gap: 20px; margin-bottom: 12px; font-size: 13px;">
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
              <input type="checkbox" id="script-32bit-check" ${s.run_as_32bit ? 'checked' : ''} />
              Run script in 32-bit PowerShell Host (SysWOW64)
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
              <input type="checkbox" id="script-enabled-check" ${s.enabled ? 'checked' : ''} />
              Enabled / Active Policy
            </label>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label style="font-weight: 600; font-size: 13px;">PowerShell Script Content *</label>
            <textarea id="script-content-input" class="form-control" rows="12" style="width: 100%; font-family: monospace; font-size: 12px; background: #0d1117; color: #58a6ff; line-height: 1.4; padding: 10px;">${esc(s.script_content)}</textarea>
          </div>
        </div>
        <div class="modal-footer" style="padding: 12px 16px; display: flex; justify-content: flex-end; gap: 10px;">
          <button class="btn btn-secondary" id="btn-cancel-editor-modal">Cancel</button>
          <button class="btn btn-primary" id="btn-save-script-modal">Save Script</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';
    const close = () => { modal.style.display = 'none'; };
    modal.querySelector('#btn-close-editor-modal')?.addEventListener('click', close);
    modal.querySelector('#btn-cancel-editor-modal')?.addEventListener('click', close);

    modal.querySelectorAll('.btn-load-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.getAttribute('data-idx'));
        const p = PRESETS[idx];
        if (!p) return;
        modal.querySelector('#script-name-input').value = p.name;
        modal.querySelector('#script-desc-input').value = p.desc;
        modal.querySelector('#script-freq-select').value = p.freq;
        modal.querySelector('#script-context-select').value = p.context;
        modal.querySelector('#script-32bit-check').checked = p.is32;
        modal.querySelector('#script-content-input').value = p.script;
      });
    });

    modal.querySelector('#btn-save-script-modal')?.addEventListener('click', async () => {
      const name = modal.querySelector('#script-name-input').value.trim();
      const desc = modal.querySelector('#script-desc-input').value.trim();
      const content = modal.querySelector('#script-content-input').value;
      const targetGroup = modal.querySelector('#script-group-select').value;
      const freq = modal.querySelector('#script-freq-select').value;
      const context = modal.querySelector('#script-context-select').value;
      const is32 = modal.querySelector('#script-32bit-check').checked;
      const enabled = modal.querySelector('#script-enabled-check').checked;

      if (!name) {
        alert('Script Name is required.');
        return;
      }
      if (!content || !content.trim()) {
        alert('Script Content cannot be empty.');
        return;
      }

      const payload = {
        name,
        description: desc,
        script_content: content,
        target_group_id: targetGroup,
        run_frequency: freq,
        run_as_account: context,
        run_as_32bit: is32,
        enabled
      };

      try {
        if (isEdit) {
          await window.FleetAPI.updateScript(s.id, payload);
        } else {
          await window.FleetAPI.createScript(payload);
        }
        close();
        await loadData();
      } catch (err) {
        alert(`Failed to save script: ${err.message}`);
      }
    });
  }

  window.ScriptsTable = {
    init: loadData,
    refresh: loadData
  };
})();
