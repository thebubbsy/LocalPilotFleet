/**
 * LocalPilot Fleet — Device Remote Actions, Diagnostics & Bulk Orchestrator UI Blade
 * dashboard/js/components/remoteActionsTable.js
 *
 * Implements Microsoft Intune Remote Device Actions & Diagnostics Orchestration:
 * - Executive KPI summary cards (Total Dispatched, In-Flight, Completed Today, Diagnostic Bundles)
 * - 3 sub-tabs: Action History, Diagnostic Log Bundles, Bulk Action Orchestrator
 * - Modal action launchers for individual devices & dynamic group bulk executions
 * - Streaming download for diagnostics ZIP archives
 * - Real-time auto-refresh on SSE dispatch
 */

(function() {
  let _activeSubTab = 'history';
  let _actionsCache = [];
  let _diagnosticsCache = [];
  let _bulkCache = [];
  let _devicesCache = [];
  let _groupsCache = [];
  let _searchQuery = '';
  let _statusFilter = '';
  let _typeFilter = '';

  function init() {
    renderLayout();
    loadAllData();
  }

  function renderLayout() {
    const container = document.getElementById('tab-remote-actions');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <div>
          <div style="font-size:20px;font-weight:600;color:var(--text-bright);display:flex;align-items:center;gap:8px;">
            <span>⚡</span> Remote Actions &amp; Diagnostics Orchestrator
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">
            Zero-cloud Microsoft Intune device lifecycle actions, scheduled reboots, lock workstation, diagnostic collection &amp; bulk group orchestration
          </div>
        </div>
        <div style="display:flex;gap:8px;">
          <button class="intune-btn" id="btn-ra-refresh" style="display:flex;align-items:center;gap:6px;">
            <span>🔄</span> Refresh
          </button>
          <button class="intune-btn" id="btn-ra-bulk-action" style="display:flex;align-items:center;gap:6px;">
            <span>🚀</span> Bulk Group Action
          </button>
          <button class="intune-btn primary" id="btn-ra-dispatch-action" style="display:flex;align-items:center;gap:6px;">
            <span>⚡</span> Dispatch Action
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="ra-kpis" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;padding:20px 24px;background:var(--bg-main);">
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);font-weight:500;">TOTAL DISPATCHED</div>
          <div id="kpi-ra-total" style="font-size:28px;font-weight:700;color:var(--text-bright);margin-top:4px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">All-time device lifecycle actions</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);font-weight:500;">IN-FLIGHT / PENDING</div>
          <div id="kpi-ra-inflight" style="font-size:28px;font-weight:700;color:var(--accent-blue, #3b82f6);margin-top:4px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Queued or currently executing</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);font-weight:500;">COMPLETED (24H)</div>
          <div id="kpi-ra-completed" style="font-size:28px;font-weight:700;color:var(--accent-green, #10b981);margin-top:4px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Successfully acknowledged runs</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);font-weight:500;">DIAGNOSTIC BUNDLES</div>
          <div id="kpi-ra-diagnostics" style="font-size:28px;font-weight:700;color:var(--accent-purple, #8b5cf6);margin-top:4px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">System archives ready for download</div>
        </div>
      </div>

      <!-- Tab Bar -->
      <div class="tab-bar" style="display:flex;gap:24px;padding:0 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <button class="sub-tab active" data-subtab="history" style="background:none;border:none;padding:12px 4px;font-size:13px;font-weight:600;color:var(--text-bright);border-bottom:2px solid var(--accent-blue);cursor:pointer;">
          📜 Action History
        </button>
        <button class="sub-tab" data-subtab="diagnostics" style="background:none;border:none;padding:12px 4px;font-size:13px;font-weight:600;color:var(--text-muted);border-bottom:2px solid transparent;cursor:pointer;">
          📦 Diagnostic Log Bundles
        </button>
        <button class="sub-tab" data-subtab="bulk" style="background:none;border:none;padding:12px 4px;font-size:13px;font-weight:600;color:var(--text-muted);border-bottom:2px solid transparent;cursor:pointer;">
          🚀 Bulk Group Orchestrator
        </button>
      </div>

      <!-- Tab Content Area -->
      <div id="ra-subtab-content" style="padding:20px 24px;"></div>

      <!-- Action Modal -->
      <div id="modal-ra-dispatch" class="modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:560px;max-width:90vw;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,0.5);">
          <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
            <div style="font-weight:600;font-size:16px;color:var(--text-bright);display:flex;align-items:center;gap:8px;">
              <span>⚡</span> Dispatch Remote Device Action
            </div>
            <button class="ra-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;">&times;</button>
          </div>
          <div style="padding:20px;display:flex;flex-direction:column;gap:14px;max-height:75vh;overflow-y:auto;">
            <div>
              <label class="intune-label">Target Device</label>
              <select id="sel-ra-device" class="intune-input" style="width:100%;">
                <option value="">Loading devices…</option>
              </select>
            </div>
            <div>
              <label class="intune-label">Action Type</label>
              <select id="sel-ra-action" class="intune-input" style="width:100%;">
                <option value="REMOTE_LOCK">🔒 Remote Lock (Lock console session)</option>
                <option value="RESTART">↻ Restart Machine (Scheduled countdown)</option>
                <option value="SHUTDOWN">⏻ Shutdown Machine (Scheduled countdown)</option>
                <option value="CANCEL_SHUTDOWN">❌ Cancel Pending Shutdown/Restart</option>
                <option value="COLLECT_DIAGNOSTICS">📦 Collect Windows MDM Diagnostics Package</option>
                <option value="SYNC_MDM">🔄 Sync MDM Policies &amp; Telemetry</option>
                <option value="DEFENDER_SCAN">⚡ Microsoft Defender Quick Scan</option>
                <option value="FRESH_START">✨ Fresh Start (Reinstall Windows &amp; Clean Apps)</option>
                <option value="WIPE">⚠️ Remote Wipe (Full Enterprise Decommission)</option>
              </select>
            </div>
            <div id="ra-param-delay-container" style="display:none;">
              <label class="intune-label">Countdown Delay (Seconds)</label>
              <input id="input-ra-delay" type="number" class="intune-input" value="60" min="0" max="3600" style="width:100%;">
              <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">User will see native Windows countdown prompt before reboot.</div>
            </div>
            <div id="ra-param-msg-container" style="display:none;">
              <label class="intune-label">Custom Notification Message</label>
              <input id="input-ra-message" type="text" class="intune-input" value="LocalPilot Fleet Administrator has scheduled a reboot for system maintenance." style="width:100%;">
            </div>
            <div id="ra-param-diag-container" style="display:none;">
              <label class="intune-label">Diagnostic Packages to Collect</label>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;margin-top:6px;">
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chk-diag-sys" checked> System Specs &amp; Uptime</label>
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chk-diag-events" checked> Windows Event Logs (4720/Sys)</label>
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chk-diag-net" checked> IP &amp; Network Adapters</label>
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chk-diag-bit" checked> BitLocker Status</label>
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chk-diag-patches" checked> Installed Hotfixes</label>
              </div>
            </div>
          </div>
          <div style="padding:14px 20px;border-top:1px solid var(--border-color);background:var(--bg-main);display:flex;justify-content:flex-end;gap:8px;">
            <button class="intune-btn ra-modal-close">Cancel</button>
            <button class="intune-btn primary" id="btn-ra-submit-dispatch">⚡ Dispatch Command</button>
          </div>
        </div>
      </div>

      <!-- Bulk Action Modal -->
      <div id="modal-ra-bulk" class="modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:560px;max-width:90vw;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,0.5);">
          <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
            <div style="font-weight:600;font-size:16px;color:var(--text-bright);display:flex;align-items:center;gap:8px;">
              <span>🚀</span> Dispatch Bulk Action across Dynamic Group
            </div>
            <button class="ra-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;">&times;</button>
          </div>
          <div style="padding:20px;display:flex;flex-direction:column;gap:14px;">
            <div>
              <label class="intune-label">Operation Title / Identifier</label>
              <input id="input-ra-bulk-name" type="text" class="intune-input" value="Emergency Fleet Telemetry Sync" style="width:100%;">
            </div>
            <div>
              <label class="intune-label">Target Dynamic Group</label>
              <select id="sel-ra-bulk-group" class="intune-input" style="width:100%;">
                <option value="grp-all">All Enrolled Devices (Entire Fleet)</option>
              </select>
            </div>
            <div>
              <label class="intune-label">Action Type</label>
              <select id="sel-ra-bulk-action" class="intune-input" style="width:100%;">
                <option value="SYNC_MDM">🔄 Force Telemetry &amp; Policy Sync</option>
                <option value="DEFENDER_SCAN">⚡ Microsoft Defender Quick Scan</option>
                <option value="COLLECT_DIAGNOSTICS">📦 Collect Diagnostic Packages</option>
                <option value="RESTART">↻ Scheduled Fleet Reboot</option>
                <option value="REMOTE_LOCK">🔒 Fleet Remote Lock</option>
              </select>
            </div>
          </div>
          <div style="padding:14px 20px;border-top:1px solid var(--border-color);background:var(--bg-main);display:flex;justify-content:flex-end;gap:8px;">
            <button class="intune-btn ra-modal-close">Cancel</button>
            <button class="intune-btn primary" id="btn-ra-submit-bulk">🚀 Fan-Out Bulk Action</button>
          </div>
        </div>
      </div>
    `;

    bindLayoutEvents();
  }

  function bindLayoutEvents() {
    // Refresh button
    document.getElementById('btn-ra-refresh')?.addEventListener('click', loadAllData);

    // Sub-tab switcher
    document.querySelectorAll('.sub-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.sub-tab').forEach(t => {
          t.classList.remove('active');
          t.style.color = 'var(--text-muted)';
          t.style.borderBottomColor = 'transparent';
        });
        tab.classList.add('active');
        tab.style.color = 'var(--text-bright)';
        tab.style.borderBottomColor = 'var(--accent-blue)';
        _activeSubTab = tab.dataset.subtab;
        renderSubTab();
      });
    });

    // Modals
    const modalDispatch = document.getElementById('modal-ra-dispatch');
    const modalBulk = document.getElementById('modal-ra-bulk');

    document.getElementById('btn-ra-dispatch-action')?.addEventListener('click', () => {
      if (modalDispatch) modalDispatch.style.display = 'flex';
      populateDeviceSelect();
      updateParamVisibility();
    });

    document.getElementById('btn-ra-bulk-action')?.addEventListener('click', () => {
      if (modalBulk) modalBulk.style.display = 'flex';
      populateGroupSelect();
    });

    document.querySelectorAll('.ra-modal-close').forEach(btn => {
      btn.addEventListener('click', () => {
        if (modalDispatch) modalDispatch.style.display = 'none';
        if (modalBulk) modalBulk.style.display = 'none';
      });
    });

    // Dynamic parameter form display
    document.getElementById('sel-ra-action')?.addEventListener('change', updateParamVisibility);

    // Submit individual dispatch
    document.getElementById('btn-ra-submit-dispatch')?.addEventListener('click', async () => {
      const deviceId = document.getElementById('sel-ra-device')?.value;
      const actionType = document.getElementById('sel-ra-action')?.value;
      if (!deviceId) return alert('Please select a target device.');

      const parameters = {};
      if (actionType === 'RESTART' || actionType === 'SHUTDOWN') {
        parameters.delay_sec = Number(document.getElementById('input-ra-delay')?.value || 60);
        parameters.message = document.getElementById('input-ra-message')?.value;
      } else if (actionType === 'COLLECT_DIAGNOSTICS') {
        parameters.categories = [];
        if (document.getElementById('chk-diag-sys')?.checked) parameters.categories.push('SYSTEM_LOGS');
        if (document.getElementById('chk-diag-events')?.checked) parameters.categories.push('SECURITY_LOGS');
        if (document.getElementById('chk-diag-net')?.checked) parameters.categories.push('NETWORK');
        if (document.getElementById('chk-diag-bit')?.checked) parameters.categories.push('BITLOCKER');
        if (document.getElementById('chk-diag-patches')?.checked) parameters.categories.push('HOTFIXES');
      }

      try {
        await window.FleetAPI.queueRemoteAction({
          device_id: deviceId,
          action_type: actionType,
          parameters,
          initiated_by: 'Fleet Admin (Console)'
        });
        if (typeof showToast === 'function') showToast('Action Dispatched', `${actionType} queued for node.`, 'success');
        if (modalDispatch) modalDispatch.style.display = 'none';
        loadAllData();
      } catch (err) {
        alert(`Dispatch failed: ${err.message}`);
      }
    });

    // Submit bulk action
    document.getElementById('btn-ra-submit-bulk')?.addEventListener('click', async () => {
      const name = document.getElementById('input-ra-bulk-name')?.value.trim();
      const targetGroupId = document.getElementById('sel-ra-bulk-group')?.value;
      const actionType = document.getElementById('sel-ra-bulk-action')?.value;

      if (!name) return alert('Please enter an action title.');

      try {
        const bulk = await window.FleetAPI.createBulkAction({
          name,
          action_type: actionType,
          target_group_id: targetGroupId,
          parameters: {},
          initiated_by: 'Fleet Admin (Bulk Console)'
        });
        if (typeof showToast === 'function') showToast('Bulk Action Dispatched', `Fanned out ${actionType} across ${bulk.total_devices} nodes.`, 'success');
        if (modalBulk) modalBulk.style.display = 'none';
        _activeSubTab = 'bulk';
        document.querySelectorAll('.sub-tab').forEach(t => {
          if (t.dataset.subtab === 'bulk') t.click();
        });
        loadAllData();
      } catch (err) {
        alert(`Bulk dispatch failed: ${err.message}`);
      }
    });
  }

  function updateParamVisibility() {
    const actionType = document.getElementById('sel-ra-action')?.value;
    const delayCont = document.getElementById('ra-param-delay-container');
    const msgCont = document.getElementById('ra-param-msg-container');
    const diagCont = document.getElementById('ra-param-diag-container');

    const isReboot = (actionType === 'RESTART' || actionType === 'SHUTDOWN');
    const isDiag = (actionType === 'COLLECT_DIAGNOSTICS');

    if (delayCont) delayCont.style.display = isReboot ? 'block' : 'none';
    if (msgCont) msgCont.style.display = isReboot ? 'block' : 'none';
    if (diagCont) diagCont.style.display = isDiag ? 'block' : 'none';
  }

  async function populateDeviceSelect() {
    const sel = document.getElementById('sel-ra-device');
    if (!sel) return;
    try {
      const res = await window.FleetAPI.getDevices();
      const devs = res.devices || [];
      _devicesCache = devs;
      sel.innerHTML = devs.map(d => `<option value="${d.id}">${escapeHtml(d.hostname)} (${escapeHtml(d.friendly_name || d.serial_number || d.status)})</option>`).join('');
    } catch (_) {}
  }

  async function populateGroupSelect() {
    const sel = document.getElementById('sel-ra-bulk-group');
    if (!sel) return;
    try {
      const groups = await window.FleetAPI.getGroups();
      _groupsCache = groups || [];
      sel.innerHTML = `
        <option value="grp-all">All Enrolled Devices (Entire Fleet)</option>
        ${_groupsCache.map(g => `<option value="${g.id}">${escapeHtml(g.name)} (${g.members_count || 0} nodes)</option>`).join('')}
      `;
    } catch (_) {}
  }

  async function loadAllData() {
    try {
      const [stats, actionsRes, bulkRes] = await Promise.all([
        window.FleetAPI.getRemoteActionStats(),
        window.FleetAPI.getRemoteActions({ limit: 100 }),
        window.FleetAPI.getBulkActions()
      ]);

      // Update KPI Cards
      document.getElementById('kpi-ra-total').textContent = stats.total_actions ?? 0;
      document.getElementById('kpi-ra-inflight').textContent = (stats.pending_actions || 0) + (stats.in_flight_actions || 0);
      document.getElementById('kpi-ra-completed').textContent = stats.completed_today ?? 0;
      document.getElementById('kpi-ra-diagnostics').textContent = stats.total_diagnostics ?? 0;

      _actionsCache = actionsRes.actions || [];
      _bulkCache = bulkRes.bulk_actions || [];

      renderSubTab();
    } catch (err) {
      console.error('[RemoteActionsTable] Error loading data:', err);
    }
  }

  function renderSubTab() {
    const container = document.getElementById('ra-subtab-content');
    if (!container) return;

    switch (_activeSubTab) {
      case 'history':
        renderActionHistory(container);
        break;
      case 'diagnostics':
        renderDiagnosticBundles(container);
        break;
      case 'bulk':
        renderBulkOrchestrator(container);
        break;
    }
  }

  /* ── 1. Action History Sub-tab ── */
  function renderActionHistory(container) {
    let filtered = _actionsCache.slice();
    if (_searchQuery) {
      const q = _searchQuery.toLowerCase();
      filtered = filtered.filter(a =>
        (a.hostname && a.hostname.toLowerCase().includes(q)) ||
        (a.action_type && a.action_type.toLowerCase().includes(q)) ||
        (a.initiated_by && a.initiated_by.toLowerCase().includes(q))
      );
    }
    if (_statusFilter) {
      filtered = filtered.filter(a => a.status === _statusFilter);
    }
    if (_typeFilter) {
      filtered = filtered.filter(a => a.action_type === _typeFilter);
    }

    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px;flex-wrap:wrap;">
        <div style="display:flex;gap:8px;flex:1;max-width:600px;">
          <input type="text" id="ra-search-input" class="intune-input" placeholder="Search by hostname, action, initiator…" value="${escapeHtml(_searchQuery)}" style="flex:1;">
          <select id="ra-filter-status" class="intune-input" style="width:140px;">
            <option value="">All Statuses</option>
            <option value="PENDING" ${_statusFilter === 'PENDING' ? 'selected' : ''}>Pending</option>
            <option value="DISPATCHED" ${_statusFilter === 'DISPATCHED' ? 'selected' : ''}>Dispatched</option>
            <option value="COMPLETED" ${_statusFilter === 'COMPLETED' ? 'selected' : ''}>Completed</option>
            <option value="FAILED" ${_statusFilter === 'FAILED' ? 'selected' : ''}>Failed</option>
            <option value="CANCELLED" ${_statusFilter === 'CANCELLED' ? 'selected' : ''}>Cancelled</option>
          </select>
          <select id="ra-filter-type" class="intune-input" style="width:160px;">
            <option value="">All Actions</option>
            <option value="REMOTE_LOCK" ${_typeFilter === 'REMOTE_LOCK' ? 'selected' : ''}>Remote Lock</option>
            <option value="RESTART" ${_typeFilter === 'RESTART' ? 'selected' : ''}>Restart</option>
            <option value="SHUTDOWN" ${_typeFilter === 'SHUTDOWN' ? 'selected' : ''}>Shutdown</option>
            <option value="COLLECT_DIAGNOSTICS" ${_typeFilter === 'COLLECT_DIAGNOSTICS' ? 'selected' : ''}>Diagnostics</option>
            <option value="SYNC_MDM" ${_typeFilter === 'SYNC_MDM' ? 'selected' : ''}>Sync MDM</option>
            <option value="DEFENDER_SCAN" ${_typeFilter === 'DEFENDER_SCAN' ? 'selected' : ''}>Defender Scan</option>
          </select>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          Showing <strong>${filtered.length}</strong> of ${_actionsCache.length} actions
        </div>
      </div>

      <div class="blade-table-wrapper" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">
        <table class="blade-table" style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);text-align:left;color:var(--text-muted);background:var(--bg-main);">
              <th style="padding:10px 14px;">Timestamp</th>
              <th style="padding:10px 14px;">Device</th>
              <th style="padding:10px 14px;">Action</th>
              <th style="padding:10px 14px;">Status</th>
              <th style="padding:10px 14px;">Initiated By</th>
              <th style="padding:10px 14px;">Execution Result</th>
              <th style="padding:10px 14px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.length === 0 ? `
              <tr>
                <td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted);">
                  No remote lifecycle actions match the selected filter.
                </td>
              </tr>
            ` : filtered.map(a => {
              const statusColor = a.status === 'COMPLETED' ? '#10b981' : (a.status === 'FAILED' ? '#ef4444' : (a.status === 'PENDING' ? '#f59e0b' : '#3b82f6'));
              const actionIcon = {
                REMOTE_LOCK: '🔒',
                RESTART: '↻',
                SHUTDOWN: '⏻',
                CANCEL_SHUTDOWN: '❌',
                COLLECT_DIAGNOSTICS: '📦',
                SYNC_MDM: '🔄',
                DEFENDER_SCAN: '⚡',
                FRESH_START: '✨',
                WIPE: '⚠️'
              }[a.action_type] || '⚡';

              const resSnippet = a.error_message ? `<span style="color:#ef4444;">${escapeHtml(a.error_message)}</span>` : (a.result_data && a.result_data.message ? escapeHtml(a.result_data.message) : '—');

              return `
                <tr style="border-bottom:1px solid var(--border-color);">
                  <td style="padding:10px 14px;color:var(--text-muted);">${new Date(a.created_at).toLocaleString()}</td>
                  <td style="padding:10px 14px;font-weight:600;color:var(--text-bright);">
                    ${escapeHtml(a.hostname || a.device_id)}
                  </td>
                  <td style="padding:10px 14px;">
                    <span style="font-weight:500;">${actionIcon} ${escapeHtml(a.action_type)}</span>
                  </td>
                  <td style="padding:10px 14px;">
                    <span class="badge" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}55;font-weight:600;">
                      ${escapeHtml(a.status)}
                    </span>
                  </td>
                  <td style="padding:10px 14px;color:var(--text-muted);">${escapeHtml(a.initiated_by || 'LocalPilot Administrator')}</td>
                  <td style="padding:10px 14px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    ${resSnippet}
                  </td>
                  <td style="padding:10px 14px;text-align:right;">
                    ${(a.status === 'PENDING' || a.status === 'DISPATCHED') ? `
                      <button class="intune-btn small btn-ra-cancel" data-id="${a.id}" style="padding:2px 8px;font-size:11px;color:#ef4444;">
                        Cancel
                      </button>
                    ` : ''}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;

    // Filter bindings
    document.getElementById('ra-search-input')?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      renderActionHistory(container);
    });
    document.getElementById('ra-filter-status')?.addEventListener('change', (e) => {
      _statusFilter = e.target.value;
      renderActionHistory(container);
    });
    document.getElementById('ra-filter-type')?.addEventListener('change', (e) => {
      _typeFilter = e.target.value;
      renderActionHistory(container);
    });

    // Cancel action button
    container.querySelectorAll('.btn-ra-cancel').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (!confirm('Are you sure you want to cancel this pending remote action?')) return;
        try {
          await window.FleetAPI.cancelRemoteAction(id);
          if (typeof showToast === 'function') showToast('Action Cancelled', 'Pending action has been cancelled.', 'info');
          loadAllData();
        } catch (err) {
          alert(`Cancellation failed: ${err.message}`);
        }
      });
    });
  }

  /* ── 2. Diagnostic Log Bundles Sub-tab ── */
  async function renderDiagnosticBundles(container) {
    container.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text-muted);">⏳ Loading diagnostic package vault…</div>`;

    try {
      const devRes = await window.FleetAPI.getDevices();
      const devices = devRes.devices || [];

      // Query diagnostics for all devices
      const bundlesList = [];
      await Promise.all(devices.map(async d => {
        try {
          const res = await window.FleetAPI.getDeviceDiagnostics(d.id);
          (res.bundles || []).forEach(b => {
            bundlesList.push({ ...b, hostname: d.hostname });
          });
        } catch (_) {}
      }));

      bundlesList.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

      container.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div>
            <div style="font-weight:600;font-size:14px;color:var(--text-bright);">Standard Windows MDM Diagnostic Packages</div>
            <div style="font-size:12px;color:var(--text-muted);">Archived system, security, event log, and BitLocker diagnostic zip bundles collected from nodes</div>
          </div>
          <button class="intune-btn primary" id="btn-ra-trigger-diag">
            <span>📦</span> Collect Diagnostics Now
          </button>
        </div>

        <div class="blade-table-wrapper" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">
          <table class="blade-table" style="width:100%;border-collapse:collapse;font-size:12px;">
            <thead>
              <tr style="border-bottom:1px solid var(--border-color);text-align:left;color:var(--text-muted);background:var(--bg-main);">
                <th style="padding:10px 14px;">Collected At</th>
                <th style="padding:10px 14px;">Device</th>
                <th style="padding:10px 14px;">Package File Name</th>
                <th style="padding:10px 14px;">Size</th>
                <th style="padding:10px 14px;">Categories Included</th>
                <th style="padding:10px 14px;">Status</th>
                <th style="padding:10px 14px;text-align:right;">Download</th>
              </tr>
            </thead>
            <tbody>
              ${bundlesList.length === 0 ? `
                <tr>
                  <td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted);">
                    No diagnostic bundles collected yet. Click "Collect Diagnostics Now" to gather a package from a node.
                  </td>
                </tr>
              ` : bundlesList.map(b => {
                const kb = Math.round(b.file_size_bytes / 1024);
                const cats = Array.isArray(b.categories) ? b.categories : [];
                const downloadUrl = window.FleetAPI.getDiagnosticsDownloadUrl(b.id);

                return `
                  <tr style="border-bottom:1px solid var(--border-color);">
                    <td style="padding:10px 14px;color:var(--text-muted);">${new Date(b.created_at).toLocaleString()}</td>
                    <td style="padding:10px 14px;font-weight:600;color:var(--text-bright);">${escapeHtml(b.hostname)}</td>
                    <td style="padding:10px 14px;font-family:monospace;color:var(--accent-blue);">${escapeHtml(b.file_name)}</td>
                    <td style="padding:10px 14px;">${kb} KB</td>
                    <td style="padding:10px 14px;">
                      <div style="display:flex;gap:4px;flex-wrap:wrap;">
                        ${cats.map(c => `<span class="badge badge-neutral" style="font-size:10px;">${escapeHtml(c)}</span>`).join('')}
                      </div>
                    </td>
                    <td style="padding:10px 14px;">
                      <span class="badge badge-success">READY</span>
                    </td>
                    <td style="padding:10px 14px;text-align:right;">
                      <a href="${downloadUrl}" download="${escapeHtml(b.file_name)}" class="intune-btn small primary" style="text-decoration:none;display:inline-flex;align-items:center;gap:4px;padding:2px 10px;font-size:11px;">
                        <span>📥</span> Download ZIP
                      </a>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `;

      document.getElementById('btn-ra-trigger-diag')?.addEventListener('click', () => {
        document.getElementById('btn-ra-dispatch-action')?.click();
        const selAction = document.getElementById('sel-ra-action');
        if (selAction) {
          selAction.value = 'COLLECT_DIAGNOSTICS';
          updateParamVisibility();
        }
      });
    } catch (err) {
      container.innerHTML = `<div style="padding:24px;color:#ef4444;">Failed to load diagnostics: ${escapeHtml(err.message)}</div>`;
    }
  }

  /* ── 3. Bulk Group Orchestrator Sub-tab ── */
  function renderBulkOrchestrator(container) {
    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-weight:600;font-size:14px;color:var(--text-bright);">Dynamic Group Bulk Execution Registry</div>
          <div style="font-size:12px;color:var(--text-muted);">Track fleet-wide fan-out actions dispatched across target device groups with real-time completion progress</div>
        </div>
        <button class="intune-btn primary" id="btn-ra-new-bulk">
          <span>🚀</span> Dispatch New Bulk Action
        </button>
      </div>

      <div class="blade-table-wrapper" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">
        <table class="blade-table" style="width:100%;border-collapse:collapse;font-size:12px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);text-align:left;color:var(--text-muted);background:var(--bg-main);">
              <th style="padding:10px 14px;">Timestamp</th>
              <th style="padding:10px 14px;">Operation Title</th>
              <th style="padding:10px 14px;">Action Type</th>
              <th style="padding:10px 14px;">Target Group</th>
              <th style="padding:10px 14px;">Progress (Done / Total)</th>
              <th style="padding:10px 14px;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${_bulkCache.length === 0 ? `
              <tr>
                <td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">
                  No bulk actions recorded. Click "Dispatch New Bulk Action" to run commands across groups.
                </td>
              </tr>
            ` : _bulkCache.map(b => {
              const pct = b.total_devices > 0 ? Math.round(((b.completed_count + b.failed_count) / b.total_devices) * 100) : 100;
              const statusColor = b.status === 'COMPLETED' ? '#10b981' : (b.status === 'FAILED' ? '#ef4444' : '#3b82f6');

              return `
                <tr style="border-bottom:1px solid var(--border-color);">
                  <td style="padding:10px 14px;color:var(--text-muted);">${new Date(b.created_at).toLocaleString()}</td>
                  <td style="padding:10px 14px;font-weight:600;color:var(--text-bright);">${escapeHtml(b.name)}</td>
                  <td style="padding:10px 14px;"><span class="badge badge-neutral">${escapeHtml(b.action_type)}</span></td>
                  <td style="padding:10px 14px;color:var(--accent-blue);">${escapeHtml(b.target_group_name || 'All Enrolled Devices')}</td>
                  <td style="padding:10px 14px;min-width:180px;">
                    <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;">
                      <span>${b.completed_count} / ${b.total_devices} nodes</span>
                      <span>${pct}%</span>
                    </div>
                    <div style="width:100%;height:6px;background:#334155;border-radius:3px;overflow:hidden;">
                      <div style="width:${pct}%;height:100%;background:${statusColor};border-radius:3px;"></div>
                    </div>
                  </td>
                  <td style="padding:10px 14px;">
                    <span class="badge" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}55;font-weight:600;">
                      ${escapeHtml(b.status)}
                    </span>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;

    document.getElementById('btn-ra-new-bulk')?.addEventListener('click', () => {
      document.getElementById('btn-ra-bulk-action')?.click();
    });
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m]));
  }

  // SSE Listener for live real-time action progress updates
  window.addEventListener('fleet:remote_action_queued', () => loadAllData());
  window.addEventListener('fleet:remote_action_dispatched', () => loadAllData());
  window.addEventListener('fleet:remote_action_completed', () => loadAllData());
  window.addEventListener('fleet:bulk_action_dispatched', () => loadAllData());

  window.RemoteActionsTable = {
    init,
    loadAllData
  };
})();
