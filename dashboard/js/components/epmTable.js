/**
 * LocalPilot Fleet — Endpoint Privilege Management (EPM) UI Blade
 * dashboard/js/components/epmTable.js
 *
 * Implements Microsoft Intune Endpoint Privilege Management (EPM) governance blade:
 * - Executive KPI summary cards (Rules, Policies, Pending Requests, 24h Elevations)
 * - 3 sub-tabs: Elevation Rules, Approval Queue, Elevation Audit Log
 * - Create Elevation Rule Wizard with enterprise presets
 * - Elevation Request Review Modal (Approve / Deny with justification notes)
 */

(function() {
  let _activeSubTab = 'rules';
  let _rulesCache = [];
  let _policiesCache = [];
  let _requestsCache = [];
  let _logsCache = [];
  let _searchQuery = '';
  let _elevationTypeFilter = '';
  let _requestStatusFilter = '';

  function init() {
    renderLayout();
    loadAllData();
  }

  function renderLayout() {
    const container = document.getElementById('tab-epm');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <div>
          <div style="font-size:20px;font-weight:600;color:var(--text-bright);display:flex;align-items:center;gap:8px;">
            <span>🛡️</span> Endpoint Privilege Management (EPM)
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">
            Intune standard-user elevation governance, granular file/hash rules, operator approval queue &amp; execution audit trail
          </div>
        </div>
        <div style="display:flex;gap:8px;">
          <button class="intune-btn" id="btn-epm-refresh" style="display:flex;align-items:center;gap:6px;">
            <span>🔄</span> Refresh
          </button>
          <button class="intune-btn primary" id="btn-epm-create-rule" style="display:flex;align-items:center;gap:6px;">
            <span>➕</span> Create Elevation Rule
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="epm-kpis" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;padding:20px 24px;background:var(--bg-main);">
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Active Elevation Rules</div>
          <div id="kpi-epm-rules" style="font-size:28px;font-weight:700;color:var(--text-bright);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-epm-policies-sub">Across 0 active policies</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Pending Approval Requests</div>
          <div id="kpi-epm-pending" style="font-size:28px;font-weight:700;color:var(--accent-orange, #f59e0b);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Awaiting operator review</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Elevations (Last 24h)</div>
          <div id="kpi-epm-24h" style="font-size:28px;font-weight:700;color:var(--accent-green, #10b981);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-epm-auto-sub">0 auto-approved</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Total Audited Executions</div>
          <div id="kpi-epm-total" style="font-size:28px;font-weight:700;color:var(--accent-blue, #3b82f6);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Tamper-evident logs recorded</div>
        </div>
      </div>

      <!-- Navigation Sub-Tabs -->
      <div class="sub-nav-bar" style="display:flex;gap:4px;padding:0 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <button class="sub-tab-btn active" data-subtab="rules" style="padding:10px 16px;font-size:13px;font-weight:600;border:none;background:none;color:var(--text-bright);border-bottom:2px solid var(--accent-blue, #3b82f6);cursor:pointer;">
          🛡️ Elevation Rules (<span id="count-subtab-rules">0</span>)
        </button>
        <button class="sub-tab-btn" data-subtab="requests" style="padding:10px 16px;font-size:13px;font-weight:500;border:none;background:none;color:var(--text-muted);border-bottom:2px solid transparent;cursor:pointer;">
          ⏳ Approval Queue (<span id="count-subtab-requests">0</span>)
        </button>
        <button class="sub-tab-btn" data-subtab="logs" style="padding:10px 16px;font-size:13px;font-weight:500;border:none;background:none;color:var(--text-muted);border-bottom:2px solid transparent;cursor:pointer;">
          📜 Elevation Audit Log (<span id="count-subtab-logs">0</span>)
        </button>
      </div>

      <!-- Content Area -->
      <div id="epm-subtab-content" style="padding:20px 24px;">
        <div style="color:var(--text-muted);text-align:center;padding:40px;">Loading Endpoint Privilege Management posture…</div>
      </div>
    `;

    // Event listeners
    container.querySelector('#btn-epm-refresh')?.addEventListener('click', loadAllData);
    container.querySelector('#btn-epm-create-rule')?.addEventListener('click', showCreateRuleModal);

    container.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        container.querySelectorAll('.sub-tab-btn').forEach(b => {
          b.classList.remove('active');
          b.style.color = 'var(--text-muted)';
          b.style.fontWeight = '500';
          b.style.borderBottom = '2px solid transparent';
        });
        btn.classList.add('active');
        btn.style.color = 'var(--text-bright)';
        btn.style.fontWeight = '600';
        btn.style.borderBottom = '2px solid var(--accent-blue, #3b82f6)';
        _activeSubTab = btn.dataset.subtab;
        renderActiveSubTab();
      });
    });
  }

  async function loadAllData() {
    try {
      const [stats, rulesRes, policiesRes, requestsRes, logsRes] = await Promise.all([
        window.FleetAPI.getEpmStats(),
        window.FleetAPI.getEpmRules(),
        window.FleetAPI.getEpmPolicies(),
        window.FleetAPI.getEpmRequests({ limit: 100 }),
        window.FleetAPI.getEpmElevationLogs({ limit: 100 })
      ]);

      // Update KPI Cards
      const kpiRules = document.getElementById('kpi-epm-rules');
      const kpiPending = document.getElementById('kpi-epm-pending');
      const kpi24h = document.getElementById('kpi-epm-24h');
      const kpiTotal = document.getElementById('kpi-epm-total');
      const kpiPoliciesSub = document.getElementById('kpi-epm-policies-sub');
      const kpiAutoSub = document.getElementById('kpi-epm-auto-sub');

      if (kpiRules) kpiRules.textContent = stats.active_rules ?? 0;
      if (kpiPending) kpiPending.textContent = stats.pending_requests ?? 0;
      if (kpi24h) kpi24h.textContent = stats.elevations_24h ?? 0;
      if (kpiTotal) kpiTotal.textContent = stats.total_elevations ?? 0;
      if (kpiPoliciesSub) kpiPoliciesSub.textContent = `Across ${stats.active_policies ?? 0} active policies`;
      if (kpiAutoSub) kpiAutoSub.textContent = `${stats.auto_elevations ?? 0} auto-approved / ${stats.user_confirmed_elevations ?? 0} user-confirmed`;

      _rulesCache = rulesRes.rules || [];
      _policiesCache = policiesRes.policies || [];
      _requestsCache = requestsRes.requests || [];
      _logsCache = logsRes.elevation_logs || [];

      // Subtab counts
      const countRules = document.getElementById('count-subtab-rules');
      const countRequests = document.getElementById('count-subtab-requests');
      const countLogs = document.getElementById('count-subtab-logs');

      if (countRules) countRules.textContent = _rulesCache.length;
      if (countRequests) countRequests.textContent = _requestsCache.filter(r => r.status === 'PENDING').length;
      if (countLogs) countLogs.textContent = _logsCache.length;

      renderActiveSubTab();
    } catch (err) {
      const content = document.getElementById('epm-subtab-content');
      if (content) {
        content.innerHTML = `<div style="color:var(--accent-red, #ef4444);padding:24px;text-align:center;">Failed to load EPM telemetry: ${escapeHtml(err.message)}</div>`;
      }
    }
  }

  function renderActiveSubTab() {
    const content = document.getElementById('epm-subtab-content');
    if (!content) return;

    if (_activeSubTab === 'rules') {
      renderRulesTab(content);
    } else if (_activeSubTab === 'requests') {
      renderRequestsTab(content);
    } else if (_activeSubTab === 'logs') {
      renderLogsTab(content);
    }
  }

  /* ── 1. ELEVATION RULES SUBTAB ─────────────────────────────────────── */
  function renderRulesTab(content) {
    content.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px;flex-wrap:wrap;">
        <div style="display:flex;gap:10px;align-items:center;">
          <input type="text" id="epm-rules-search" class="search-input" placeholder="🔍 Search rules, files, hashes…" value="${escapeHtml(_searchQuery)}" style="width:280px;padding:6px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-card);color:var(--text-bright);">
          <select id="epm-filter-elevation-type" style="padding:6px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-card);color:var(--text-bright);font-size:12px;">
            <option value="">All Elevation Types</option>
            <option value="AUTOMATIC" ${_elevationTypeFilter === 'AUTOMATIC' ? 'selected' : ''}>Automatic</option>
            <option value="USER_CONFIRMED" ${_elevationTypeFilter === 'USER_CONFIRMED' ? 'selected' : ''}>User Confirmed</option>
            <option value="SUPPORT_APPROVED" ${_elevationTypeFilter === 'SUPPORT_APPROVED' ? 'selected' : ''}>Support Approved</option>
          </select>
        </div>
      </div>

      <div class="table-container" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table class="data-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);background:var(--bg-main);text-align:left;color:var(--text-muted);font-size:11px;text-transform:uppercase;">
              <th style="padding:10px 16px;">Rule Name</th>
              <th style="padding:10px 16px;">Target File</th>
              <th style="padding:10px 16px;">Elevation Type</th>
              <th style="padding:10px 16px;">Policy &amp; Scope</th>
              <th style="padding:10px 16px;">Child Processes</th>
              <th style="padding:10px 16px;">Status</th>
              <th style="padding:10px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody id="epm-rules-tbody">
            ${renderRulesRows()}
          </tbody>
        </table>
      </div>
    `;

    content.querySelector('#epm-rules-search')?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      const tbody = content.querySelector('#epm-rules-tbody');
      if (tbody) tbody.innerHTML = renderRulesRows();
      bindRuleRowEvents(content);
    });

    content.querySelector('#epm-filter-elevation-type')?.addEventListener('change', (e) => {
      _elevationTypeFilter = e.target.value;
      const tbody = content.querySelector('#epm-rules-tbody');
      if (tbody) tbody.innerHTML = renderRulesRows();
      bindRuleRowEvents(content);
    });

    bindRuleRowEvents(content);
  }

  function renderRulesRows() {
    let filtered = _rulesCache;
    if (_searchQuery) {
      const q = _searchQuery.toLowerCase();
      filtered = filtered.filter(r =>
        (r.rule_name && r.rule_name.toLowerCase().includes(q)) ||
        (r.file_name && r.file_name.toLowerCase().includes(q)) ||
        (r.file_path && r.file_path.toLowerCase().includes(q)) ||
        (r.file_hash_sha256 && r.file_hash_sha256.toLowerCase().includes(q))
      );
    }
    if (_elevationTypeFilter) {
      filtered = filtered.filter(r => r.elevation_type === _elevationTypeFilter);
    }

    if (filtered.length === 0) {
      return `<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--text-muted);">No elevation rules match your filter criteria.</td></tr>`;
    }

    return filtered.map(rule => {
      const isAuto = rule.elevation_type === 'AUTOMATIC';
      const isUser = rule.elevation_type === 'USER_CONFIRMED';
      const typeColor = isAuto ? '#10b981' : (isUser ? '#3b82f6' : '#f59e0b');
      const typeBadge = isAuto ? '⚡ Automatic' : (isUser ? '👤 User Confirmed' : '⏳ Support Approved');

      return `
        <tr style="border-bottom:1px solid var(--border-color);transition:background 0.15s;" onmouseover="this.style.background='var(--bg-main)'" onmouseout="this.style.background=''">
          <td style="padding:12px 16px;">
            <div style="font-weight:600;color:var(--text-bright);">${escapeHtml(rule.rule_name)}</div>
            <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(rule.description || 'No description provided')}</div>
          </td>
          <td style="padding:12px 16px;">
            <span class="mono" style="background:#0f172a;padding:3px 6px;border-radius:4px;border:1px solid #334155;font-weight:600;">${escapeHtml(rule.file_name)}</span>
            ${rule.file_path ? `<div class="mono" style="font-size:10px;color:var(--text-muted);margin-top:2px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(rule.file_path)}</div>` : ''}
          </td>
          <td style="padding:12px 16px;">
            <span class="badge" style="background:${typeColor}22;color:${typeColor};border:1px solid ${typeColor}55;font-weight:600;font-size:11px;">
              ${typeBadge}
            </span>
          </td>
          <td style="padding:12px 16px;">
            <div style="font-weight:500;color:var(--text-bright);font-size:12px;">${escapeHtml(rule.policy_name || 'Policy')}</div>
            <div style="font-size:11px;color:var(--text-muted);">Group: ${escapeHtml(rule.target_group_name || 'All Devices')}</div>
          </td>
          <td style="padding:12px 16px;font-size:12px;color:var(--text-muted);">
            ${rule.child_process_rule === 'ELEVATE_ALL_CHILDREN' ? '<span style="color:var(--accent-orange, #f59e0b);">Elevate All</span>' : 'None'}
          </td>
          <td style="padding:12px 16px;">
            <span class="badge ${rule.is_enabled ? 'badge-success' : 'badge-neutral'}" style="font-size:11px;">
              ${rule.is_enabled ? '✔ Active' : 'Disabled'}
            </span>
          </td>
          <td style="padding:12px 16px;text-align:right;">
            <button class="intune-btn small btn-delete-rule" data-id="${escapeHtml(rule.id)}" style="color:var(--accent-red, #ef4444);font-size:11px;padding:3px 8px;">
              🗑️ Delete
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function bindRuleRowEvents(content) {
    content.querySelectorAll('.btn-delete-rule').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (!confirm('Are you sure you want to permanently delete this elevation rule?')) return;
        try {
          await window.FleetAPI.deleteEpmRule(id);
          if (typeof showToast === 'function') showToast('Rule Deleted', 'Elevation rule removed.', 'info');
          loadAllData();
        } catch (err) {
          if (typeof showToast === 'function') showToast('Delete Failed', err.message, 'critical');
        }
      });
    });
  }

  /* ── 2. APPROVAL QUEUE SUBTAB ─────────────────────────────────────── */
  function renderRequestsTab(content) {
    content.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="font-size:14px;font-weight:600;color:var(--text-bright);">
          Standard User Elevation Requests &amp; Operator Approval Queue
        </div>
        <select id="epm-filter-req-status" style="padding:6px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-card);color:var(--text-bright);font-size:12px;">
          <option value="">All Statuses</option>
          <option value="PENDING" ${_requestStatusFilter === 'PENDING' ? 'selected' : ''}>Pending Review</option>
          <option value="APPROVED" ${_requestStatusFilter === 'APPROVED' ? 'selected' : ''}>Approved</option>
          <option value="DENIED" ${_requestStatusFilter === 'DENIED' ? 'selected' : ''}>Denied</option>
        </select>
      </div>

      <div class="table-container" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table class="data-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);background:var(--bg-main);text-align:left;color:var(--text-muted);font-size:11px;text-transform:uppercase;">
              <th style="padding:10px 16px;">Target Executable</th>
              <th style="padding:10px 16px;">Device &amp; User</th>
              <th style="padding:10px 16px;">Justification</th>
              <th style="padding:10px 16px;">Status</th>
              <th style="padding:10px 16px;">Submitted</th>
              <th style="padding:10px 16px;text-align:right;">Operator Action</th>
            </tr>
          </thead>
          <tbody id="epm-requests-tbody">
            ${renderRequestsRows()}
          </tbody>
        </table>
      </div>
    `;

    content.querySelector('#epm-filter-req-status')?.addEventListener('change', (e) => {
      _requestStatusFilter = e.target.value;
      const tbody = content.querySelector('#epm-requests-tbody');
      if (tbody) tbody.innerHTML = renderRequestsRows();
      bindRequestRowEvents(content);
    });

    bindRequestRowEvents(content);
  }

  function renderRequestsRows() {
    let filtered = _requestsCache;
    if (_requestStatusFilter) {
      filtered = filtered.filter(r => r.status === _requestStatusFilter);
    }

    if (filtered.length === 0) {
      return `<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">No elevation requests found.</td></tr>`;
    }

    return filtered.map(req => {
      const isPending = req.status === 'PENDING';
      const isApproved = req.status === 'APPROVED';
      const isDenied = req.status === 'DENIED';
      const statusColor = isPending ? '#f59e0b' : (isApproved ? '#10b981' : '#ef4444');

      return `
        <tr style="border-bottom:1px solid var(--border-color);transition:background 0.15s;" onmouseover="this.style.background='var(--bg-main)'" onmouseout="this.style.background=''">
          <td style="padding:12px 16px;">
            <div class="mono" style="font-weight:600;color:var(--text-bright);">${escapeHtml(req.file_name)}</div>
            <div class="mono" style="font-size:10px;color:var(--text-muted);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(req.file_path || '—')}</div>
          </td>
          <td style="padding:12px 16px;">
            <div style="font-weight:600;color:var(--text-bright);font-size:12px;">${escapeHtml(req.hostname || 'Device')}</div>
            <div style="font-size:11px;color:var(--text-muted);">User: <span class="mono">${escapeHtml(req.requested_by_user)}</span></div>
          </td>
          <td style="padding:12px 16px;max-width:280px;">
            <div style="font-size:12px;color:var(--text-bright);font-style:italic;">"${escapeHtml(req.justification)}"</div>
            ${req.review_notes ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Review note: ${escapeHtml(req.review_notes)}</div>` : ''}
          </td>
          <td style="padding:12px 16px;">
            <span class="badge" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}55;font-weight:600;font-size:11px;">
              ${escapeHtml(req.status)}
            </span>
          </td>
          <td style="padding:12px 16px;font-size:12px;color:var(--text-muted);">
            ${req.created_at ? new Date(req.created_at).toLocaleString() : '—'}
          </td>
          <td style="padding:12px 16px;text-align:right;">
            ${isPending ? `
              <div style="display:flex;gap:6px;justify-content:flex-end;">
                <button class="intune-btn small primary btn-approve-req" data-id="${escapeHtml(req.id)}" data-name="${escapeHtml(req.file_name)}" style="font-size:11px;padding:3px 8px;">
                  ✔ Approve
                </button>
                <button class="intune-btn small btn-deny-req" data-id="${escapeHtml(req.id)}" data-name="${escapeHtml(req.file_name)}" style="color:var(--accent-red, #ef4444);font-size:11px;padding:3px 8px;">
                  ✖ Deny
                </button>
              </div>
            ` : `<span style="font-size:11px;color:var(--text-muted);">Reviewed by ${escapeHtml(req.reviewed_by || 'Admin')}</span>`}
          </td>
        </tr>
      `;
    }).join('');
  }

  function bindRequestRowEvents(content) {
    content.querySelectorAll('.btn-approve-req').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const notes = prompt(`Enter approval notes for ${btn.dataset.name}:`, 'Approved for business maintenance window');
        if (notes === null) return;
        try {
          await window.FleetAPI.reviewEpmRequest(id, {
            decision: 'APPROVED',
            notes,
            valid_hours: 4
          });
          if (typeof showToast === 'function') showToast('Elevation Approved', `Granted 4-hour elevation window for ${btn.dataset.name}`, 'success');
          loadAllData();
        } catch (err) {
          if (typeof showToast === 'function') showToast('Approval Failed', err.message, 'critical');
        }
      });
    });

    content.querySelectorAll('.btn-deny-req').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const notes = prompt(`Enter reason for denying ${btn.dataset.name}:`, 'Elevation rejected by operator policy');
        if (notes === null) return;
        try {
          await window.FleetAPI.reviewEpmRequest(id, {
            decision: 'DENIED',
            notes
          });
          if (typeof showToast === 'function') showToast('Elevation Denied', `Denied elevation request for ${btn.dataset.name}`, 'warning');
          loadAllData();
        } catch (err) {
          if (typeof showToast === 'function') showToast('Denial Failed', err.message, 'critical');
        }
      });
    });
  }

  /* ── 3. ELEVATION AUDIT LOG SUBTAB ─────────────────────────────────── */
  function renderLogsTab(content) {
    content.innerHTML = `
      <div style="font-size:14px;font-weight:600;color:var(--text-bright);margin-bottom:16px;">
        Tamper-Evident Process Elevation Execution History
      </div>

      <div class="table-container" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table class="data-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--border-color);background:var(--bg-main);text-align:left;color:var(--text-muted);font-size:11px;text-transform:uppercase;">
              <th style="padding:10px 16px;">Executable (PID)</th>
              <th style="padding:10px 16px;">Device &amp; User</th>
              <th style="padding:10px 16px;">Elevation Type</th>
              <th style="padding:10px 16px;">Justification / Context</th>
              <th style="padding:10px 16px;">Parent Process</th>
              <th style="padding:10px 16px;text-align:right;">Executed At</th>
            </tr>
          </thead>
          <tbody>
            ${_logsCache.length === 0 ? `
              <tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">No process elevation logs recorded yet.</td></tr>
            ` : _logsCache.map(log => `
              <tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:12px 16px;">
                  <span class="mono" style="font-weight:600;color:var(--text-bright);">${escapeHtml(log.file_name)}</span>
                  ${log.process_id ? `<span class="mono" style="font-size:11px;color:var(--accent-blue, #3b82f6);margin-left:6px;">(PID: ${log.process_id})</span>` : ''}
                  <div class="mono" style="font-size:10px;color:var(--text-muted);margin-top:2px;">${escapeHtml(log.file_path || '—')}</div>
                </td>
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-bright);">${escapeHtml(log.hostname || 'Device')}</div>
                  <div style="font-size:11px;color:var(--text-muted);">User: <span class="mono">${escapeHtml(log.user_name)}</span></div>
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge badge-neutral" style="font-size:10px;">${escapeHtml(log.elevation_type)}</span>
                </td>
                <td style="padding:12px 16px;font-size:12px;color:var(--text-muted);max-width:300px;">
                  ${escapeHtml(log.justification || '—')}
                </td>
                <td style="padding:12px 16px;font-size:12px;" class="mono">
                  ${escapeHtml(log.parent_process_name || 'explorer.exe')}
                </td>
                <td style="padding:12px 16px;text-align:right;font-size:12px;color:var(--text-muted);">
                  ${log.executed_at ? new Date(log.executed_at).toLocaleString() : '—'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  /* ── CREATE ELEVATION RULE MODAL ───────────────────────────────────── */
  function showCreateRuleModal() {
    const modalId = 'modal-epm-create-rule';
    document.getElementById(modalId)?.remove();

    const overlay = document.createElement('div');
    overlay.id = modalId;
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;';

    const policyOptions = _policiesCache.map(p => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} (${escapeHtml(p.target_group_name || 'All Devices')})</option>`).join('');

    overlay.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;width:600px;max-width:95vw;max-height:90vh;overflow-y:auto;display:flex;flex-direction:column;box-shadow:0 20px 40px rgba(0,0,0,0.5);">
        <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:600;font-size:16px;color:var(--text-bright);">➕ Create Endpoint Privilege Management Rule</div>
          <button id="btn-close-modal" style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>

        <div style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <div>
            <label style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;">Quick-Apply Rule Preset</label>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px;">
              <button class="intune-btn small preset-btn" data-name="Sysinternals Process Monitor" data-file="procmon.exe" data-path="C:\\Program Files\\Sysinternals\\procmon.exe" data-type="USER_CONFIRMED" data-cert="Microsoft Corporation" style="text-align:left;font-size:11px;">
                🛠️ Process Monitor
              </button>
              <button class="intune-btn small preset-btn" data-name="Wireshark Packet Capture" data-file="Wireshark.exe" data-path="C:\\Program Files\\Wireshark\\Wireshark.exe" data-type="SUPPORT_APPROVED" data-cert="Wireshark Foundation" style="text-align:left;font-size:11px;">
                🌐 Wireshark Analyzer
              </button>
              <button class="intune-btn small preset-btn" data-name="Windows Package Manager" data-file="winget.exe" data-path="C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe" data-type="AUTOMATIC" data-cert="Microsoft Corporation" style="text-align:left;font-size:11px;">
                📦 Winget CLI Installer
              </button>
              <button class="intune-btn small preset-btn" data-name="MSI Afterburner Hardware" data-file="MSIAfterburner.exe" data-path="C:\\Program Files (x86)\\MSI Afterburner\\MSIAfterburner.exe" data-type="USER_CONFIRMED" data-cert="Micro-Star International" style="text-align:left;font-size:11px;">
                🎮 MSI Afterburner
              </button>
            </div>
          </div>

          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-bright);">Target EPM Policy</label>
            <select id="modal-rule-policy" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
              ${policyOptions}
            </select>
          </div>

          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-bright);">Rule Name</label>
            <input type="text" id="modal-rule-name" placeholder="e.g. Sysinternals Process Monitor" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="font-size:12px;font-weight:600;color:var(--text-bright);">File Name (*.exe)</label>
              <input type="text" id="modal-rule-file" placeholder="e.g. procmon.exe" class="mono" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
            </div>
            <div>
              <label style="font-size:12px;font-weight:600;color:var(--text-bright);">Elevation Type</label>
              <select id="modal-rule-type" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
                <option value="USER_CONFIRMED">User Confirmed (Requires Justification)</option>
                <option value="AUTOMATIC">Automatic (Silent Elevation)</option>
                <option value="SUPPORT_APPROVED">Support Approved (Queues for Operator)</option>
              </select>
            </div>
          </div>

          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-bright);">File Path Pattern (Optional)</label>
            <input type="text" id="modal-rule-path" placeholder="e.g. C:\\Program Files\\Sysinternals\\procmon.exe" class="mono" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
          </div>

          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-bright);">SHA-256 Hash or Publisher Certificate (Optional)</label>
            <input type="text" id="modal-rule-hash" placeholder="e.g. Microsoft Corporation or SHA-256 checksum" class="mono" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
          </div>

          <div>
            <label style="font-size:12px;font-weight:600;color:var(--text-bright);">Child Process Handling</label>
            <select id="modal-rule-child" style="width:100%;margin-top:4px;padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-bright);">
              <option value="ELEVATE_NONE">Elevate target process only</option>
              <option value="ELEVATE_ALL_CHILDREN">Elevate all spawned child processes</option>
            </select>
          </div>
        </div>

        <div style="padding:16px 20px;border-top:1px solid var(--border-color);display:flex;justify-content:flex-end;gap:10px;">
          <button class="intune-btn" id="btn-cancel-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-modal">Create Rule</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Preset button handlers
    overlay.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        overlay.querySelector('#modal-rule-name').value = btn.dataset.name;
        overlay.querySelector('#modal-rule-file').value = btn.dataset.file;
        overlay.querySelector('#modal-rule-path').value = btn.dataset.path;
        overlay.querySelector('#modal-rule-type').value = btn.dataset.type;
        overlay.querySelector('#modal-rule-hash').value = btn.dataset.cert;
      });
    });

    const closeModal = () => overlay.remove();
    overlay.querySelector('#btn-close-modal')?.addEventListener('click', closeModal);
    overlay.querySelector('#btn-cancel-modal')?.addEventListener('click', closeModal);

    overlay.querySelector('#btn-submit-modal')?.addEventListener('click', async () => {
      const policyId = overlay.querySelector('#modal-rule-policy').value;
      const ruleName = overlay.querySelector('#modal-rule-name').value.trim();
      const fileName = overlay.querySelector('#modal-rule-file').value.trim();
      const elevationType = overlay.querySelector('#modal-rule-type').value;
      const filePath = overlay.querySelector('#modal-rule-path').value.trim();
      const hashOrCert = overlay.querySelector('#modal-rule-hash').value.trim();
      const childRule = overlay.querySelector('#modal-rule-child').value;

      if (!ruleName || !fileName) {
        alert('Please specify both a Rule Name and File Name.');
        return;
      }

      try {
        await window.FleetAPI.createEpmRule({
          policy_id: policyId,
          rule_name: ruleName,
          file_name: fileName,
          elevation_type: elevationType,
          file_path: filePath,
          publisher_certificate: hashOrCert,
          child_process_rule: childRule
        });
        if (typeof showToast === 'function') showToast('Rule Created', `Elevation rule '${ruleName}' active.`, 'success');
        closeModal();
        loadAllData();
      } catch (err) {
        alert(`Failed to create rule: ${err.message}`);
      }
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  window.EpmTable = {
    init,
    refresh: loadAllData,
    showCreateRuleModal
  };
})();
