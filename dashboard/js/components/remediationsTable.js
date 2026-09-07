/**
 * LocalPilot Fleet — Proactive Remediations UI Component
 * dashboard/js/components/remediationsTable.js
 */

(function () {
  let _remediations = [];
  let _stats = null;
  let _searchQuery = '';

  function esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function loadData() {
    try {
      const [remRes, statsRes] = await Promise.all([
        window.FleetAPI.getRemediations(),
        window.FleetAPI.getRemediationStats()
      ]);
      _remediations = remRes.remediations || [];
      _stats = statsRes || null;
      render();
    } catch (err) {
      console.error('Failed to load remediations:', err);
    }
  }

  function renderKpiCards() {
    const s = _stats || {
      total_packages: _remediations.length,
      evaluated_devices: 0,
      issues_detected: 0,
      issues_remediated: 0,
      self_healing_rate_pct: 100
    };

    return `
      <div class="kpi-grid" style="margin-bottom: 20px;">
        <div class="kpi-card">
          <div class="kpi-label">Active Packages</div>
          <div class="kpi-value">${s.total_packages}</div>
          <div class="kpi-sub">Self-healing scripts</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Evaluated Nodes</div>
          <div class="kpi-value">${s.evaluated_devices}</div>
          <div class="kpi-sub">Reporting compliance</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Issues Detected</div>
          <div class="kpi-value" style="color: ${s.issues_detected > 0 ? '#F59E0B' : '#10B981'};">
            ${s.issues_detected}
          </div>
          <div class="kpi-sub">Anomalies caught</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Issues Remediated</div>
          <div class="kpi-value" style="color: #10B981;">${s.issues_remediated}</div>
          <div class="kpi-sub">Auto-healed by agent</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Self-Healing Rate</div>
          <div class="kpi-value" style="color: #3B82F6;">${s.self_healing_rate_pct}%</div>
          <div class="kpi-sub">Fleet resolution rate</div>
        </div>
      </div>
    `;
  }

  function renderTable() {
    const q = _searchQuery.toLowerCase();
    const filtered = _remediations.filter(r =>
      r.name.toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q) ||
      (r.publisher || '').toLowerCase().includes(q)
    );

    if (filtered.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">🩺</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No Remediations Found</div>
          <p>Create a script package or adjust your search filter.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Package Name</th>
            <th>Publisher</th>
            <th>Target Group</th>
            <th>Schedule</th>
            <th>Detection Status</th>
            <th>Remediation Rate</th>
            <th>Last Run</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(pkg => {
            const st = pkg.stats || {};
            const issues = st.issue_detected_count || 0;
            const fixed = st.remediated_count || 0;
            const healthy = st.no_issue_count || 0;
            const total = st.total_runs || 0;

            let statusBadge = '<span class="badge badge-online">Compliant</span>';
            if (issues > 0 && fixed >= issues) {
              statusBadge = '<span class="badge" style="background:#10b98122;color:#10b981;border:1px solid #10b98155;">Auto-Healed</span>';
            } else if (issues > fixed) {
              statusBadge = '<span class="badge badge-quarantined">Issue Active</span>';
            } else if (total === 0) {
              statusBadge = '<span class="badge badge-offline">Pending Run</span>';
            }

            const targetBadge = pkg.target_group_name
              ? `<span class="badge" style="background:${pkg.target_group_color || '#3B82F6'}22;color:${pkg.target_group_color || '#3B82F6'};border:1px solid ${pkg.target_group_color || '#3B82F6'}44;">${esc(pkg.target_group_name)}</span>`
              : '<span class="badge badge-offline">All Devices</span>';

            const lastRunStr = st.last_run_at
              ? new Date(st.last_run_at).toLocaleString()
              : 'Never';

            return `
              <tr class="rem-row" data-id="${esc(pkg.id)}" style="cursor: pointer;">
                <td>
                  <div style="font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
                    <span>🩺</span>
                    <span>${esc(pkg.name)}</span>
                  </div>
                  <div style="font-size: 11px; color: var(--text-muted); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    ${esc(pkg.description || 'No description provided.')}
                  </div>
                </td>
                <td style="color: var(--text-secondary); font-size: 12px;">${esc(pkg.publisher || 'Custom')}</td>
                <td>${targetBadge}</td>
                <td><span class="badge badge-route">${esc(pkg.schedule_type || 'HEARTBEAT')}</span></td>
                <td>${statusBadge}</td>
                <td>
                  <div style="font-size: 12px; font-weight: 600;">
                    ${issues > 0 ? `${fixed} / ${issues} healed` : `${healthy} clean runs`}
                  </div>
                </td>
                <td style="font-size: 12px; color: var(--text-muted);">${esc(lastRunStr)}</td>
                <td style="text-align: right;" onclick="event.stopPropagation();">
                  <div style="display: flex; gap: 6px; justify-content: flex-end;">
                    <button class="btn-action-sm btn-run-rem" data-id="${esc(pkg.id)}" title="Run across fleet immediately">⚡ Run</button>
                    <button class="btn-action-sm btn-view-rem" data-id="${esc(pkg.id)}" title="View details and code">👁 Details</button>
                    <button class="btn-action-sm btn-del-rem" data-id="${esc(pkg.id)}" style="color: #ef4444;" title="Delete package">🗑</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function render() {
    const container = document.getElementById('view-remediations');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header-row" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <h2 class="view-title" style="margin: 0;">🩺 Remediations</h2>
          <div class="view-subtitle" style="color: var(--text-muted); font-size: 13px;">
            Proactive detection and self-healing PowerShell scripts across your fleet (Microsoft Intune Endpoint Analytics).
          </div>
        </div>
        <div style="display: flex; gap: 10px;">
          <button class="btn btn-secondary" id="btn-refresh-remediations">↻ Refresh</button>
          <button class="btn btn-primary" id="btn-create-remediation">+ Create script package</button>
        </div>
      </div>

      ${renderKpiCards()}

      <div class="table-controls-bar" style="display: flex; justify-content: space-between; margin-bottom: 12px;">
        <div style="position: relative; width: 340px;">
          <input
            type="text"
            id="rem-search-input"
            class="search-input"
            placeholder="🔍 Filter remediation packages…"
            value="${esc(_searchQuery)}"
            style="width: 100%;"
          />
        </div>
        <div style="font-size: 13px; color: var(--text-muted); display: flex; align-items: center;">
          Total Packages: <strong style="color: var(--text-primary); margin-left: 4px;">${_remediations.length}</strong>
        </div>
      </div>

      <div class="table-container" style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px;">
        ${renderTable()}
      </div>
    `;

    bindEvents(container);
  }

  function bindEvents(container) {
    const searchInput = container.querySelector('#rem-search-input');
    searchInput?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      const tbody = container.querySelector('.table-container');
      if (tbody) tbody.innerHTML = renderTable();
      bindRowActions(container);
    });

    container.querySelector('#btn-refresh-remediations')?.addEventListener('click', () => {
      loadData();
    });

    container.querySelector('#btn-create-remediation')?.addEventListener('click', () => {
      if (window.RemediationModal) {
        window.RemediationModal.open(null, () => loadData());
      }
    });

    bindRowActions(container);
  }

  function bindRowActions(container) {
    container.querySelectorAll('.rem-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-id');
        if (id && window.RemediationDetailModal) {
          window.RemediationDetailModal.open(id);
        }
      });
    });

    container.querySelectorAll('.btn-view-rem').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        if (id && window.RemediationDetailModal) {
          window.RemediationDetailModal.open(id);
        }
      });
    });

    container.querySelectorAll('.btn-run-rem').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!id) return;
        btn.disabled = true;
        btn.textContent = '⏳ Queuing…';
        try {
          const res = await window.FleetAPI.runRemediationNow(id);
          if (typeof showToast === 'function') {
            showToast('Remediation Dispatched', `Queued "${res.remediation_name}" across ${res.target_count} device(s)`, 'success');
          }
          btn.textContent = '✓ Dispatched';
          setTimeout(() => {
            btn.disabled = false;
            btn.textContent = '⚡ Run';
          }, 2000);
        } catch (err) {
          if (typeof showToast === 'function') {
            showToast('Dispatch Failed', err.message, 'critical');
          }
          btn.disabled = false;
          btn.textContent = '⚡ Run';
        }
      });
    });

    container.querySelectorAll('.btn-del-rem').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!id) return;
        if (!confirm('Are you sure you want to delete this remediation package and its historical execution logs?')) return;
        try {
          await window.FleetAPI.deleteRemediation(id);
          if (typeof showToast === 'function') {
            showToast('Package Deleted', 'Remediation package removed', 'info');
          }
          loadData();
        } catch (err) {
          if (typeof showToast === 'function') {
            showToast('Delete Failed', err.message, 'critical');
          }
        }
      });
    });
  }

  window.RemediationsTable = {
    loadData,
    render
  };
})();
