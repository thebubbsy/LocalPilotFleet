/**
 * LocalPilot Fleet — Enterprise Governance, Granular RBAC & SIEM Dashboard Blade
 * dashboard/js/components/governanceRbacTable.js
 *
 * Dimension 6: Enterprise Governance, RBAC & Multi-Tenancy
 * Displays Role-Based Access Control definitions, Dual-Custody 4-Eyes Approval workflow,
 * and RFC 5424 Immutable SIEM Syslog audit forwarders.
 */

window.GovernanceRbacTable = {
  currentTab: 'roles',
  rbacStats: null,
  siemStats: null,
  roles: [],
  approvals: [],
  forwarders: [],

  async render() {
    const container = document.getElementById('tab-governance');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="margin: 0; font-size: 1.4rem; display: flex; align-items: center; gap: 0.5rem;">
            <span>🏛️</span> Enterprise Governance, Granular RBAC &amp; SIEM
            <span class="badge badge-success" style="font-size: 0.75rem; padding: 2px 8px; border-radius: 9999px;">Dimension 6</span>
          </h2>
          <p class="text-muted" style="margin: 0.25rem 0 0 0; font-size: 0.85rem;">
            Granular Role-Based Access Control, Dual-Custody 4-Eyes Principle for destructive operations, and RFC 5424 Immutable SIEM forwarders.
          </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="GovernanceRbacTable.refresh()">
            <span>🔄</span> Refresh
          </button>
          <button class="btn btn-primary btn-sm" onclick="GovernanceRbacTable.openActionModal()">
            <span>➕</span> New...
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Active RBAC Roles</div>
          <div class="kpi-value" id="kpi-rbac-roles" style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-rbac-roles-sub" style="font-size: 0.75rem; color: #64748b;">Granular Permission Sets</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Pending 4-Eyes Reviews</div>
          <div class="kpi-value" id="kpi-rbac-pending" style="font-size: 1.6rem; font-weight: 700; color: #f59e0b; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">Awaiting 2nd Admin Approval</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">4-Eyes Enforcement</div>
          <div class="kpi-value" id="kpi-rbac-enforced" style="font-size: 1.6rem; font-weight: 700; color: #10b981; margin: 0.25rem 0;">100%</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">Self-Approval Blocked</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">SIEM Events Exported</div>
          <div class="kpi-value" id="kpi-rbac-siem" style="font-size: 1.6rem; font-weight: 700; color: #a855f7; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-rbac-siem-sub" style="font-size: 0.75rem; color: #64748b;">RFC 5424 Immutable Logs</div>
        </div>
      </div>

      <!-- Navigation Sub-tabs -->
      <div class="tabs-nav" style="display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border-color, #334155); margin-bottom: 1rem;">
        <button class="tab-btn ${this.currentTab === 'roles' ? 'active' : ''}" onclick="GovernanceRbacTable.switchTab('roles')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'roles' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'roles' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          🛡️ RBAC Roles
        </button>
        <button class="tab-btn ${this.currentTab === 'approvals' ? 'active' : ''}" onclick="GovernanceRbacTable.switchTab('approvals')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'approvals' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'approvals' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          👁️👁️ Dual-Custody 4-Eyes Approvals
        </button>
        <button class="tab-btn ${this.currentTab === 'siem' ? 'active' : ''}" onclick="GovernanceRbacTable.switchTab('siem')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'siem' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'siem' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          📡 RFC 5424 SIEM Forwarders
        </button>
      </div>

      <!-- Tab Content Area -->
      <div id="governance-tab-content">
        ${this.renderCurrentSubTab()}
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const [rbacStats, siemStats, rolesRes, approvalsRes, forwardersRes] = await Promise.all([
        window.FleetAPI.getRbacStats().catch(() => null),
        window.FleetAPI.getSiemStats().catch(() => null),
        window.FleetAPI.getRbacRoles().catch(() => ({ roles: [] })),
        window.FleetAPI.getDualCustodyApprovals().catch(() => ({ approvals: [] })),
        window.FleetAPI.getSiemForwarders().catch(() => ({ forwarders: [] }))
      ]);

      this.rbacStats = rbacStats;
      this.siemStats = siemStats;
      this.roles = rolesRes?.roles || [];
      this.approvals = approvalsRes?.approvals || [];
      this.forwarders = forwardersRes?.forwarders || [];

      this.updateKpis();
      const content = document.getElementById('governance-tab-content');
      if (content) {
        content.innerHTML = this.renderCurrentSubTab();
      }
    } catch (err) {
      console.error('[GovernanceRbacTable] loadData error:', err);
    }
  },

  updateKpis() {
    if (this.rbacStats) {
      const r = this.rbacStats.roles;
      const d = this.rbacStats.dual_custody;
      const elRoles = document.getElementById('kpi-rbac-roles');
      const elRolesSub = document.getElementById('kpi-rbac-roles-sub');
      const elPending = document.getElementById('kpi-rbac-pending');

      if (elRoles) elRoles.textContent = r ? r.total : '--';
      if (elRolesSub && r) elRolesSub.textContent = `${r.built_in} Built-in, ${r.custom} Custom`;
      if (elPending) elPending.textContent = d ? d.pending : '0';
    }

    if (this.siemStats) {
      const elSiem = document.getElementById('kpi-rbac-siem');
      const elSiemSub = document.getElementById('kpi-rbac-siem-sub');
      if (elSiem) elSiem.textContent = this.siemStats.total_events_forwarded || '0';
      if (elSiemSub) elSiemSub.textContent = `${this.siemStats.active_forwarders} Active Forwarder(s)`;
    }
  },

  switchTab(tab) {
    this.currentTab = tab;
    this.render();
  },

  refresh() {
    return this.loadData();
  },

  renderCurrentSubTab() {
    if (this.currentTab === 'roles') return this.renderRolesTab();
    if (this.currentTab === 'approvals') return this.renderApprovalsTab();
    if (this.currentTab === 'siem') return this.renderSiemTab();
    return '';
  },

  renderRolesTab() {
    if (!this.roles.length) {
      return `<div class="empty-state" style="text-align: center; padding: 2rem; color: #64748b;">No RBAC roles configured</div>`;
    }

    return `
      <div class="table-responsive" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow-x: auto;">
        <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;">
              <th style="padding: 0.75rem 1rem;">Role Name</th>
              <th style="padding: 0.75rem 1rem;">Type</th>
              <th style="padding: 0.75rem 1rem;">Description</th>
              <th style="padding: 0.75rem 1rem;">Granted Permissions</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${this.roles.map(r => `
              <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 0.75rem 1rem; font-weight: 600; color: #f8fafc;">
                  ${escapeHtml(r.display_name || r.name)}
                  <div style="font-size: 0.7rem; color: #64748b; font-family: monospace;">${r.name}</div>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${r.is_built_in === 1
                    ? '<span class="badge badge-info" style="background: #0284c7; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">BUILT-IN</span>'
                    : '<span class="badge badge-secondary" style="background: #475569; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">CUSTOM</span>'}
                </td>
                <td style="padding: 0.75rem 1rem; color: #cbd5e1; max-width: 280px;">
                  ${escapeHtml(r.description || '')}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <div style="display: flex; flex-wrap: wrap; gap: 4px; max-width: 360px;">
                    ${(r.permissions || []).map(p => `
                      <span style="background: #0f172a; border: 1px solid #334155; color: #38bdf8; font-size: 0.7rem; padding: 1px 6px; border-radius: 4px; font-family: monospace;">
                        ${p}
                      </span>
                    `).join('')}
                  </div>
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right;">
                  ${r.is_built_in === 0 ? `
                    <button class="btn btn-danger btn-xs" onclick="GovernanceRbacTable.deleteRole('${r.id}')" style="padding: 2px 6px; font-size: 0.7rem;">
                      Delete
                    </button>
                  ` : '<span class="text-muted" style="font-size: 0.75rem;">Protected</span>'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  renderApprovalsTab() {
    if (!this.approvals.length) {
      return `<div class="empty-state" style="text-align: center; padding: 2rem; color: #64748b;">No dual-custody approval requests found</div>`;
    }

    return `
      <div class="table-responsive" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow-x: auto;">
        <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;">
              <th style="padding: 0.75rem 1rem;">Action &amp; Target</th>
              <th style="padding: 0.75rem 1rem;">Requested By &amp; Reason</th>
              <th style="padding: 0.75rem 1rem;">Status</th>
              <th style="padding: 0.75rem 1rem;">Reviewer / Timestamp</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">4-Eyes Decision</th>
            </tr>
          </thead>
          <tbody>
            ${this.approvals.map(a => {
              let statusBadge = '';
              if (a.status === 'PENDING') statusBadge = '<span class="badge" style="background: #f59e0b; color: #000; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 700;">PENDING 4-EYES</span>';
              else if (a.status === 'APPROVED') statusBadge = '<span class="badge" style="background: #10b981; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">APPROVED</span>';
              else if (a.status === 'REJECTED') statusBadge = '<span class="badge" style="background: #ef4444; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">REJECTED</span>';
              else if (a.status === 'EXECUTED') statusBadge = '<span class="badge" style="background: #8b5cf6; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">EXECUTED</span>';
              else statusBadge = '<span class="badge" style="background: #64748b; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">EXPIRED</span>';

              return `
                <tr style="border-bottom: 1px solid #334155;">
                  <td style="padding: 0.75rem 1rem;">
                    <div style="font-weight: 700; color: #f43f5e; display: flex; align-items: center; gap: 0.25rem;">
                      <span>💣</span> ${a.action_type}
                    </div>
                    <div style="font-size: 0.75rem; color: #94a3b8;">
                      ${a.target_type}: ${escapeHtml(a.target_name || a.target_id)}
                    </div>
                  </td>
                  <td style="padding: 0.75rem 1rem;">
                    <div style="font-weight: 600; color: #38bdf8;">${escapeHtml(a.requested_by)}</div>
                    <div style="font-size: 0.75rem; color: #cbd5e1; max-width: 260px;">${escapeHtml(a.requested_reason)}</div>
                  </td>
                  <td style="padding: 0.75rem 1rem;">${statusBadge}</td>
                  <td style="padding: 0.75rem 1rem; color: #94a3b8; font-size: 0.75rem;">
                    ${a.reviewed_by ? `
                      <div style="color: #f8fafc; font-weight: 600;">${escapeHtml(a.reviewed_by)}</div>
                      <div>${a.reviewed_at || ''}</div>
                      ${a.reviewed_reason ? `<div style="font-style: italic; color: #64748b;">"${escapeHtml(a.reviewed_reason)}"</div>` : ''}
                    ` : '<span class="text-muted">Awaiting 2nd Reviewer</span>'}
                  </td>
                  <td style="padding: 0.75rem 1rem; text-align: right;">
                    ${a.status === 'PENDING' ? `
                      <button class="btn btn-success btn-xs" onclick="GovernanceRbacTable.openReviewModal('${a.id}', 'APPROVE')" style="padding: 2px 6px; font-size: 0.7rem; margin-right: 4px;">
                        Approve (2nd Eye)
                      </button>
                      <button class="btn btn-danger btn-xs" onclick="GovernanceRbacTable.openReviewModal('${a.id}', 'REJECT')" style="padding: 2px 6px; font-size: 0.7rem;">
                        Reject
                      </button>
                    ` : a.status === 'APPROVED' ? `
                      <button class="btn btn-primary btn-xs" onclick="GovernanceRbacTable.executeApproval('${a.id}')" style="padding: 2px 6px; font-size: 0.7rem;">
                        ⚡ Execute Action
                      </button>
                    ` : '<span class="text-muted" style="font-size: 0.75rem;">Closed</span>'}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  renderSiemTab() {
    return `
      <div style="display: grid; grid-template-columns: 1fr 380px; gap: 1rem;">
        <div class="table-responsive" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow-x: auto;">
          <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;">
                <th style="padding: 0.75rem 1rem;">Destination &amp; Host</th>
                <th style="padding: 0.75rem 1rem;">Protocol</th>
                <th style="padding: 0.75rem 1rem;">Severity Filter</th>
                <th style="padding: 0.75rem 1rem;">Events Forwarded</th>
                <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${this.forwarders.map(f => `
                <tr style="border-bottom: 1px solid #334155;">
                  <td style="padding: 0.75rem 1rem;">
                    <div style="font-weight: 600; color: #f8fafc;">${escapeHtml(f.name)}</div>
                    <div style="font-size: 0.75rem; color: #64748b; font-family: monospace;">${f.host}:${f.port}</div>
                  </td>
                  <td style="padding: 0.75rem 1rem;">
                    <span class="badge" style="background: #0f172a; border: 1px solid #38bdf8; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-family: monospace;">
                      ${f.destination_type}
                    </span>
                    ${f.tls_enabled ? '<span title="TLS Encrypted" style="margin-left: 4px;">🔒</span>' : ''}
                  </td>
                  <td style="padding: 0.75rem 1rem; color: #cbd5e1;">${f.severity_filter}</td>
                  <td style="padding: 0.75rem 1rem; font-weight: 700; color: #10b981;">${f.total_events_forwarded || 0}</td>
                  <td style="padding: 0.75rem 1rem; text-align: right;">
                    <button class="btn btn-secondary btn-xs" onclick="GovernanceRbacTable.testForwarder('${f.id}')" style="padding: 2px 6px; font-size: 0.7rem; margin-right: 4px;">
                      Test Ping
                    </button>
                    <button class="btn btn-danger btn-xs" onclick="GovernanceRbacTable.deleteForwarder('${f.id}')" style="padding: 2px 6px; font-size: 0.7rem;">
                      Delete
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <h4 style="margin: 0 0 0.5rem 0; font-size: 0.95rem; color: #f8fafc; display: flex; align-items: center; gap: 0.5rem;">
            <span>📜</span> RFC 5424 Syslog Format Validator
          </h4>
          <p style="font-size: 0.75rem; color: #94a3b8; margin: 0 0 0.75rem 0;">
            Strict header syntax: <code>&lt;PRI&gt;1 TIMESTAMP HOSTNAME APP PROCID MSGID [STRUCTURED-DATA] MSG</code>
          </p>
          <pre id="siem-rfc5424-preview" style="background: #090d16; border: 1px solid #1e293b; color: #10b981; padding: 0.75rem; border-radius: 6px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; font-family: monospace;">&lt;134&gt;1 ${new Date().toISOString()} localpilot-fleet LocalPilotAudit 4112 SEC01 [localpilot@59214 event_type="APP_PROHIBITED_DETECTED" device_id="dev-livingroom-pc"] Prohibited application "uTorrent" detected on LIVINGROOM-PC</pre>
          <button class="btn btn-outline-primary btn-sm" onclick="GovernanceRbacTable.sendSyntheticAuditLog()" style="width: 100%; margin-top: 0.75rem; font-size: 0.8rem;">
            🚀 Emit Synthetic RFC 5424 Event
          </button>
        </div>
      </div>
    `;
  },

  openActionModal() {
    if (this.currentTab === 'roles') {
      const name = prompt('Enter role name (e.g. "Network Operator"):');
      if (!name) return;
      const desc = prompt('Enter role description:', 'Manages firewall and network configurations');
      window.FleetAPI.createRbacRole({
        name,
        display_name: name,
        description: desc || '',
        permissions: ['devices:read', 'network:read', 'firewall:read', 'firewall:write']
      }).then(() => {
        alert('Role created successfully!');
        this.refresh();
      }).catch(err => alert('Error: ' + err.message));
    } else if (this.currentTab === 'approvals') {
      const reason = prompt('Reason for high-impact operation request:');
      if (!reason) return;
      window.FleetAPI.requestDualCustodyApproval({
        action_type: 'REMOTE_WIPE',
        target_type: 'DEVICE',
        target_id: 'dev-livingroom-pc',
        target_name: 'Living Room PC',
        requested_by: 'lead.admin@localpilot.corp',
        requested_reason: reason,
        ttl_minutes: 1440
      }).then(() => {
        alert('Dual-custody approval requested! Requires approval from a DIFFERENT administrator.');
        this.refresh();
      }).catch(err => alert('Error: ' + err.message));
    } else if (this.currentTab === 'siem') {
      const host = prompt('Enter SIEM destination host/IP:', '10.1.1.100');
      if (!host) return;
      window.FleetAPI.createSiemForwarder({
        name: 'Enterprise Splunk/Elastic Forwarder',
        destination_type: 'RFC5424_SYSLOG_UDP',
        host,
        port: 514,
        severity_filter: 'ALL'
      }).then(() => {
        alert('SIEM Forwarder registered!');
        this.refresh();
      }).catch(err => alert('Error: ' + err.message));
    }
  },

  openReviewModal(id, action) {
    const reviewer = prompt(`Enter YOUR Administrator Email/Identity for 4-Eyes verification (${action}):`, 'auditor.jane@localpilot.corp');
    if (!reviewer) return;
    const reason = prompt(`Enter reason for ${action}:`, `Authorized via operational ticket ${action}`);

    window.FleetAPI.reviewDualCustodyApproval(id, {
      reviewed_by: reviewer,
      action,
      reviewed_reason: reason || ''
    }).then(res => {
      alert(`Action ${action} successfully recorded by ${reviewer}!`);
      this.refresh();
    }).catch(err => {
      alert('4-Eyes Violation or Error: ' + err.message);
    });
  },

  executeApproval(id) {
    if (!confirm('Execute this approved high-impact dual-custody action now?')) return;
    window.FleetAPI.executeDualCustodyApproval(id).then(res => {
      alert('High-impact action EXECUTED successfully!');
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  },

  deleteRole(id) {
    if (!confirm('Delete custom RBAC role?')) return;
    window.FleetAPI.deleteRbacRole(id).then(() => {
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  },

  testForwarder(id) {
    window.FleetAPI.testSiemForwarder(id).then(res => {
      alert(`SIEM Connection Test: ${res.status} (${res.latency_ms} ms)\n\nSample RFC 5424 Message:\n${res.rfc5424_sample}`);
      const preview = document.getElementById('siem-rfc5424-preview');
      if (preview && res.rfc5424_sample) {
        preview.textContent = res.rfc5424_sample;
      }
    }).catch(err => alert('Error: ' + err.message));
  },

  deleteForwarder(id) {
    if (!confirm('Delete SIEM forwarder?')) return;
    window.FleetAPI.deleteSiemForwarder(id).then(() => {
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  },

  sendSyntheticAuditLog() {
    window.FleetAPI.forwardSiemEvent({
      event_type: 'PRIVILEGE_ELEVATION_APPROVED',
      severity: 'HIGH',
      hostname: 'DESKTOP-R0H12DJ',
      summary: 'EPM rule granted elevation for ProcessHacker.exe to Tony (Dual-Custody verified)'
    }).then(res => {
      alert(`Synthetic audit log forwarded to ${res.forwarded_count} SIEM target(s)!\n\nRFC 5424 Payload:\n${res.sample_rfc5424}`);
      const preview = document.getElementById('siem-rfc5424-preview');
      if (preview && res.sample_rfc5424) {
        preview.textContent = res.sample_rfc5424;
      }
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  }
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
