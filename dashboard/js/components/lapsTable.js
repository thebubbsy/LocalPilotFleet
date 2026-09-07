/**
 * LocalPilot Fleet — Windows LAPS (Local Administrator Password Solution) UI Blade
 * dashboard/js/components/lapsTable.js
 *
 * Implements Microsoft Intune LAPS Administrator Password Governance interface:
 * - Executive KPI summary strip & fleet LAPS coverage metrics
 * - Sub-blades: Password Vault, LAPS Policies, Access & Rotation Audit Log
 * - Tamper-evident password reveal with compliance justification paper trail
 * - Remote on-demand password rotation dispatch
 * - Policy creation wizard with enterprise presets
 */

(function () {
  'use strict';

  function esc(v) {
    return String(v ?? '—')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  let _activeSubTab = 'vault'; // 'vault' | 'policies' | 'audit'
  let _lapsStats = null;
  let _passwords = [];
  let _policies = [];
  let _auditLogs = [];
  let _groups = [];
  let _searchQuery = '';
  let _statusFilter = '';

  async function loadData() {
    const container = document.getElementById('view-laps');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;">
        <div class="skeleton skeleton-text" style="width:250px;height:24px;margin-bottom:12px;"></div>
        <div class="skeleton skeleton-text" style="width:400px;height:16px;margin-bottom:24px;"></div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
          ${[...Array(4)].map(() => '<div class="skeleton skeleton-card" style="height:90px;"></div>').join('')}
        </div>
      </div>
    `;

    try {
      const [stats, passData, policiesData, auditData, groups] = await Promise.all([
        window.FleetAPI.getLapsStats().catch(() => ({})),
        window.FleetAPI.getLapsPasswords({ query: _searchQuery, status: _statusFilter }).catch(() => ({ passwords: [] })),
        window.FleetAPI.getLapsPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getLapsAuditLogs().catch(() => ({ audit_logs: [] })),
        window.FleetAPI.getGroups().catch(() => [])
      ]);

      _lapsStats = stats;
      _passwords = passData.passwords || [];
      _policies = policiesData.policies || [];
      _auditLogs = auditData.audit_logs || [];
      _groups = Array.isArray(groups) ? groups : (groups.groups || []);

      render(container);
    } catch (err) {
      container.innerHTML = `
        <div style="padding:32px;color:var(--ms-danger);">
          <h3>Failed to load LAPS Password Vault</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.LapsTable.refresh()">Retry</button>
        </div>
      `;
    }
  }

  function render(container) {
    const stats = _lapsStats || {};
    const coverage = stats.coverage_percent !== undefined ? stats.coverage_percent : 100;
    const managedCount = stats.managed_devices || 0;
    const expiringSoon = stats.expiring_soon_passwords || 0;
    const expiredCount = stats.expired_passwords || 0;
    const auditCount = stats.total_audit_events || 0;

    container.innerHTML = `
      <div class="intune-blade-header" style="padding:24px 32px 16px;border-bottom:1px solid var(--ms-border);">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
              <span style="font-size:24px;">🔐</span>
              <h1 style="font-size:22px;font-weight:600;margin:0;color:var(--ms-text-primary);">Windows LAPS Administrator Passwords</h1>
              <span class="intune-badge" style="background:#0F7B0F22;color:#0F7B0F;border:1px solid #0F7B0F44;font-size:11px;">Zero-Trust Credential Vault</span>
            </div>
            <p style="margin:0;font-size:13px;color:var(--ms-text-secondary);">
              Automated rotation, AES-256-GCM vaulting, and tamper-evident access logs for local built-in and custom administrator credentials across your fleet.
            </p>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="intune-btn intune-btn-secondary" id="btn-refresh-laps" title="Refresh Vault">
              🔄 Refresh
            </button>
            <button class="intune-btn intune-btn-primary" id="btn-create-laps-policy">
              + Create LAPS Policy
            </button>
          </div>
        </div>

        <!-- KPI Strip -->
        <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:16px;margin-top:20px;">
          <div class="kpi-card" style="border-left:4px solid #10B981;">
            <div class="kpi-label">LAPS Fleet Coverage</div>
            <div class="kpi-value" style="color:#10B981;">${coverage}%</div>
            <div class="kpi-subtext">${managedCount} of ${stats.total_devices || managedCount} machines vaulted</div>
          </div>
          <div class="kpi-card" style="border-left:4px solid #3B82F6;">
            <div class="kpi-label">Managed Admin Accounts</div>
            <div class="kpi-value" style="color:#3B82F6;">${managedCount}</div>
            <div class="kpi-subtext">Active credentials vaulted</div>
          </div>
          <div class="kpi-card" style="border-left:4px solid #F59E0B;">
            <div class="kpi-label">Expiring Soon (&le;7d)</div>
            <div class="kpi-value" style="color:#F59E0B;">${expiringSoon}</div>
            <div class="kpi-subtext">Automatic rotation pending</div>
          </div>
          <div class="kpi-card" style="border-left:4px solid ${expiredCount > 0 ? '#EF4444' : '#64748B'};">
            <div class="kpi-label">Expired / Overdue</div>
            <div class="kpi-value" style="color:${expiredCount > 0 ? '#EF4444' : 'var(--ms-text-secondary)'};">${expiredCount}</div>
            <div class="kpi-subtext">Requires immediate rotation</div>
          </div>
          <div class="kpi-card" style="border-left:4px solid #8B5CF6;">
            <div class="kpi-label">Access Audit Trail</div>
            <div class="kpi-value" style="color:#8B5CF6;">${auditCount}</div>
            <div class="kpi-subtext">Logged reveal / rotation events</div>
          </div>
        </div>

        <!-- Navigation Sub-Tabs -->
        <div class="intune-subtabs" style="margin-top:20px;display:flex;gap:24px;border-bottom:1px solid var(--ms-border);">
          <div class="subtab-item ${_activeSubTab === 'vault' ? 'active' : ''}" data-subtab="vault" style="cursor:pointer;padding:8px 4px;font-size:13px;font-weight:600;color:${_activeSubTab === 'vault' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};border-bottom:${_activeSubTab === 'vault' ? '2px solid var(--ms-primary)' : 'none'};">
            🔐 Password Vault (${_passwords.length})
          </div>
          <div class="subtab-item ${_activeSubTab === 'policies' ? 'active' : ''}" data-subtab="policies" style="cursor:pointer;padding:8px 4px;font-size:13px;font-weight:600;color:${_activeSubTab === 'policies' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};border-bottom:${_activeSubTab === 'policies' ? '2px solid var(--ms-primary)' : 'none'};">
            ⚙️ LAPS Policies (${_policies.length})
          </div>
          <div class="subtab-item ${_activeSubTab === 'audit' ? 'active' : ''}" data-subtab="audit" style="cursor:pointer;padding:8px 4px;font-size:13px;font-weight:600;color:${_activeSubTab === 'audit' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};border-bottom:${_activeSubTab === 'audit' ? '2px solid var(--ms-primary)' : 'none'};">
            📜 Access &amp; Rotation Audit Trail (${_auditLogs.length})
          </div>
        </div>
      </div>

      <!-- Main Sub-Blade Body -->
      <div style="padding:20px 32px;">
        ${_activeSubTab === 'vault' ? renderVaultSubTab() : ''}
        ${_activeSubTab === 'policies' ? renderPoliciesSubTab() : ''}
        ${_activeSubTab === 'audit' ? renderAuditSubTab() : ''}
      </div>
    `;

    bindEvents(container);
  }

  /* ── 1. Password Vault Sub-Tab ───────────────────────────────────── */
  function renderVaultSubTab() {
    return `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="display:flex;gap:12px;align-items:center;">
          <input type="text" class="intune-input" id="laps-search-input" placeholder="🔍 Search by device or account..." value="${esc(_searchQuery)}" style="width:280px;padding:6px 12px;font-size:13px;">
          <select class="intune-input" id="laps-status-filter" style="width:160px;padding:6px 12px;font-size:13px;">
            <option value="" ${_statusFilter === '' ? 'selected' : ''}>All Statuses</option>
            <option value="ACTIVE" ${_statusFilter === 'ACTIVE' ? 'selected' : ''}>Active / Healthy</option>
            <option value="ROTATION_PENDING" ${_statusFilter === 'ROTATION_PENDING' ? 'selected' : ''}>Rotation Pending</option>
            <option value="EXPIRED" ${_statusFilter === 'EXPIRED' ? 'selected' : ''}>Expired</option>
          </select>
        </div>
        <div style="font-size:12px;color:var(--ms-text-secondary);">
          Showing ${_passwords.length} vaulted credential(s)
        </div>
      </div>

      ${_passwords.length === 0 ? `
        <div class="empty-state" style="padding:48px 0;text-align:center;">
          <div style="font-size:36px;margin-bottom:12px;">🔐</div>
          <div style="font-size:15px;font-weight:600;color:var(--ms-text-primary);">No LAPS Passwords Escrowed</div>
          <div style="font-size:13px;color:var(--ms-text-secondary);margin-top:4px;">
            Enrolled Windows devices will automatically generate and escrow local administrator credentials according to their assigned LAPS policy.
          </div>
        </div>
      ` : `
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--ms-border);text-align:left;color:var(--ms-text-secondary);font-size:12px;">
              <th style="padding:10px 12px;">DEVICE</th>
              <th style="padding:10px 12px;">ACCOUNT</th>
              <th style="padding:10px 12px;">PASSWORD (MASKED)</th>
              <th style="padding:10px 12px;">COMPLEXITY</th>
              <th style="padding:10px 12px;">EXPIRATION</th>
              <th style="padding:10px 12px;">STATUS</th>
              <th style="padding:10px 12px;">LAST ACCESSED</th>
              <th style="padding:10px 12px;text-align:right;">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            ${_passwords.map(p => {
              const isExpired = p.health_status === 'EXPIRED';
              const isExpSoon = p.health_status === 'EXPIRING_SOON';
              const isPending = p.health_status === 'ROTATION_PENDING';

              const badgeColor = isExpired ? '#EF4444' : (isPending ? '#3B82F6' : (isExpSoon ? '#F59E0B' : '#10B981'));
              const badgeLabel = isExpired ? 'Expired' : (isPending ? 'Rotating…' : (isExpSoon ? `Expiring (${p.days_remaining}d)` : 'Healthy'));

              return `
                <tr style="border-bottom:1px solid var(--ms-border);height:48px;">
                  <td style="padding:8px 12px;">
                    <div style="font-weight:600;color:var(--ms-text-primary);">${esc(p.hostname)}</div>
                    <div style="font-size:11px;color:var(--ms-text-secondary);">${esc(p.ip_address || 'LAN')}</div>
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="mono" style="background:#33415522;padding:2px 6px;border-radius:4px;font-size:12px;font-weight:600;">
                      👤 ${esc(p.account_name)}
                    </span>
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="mono" style="letter-spacing:1px;color:var(--ms-text-secondary);font-size:12px;">
                      ${esc(p.password_masked)}
                    </span>
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="intune-badge" style="font-size:11px;">
                      ${esc(p.complexity_level)} (${p.password_length} chars)
                    </span>
                  </td>
                  <td style="padding:8px 12px;">
                    <div style="color:${isExpired ? '#EF4444' : (isExpSoon ? '#F59E0B' : 'inherit')};font-weight:${isExpired || isExpSoon ? '600' : '400'};">
                      ${p.days_remaining <= 0 ? 'Overdue' : `In ${p.days_remaining} days`}
                    </div>
                    <div style="font-size:11px;color:var(--ms-text-secondary);">
                      ${p.expires_at ? new Date(p.expires_at).toLocaleDateString() : '—'}
                    </div>
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="badge" style="background:${badgeColor}22;color:${badgeColor};border:1px solid ${badgeColor}44;font-size:11px;font-weight:600;">
                      ${badgeLabel}
                    </span>
                  </td>
                  <td style="padding:8px 12px;font-size:12px;color:var(--ms-text-secondary);">
                    ${p.last_accessed_at ? new Date(p.last_accessed_at).toLocaleString() : 'Never'}
                    ${p.access_count > 0 ? `<span style="font-size:10px;color:var(--ms-text-secondary);"> (${p.access_count}x)</span>` : ''}
                  </td>
                  <td style="padding:8px 12px;text-align:right;">
                    <div style="display:flex;gap:6px;justify-content:flex-end;">
                      <button class="intune-btn small primary btn-reveal-laps" data-device="${esc(p.device_id)}" data-hostname="${esc(p.hostname)}" data-account="${esc(p.account_name)}">
                        👁️ Reveal
                      </button>
                      <button class="intune-btn small btn-rotate-laps" data-device="${esc(p.device_id)}" data-hostname="${esc(p.hostname)}" title="Rotate Password Now">
                        🔄 Rotate
                      </button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `}
    `;
  }

  /* ── 2. LAPS Policies Sub-Tab ────────────────────────────────────── */
  function renderPoliciesSubTab() {
    return `
      <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(360px, 1fr));gap:16px;">
        ${_policies.map(p => {
          const group = _groups.find(g => g.id === p.target_group_id);
          const grpName = group ? group.name : (p.target_group_name || 'All Devices');
          const grpColor = group ? group.color : (p.target_group_color || '#64748B');

          return `
            <div class="intune-card" style="border:1px solid var(--ms-border);border-radius:8px;padding:16px;background:var(--ms-surface);">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                <div>
                  <h3 style="margin:0 0 4px;font-size:15px;color:var(--ms-text-primary);">${esc(p.name)}</h3>
                  <span class="intune-badge" style="background:${grpColor}22;color:${grpColor};border:1px solid ${grpColor}55;font-size:11px;">
                    🏷️ ${esc(grpName)}
                  </span>
                </div>
                <span class="badge ${p.is_enabled ? 'badge-success' : 'badge-neutral'}" style="font-size:11px;">
                  ${p.is_enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
              <p style="font-size:12px;color:var(--ms-text-secondary);margin:0 0 12px;line-height:1.4;">
                ${esc(p.description || 'No description provided.')}
              </p>

              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;border-top:1px solid var(--ms-border);padding-top:10px;margin-bottom:12px;">
                <div><span style="color:var(--ms-text-secondary);">Target Account:</span> <strong>${esc(p.admin_account_name)}</strong></div>
                <div><span style="color:var(--ms-text-secondary);">Complexity:</span> <strong>${esc(p.password_complexity)}</strong></div>
                <div><span style="color:var(--ms-text-secondary);">Password Length:</span> <strong>${p.password_length} chars</strong></div>
                <div><span style="color:var(--ms-text-secondary);">Rotation Interval:</span> <strong>${p.password_age_days} days</strong></div>
                <div><span style="color:var(--ms-text-secondary);">Post-Auth Reset:</span> <strong>${p.post_auth_reset_enabled ? `Yes (${p.post_auth_reset_delay_hours}h)` : 'No'}</strong></div>
                <div><span style="color:var(--ms-text-secondary);">Auto-Enable Acct:</span> <strong>${p.auto_enable_account ? 'Yes' : 'No'}</strong></div>
              </div>

              <div style="border-top:1px solid var(--ms-border);padding-top:10px;display:flex;justify-content:space-between;align-items:center;">
                <div style="font-size:12px;color:var(--ms-text-secondary);">
                  Coverage: <strong style="color:var(--accent-green);">${p.compliant_devices_count || 0}/${p.targeted_devices_count || 0} (${p.coverage_percent || 100}%)</strong>
                </div>
                <div style="display:flex;gap:6px;">
                  <button class="intune-btn small btn-edit-laps-policy" data-id="${esc(p.id)}">Edit</button>
                  <button class="intune-btn small delete btn-delete-laps-policy" data-id="${esc(p.id)}" style="color:#EF4444;">Delete</button>
                </div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  /* ── 3. Access & Rotation Audit Sub-Tab ──────────────────────────── */
  function renderAuditSubTab() {
    return `
      ${_auditLogs.length === 0 ? `
        <div class="empty-state" style="padding:48px 0;text-align:center;">
          <div style="font-size:36px;margin-bottom:12px;">📜</div>
          <div style="font-size:15px;font-weight:600;color:var(--ms-text-primary);">No Access Audit Events</div>
          <div style="font-size:13px;color:var(--ms-text-secondary);margin-top:4px;">
            Every password reveal and rotation request generates an immutable audit record here.
          </div>
        </div>
      ` : `
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid var(--ms-border);text-align:left;color:var(--ms-text-secondary);font-size:12px;">
              <th style="padding:10px 12px;">TIMESTAMP</th>
              <th style="padding:10px 12px;">ACTION</th>
              <th style="padding:10px 12px;">DEVICE</th>
              <th style="padding:10px 12px;">ACCOUNT</th>
              <th style="padding:10px 12px;">OPERATOR</th>
              <th style="padding:10px 12px;">JUSTIFICATION REASON</th>
              <th style="padding:10px 12px;">IP ADDRESS</th>
            </tr>
          </thead>
          <tbody>
            ${_auditLogs.map(a => {
              const isReveal = a.action === 'REVEAL' || a.action === 'HISTORY_REVEAL';
              const isRotate = a.action === 'ROTATE_REQUEST';
              const actionBadge = isReveal ? 'badge-error' : (isRotate ? 'badge-warning' : 'badge-neutral');

              return `
                <tr style="border-bottom:1px solid var(--ms-border);height:44px;">
                  <td style="padding:8px 12px;color:var(--ms-text-secondary);font-size:12px;">
                    ${a.accessed_at ? new Date(a.accessed_at).toLocaleString() : '—'}
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="badge ${actionBadge}" style="font-size:11px;font-weight:600;">
                      ${esc(a.action)}
                    </span>
                  </td>
                  <td style="padding:8px 12px;font-weight:600;color:var(--ms-text-primary);">
                    ${esc(a.hostname || a.device_id)}
                  </td>
                  <td style="padding:8px 12px;">
                    <span class="mono" style="font-size:12px;">${esc(a.account_name)}</span>
                  </td>
                  <td style="padding:8px 12px;font-weight:600;">
                    ${esc(a.accessed_by)}
                  </td>
                  <td style="padding:8px 12px;color:var(--ms-text-secondary);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                    ${esc(a.access_reason)}
                  </td>
                  <td style="padding:8px 12px;font-size:12px;color:var(--ms-text-secondary);" class="mono">
                    ${esc(a.ip_address)}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `}
    `;
  }

  /* ── Interactive Modal: Reveal Password ─────────────────────────── */
  function openRevealModal(deviceId, hostname, accountName) {
    let overlay = document.getElementById('laps-modal-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'laps-modal-overlay';
      overlay.className = 'intune-modal-overlay';
      document.body.appendChild(overlay);
    }

    overlay.innerHTML = `
      <div class="intune-modal-card" style="max-width:480px;background:var(--ms-surface);border:1px solid var(--ms-border);border-radius:8px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:20px;">🔐</span>
            <h2 style="margin:0;font-size:18px;color:var(--ms-text-primary);">Reveal LAPS Password</h2>
          </div>
          <button class="modal-close-btn" style="background:none;border:none;font-size:20px;cursor:pointer;color:var(--ms-text-secondary);">&times;</button>
        </div>

        <div style="background:#EF444415;border:1px solid #EF444444;border-radius:6px;padding:12px;margin-bottom:16px;">
          <div style="font-weight:600;color:#EF4444;font-size:12px;margin-bottom:4px;">⚠️ Security &amp; Compliance Audit Notice</div>
          <div style="font-size:12px;color:var(--ms-text-secondary);line-height:1.4;">
            Revealing the administrator password for <strong>${esc(accountName)}</strong> on <strong>${esc(hostname)}</strong> generates an immutable security audit record dispatched to the fleet event log.
          </div>
        </div>

        <div id="laps-reveal-form">
          <div class="intune-form-group" style="margin-bottom:12px;">
            <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Operator Name</label>
            <input class="intune-input" id="laps-reveal-operator" type="text" value="Matthew Bubb (Fleet Admin)" style="width:100%;">
          </div>
          <div class="intune-form-group" style="margin-bottom:16px;">
            <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Justification Reason (Mandatory &ge;5 chars)</label>
            <textarea class="intune-input" id="laps-reveal-reason" rows="3" placeholder="Enter reason for password access (e.g. Scheduled maintenance, emergency troubleshooting)..." style="width:100%;font-size:13px;"></textarea>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button class="intune-btn intune-btn-secondary modal-cancel-btn">Cancel</button>
            <button class="intune-btn intune-btn-primary" id="btn-submit-reveal" style="background:#EF4444;border-color:#EF4444;">
              Authorize &amp; Reveal Password
            </button>
          </div>
        </div>

        <div id="laps-revealed-view" style="display:none;margin-top:16px;">
          <div style="font-size:12px;color:var(--ms-text-secondary);margin-bottom:6px;">Plaintext Administrator Password:</div>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;">
            <input type="text" id="laps-plaintext-val" class="intune-input mono" readonly style="flex:1;font-size:15px;font-weight:600;color:var(--accent-green);background:#1e293b;padding:8px 12px;">
            <button class="intune-btn primary" id="btn-copy-laps-pwd" style="white-space:nowrap;">📋 Copy</button>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--ms-text-secondary);">
            <span>Audit Ref: <span class="mono" id="laps-reveal-audit-id">—</span></span>
            <span id="laps-timer-text">Auto-closing in 60s</span>
          </div>
        </div>
      </div>
    `;

    overlay.style.display = 'flex';

    overlay.querySelector('.modal-close-btn').addEventListener('click', () => { overlay.style.display = 'none'; });
    overlay.querySelector('.modal-cancel-btn').addEventListener('click', () => { overlay.style.display = 'none'; });

    overlay.querySelector('#btn-submit-reveal').addEventListener('click', async () => {
      const operator = overlay.querySelector('#laps-reveal-operator').value.trim() || 'Administrator';
      const reason = overlay.querySelector('#laps-reveal-reason').value.trim();

      if (!reason || reason.length < 5) {
        if (typeof showToast === 'function') showToast('Justification Required', 'Please enter a valid reason of at least 5 characters.', 'warning');
        return;
      }

      try {
        const result = await window.FleetAPI.revealLapsPassword(deviceId, {
          accessed_by: operator,
          access_reason: reason
        });

        overlay.querySelector('#laps-reveal-form').style.display = 'none';
        const revealedView = overlay.querySelector('#laps-revealed-view');
        revealedView.style.display = 'block';
        revealedView.querySelector('#laps-plaintext-val').value = result.password;
        revealedView.querySelector('#laps-reveal-audit-id').textContent = result.audit_record_id;

        // Copy button
        const copyBtn = revealedView.querySelector('#btn-copy-laps-pwd');
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(result.password).then(() => {
            copyBtn.textContent = '✔ Copied!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy'; }, 2000);
          });
        });

        // 60-second countdown
        let secondsLeft = 60;
        const timerText = revealedView.querySelector('#laps-timer-text');
        const interval = setInterval(() => {
          secondsLeft--;
          if (timerText) timerText.textContent = `Auto-closing in ${secondsLeft}s`;
          if (secondsLeft <= 0) {
            clearInterval(interval);
            overlay.style.display = 'none';
          }
        }, 1000);

        if (typeof showToast === 'function') showToast('Password Revealed', `LAPS password revealed for ${hostname}`, 'success');
      } catch (err) {
        if (typeof showToast === 'function') showToast('Reveal Failed', err.message, 'critical');
      }
    });
  }

  /* ── Interactive Modal: Create Policy Wizard ─────────────────────── */
  function openCreatePolicyModal() {
    let overlay = document.getElementById('laps-modal-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'laps-modal-overlay';
      overlay.className = 'intune-modal-overlay';
      document.body.appendChild(overlay);
    }

    overlay.innerHTML = `
      <div class="intune-modal-card" style="max-width:540px;background:var(--ms-surface);border:1px solid var(--ms-border);border-radius:8px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:20px;">⚙️</span>
            <h2 style="margin:0;font-size:18px;color:var(--ms-text-primary);">Create Windows LAPS Policy</h2>
          </div>
          <button class="modal-close-btn" style="background:none;border:none;font-size:20px;cursor:pointer;color:var(--ms-text-secondary);">&times;</button>
        </div>

        <div style="margin-bottom:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--ms-text-secondary);margin-bottom:6px;">QUICK PRESETS</div>
          <div style="display:flex;gap:8px;">
            <button class="intune-btn small btn-laps-preset" data-preset="enterprise" style="flex:1;">🏢 Enterprise (30d)</button>
            <button class="intune-btn small btn-laps-preset" data-preset="highsec" style="flex:1;">🛡️ High-Assurance (14d)</button>
            <button class="intune-btn small btn-laps-preset" data-preset="family" style="flex:1;">🏠 Family Fleet (60d)</button>
          </div>
        </div>

        <form id="laps-create-policy-form">
          <div class="intune-form-group" style="margin-bottom:12px;">
            <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Policy Name</label>
            <input class="intune-input" id="new-laps-name" type="text" required value="Enterprise LAPS Baseline" style="width:100%;">
          </div>
          <div class="intune-form-group" style="margin-bottom:12px;">
            <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Target Dynamic Group</label>
            <select class="intune-input" id="new-laps-group" style="width:100%;">
              ${_groups.map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('')}
            </select>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
            <div class="intune-form-group">
              <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Target Account Name</label>
              <input class="intune-input" id="new-laps-account" type="text" required value="Administrator" style="width:100%;">
            </div>
            <div class="intune-form-group">
              <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Password Complexity</label>
              <select class="intune-input" id="new-laps-complexity" style="width:100%;">
                <option value="COMPLEX" selected>Complex (A-Z, a-z, 0-9, Symbols)</option>
                <option value="ALPHANUMERIC">Alphanumeric (A-Z, a-z, 0-9)</option>
                <option value="ALPHABETICAL">Alphabetical (A-Z, a-z)</option>
                <option value="NUMERIC">Numeric (0-9 PIN)</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
            <div class="intune-form-group">
              <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Password Length (12-64)</label>
              <input class="intune-input" id="new-laps-length" type="number" min="12" max="64" value="16" style="width:100%;">
            </div>
            <div class="intune-form-group">
              <label class="intune-label" style="font-size:12px;font-weight:600;display:block;margin-bottom:4px;">Rotation Interval (Days)</label>
              <input class="intune-input" id="new-laps-age" type="number" min="1" max="365" value="30" style="width:100%;">
            </div>
          </div>

          <div style="display:flex;gap:16px;margin-bottom:20px;font-size:13px;">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
              <input type="checkbox" id="new-laps-auto-enable" checked> Auto-Enable Account
            </label>
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">
              <input type="checkbox" id="new-laps-post-auth"> Post-Auth Reset
            </label>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button type="button" class="intune-btn intune-btn-secondary modal-cancel-btn">Cancel</button>
            <button type="submit" class="intune-btn intune-btn-primary">Create Policy</button>
          </div>
        </form>
      </div>
    `;

    overlay.style.display = 'flex';

    overlay.querySelector('.modal-close-btn').addEventListener('click', () => { overlay.style.display = 'none'; });
    overlay.querySelector('.modal-cancel-btn').addEventListener('click', () => { overlay.style.display = 'none'; });

    // Presets handler
    overlay.querySelectorAll('.btn-laps-preset').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const p = btn.dataset.preset;
        if (p === 'enterprise') {
          overlay.querySelector('#new-laps-name').value = 'Enterprise LAPS Baseline';
          overlay.querySelector('#new-laps-account').value = 'Administrator';
          overlay.querySelector('#new-laps-complexity').value = 'COMPLEX';
          overlay.querySelector('#new-laps-length').value = '16';
          overlay.querySelector('#new-laps-age').value = '30';
          overlay.querySelector('#new-laps-auto-enable').checked = true;
          overlay.querySelector('#new-laps-post-auth').checked = false;
        } else if (p === 'highsec') {
          overlay.querySelector('#new-laps-name').value = 'High-Assurance Workstation LAPS';
          overlay.querySelector('#new-laps-account').value = 'Administrator';
          overlay.querySelector('#new-laps-complexity').value = 'COMPLEX';
          overlay.querySelector('#new-laps-length').value = '24';
          overlay.querySelector('#new-laps-age').value = '14';
          overlay.querySelector('#new-laps-auto-enable').checked = true;
          overlay.querySelector('#new-laps-post-auth').checked = true;
        } else if (p === 'family') {
          overlay.querySelector('#new-laps-name').value = 'Family Fleet Standard Admin';
          overlay.querySelector('#new-laps-account').value = 'LocalAdmin';
          overlay.querySelector('#new-laps-complexity').value = 'ALPHANUMERIC';
          overlay.querySelector('#new-laps-length').value = '14';
          overlay.querySelector('#new-laps-age').value = '60';
          overlay.querySelector('#new-laps-auto-enable').checked = true;
          overlay.querySelector('#new-laps-post-auth').checked = false;
        }
      });
    });

    // Form submit
    overlay.querySelector('#laps-create-policy-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: overlay.querySelector('#new-laps-name').value.trim(),
        target_group_id: overlay.querySelector('#new-laps-group').value,
        admin_account_name: overlay.querySelector('#new-laps-account').value.trim(),
        password_complexity: overlay.querySelector('#new-laps-complexity').value,
        password_length: parseInt(overlay.querySelector('#new-laps-length').value, 10),
        password_age_days: parseInt(overlay.querySelector('#new-laps-age').value, 10),
        auto_enable_account: overlay.querySelector('#new-laps-auto-enable').checked,
        post_auth_reset_enabled: overlay.querySelector('#new-laps-post-auth').checked
      };

      try {
        await window.FleetAPI.createLapsPolicy(payload);
        overlay.style.display = 'none';
        if (typeof showToast === 'function') showToast('Policy Created', `Created LAPS policy: ${payload.name}`, 'success');
        loadData();
      } catch (err) {
        if (typeof showToast === 'function') showToast('Creation Failed', err.message, 'critical');
      }
    });
  }

  /* ── Event Bindings ──────────────────────────────────────────────── */
  function bindEvents(container) {
    // Refresh button
    container.querySelector('#btn-refresh-laps')?.addEventListener('click', () => {
      loadData();
    });

    // Create policy button
    container.querySelector('#btn-create-laps-policy')?.addEventListener('click', () => {
      openCreatePolicyModal();
    });

    // Sub-tab switching
    container.querySelectorAll('.subtab-item').forEach(el => {
      el.addEventListener('click', () => {
        _activeSubTab = el.dataset.subtab;
        render(container);
      });
    });

    // Search and filter
    const searchInput = container.querySelector('#laps-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        _searchQuery = searchInput.value.trim();
        clearTimeout(searchInput._t);
        searchInput._t = setTimeout(() => {
          loadData();
        }, 300);
      });
    }

    const statusFilter = container.querySelector('#laps-status-filter');
    if (statusFilter) {
      statusFilter.addEventListener('change', () => {
        _statusFilter = statusFilter.value;
        loadData();
      });
    }

    // Reveal buttons
    container.querySelectorAll('.btn-reveal-laps').forEach(btn => {
      btn.addEventListener('click', () => {
        openRevealModal(btn.dataset.device, btn.dataset.hostname, btn.dataset.account);
      });
    });

    // Rotate buttons
    container.querySelectorAll('.btn-rotate-laps').forEach(btn => {
      btn.addEventListener('click', async () => {
        const deviceId = btn.dataset.device;
        const hostname = btn.dataset.hostname;
        if (confirm(`Trigger immediate LAPS password rotation for ${hostname}? The node agent will generate and apply a new password on next heartbeat.`)) {
          try {
            await window.FleetAPI.rotateDeviceLapsPassword(deviceId, { requested_by: 'Fleet Admin' });
            if (typeof showToast === 'function') showToast('Rotation Queued', `Password rotation command dispatched to ${hostname}`, 'info');
            loadData();
          } catch (err) {
            if (typeof showToast === 'function') showToast('Rotation Failed', err.message, 'critical');
          }
        }
      });
    });

    // Delete policy buttons
    container.querySelectorAll('.btn-delete-laps-policy').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (confirm('Are you sure you want to delete this LAPS policy?')) {
          try {
            await window.FleetAPI.deleteLapsPolicy(id);
            if (typeof showToast === 'function') showToast('Policy Deleted', 'LAPS policy removed successfully.', 'info');
            loadData();
          } catch (err) {
            if (typeof showToast === 'function') showToast('Delete Failed', err.message, 'critical');
          }
        }
      });
    });
  }

  /* ── Public Module Interface ─────────────────────────────────────── */
  window.LapsTable = {
    init: function () {
      loadData();
    },
    refresh: function () {
      loadData();
    },
    reveal: function (deviceId, hostname, accountName) {
      openRevealModal(deviceId, hostname, accountName);
    }
  };

})();
