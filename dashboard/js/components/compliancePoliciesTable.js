/**
 * LocalPilot Fleet — Device Compliance Policies & Conditional Access UI Component
 * dashboard/js/components/compliancePoliciesTable.js
 */

(function () {
  let _policies = [];
  let _stats = null;
  let _groups = [];
  let _searchQuery = '';
  let _actionFilter = 'ALL';

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
      const [polsRes, statsRes, grpRes] = await Promise.all([
        window.FleetAPI.getCompliancePolicies(),
        window.FleetAPI.getComplianceStats(),
        window.FleetAPI.getGroups()
      ]);
      _policies = polsRes.policies || [];
      _stats = statsRes || null;
      _groups = grpRes.groups || [];
      render();
    } catch (err) {
      console.error('Failed to load compliance policies:', err);
    }
  }

  function renderKpiCards() {
    const s = _stats || {
      compliance_rate_percent: 100,
      total_policies: _policies.length,
      monitored_devices: 0,
      compliant_devices: 0,
      in_grace_period_devices: 0,
      non_compliant_devices: 0,
      quarantined_devices: 0
    };

    return `
      <div class="kpi-grid" style="margin-bottom: 20px;">
        <div class="kpi-card">
          <div class="kpi-label">Zero-Trust Compliance Rate</div>
          <div class="kpi-value" style="color: ${s.compliance_rate_percent >= 80 ? '#10B981' : (s.compliance_rate_percent >= 50 ? '#F59E0B' : '#EF4444')};">
            ${s.compliance_rate_percent}%
          </div>
          <div class="kpi-sub">${s.compliant_devices} of ${s.monitored_devices} nodes compliant</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">In Grace Period</div>
          <div class="kpi-value" style="color: ${s.in_grace_period_devices > 0 ? '#F59E0B' : '#10B981'};">
            ${s.in_grace_period_devices}
          </div>
          <div class="kpi-sub">Warning active before penalty</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Non-Compliant Nodes</div>
          <div class="kpi-value" style="color: ${s.non_compliant_devices > 0 ? '#EF4444' : '#10B981'};">
            ${s.non_compliant_devices}
          </div>
          <div class="kpi-sub">Breaching zero-trust rules</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Quarantined Nodes</div>
          <div class="kpi-value" style="color: ${s.quarantined_devices > 0 ? '#EF4444' : '#64748B'};">
            ${s.quarantined_devices}
          </div>
          <div class="kpi-sub">Isolated from fleet network</div>
        </div>
      </div>
    `;
  }

  function renderTable() {
    const q = _searchQuery.toLowerCase();
    const filtered = _policies.filter(p => {
      const matchSearch = p.name.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.target_group_name || '').toLowerCase().includes(q);
      const matchAction = _actionFilter === 'ALL' || p.non_compliance_action === _actionFilter;
      return matchSearch && matchAction;
    });

    if (filtered.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">🛡️</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No Compliance Policies Found</div>
          <p>Create a zero-trust compliance policy or adjust your filter.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Policy Name</th>
            <th>Platform</th>
            <th>Target Group</th>
            <th>Required Rules</th>
            <th>Grace Period</th>
            <th>Non-Compliance Action</th>
            <th>Compliance Rate</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(p => {
            const stats = p.stats || {};
            const total = stats.total_evaluations || 0;
            const rate = stats.compliance_rate_percent ?? 100;

            const rules = [];
            if (p.require_bitlocker) rules.push('BitLocker');
            if (p.require_secure_boot) rules.push('SecureBoot');
            if (p.require_tpm) rules.push('TPM 2.0');
            if (p.require_defender_rtp) rules.push('Defender RTP');
            if (p.require_firewall) rules.push('Firewall');

            let actionBadgeClass = 'badge-action-mark';
            let actionLabel = 'Mark Non-Compliant';
            if (p.non_compliance_action === 'QUARANTINE') {
              actionBadgeClass = 'badge-action-quarantine';
              actionLabel = '🚨 Quarantine';
            } else if (p.non_compliance_action === 'ALERT_ONLY') {
              actionBadgeClass = 'badge-action-alert';
              actionLabel = '⚠️ Alert Only';
            }

            return `
              <tr data-policy-id="${esc(p.id)}">
                <td>
                  <div style="font-weight: 600; color: var(--text-bright); display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 16px;">🛡️</span>
                    ${esc(p.name)}
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px; max-width: 320px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                    ${esc(p.description || 'No description')}
                  </div>
                </td>
                <td>
                  <span class="badge" style="background: #334155; color: #94a3b8;">${esc(p.platform)}</span>
                </td>
                <td>
                  <span class="badge" style="background: ${p.target_group_color || '#3B82F6'}22; color: ${p.target_group_color || '#3B82F6'}; border: 1px solid ${p.target_group_color || '#3B82F6'}55;">
                    🏷️ ${esc(p.target_group_name || p.target_group_id)}
                  </span>
                </td>
                <td style="max-width: 220px;">
                  <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                    ${rules.map(r => `
                      <span class="badge" style="background: #1e293b; border: 1px solid #334155; font-size: 10px; padding: 2px 6px;">
                        ✓ ${esc(r)}
                      </span>
                    `).join('')}
                  </div>
                </td>
                <td>
                  <span style="font-weight: 600;">${p.grace_period_days}</span>
                  <span style="font-size: 11px; color: var(--text-muted);"> days</span>
                </td>
                <td>
                  <span class="badge ${actionBadgeClass}">${actionLabel}</span>
                </td>
                <td>
                  <span style="font-weight: 700; color: ${rate >= 80 ? '#10B981' : (rate >= 50 ? '#F59E0B' : '#EF4444')};">
                    ${rate}%
                  </span>
                  <span style="font-size: 11px; color: var(--text-muted); margin-left: 4px;">(${total} nodes)</span>
                </td>
                <td style="text-align: right; white-space: nowrap;">
                  <button class="intune-btn small secondary btn-inspect-comp" data-id="${esc(p.id)}" title="Inspect device evaluations">
                    🔍 Inspect
                  </button>
                  <button class="intune-btn small secondary btn-edit-comp" data-id="${esc(p.id)}" title="Edit compliance rules">
                    ✏️ Edit
                  </button>
                  <button class="intune-btn small danger btn-delete-comp" data-id="${esc(p.id)}" title="Delete compliance policy">
                    🗑️
                  </button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function render() {
    const container = document.getElementById('view-compliance');
    if (!container) return;

    container.innerHTML = `
      <style>
        .badge-action-mark { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b55; }
        .badge-action-quarantine { background: #ef444422; color: #f87171; border: 1px solid #ef444455; font-weight: 600; }
        .badge-action-alert { background: #3b82f622; color: #60a5fa; border: 1px solid #3b82f655; }
      </style>

      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Devices &gt; Compliance policies</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">🛡️</div>
          <div>
            <h1 class="intune-blade-title">Devices | Compliance policies</h1>
            <p class="intune-blade-subtitle">Microsoft Intune zero-trust security compliance, grace period enforcement, and conditional access quarantine</p>
          </div>
        </div>
      </div>

      <!-- Action Command Bar -->
      <div class="intune-command-bar" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:16px;">
        <div style="display:flex; gap:8px; align-items:center;">
          <button class="intune-btn primary" id="btn-create-comp">
            <span style="font-weight:bold; margin-right:4px;">+</span> Create policy
          </button>
          <button class="intune-btn secondary" id="btn-refresh-comp">
            ↻ Refresh
          </button>
        </div>

        <div style="display:flex; gap:10px; align-items:center;">
          <select class="intune-input" id="comp-action-filter" style="width:180px;">
            <option value="ALL" ${_actionFilter === 'ALL' ? 'selected' : ''}>All actions</option>
            <option value="MARK_NON_COMPLIANT" ${_actionFilter === 'MARK_NON_COMPLIANT' ? 'selected' : ''}>Mark non-compliant</option>
            <option value="QUARANTINE" ${_actionFilter === 'QUARANTINE' ? 'selected' : ''}>Quarantine</option>
            <option value="ALERT_ONLY" ${_actionFilter === 'ALERT_ONLY' ? 'selected' : ''}>Alert only</option>
          </select>
          <input class="intune-input" id="comp-search-input" type="text" placeholder="Search policies or groups..." value="${esc(_searchQuery)}" style="width:240px;">
        </div>
      </div>

      <!-- Executive KPI Cards -->
      ${renderKpiCards()}

      <!-- Compliance Policies Data Table -->
      <div class="intune-card" style="padding: 0; overflow-x: auto;">
        ${renderTable()}
      </div>

      <!-- Container for Dynamic Modals -->
      <div id="compliance-modal-container"></div>
    `;

    bindEvents();
  }

  function bindEvents() {
    document.getElementById('btn-create-comp')?.addEventListener('click', () => {
      openCreatePolicyModal();
    });

    document.getElementById('btn-refresh-comp')?.addEventListener('click', () => {
      loadData();
    });

    document.getElementById('comp-action-filter')?.addEventListener('change', (e) => {
      _actionFilter = e.target.value;
      render();
    });

    document.getElementById('comp-search-input')?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      render();
    });

    document.querySelectorAll('.btn-inspect-comp').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        openInspectPolicyModal(id);
      });
    });

    document.querySelectorAll('.btn-edit-comp').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const policy = _policies.find(p => p.id === id);
        if (policy) openCreatePolicyModal(policy);
      });
    });

    document.querySelectorAll('.btn-delete-comp').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const policy = _policies.find(p => p.id === id);
        if (!confirm(`Are you sure you want to delete compliance policy "${policy?.name || id}"?`)) return;

        try {
          await window.FleetAPI.deleteCompliancePolicy(id);
          if (window.showToast) window.showToast('Compliance Policy Deleted', 'Policy removed successfully.', 'info');
          loadData();
        } catch (err) {
          alert('Failed to delete compliance policy: ' + err.message);
        }
      });
    });
  }

  function openCreatePolicyModal(editingPolicy = null) {
    const isEdit = !!editingPolicy;
    const modalContainer = document.getElementById('compliance-modal-container');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="modal-backdrop" id="comp-modal-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
        <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:680px; max-width:92vw; max-height:90vh; overflow-y:auto; box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
          <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid #334155;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:20px;">🛡️</span>
              <h2 style="font-size:16px; font-weight:600; margin:0;">${isEdit ? 'Edit Compliance Policy' : 'Create Device Compliance Policy'}</h2>
            </div>
            <button id="modal-comp-close" style="background:none; border:none; color:#94a3b8; font-size:20px; cursor:pointer;">&times;</button>
          </div>

          <div style="padding:20px; display:flex; flex-direction:column; gap:16px;">
            ${!isEdit ? `
              <div class="intune-form-group">
                <label class="intune-label">Security Template Preset</label>
                <select class="intune-input" id="comp-preset-select">
                  <option value="">Custom Rules (Configure manually)</option>
                  <option value="zero-trust" selected>Windows 11 Enterprise Zero-Trust (BitLocker, TPM 2.0, SecureBoot, Defender, 3d grace)</option>
                  <option value="anti-tamper">Strict Anti-Tamper Quarantine (Zero-day tolerance - Immediate Fleet Quarantine)</option>
                  <option value="relaxed">Homelab & Gaming Rig Relaxed (Defender only, 7-day grace, Alert only)</option>
                </select>
              </div>
            ` : ''}

            <div class="intune-form-group">
              <label class="intune-label">Policy Name *</label>
              <input class="intune-input" id="modal-comp-name" type="text" placeholder="e.g. Windows 11 Enterprise Zero-Trust Baseline" value="${esc(editingPolicy?.name || '')}" required>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Description</label>
              <input class="intune-input" id="modal-comp-desc" type="text" placeholder="e.g. Enforces hardware encryption and endpoint security posture" value="${esc(editingPolicy?.description || '')}">
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Target Dynamic Group</label>
                <select class="intune-input" id="modal-comp-group">
                  <option value="grp-all" ${editingPolicy?.target_group_id === 'grp-all' ? 'selected' : ''}>All Enrolled Devices (grp-all)</option>
                  ${_groups.map(g => `
                    <option value="${esc(g.id)}" ${editingPolicy?.target_group_id === g.id ? 'selected' : ''}>
                      ${esc(g.name)} (${esc(g.id)})
                    </option>
                  `).join('')}
                </select>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Minimum OS Build</label>
                <input class="intune-input" id="modal-comp-minbuild" type="text" placeholder="10.0.22000" value="${esc(editingPolicy?.min_os_build || '10.0.22000')}">
              </div>
            </div>

            <div class="intune-form-group">
              <label class="intune-label" style="margin-bottom:8px;">Zero-Trust Device Security Rules</label>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; background:#1e293b; padding:12px; border-radius:6px; border:1px solid #334155;">
                <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                  <input type="checkbox" id="chk-bitlocker" ${editingPolicy ? (editingPolicy.require_bitlocker ? 'checked' : '') : 'checked'}>
                  Require BitLocker Drive Encryption
                </label>
                <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                  <input type="checkbox" id="chk-secureboot" ${editingPolicy ? (editingPolicy.require_secure_boot ? 'checked' : '') : 'checked'}>
                  Require UEFI Secure Boot
                </label>
                <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                  <input type="checkbox" id="chk-tpm" ${editingPolicy ? (editingPolicy.require_tpm ? 'checked' : '') : 'checked'}>
                  Require TPM 2.0 Activated
                </label>
                <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                  <input type="checkbox" id="chk-defender-rtp" ${editingPolicy ? (editingPolicy.require_defender_rtp ? 'checked' : '') : 'checked'}>
                  Require Defender Real-Time Protection
                </label>
                <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
                  <input type="checkbox" id="chk-firewall" ${editingPolicy ? (editingPolicy.require_firewall ? 'checked' : '') : 'checked'}>
                  Require Windows Defender Firewall
                </label>
              </div>
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Grace Period (Days: 0-30)</label>
                <input class="intune-input" id="modal-comp-grace" type="number" min="0" max="30" value="${editingPolicy ? editingPolicy.grace_period_days : 3}">
                <div class="form-hint">Days before non-compliance action triggers</div>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Action for Non-Compliance</label>
                <select class="intune-input" id="modal-comp-action">
                  <option value="MARK_NON_COMPLIANT" ${editingPolicy?.non_compliance_action === 'MARK_NON_COMPLIANT' ? 'selected' : ''}>Mark device non-compliant</option>
                  <option value="QUARANTINE" ${editingPolicy?.non_compliance_action === 'QUARANTINE' ? 'selected' : ''}>🚨 Quarantine (Fleet Network Isolation)</option>
                  <option value="ALERT_ONLY" ${editingPolicy?.non_compliance_action === 'ALERT_ONLY' ? 'selected' : ''}>⚠️ Alert Only (No penalty)</option>
                </select>
              </div>
            </div>
          </div>

          <div style="display:flex; justify-content:flex-end; gap:10px; padding:16px 20px; border-top:1px solid #334155; background:#0b1120;">
            <button class="intune-btn secondary" id="modal-comp-cancel">Cancel</button>
            <button class="intune-btn primary" id="modal-comp-save">${isEdit ? 'Save Changes' : 'Create Policy'}</button>
          </div>
        </div>
      </div>
    `;

    // Presets listener
    document.getElementById('comp-preset-select')?.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === 'zero-trust') {
        document.getElementById('modal-comp-name').value = 'Windows 11 Enterprise Zero-Trust Compliance Policy';
        document.getElementById('modal-comp-desc').value = 'Enforces BitLocker, Secure Boot, TPM 2.0, Defender RTP, and Firewall with 3-day grace period';
        document.getElementById('chk-bitlocker').checked = true;
        document.getElementById('chk-secureboot').checked = true;
        document.getElementById('chk-tpm').checked = true;
        document.getElementById('chk-defender-rtp').checked = true;
        document.getElementById('chk-firewall').checked = true;
        document.getElementById('modal-comp-grace').value = 3;
        document.getElementById('modal-comp-action').value = 'MARK_NON_COMPLIANT';
      } else if (val === 'anti-tamper') {
        document.getElementById('modal-comp-name').value = 'Strict Anti-Tamper & Zero-Tolerance Quarantine Policy';
        document.getElementById('modal-comp-desc').value = 'Immediate fleet network quarantine upon missing Defender RTP or disabled Firewall';
        document.getElementById('chk-bitlocker').checked = true;
        document.getElementById('chk-secureboot').checked = true;
        document.getElementById('chk-tpm').checked = true;
        document.getElementById('chk-defender-rtp').checked = true;
        document.getElementById('chk-firewall').checked = true;
        document.getElementById('modal-comp-grace').value = 0;
        document.getElementById('modal-comp-action').value = 'QUARANTINE';
      } else if (val === 'relaxed') {
        document.getElementById('modal-comp-name').value = 'Homelab & Gaming Rig Relaxed Compliance';
        document.getElementById('modal-comp-desc').value = 'Relaxed policy for personal gaming rigs with 7-day grace period and alert-only status';
        document.getElementById('chk-bitlocker').checked = false;
        document.getElementById('chk-secureboot').checked = false;
        document.getElementById('chk-tpm').checked = false;
        document.getElementById('chk-defender-rtp').checked = true;
        document.getElementById('chk-firewall').checked = false;
        document.getElementById('modal-comp-grace').value = 7;
        document.getElementById('modal-comp-action').value = 'ALERT_ONLY';
      }
    });

    const closeModal = () => { modalContainer.innerHTML = ''; };
    document.getElementById('modal-comp-close')?.addEventListener('click', closeModal);
    document.getElementById('modal-comp-cancel')?.addEventListener('click', closeModal);

    document.getElementById('modal-comp-save')?.addEventListener('click', async () => {
      const name = document.getElementById('modal-comp-name')?.value?.trim();
      if (!name) {
        alert('Policy name is required');
        return;
      }

      const payload = {
        name,
        description: document.getElementById('modal-comp-desc')?.value?.trim() || '',
        target_group_id: document.getElementById('modal-comp-group')?.value || 'grp-all',
        min_os_build: document.getElementById('modal-comp-minbuild')?.value?.trim() || '10.0.22000',
        require_bitlocker: document.getElementById('chk-bitlocker')?.checked ? 1 : 0,
        require_secure_boot: document.getElementById('chk-secureboot')?.checked ? 1 : 0,
        require_tpm: document.getElementById('chk-tpm')?.checked ? 1 : 0,
        require_defender_rtp: document.getElementById('chk-defender-rtp')?.checked ? 1 : 0,
        require_firewall: document.getElementById('chk-firewall')?.checked ? 1 : 0,
        grace_period_days: parseInt(document.getElementById('modal-comp-grace')?.value || '3', 10),
        non_compliance_action: document.getElementById('modal-comp-action')?.value || 'MARK_NON_COMPLIANT'
      };

      try {
        if (isEdit) {
          await window.FleetAPI.updateCompliancePolicy(editingPolicy.id, payload);
          if (window.showToast) window.showToast('Compliance Policy Updated', `Policy "${name}" updated.`, 'success');
        } else {
          await window.FleetAPI.createCompliancePolicy(payload);
          if (window.showToast) window.showToast('Compliance Policy Created', `Policy "${name}" established.`, 'success');
        }
        closeModal();
        loadData();
      } catch (err) {
        alert('Failed to save compliance policy: ' + err.message);
      }
    });
  }

  async function openInspectPolicyModal(policyId) {
    const modalContainer = document.getElementById('compliance-modal-container');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="modal-backdrop" id="inspect-comp-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
        <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:760px; max-width:92vw; max-height:90vh; overflow-y:auto;">
          <div style="padding:24px; text-align:center;">
            <div style="font-size:24px; margin-bottom:8px;">⏳</div>
            <div>Loading compliance policy evaluations...</div>
          </div>
        </div>
      </div>
    `;

    try {
      const policy = await window.FleetAPI.getCompliancePolicy(policyId);
      const evals = policy.evaluations || [];

      modalContainer.innerHTML = `
        <div class="modal-backdrop" id="inspect-comp-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
          <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:820px; max-width:94vw; max-height:90vh; overflow-y:auto; box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
            <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid #334155;">
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:20px;">🛡️</span>
                <div>
                  <h2 style="font-size:16px; font-weight:600; margin:0;">${esc(policy.name)}</h2>
                  <div style="font-size:12px; color:var(--text-muted);">${esc(policy.non_compliance_action)} &bull; ${evals.length} Evaluated Nodes</div>
                </div>
              </div>
              <button id="modal-inspect-comp-close" style="background:none; border:none; color:#94a3b8; font-size:20px; cursor:pointer;">&times;</button>
            </div>

            <div style="padding:20px;">
              <h3 style="font-size:14px; font-weight:600; margin-bottom:12px;">Assigned Fleet Nodes & Posture</h3>
              ${evals.length === 0 ? `
                <div style="padding:32px; text-align:center; color:var(--text-muted); background:#1e293b; border-radius:6px;">
                  No device evaluations recorded for this policy yet. Devices evaluate during their heartbeat.
                </div>
              ` : `
                <div style="display:flex; flex-direction:column; gap:12px;">
                  ${evals.map(e => {
                    const isCompliant = e.compliance_status === 'COMPLIANT';
                    const inGrace = e.compliance_status === 'IN_GRACE_PERIOD';
                    const color = isCompliant ? '#10B981' : (inGrace ? '#F59E0B' : '#EF4444');
                    const label = isCompliant ? '✓ Compliant' : (inGrace ? '⏳ In Grace Period' : '⚠️ Non-Compliant');
                    const rules = e.rule_results || [];

                    return `
                      <div style="background:#1e293b; border:1px solid #334155; border-radius:6px; padding:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                          <div>
                            <div style="font-weight:600; color:var(--text-bright);">💻 ${esc(e.hostname)}</div>
                            <div style="font-size:11px; color:var(--text-muted);">${esc(e.primary_user || 'SYSTEM')} &bull; Status: ${esc(e.device_status)}</div>
                          </div>
                          <span class="badge" style="background:${color}22; color:${color}; border:1px solid ${color}55; font-weight:600;">
                            ${label}
                          </span>
                        </div>

                        ${inGrace && e.grace_period_expires_at ? `
                          <div style="font-size:11px; color:#fbbf24; background:#451a0344; padding:4px 8px; border-radius:4px; border:1px solid #78350f; margin-bottom:8px;">
                            ⚠️ Grace period active until: ${new Date(e.grace_period_expires_at).toLocaleString()}
                          </div>
                        ` : ''}

                        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:6px;">
                          ${rules.map(r => `
                            <div style="font-size:11px; padding:4px 8px; border-radius:4px; background:#0f172a; border:1px solid ${r.passed ? '#10B98133' : '#EF444455'}; display:flex; justify-content:space-between; align-items:center;">
                              <span>${esc(r.name || r.rule)}</span>
                              <span style="color:${r.passed ? '#10B981' : '#EF4444'}; font-weight:600;">${r.passed ? 'PASS' : 'FAIL'}</span>
                            </div>
                          `).join('')}
                        </div>
                      </div>
                    `;
                  }).join('')}
                </div>
              `}
            </div>

            <div style="display:flex; justify-content:flex-end; padding:16px 20px; border-top:1px solid #334155; background:#0b1120;">
              <button class="intune-btn secondary" id="modal-inspect-comp-close-btn">Close</button>
            </div>
          </div>
        </div>
      `;

      const closeInspect = () => { modalContainer.innerHTML = ''; };
      document.getElementById('modal-inspect-comp-close')?.addEventListener('click', closeInspect);
      document.getElementById('modal-inspect-comp-close-btn')?.addEventListener('click', closeInspect);
    } catch (err) {
      alert('Failed to load compliance policy details: ' + err.message);
      modalContainer.innerHTML = '';
    }
  }

  // Export globally
  window.CompliancePoliciesTable = {
    loadData
  };
})();
