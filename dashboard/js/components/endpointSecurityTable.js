/**
 * LocalPilot Fleet — Microsoft Defender & Endpoint Security UI Blade
 * dashboard/js/components/endpointSecurityTable.js
 *
 * Implements full Microsoft Intune Endpoint Security portal interface:
 * - Executive KPI summary strip & posture health rings
 * - Sub-blades: Antivirus Posture, Security Baselines & Policies, Threat Detections
 * - Remote scan dispatching & signature updates
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

  let _activeSubTab = 'antivirus'; // 'antivirus' | 'policies' | 'threats'
  let _securityStats = null;
  let _antivirusStatuses = [];
  let _policies = [];
  let _threats = [];
  let _groups = [];

  async function loadData() {
    const container = document.getElementById('view-security');
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
      const [stats, statuses, policies, threats, groups] = await Promise.all([
        window.FleetAPI.getSecurityStats().catch(() => ({})),
        window.FleetAPI.getAntivirusStatuses().catch(() => []),
        window.FleetAPI.getSecurityPolicies().catch(() => []),
        window.FleetAPI.getSecurityThreats().catch(() => []),
        window.FleetAPI.getGroups().catch(() => [])
      ]);

      _securityStats = stats;
      _antivirusStatuses = Array.isArray(statuses) ? statuses : [];
      _policies = Array.isArray(policies) ? policies : [];
      _threats = Array.isArray(threats) ? threats : [];
      _groups = Array.isArray(groups) ? groups : (groups.groups || []);

      render(container);
    } catch (err) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">❌</div>
          <div class="empty-state-title">Failed to load Endpoint Security</div>
          <div class="empty-state-msg">${esc(err.message)}</div>
          <button class="intune-btn primary" onclick="EndpointSecurityTable.loadData()">Retry</button>
        </div>
      `;
    }
  }

  function render(container) {
    const s = _securityStats || {};
    const totalDevices = s.total_devices || 0;
    const fullyProtected = s.fully_protected_devices || 0;
    const rtpDisabled = s.rtp_disabled_count || 0;
    const outdatedSigs = s.outdated_signatures_count || 0;
    const activeThreats = s.active_threats_count || 0;
    const protRate = s.protection_rate_percent !== undefined ? s.protection_rate_percent : 100.0;

    container.innerHTML = `
      <!-- Intune Title Header -->
      <div class="intune-blade-header">
        <div class="intune-title-row">
          <div class="intune-title-icon" style="background:rgba(216,59,1,0.1);color:#d83b01;">🛡️</div>
          <div>
            <h1 class="intune-blade-title">Endpoint security | Microsoft Defender for Endpoint</h1>
            <p class="intune-blade-subtitle">Antivirus posture, real-time protection, ransomware mitigation (Controlled Folders), and fleet-wide malware containment</p>
          </div>
        </div>
      </div>

      <!-- Action Command Bar -->
      <div class="intune-command-bar">
        <button class="intune-cmd-btn primary" id="btn-sec-create-policy">
          <span class="cmd-icon">➕</span> Create policy
        </button>
        <button class="intune-cmd-btn" id="btn-sec-quick-scan-all">
          <span class="cmd-icon">⚡</span> Quick scan fleet
        </button>
        <button class="intune-cmd-btn" id="btn-sec-update-sigs-all">
          <span class="cmd-icon">🔄</span> Update signatures
        </button>
        <button class="intune-cmd-btn" onclick="EndpointSecurityTable.loadData()">
          <span class="cmd-icon">🔄</span> Refresh
        </button>
      </div>

      <!-- KPI Metrics Strip -->
      <div class="kpi-strip" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;padding:16px 24px;">
        <!-- Card 1: Protection Rate -->
        <div class="kpi-card" style="border-left:4px solid ${protRate === 100 ? 'var(--accent-green)' : 'var(--accent-amber)'};">
          <div class="kpi-header">
            <span class="kpi-label">Fleet Protection Rate</span>
            <span class="kpi-badge ${protRate === 100 ? 'badge-success' : 'badge-warning'}">${protRate}%</span>
          </div>
          <div class="kpi-value" style="color:var(--text-primary);">${fullyProtected} / ${totalDevices}</div>
          <div class="kpi-subtext">Nodes with Defender Real-Time Protection active</div>
        </div>

        <!-- Card 2: RTP Disabled -->
        <div class="kpi-card" style="border-left:4px solid ${rtpDisabled > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">
          <div class="kpi-header">
            <span class="kpi-label">Real-Time Protection Off</span>
            <span class="kpi-badge ${rtpDisabled > 0 ? 'badge-error' : 'badge-success'}">${rtpDisabled > 0 ? 'CRITICAL' : 'SECURE'}</span>
          </div>
          <div class="kpi-value" style="color:${rtpDisabled > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">${rtpDisabled}</div>
          <div class="kpi-subtext">Immediate action required on unprotected nodes</div>
        </div>

        <!-- Card 3: Outdated Signatures -->
        <div class="kpi-card" style="border-left:4px solid ${outdatedSigs > 0 ? 'var(--accent-amber)' : 'var(--accent-green)'};">
          <div class="kpi-header">
            <span class="kpi-label">Outdated Signatures (>7d)</span>
            <span class="kpi-badge ${outdatedSigs > 0 ? 'badge-warning' : 'badge-success'}">${outdatedSigs > 0 ? 'STALE' : 'FRESH'}</span>
          </div>
          <div class="kpi-value" style="color:${outdatedSigs > 0 ? 'var(--accent-amber)' : 'var(--text-primary)'};">${outdatedSigs}</div>
          <div class="kpi-subtext">Devices requiring security definition sync</div>
        </div>

        <!-- Card 4: Active Threats -->
        <div class="kpi-card" style="border-left:4px solid ${activeThreats > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">
          <div class="kpi-header">
            <span class="kpi-label">Active Threat Incidents</span>
            <span class="kpi-badge ${activeThreats > 0 ? 'badge-error' : 'badge-success'}">${activeThreats > 0 ? 'MALWARE' : 'CLEAN'}</span>
          </div>
          <div class="kpi-value" style="color:${activeThreats > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">${activeThreats}</div>
          <div class="kpi-subtext">${s.total_threats_detected || 0} total lifetime threats blocked</div>
        </div>
      </div>

      <!-- Sub-Blade Navigation Tabs -->
      <div class="intune-sub-tabs" style="display:flex;gap:8px;padding:0 24px;border-bottom:1px solid var(--border-color);margin-bottom:16px;">
        <button class="intune-tab-btn ${_activeSubTab === 'antivirus' ? 'active' : ''}" id="tab-btn-sec-av">
          🛡️ Antivirus Posture &amp; Devices (${_antivirusStatuses.length})
        </button>
        <button class="intune-tab-btn ${_activeSubTab === 'policies' ? 'active' : ''}" id="tab-btn-sec-pols">
          ⚙️ Security Policies &amp; Baselines (${_policies.length})
        </button>
        <button class="intune-tab-btn ${_activeSubTab === 'threats' ? 'active' : ''}" id="tab-btn-sec-threats">
          ⚠️ Malware &amp; Threat Detections (${_threats.length})
        </button>
      </div>

      <!-- Content Area -->
      <div id="sec-subtab-content" style="padding:0 24px 24px 24px;">
        ${renderSubTabContent()}
      </div>

      <!-- Modal Container -->
      <div id="sec-modal-container"></div>
    `;

    bindEvents(container);
  }

  function renderSubTabContent() {
    switch (_activeSubTab) {
      case 'antivirus':
        return renderAntivirusTable();
      case 'policies':
        return renderPoliciesTable();
      case 'threats':
        return renderThreatsTable();
      default:
        return '';
    }
  }

  /* ── 1. Antivirus Posture Table ────────────────────────────────────── */
  function renderAntivirusTable() {
    if (_antivirusStatuses.length === 0) {
      return `
        <div class="empty-state">
          <div class="empty-state-icon">🛡️</div>
          <div class="empty-state-title">No Defender telemetry reported yet</div>
          <div class="empty-state-msg">Fleet nodes report Microsoft Defender telemetry automatically via Invoke-LocalPilotAgent.ps1.</div>
        </div>
      `;
    }

    return `
      <table class="intune-table">
        <thead>
          <tr>
            <th>Device</th>
            <th>Health Status</th>
            <th>Real-Time Protection</th>
            <th>Signature Version</th>
            <th>Signature Age</th>
            <th>Ransomware Shield (CFA)</th>
            <th>Last Quick Scan</th>
            <th>Quick Actions</th>
          </tr>
        </thead>
        <tbody>
          ${_antivirusStatuses.map(dev => {
            const isHealthy = dev.health_status === 'HEALTHY';
            const isCritical = dev.health_status === 'CRITICAL';
            const rtpOn = dev.real_time_protection_enabled === 1;
            const sigAge = dev.signature_age_days ?? 0;

            let cfaText = 'Disabled';
            if (dev.controlled_folder_access_enabled === 1) cfaText = '<span style="color:var(--accent-green);">✔ Enforced</span>';
            else if (dev.controlled_folder_access_enabled === 2) cfaText = '<span style="color:var(--accent-amber);">Audit Only</span>';

            return `
              <tr>
                <td>
                  <div style="font-weight:600;cursor:pointer;color:var(--accent-blue);" onclick="window.BirthCertificate && window.BirthCertificate.open('${esc(dev.device_id)}')">
                    ${esc(dev.hostname)}
                  </div>
                  <div style="font-size:11px;color:var(--text-muted);">${esc(dev.friendly_name || dev.primary_user || '—')}</div>
                </td>
                <td>
                  <span class="badge ${isHealthy ? 'badge-success' : isCritical ? 'badge-error' : 'badge-warning'}">
                    ${isHealthy ? '✔ Healthy' : isCritical ? '✖ Critical' : '⚠️ Needs Attention'}
                  </span>
                </td>
                <td>
                  ${rtpOn
                    ? '<span style="color:var(--accent-green);font-weight:600;">✔ Active</span>'
                    : '<span style="color:var(--accent-red);font-weight:600;">✘ Disabled</span>'
                  }
                </td>
                <td class="mono" style="font-size:12px;">${esc(dev.signature_version || '—')}</td>
                <td>
                  <span style="color:${sigAge > 7 ? 'var(--accent-amber)' : 'var(--text-primary)'};">
                    ${sigAge === 0 ? 'Today (Fresh)' : `${sigAge} day${sigAge === 1 ? '' : 's'} ago`}
                  </span>
                </td>
                <td>${cfaText}</td>
                <td style="font-size:12px;color:var(--text-muted);">
                  ${dev.last_quick_scan_at ? new Date(dev.last_quick_scan_at).toLocaleDateString() : 'Never'}
                </td>
                <td>
                  <div style="display:flex;gap:6px;">
                    <button class="intune-action-pill" onclick="EndpointSecurityTable.triggerScan('${esc(dev.device_id)}', 'QuickScan')" title="Trigger Defender Quick Scan">
                      ⚡ Scan
                    </button>
                    <button class="intune-action-pill" onclick="EndpointSecurityTable.triggerSigUpdate('${esc(dev.device_id)}')" title="Update Defender Signatures">
                      🔄 Sync
                    </button>
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  /* ── 2. Policies & Baselines Table ─────────────────────────────────── */
  function renderPoliciesTable() {
    if (_policies.length === 0) {
      return `
        <div class="empty-state">
          <div class="empty-state-icon">⚙️</div>
          <div class="empty-state-title">No Endpoint Security Policies</div>
          <div class="empty-state-msg">Create an enterprise baseline to enforce real-time protection, ransomware mitigation, and custom exclusions.</div>
          <button class="intune-btn primary" onclick="EndpointSecurityTable.openPolicyModal()">Create policy</button>
        </div>
      `;
    }

    return `
      <table class="intune-table">
        <thead>
          <tr>
            <th>Policy Name</th>
            <th>Target Group</th>
            <th>Real-Time Protection</th>
            <th>Cloud Level</th>
            <th>Controlled Folders</th>
            <th>PUA / Network</th>
            <th>Exclusions</th>
            <th>Targeted</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${_policies.map(p => {
            const excl = p.exclusions || { paths: [], extensions: [], processes: [] };
            const exclCount = (excl.paths?.length || 0) + (excl.extensions?.length || 0) + (excl.processes?.length || 0);

            return `
              <tr>
                <td>
                  <div style="font-weight:600;">${esc(p.name)}</div>
                  <div style="font-size:11px;color:var(--text-muted);">${esc(p.description || '')}</div>
                </td>
                <td>
                  <span class="badge" style="background:${p.target_group_color || '#0078d4'}22;color:${p.target_group_color || '#0078d4'};">
                    ${esc(p.target_group_name || p.target_group_id)}
                  </span>
                </td>
                <td>${p.real_time_protection ? '<span style="color:var(--accent-green);">✔ Enabled</span>' : '<span style="color:var(--accent-red);">✘ Disabled</span>'}</td>
                <td><span class="badge badge-info">${esc(p.cloud_protection_level)}</span></td>
                <td>${p.controlled_folder_access === 'ENABLED' ? '<span style="color:var(--accent-green);">✔ Enforced</span>' : esc(p.controlled_folder_access)}</td>
                <td>${esc(p.pua_protection)} / ${esc(p.network_protection)}</td>
                <td>
                  <span class="badge badge-neutral" title="${esc(JSON.stringify(excl))}">
                    ${exclCount} rule${exclCount === 1 ? '' : 's'}
                  </span>
                </td>
                <td><strong>${p.targeted_devices || 0}</strong> node${p.targeted_devices === 1 ? '' : 's'}</td>
                <td>
                  <div style="display:flex;gap:6px;">
                    <button class="intune-action-pill" onclick="EndpointSecurityTable.openPolicyModal('${esc(p.id)}')">✏️ Edit</button>
                    <button class="intune-action-pill delete" onclick="EndpointSecurityTable.deletePolicy('${esc(p.id)}', '${esc(p.name)}')">🗑️</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  /* ── 3. Threat Detections Table ────────────────────────────────────── */
  function renderThreatsTable() {
    if (_threats.length === 0) {
      return `
        <div class="empty-state">
          <div class="empty-state-icon">🛡️</div>
          <div class="empty-state-title">No Malware Threats Detected</div>
          <div class="empty-state-msg">All fleet endpoints are clean and protected by Microsoft Defender for Endpoint.</div>
        </div>
      `;
    }

    return `
      <table class="intune-table">
        <thead>
          <tr>
            <th>Threat Name</th>
            <th>Device</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Affected Resource</th>
            <th>Action Taken</th>
            <th>Status</th>
            <th>Detected At</th>
            <th>Resolution</th>
          </tr>
        </thead>
        <tbody>
          ${_threats.map(t => {
            const isActive = t.remediation_status === 'ACTIVE';
            const resPaths = (t.resources || []).join(', ');

            return `
              <tr>
                <td>
                  <div style="font-weight:600;color:var(--accent-red);">${esc(t.threat_name)}</div>
                  <div style="font-size:11px;color:var(--text-muted);">ID: ${esc(t.threat_id || 'N/A')}</div>
                </td>
                <td>
                  <div style="font-weight:500;">${esc(t.hostname)}</div>
                </td>
                <td>
                  <span class="badge ${t.severity === 'CRITICAL' || t.severity === 'HIGH' ? 'badge-error' : 'badge-warning'}">
                    ${esc(t.severity)}
                  </span>
                </td>
                <td>${esc(t.category)}</td>
                <td class="mono" style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(resPaths)}">
                  ${esc(resPaths || '—')}
                </td>
                <td><span class="badge badge-info">${esc(t.action_taken)}</span></td>
                <td>
                  <span class="badge ${isActive ? 'badge-error' : 'badge-success'}">
                    ${isActive ? 'Active Incident' : '✔ Resolved'}
                  </span>
                </td>
                <td style="font-size:12px;color:var(--text-muted);">${t.detected_at ? new Date(t.detected_at).toLocaleString() : '—'}</td>
                <td>
                  ${isActive
                    ? `<button class="intune-action-pill" style="background:var(--accent-green);color:#fff;" onclick="EndpointSecurityTable.resolveThreat('${esc(t.id)}')">✔ Resolve</button>`
                    : '<span style="color:var(--accent-green);font-size:12px;">Remediated</span>'
                  }
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function bindEvents(container) {
    // Sub-tab switching
    document.getElementById('tab-btn-sec-av')?.addEventListener('click', () => {
      _activeSubTab = 'antivirus';
      render(container);
    });
    document.getElementById('tab-btn-sec-pols')?.addEventListener('click', () => {
      _activeSubTab = 'policies';
      render(container);
    });
    document.getElementById('tab-btn-sec-threats')?.addEventListener('click', () => {
      _activeSubTab = 'threats';
      render(container);
    });

    // Create policy button
    document.getElementById('btn-sec-create-policy')?.addEventListener('click', () => {
      openPolicyModal();
    });

    // Quick scan all online nodes
    document.getElementById('btn-sec-quick-scan-all')?.addEventListener('click', async () => {
      if (!confirm(`Dispatch Microsoft Defender Quick Scan to all ${_antivirusStatuses.length} devices?`)) return;
      let count = 0;
      for (const dev of _antivirusStatuses) {
        try {
          await window.FleetAPI.triggerSecurityScan(dev.device_id, 'QuickScan');
          count++;
        } catch {}
      }
      if (typeof showToast === 'function') showToast('Fleet Scans Initiated', `Dispatched Defender Quick Scan to ${count} devices`, 'info');
    });

    // Update signatures on all devices
    document.getElementById('btn-sec-update-sigs-all')?.addEventListener('click', async () => {
      let count = 0;
      for (const dev of _antivirusStatuses) {
        try {
          await window.FleetAPI.triggerSignatureUpdate(dev.device_id);
          count++;
        } catch {}
      }
      if (typeof showToast === 'function') showToast('Signatures Syncing', `Queued signature update on ${count} devices`, 'info');
    });
  }

  /* ── Policy Creation / Edit Modal ──────────────────────────────────── */
  function openPolicyModal(policyId = null) {
    const modalContainer = document.getElementById('sec-modal-container');
    if (!modalContainer) return;

    const existing = policyId ? _policies.find(p => p.id === policyId) : null;
    const isEdit = !!existing;

    const groupOptions = _groups.map(g => `
      <option value="${esc(g.id)}" ${existing && existing.target_group_id === g.id ? 'selected' : ''}>
        ${esc(g.name)} (${g.id})
      </option>
    `).join('');

    const excl = existing?.exclusions || { paths: [], extensions: [], processes: [] };

    modalContainer.innerHTML = `
      <div class="intune-modal-backdrop" id="sec-policy-modal-backdrop">
        <div class="intune-modal" style="max-width:680px;">
          <div class="intune-modal-header">
            <h3>${isEdit ? 'Edit Endpoint Security Policy' : 'Create Endpoint Security Baseline Policy'}</h3>
            <button class="bc-close-btn" id="sec-modal-close-btn">&times;</button>
          </div>
          <div class="intune-modal-body" style="max-height:70vh;overflow-y:auto;">
            ${!isEdit ? `
              <div class="intune-form-group">
                <label class="intune-label">Enterprise Baseline Preset</label>
                <select class="intune-input" id="sec-preset-select">
                  <option value="custom">-- Custom Configuration --</option>
                  <option value="enterprise_baseline" selected>Microsoft Defender Enterprise Baseline (Recommended)</option>
                  <option value="ransomware_shield">High-Security Ransomware Shield &amp; Controlled Folders</option>
                  <option value="dev_gaming">Developer &amp; High-Performance Rig Exclusions</option>
                </select>
              </div>
            ` : ''}

            <div class="intune-form-group">
              <label class="intune-label">Policy Name *</label>
              <input class="intune-input" id="sec-policy-name" type="text" value="${esc(existing?.name || 'Microsoft Defender Enterprise Baseline')}" required>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Description</label>
              <textarea class="intune-input" id="sec-policy-desc" rows="2">${esc(existing?.description || '')}</textarea>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Target Device Group</label>
              <select class="intune-input" id="sec-policy-group">
                <option value="grp-all" ${!existing || existing.target_group_id === 'grp-all' ? 'selected' : ''}>All Devices (grp-all)</option>
                ${groupOptions}
              </select>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Cloud-Delivered Protection Level</label>
                <select class="intune-input" id="sec-policy-cloud">
                  <option value="STANDARD" ${existing?.cloud_protection_level === 'STANDARD' ? 'selected' : ''}>Standard</option>
                  <option value="HIGH" ${!existing || existing?.cloud_protection_level === 'HIGH' ? 'selected' : ''}>High (Recommended)</option>
                  <option value="HIGH_PLUS" ${existing?.cloud_protection_level === 'HIGH_PLUS' ? 'selected' : ''}>High+ (Strict ML)</option>
                  <option value="ZERO_TOLERANCE" ${existing?.cloud_protection_level === 'ZERO_TOLERANCE' ? 'selected' : ''}>Zero Tolerance</option>
                </select>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Controlled Folder Access (Ransomware Shield)</label>
                <select class="intune-input" id="sec-policy-cfa">
                  <option value="AUDIT" ${!existing || existing?.controlled_folder_access === 'AUDIT' ? 'selected' : ''}>Audit Mode (Observe)</option>
                  <option value="ENABLED" ${existing?.controlled_folder_access === 'ENABLED' ? 'selected' : ''}>Block &amp; Protect (Enforced)</option>
                  <option value="DISABLED" ${existing?.controlled_folder_access === 'DISABLED' ? 'selected' : ''}>Disabled</option>
                </select>
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Potentially Unwanted Apps (PUA)</label>
                <select class="intune-input" id="sec-policy-pua">
                  <option value="ENABLED" ${!existing || existing?.pua_protection === 'ENABLED' ? 'selected' : ''}>Block (Enabled)</option>
                  <option value="AUDIT" ${existing?.pua_protection === 'AUDIT' ? 'selected' : ''}>Audit Only</option>
                  <option value="DISABLED" ${existing?.pua_protection === 'DISABLED' ? 'selected' : ''}>Disabled</option>
                </select>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Network Protection</label>
                <select class="intune-input" id="sec-policy-net">
                  <option value="ENABLED" ${!existing || existing?.network_protection === 'ENABLED' ? 'selected' : ''}>Block (Enabled)</option>
                  <option value="AUDIT" ${existing?.network_protection === 'AUDIT' ? 'selected' : ''}>Audit Only</option>
                  <option value="DISABLED" ${existing?.network_protection === 'DISABLED' ? 'selected' : ''}>Disabled</option>
                </select>
              </div>
            </div>

            <!-- Exclusions Section -->
            <div style="border-top:1px solid var(--border-color);padding-top:12px;margin-top:12px;">
              <h4 style="margin:0 0 8px 0;font-size:13px;">Defender Exclusions</h4>
              <div class="intune-form-group">
                <label class="intune-label">Path Exclusions (comma-separated)</label>
                <input class="intune-input" id="sec-excl-paths" type="text" placeholder="C:\dev, C:\temp" value="${esc((excl.paths || []).join(', '))}">
              </div>
              <div class="intune-form-group">
                <label class="intune-label">Process Exclusions (comma-separated)</label>
                <input class="intune-input" id="sec-excl-procs" type="text" placeholder="node.exe, git.exe" value="${esc((excl.processes || []).join(', '))}">
              </div>
            </div>
          </div>
          <div class="intune-modal-footer">
            <button class="intune-btn" id="sec-modal-cancel-btn">Cancel</button>
            <button class="intune-btn primary" id="sec-modal-save-btn">${isEdit ? 'Save Changes' : 'Create Baseline'}</button>
          </div>
        </div>
      </div>
    `;

    // Presets handler
    document.getElementById('sec-preset-select')?.addEventListener('change', (e) => {
      const p = e.target.value;
      const nameEl = document.getElementById('sec-policy-name');
      const descEl = document.getElementById('sec-policy-desc');
      const cloudEl = document.getElementById('sec-policy-cloud');
      const cfaEl = document.getElementById('sec-policy-cfa');
      const pathsEl = document.getElementById('sec-excl-paths');

      if (p === 'enterprise_baseline') {
        nameEl.value = 'Microsoft Defender Enterprise Baseline';
        descEl.value = 'Standard enterprise posture with High cloud protection and PUA blocking.';
        cloudEl.value = 'HIGH';
        cfaEl.value = 'AUDIT';
        pathsEl.value = '';
      } else if (p === 'ransomware_shield') {
        nameEl.value = 'High-Security Ransomware Shield & Controlled Folders';
        descEl.value = 'Strict anti-ransomware posture enforcing Controlled Folder Access and High+ cloud ML.';
        cloudEl.value = 'HIGH_PLUS';
        cfaEl.value = 'ENABLED';
        pathsEl.value = 'C:\\SecureVault';
      } else if (p === 'dev_gaming') {
        nameEl.value = 'Developer & High-Performance Rig Exclusions';
        descEl.value = 'Optimized configuration with developer directory exclusions (.git, node_modules, temp).';
        cloudEl.value = 'STANDARD';
        cfaEl.value = 'AUDIT';
        pathsEl.value = 'C:\\temp, C:\\dev';
      }
    });

    const closeModal = () => { modalContainer.innerHTML = ''; };
    document.getElementById('sec-modal-close-btn')?.addEventListener('click', closeModal);
    document.getElementById('sec-modal-cancel-btn')?.addEventListener('click', closeModal);

    document.getElementById('sec-modal-save-btn')?.addEventListener('click', async () => {
      const name = document.getElementById('sec-policy-name')?.value.trim();
      const description = document.getElementById('sec-policy-desc')?.value.trim();
      const target_group_id = document.getElementById('sec-policy-group')?.value;
      const cloud_protection_level = document.getElementById('sec-policy-cloud')?.value;
      const controlled_folder_access = document.getElementById('sec-policy-cfa')?.value;
      const pua_protection = document.getElementById('sec-policy-pua')?.value;
      const network_protection = document.getElementById('sec-policy-net')?.value;

      const rawPaths = document.getElementById('sec-excl-paths')?.value || '';
      const rawProcs = document.getElementById('sec-excl-procs')?.value || '';

      const paths = rawPaths.split(',').map(s => s.trim()).filter(Boolean);
      const processes = rawProcs.split(',').map(s => s.trim()).filter(Boolean);

      if (!name) {
        alert('Policy Name is required');
        return;
      }

      const payload = {
        name,
        description,
        target_group_id,
        real_time_protection: 1,
        cloud_protection_level,
        controlled_folder_access,
        pua_protection,
        network_protection,
        tamper_protection: 1,
        scan_schedule_type: 'DAILY_QUICK',
        scan_schedule_time: '02:00',
        exclusions: { paths, extensions: [], processes }
      };

      try {
        if (isEdit) {
          await window.FleetAPI.updateSecurityPolicy(policyId, payload);
          if (typeof showToast === 'function') showToast('Policy Updated', `Saved changes to ${name}`, 'success');
        } else {
          await window.FleetAPI.createSecurityPolicy(payload);
          if (typeof showToast === 'function') showToast('Policy Created', `Created security baseline ${name}`, 'success');
        }
        closeModal();
        loadData();
      } catch (err) {
        alert(`Failed to save policy: ${err.message}`);
      }
    });
  }

  /* ── Remote Scan & Update Helpers ──────────────────────────────────── */
  async function triggerScan(deviceId, scanType = 'QuickScan') {
    try {
      await window.FleetAPI.triggerSecurityScan(deviceId, scanType);
      if (typeof showToast === 'function') showToast('Scan Dispatched', `Windows Defender ${scanType} queued for device`, 'info');
    } catch (err) {
      if (typeof showToast === 'function') showToast('Scan Failed', err.message, 'critical');
    }
  }

  async function triggerSigUpdate(deviceId) {
    try {
      await window.FleetAPI.triggerSignatureUpdate(deviceId);
      if (typeof showToast === 'function') showToast('Signatures Syncing', 'Windows Defender signature update queued', 'info');
    } catch (err) {
      if (typeof showToast === 'function') showToast('Update Failed', err.message, 'critical');
    }
  }

  async function resolveThreat(threatId) {
    try {
      await window.FleetAPI.remediateThreat(threatId, 'RESOLVED');
      if (typeof showToast === 'function') showToast('Threat Remediated', 'Malware incident marked as resolved and contained', 'success');
      loadData();
    } catch (err) {
      if (typeof showToast === 'function') showToast('Resolution Failed', err.message, 'critical');
    }
  }

  async function deletePolicy(policyId, name) {
    if (!confirm(`Delete security policy "${name}"? Target devices will revert to the default enterprise baseline.`)) return;
    try {
      await window.FleetAPI.deleteSecurityPolicy(policyId);
      if (typeof showToast === 'function') showToast('Policy Deleted', `Removed ${name}`, 'success');
      loadData();
    } catch (err) {
      if (typeof showToast === 'function') showToast('Delete Failed', err.message, 'critical');
    }
  }

  // Export to global window
  window.EndpointSecurityTable = {
    loadData,
    openPolicyModal,
    triggerScan,
    triggerSigUpdate,
    resolveThreat,
    deletePolicy
  };
})();
