/**
 * LocalPilot Fleet — Windows Information Protection (WIP) & Data Loss Prevention (DLP) Blade
 * dashboard/js/components/wipTable.js
 */

(function () {
  'use strict';

  let currentTab = 'policies'; // 'policies' | 'inventory' | 'audit'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmtBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function getEnforcementBadge(level) {
    const l = String(level || 'SILENT').toUpperCase();
    const map = {
      BLOCK:    { bg: 'rgba(239,68,68,0.15)', text: '#EF4444', label: '🛑 BLOCK' },
      OVERRIDE: { bg: 'rgba(245,158,11,0.15)', text: '#F59E0B', label: '⚠️ OVERRIDE' },
      SILENT:   { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '🔍 SILENT' },
      OFF:      { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: '⭕ OFF' }
    };
    const c = map[l] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: l };
    return '<span class="badge" style="background:' + c.bg + ';color:' + c.text + ';font-weight:700;">' + c.label + '</span>';
  }

  function getComplianceBadge(status) {
    const s = String(status || 'COMPLIANT').toUpperCase();
    if (s === 'COMPLIANT') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ COMPLIANT</span>';
    } else if (s === 'NON_COMPLIANT') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🚨 NON-COMPLIANT</span>';
    } else if (s === 'POLICY_DRIFT') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⚠️ POLICY DRIFT</span>';
    }
    return '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">⏳ UNKNOWN</span>';
  }

  function getEventBadge(eventType) {
    const type = String(eventType || 'ENTERPRISE_FILE_ACCESSED').toUpperCase();
    if (type.includes('BLOCKED') || type.includes('EXFILTRATION')) {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛑 ' + esc(type) + '</span>';
    } else if (type.includes('OVERRIDE')) {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⚠️ ' + esc(type) + '</span>';
    }
    return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;font-weight:600;">📄 ' + esc(type) + '</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-wip');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Windows Information Protection &amp; Data Loss Prevention Posture…</span>' +
      '</div>';

    try {
      const [stats, policiesData, inventoryData, auditData, groupsData] = await Promise.all([
        window.FleetAPI.getWipStats().catch(() => ({})),
        window.FleetAPI.getWipPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getWipInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getWipAuditLog().catch(() => ({ logs: [] })),
        window.FleetAPI.getDynamicGroups().catch(() => [])
      ]);

      const policies = policiesData.policies || [];
      const inventory = inventoryData.inventory || [];
      const logs = auditData.logs || [];
      const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      renderView(container, stats, policies, inventory, logs, groups);
    } catch (err) {
      container.innerHTML = 
        '<div style="padding:24px;color:#EF4444;">' +
          '<h3>⚠️ Error loading WIP &amp; DLP Blade</h3>' +
          '<p>' + esc(err.message) + '</p>' +
          '<button class="intune-btn intune-btn-secondary" onclick="window.WipTable.init()">Retry</button>' +
        '</div>';
    }
  }

  function renderView(container, stats, policies, inventory, logs, groups) {
    const totalAudited = stats.total_audited_devices || 0;
    const totalFleet = stats.total_devices_in_fleet || 0;
    const blockEnforced = stats.block_enforced_devices || 0;
    const protectedFiles = stats.total_protected_files || 0;
    const encryptedBytes = stats.total_encrypted_bytes || 0;
    const clipboardViolations = stats.total_clipboard_violations_24h || 0;
    const cloudAttempts = stats.total_cloud_attempts_24h || 0;
    const compliancePct = Number(stats.compliance_pct) || 100.0;

    container.innerHTML = 
      '<div style="padding:24px;display:flex;flex-direction:column;gap:20px;">' +
        '<!-- Header -->' +
        '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">' +
          '<div>' +
            '<h2 style="margin:0;font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px;">' +
              '<span>🔒 Windows Information Protection (WIP) &amp; Data Loss Prevention</span>' +
            '</h2>' +
            '<p style="margin:4px 0 0 0;color:var(--text-muted);font-size:13px;">' +
              'Corporate data boundaries, enterprise network perimeter, application protection policies, and clipboard/cloud exfiltration prevention.' +
            '</p>' +
          '</div>' +
          '<div style="display:flex;gap:10px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="window.WipTable.init()">' +
              '🔄 Refresh' +
            '</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="window.WipTable.openCreateModal()">' +
              '+ Create WIP Policy' +
            '</button>' +
          '</div>' +
        '</div>' +

        '<!-- KPI Cards Row -->' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;">' +
          '<!-- KPI 1: Audited Workstations -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Audited Workstations</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;display:flex;align-items:baseline;gap:6px;">' +
              '<span>' + totalAudited + '</span>' +
              '<span style="font-size:14px;color:var(--text-muted);font-weight:400;">/ ' + totalFleet + ' fleet</span>' +
            '</div>' +
            '<div style="font-size:12px;color:#10B981;margin-top:4px;">' +
              '<span>🛡️ ' + compliancePct.toFixed(1) + '% Compliant</span>' +
            '</div>' +
          '</div>' +

          '<!-- KPI 2: Strict Block Enforced -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Strict BLOCK Enforcement</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:#EF4444;">' +
              blockEnforced + '<span style="font-size:14px;color:var(--text-muted);font-weight:400;"> nodes</span>' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              (stats.override_enforced_devices || 0) + ' with Audited Override' +
            '</div>' +
          '</div>' +

          '<!-- KPI 3: Protected Files & Size -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Enterprise Protected Files</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:#60A5FA;">' +
              protectedFiles +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              fmtBytes(encryptedBytes) + ' EFS/WIP Encrypted' +
            '</div>' +
          '</div>' +

          '<!-- KPI 4: Exfiltration Interceptions (24h) -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Exfiltration Interceptions (24h)</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:' + (cloudAttempts > 0 ? '#EF4444' : '#10B981') + ';">' +
              cloudAttempts + ' cloud / ' + clipboardViolations + ' clip' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              (stats.total_audit_events || 0) + ' total audit ledger events' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<!-- Tabs Navigation -->' +
        '<div style="display:flex;border-bottom:1px solid var(--border-color);gap:8px;">' +
          '<button class="intune-tab-btn ' + (currentTab === 'policies' ? 'active' : '') + '" onclick="window.WipTable.switchTab(\'policies\')">' +
            '🛡️ Data Protection Policies (' + policies.length + ')' +
          '</button>' +
          '<button class="intune-tab-btn ' + (currentTab === 'inventory' ? 'active' : '') + '" onclick="window.WipTable.switchTab(\'inventory\')">' +
            '💻 Workstation DLP Posture (' + inventory.length + ')' +
          '</button>' +
          '<button class="intune-tab-btn ' + (currentTab === 'audit' ? 'active' : '') + '" onclick="window.WipTable.switchTab(\'audit\')">' +
            '📜 DLP Exfiltration Ledger (' + logs.length + ')' +
          '</button>' +
        '</div>' +

        '<!-- Tab Content -->' +
        '<div id="wip-tab-content">' +
          (currentTab === 'policies' ? renderPoliciesTab(policies, groups) :
           currentTab === 'inventory' ? renderInventoryTab(inventory) :
           renderAuditTab(logs)) +
        '</div>' +
      '</div>';
  }

  function renderPoliciesTab(policies, groups) {
    if (policies.length === 0) {
      return '<div class="intune-card" style="padding:32px;text-align:center;color:var(--text-muted);">' +
        'No WIP policies configured. Click "+ Create WIP Policy" to define corporate data boundaries.' +
      '</div>';
    }

    let rows = policies.map(p => {
      const groupName = p.target_group_name ? esc(p.target_group_name) : '<span style="color:var(--text-muted);">All Devices</span>';
      const appCount = Array.isArray(p.protected_apps) ? p.protected_apps.length : 0;
      const netCount = Array.isArray(p.network_boundaries) ? p.network_boundaries.length : 0;

      return '<tr>' +
        '<td>' +
          '<div style="font-weight:600;color:var(--text-primary);">' + esc(p.name) + '</div>' +
          '<div style="font-size:12px;color:var(--text-muted);">' + esc(p.description || '') + '</div>' +
        '</td>' +
        '<td>' + getEnforcementBadge(p.enforcement_level) + '</td>' +
        '<td><code>' + esc(p.enterprise_domain) + '</code></td>' +
        '<td>' + groupName + '</td>' +
        '<td>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;">' +
            '<span class="badge" style="background:#1e293b;color:#94a3b8;font-size:11px;">📦 ' + appCount + ' Apps</span>' +
            '<span class="badge" style="background:#1e293b;color:#94a3b8;font-size:11px;">🌐 ' + netCount + ' Nets</span>' +
          '</div>' +
        '</td>' +
        '<td>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;">' +
            (p.show_wip_overlays ? '<span title="Briefcase icon overlay on enterprise files">💼 Overlay</span>' : '') +
            (p.revoke_on_unenroll ? '<span title="Remote wipe enterprise keys on unenroll">🧹 Wipe</span>' : '') +
          '</div>' +
        '</td>' +
        '<td>' +
          (p.enabled ? '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">ACTIVE</span>' :
                       '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">DISABLED</span>') +
        '</td>' +
        '<td>' +
          '<div style="display:flex;gap:6px;">' +
            '<button class="intune-btn intune-btn-secondary" style="padding:4px 8px;font-size:12px;" onclick="window.WipTable.viewScript(\'' + p.id + '\')">📜 Script</button>' +
            '<button class="intune-btn intune-btn-danger" style="padding:4px 8px;font-size:12px;" onclick="window.WipTable.deletePolicy(\'' + p.id + '\')">🗑️</button>' +
          '</div>' +
        '</td>' +
      '</tr>';
    }).join('');

    return '<div class="intune-card" style="overflow-x:auto;">' +
      '<table class="intune-table">' +
        '<thead>' +
          '<tr>' +
            '<th>Policy Name</th>' +
            '<th>Enforcement Mode</th>' +
            '<th>Enterprise Domain</th>' +
            '<th>Target Group</th>' +
            '<th>Boundaries</th>' +
            '<th>Protection</th>' +
            '<th>Status</th>' +
            '<th>Actions</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table>' +
    '</div>';
  }

  function renderInventoryTab(inventory) {
    if (inventory.length === 0) {
      return '<div class="intune-card" style="padding:32px;text-align:center;color:var(--text-muted);">' +
        'No workstation DLP telemetry received yet. Workstations will report file protection status upon heartbeat.' +
      '</div>';
    }

    let rows = inventory.map(d => {
      const name = d.friendly_name || d.hostname || d.device_id;
      return '<tr>' +
        '<td>' +
          '<div style="font-weight:600;color:var(--text-primary);">' + esc(name) + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);font-family:monospace;">' + esc(d.device_id) + '</div>' +
        '</td>' +
        '<td>' + getEnforcementBadge(d.enforcement_active) + '</td>' +
        '<td>' +
          '<div style="font-weight:600;color:#60A5FA;">' + (d.protected_files_count || 0) + ' files</div>' +
          '<div style="font-size:11px;color:var(--text-muted);">' + fmtBytes(d.encrypted_bytes) + ' encrypted</div>' +
        '</td>' +
        '<td>' + (d.managed_apps_count || 0) + ' apps active</td>' +
        '<td>' +
          (d.clipboard_violations_24h > 0 ? ('<span style="color:#F59E0B;font-weight:700;">' + d.clipboard_violations_24h + '</span>') : '<span style="color:var(--text-muted);">0</span>') +
        '</td>' +
        '<td>' +
          (d.cloud_exfiltration_attempts_24h > 0 ? ('<span style="color:#EF4444;font-weight:700;">' + d.cloud_exfiltration_attempts_24h + '</span>') : '<span style="color:var(--text-muted);">0</span>') +
        '</td>' +
        '<td>' + getComplianceBadge(d.compliance_status) + '</td>' +
        '<td style="font-size:11px;color:var(--text-muted);">' +
          esc(d.last_audit_at ? new Date(d.last_audit_at).toLocaleString() : 'Just now') +
        '</td>' +
      '</tr>';
    }).join('');

    return '<div class="intune-card" style="overflow-x:auto;">' +
      '<table class="intune-table">' +
        '<thead>' +
          '<tr>' +
            '<th>Device</th>' +
            '<th>Enforcement</th>' +
            '<th>Protected Data</th>' +
            '<th>Managed Apps</th>' +
            '<th>Clip Violations</th>' +
            '<th>Cloud Attempts</th>' +
            '<th>Compliance</th>' +
            '<th>Last Audited</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table>' +
    '</div>';
  }

  function renderAuditTab(logs) {
    if (logs.length === 0) {
      return '<div class="intune-card" style="padding:32px;text-align:center;color:var(--text-muted);">' +
        'No data loss prevention events recorded. Boundary transfers and exfiltration attempts will appear here.' +
      '</div>';
    }

    let rows = logs.map(l => {
      const dev = l.hostname || l.friendly_name || l.device_id;
      return '<tr>' +
        '<td>' +
          '<div style="font-weight:600;">' + esc(dev) + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);font-family:monospace;">' + esc(l.device_id) + '</div>' +
        '</td>' +
        '<td>' + getEventBadge(l.event_type) + '</td>' +
        '<td><code>' + esc(l.app_name) + '</code></td>' +
        '<td>' + esc(l.file_name || 'N/A') + '</td>' +
        '<td style="font-size:11px;color:var(--text-muted);">' + esc(l.target_location || 'Local clipboard') + '</td>' +
        '<td style="font-size:12px;max-width:260px;white-space:normal;">' + esc(l.user_justification || l.details || '') + '</td>' +
        '<td style="font-size:11px;color:var(--text-muted);">' +
          esc(l.timestamp ? new Date(l.timestamp).toLocaleString() : '') +
        '</td>' +
      '</tr>';
    }).join('');

    return '<div class="intune-card" style="overflow-x:auto;">' +
      '<table class="intune-table">' +
        '<thead>' +
          '<tr>' +
            '<th>Device</th>' +
            '<th>Event Type</th>' +
            '<th>App</th>' +
            '<th>File Name</th>' +
            '<th>Target Destination</th>' +
            '<th>Justification / Reason</th>' +
            '<th>Timestamp</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table>' +
    '</div>';
  }

  // Modals
  async function openCreateModal() {
    let groups = [];
    try {
      const g = await window.FleetAPI.getDynamicGroups();
      groups = Array.isArray(g) ? g : (g.groups || []);
    } catch {}

    const groupOptions = '<option value="">All Devices (Fleet Default)</option>' +
      groups.map(grp => '<option value="' + grp.id + '">' + esc(grp.name) + '</option>').join('');

    const modalHtml = 
      '<div class="intune-modal-backdrop" id="wip-modal">' +
        '<div class="intune-modal" style="max-width:640px;max-height:90vh;overflow-y:auto;">' +
          '<div class="intune-modal-header">' +
            '<h3>Create Windows Information Protection Policy</h3>' +
            '<button class="intune-close-btn" onclick="document.getElementById(\'wip-modal\').remove()">✕</button>' +
          '</div>' +
          '<div class="intune-modal-body" style="display:flex;flex-direction:column;gap:16px;">' +
            '<!-- Presets -->' +
            '<div style="background:var(--card-bg, #1e293b);padding:12px;border-radius:6px;border:1px solid var(--border-color);">' +
              '<div style="font-size:12px;font-weight:600;margin-bottom:8px;color:var(--text-muted);">⚡ QUICK PRESETS</div>' +
              '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.WipTable.applyPreset(\'block\')">🛑 Strict Enterprise Isolation</button>' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.WipTable.applyPreset(\'override\')">⚠️ Managed Business Override</button>' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.WipTable.applyPreset(\'silent\')">🔍 BYOD Silent Discovery</button>' +
              '</div>' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>' +
              '<input type="text" id="wip-name" class="intune-input" placeholder="e.g., Enterprise Corporate Strict Data Isolation" style="width:100%;" required>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>' +
              '<input type="text" id="wip-desc" class="intune-input" placeholder="Optional notes regarding data boundary controls" style="width:100%;">' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Enforcement Level</label>' +
                '<select id="wip-enforcement" class="intune-input" style="width:100%;">' +
                  '<option value="BLOCK">🛑 BLOCK (Prevent unauthorized copy)</option>' +
                  '<option value="OVERRIDE">⚠️ OVERRIDE (Prompt user with audit justification)</option>' +
                  '<option value="SILENT">🔍 SILENT (Log silently in background)</option>' +
                  '<option value="OFF">⭕ OFF (Protection disabled)</option>' +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Enterprise Identity Domain</label>' +
                '<input type="text" id="wip-domain" class="intune-input" value="localpilot.internal" style="width:100%;">' +
              '</div>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>' +
              '<select id="wip-target-group" class="intune-input" style="width:100%;">' + groupOptions + '</select>' +
            '</div>' +

            '<div style="background:rgba(0,0,0,0.15);padding:12px;border-radius:6px;">' +
              '<div style="font-weight:600;font-size:12px;margin-bottom:8px;">🛡️ Protection Options</div>' +
              '<div style="display:grid;grid-template-columns:1fr;gap:8px;">' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="wip-overlays" checked> Show briefcase icon overlay on corporate files</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="wip-revoke" checked> Revoke encryption keys on device unenrollment (Remote Wipe)</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="wip-allow-decrypt"> Allow user to decrypt files to personal ownership</label>' +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="intune-modal-footer" style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="document.getElementById(\'wip-modal\').remove()">Cancel</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="window.WipTable.submitCreatePolicy()">Create Policy</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  function applyPreset(type) {
    const nameEl = document.getElementById('wip-name');
    const descEl = document.getElementById('wip-desc');
    const enforceEl = document.getElementById('wip-enforcement');
    const overlaysEl = document.getElementById('wip-overlays');
    const revokeEl = document.getElementById('wip-revoke');
    const decryptEl = document.getElementById('wip-allow-decrypt');

    if (type === 'block') {
      if (nameEl) nameEl.value = 'Enterprise Corporate Strict Data Isolation';
      if (descEl) descEl.value = 'Strict data separation preventing copy-paste to unmanaged apps or consumer cloud storage.';
      if (enforceEl) enforceEl.value = 'BLOCK';
      if (overlaysEl) overlaysEl.checked = true;
      if (revokeEl) revokeEl.checked = true;
      if (decryptEl) decryptEl.checked = false;
    } else if (type === 'override') {
      if (nameEl) nameEl.value = 'Business Workstation Managed Audited Override';
      if (descEl) descEl.value = 'Prompts user with warning and mandatory justification when transferring corporate content.';
      if (enforceEl) enforceEl.value = 'OVERRIDE';
      if (overlaysEl) overlaysEl.checked = true;
      if (revokeEl) revokeEl.checked = true;
      if (decryptEl) decryptEl.checked = true;
    } else if (type === 'silent') {
      if (nameEl) nameEl.value = 'BYOD Silent Discovery & Boundary Audit';
      if (descEl) descEl.value = 'Silently audits and monitors data boundary transitions without blocking user workflows.';
      if (enforceEl) enforceEl.value = 'SILENT';
      if (overlaysEl) overlaysEl.checked = false;
      if (revokeEl) revokeEl.checked = false;
      if (decryptEl) decryptEl.checked = true;
    }
  }

  async function submitCreatePolicy() {
    const name = document.getElementById('wip-name')?.value?.trim();
    if (!name) {
      alert('Policy name is required.');
      return;
    }

    const defaultApps = [
      { name: 'Microsoft Edge', binary: 'msedge.exe', allowed: true },
      { name: 'Microsoft Outlook', binary: 'outlook.exe', allowed: true },
      { name: 'Microsoft Teams', binary: 'ms-teams.exe', allowed: true },
      { name: 'Visual Studio Code', binary: 'code.exe', allowed: true }
    ];

    const defaultBoundaries = [
      { name: 'Corporate Intranet', domain: document.getElementById('wip-domain')?.value?.trim() || 'localpilot.internal', type: 'CLOUD_RESOURCE' }
    ];

    const payload = {
      name: name,
      description: document.getElementById('wip-desc')?.value?.trim() || '',
      enforcement_level: document.getElementById('wip-enforcement')?.value || 'SILENT',
      enterprise_domain: document.getElementById('wip-domain')?.value?.trim() || 'localpilot.internal',
      target_group_id: document.getElementById('wip-target-group')?.value || null,
      protected_apps: defaultApps,
      network_boundaries: defaultBoundaries,
      show_wip_overlays: document.getElementById('wip-overlays')?.checked ? 1 : 0,
      revoke_on_unenroll: document.getElementById('wip-revoke')?.checked ? 1 : 0,
      allow_user_decryption: document.getElementById('wip-allow-decrypt')?.checked ? 1 : 0,
      enabled: 1
    };

    try {
      await window.FleetAPI.createWipPolicy(payload);
      document.getElementById('wip-modal')?.remove();
      loadData();
    } catch (err) {
      alert('Failed to create WIP policy: ' + err.message);
    }
  }

  async function viewScript(id) {
    try {
      const data = await window.FleetAPI.getWipPolicy(id);
      const script = data.powershell_script || '# No script generated';

      const modalHtml = 
        '<div class="intune-modal-backdrop" id="wip-script-modal">' +
          '<div class="intune-modal" style="max-width:720px;max-height:90vh;overflow-y:auto;">' +
            '<div class="intune-modal-header">' +
              '<h3>📜 Generated PowerShell WIP &amp; DLP Enforcement Script</h3>' +
              '<button class="intune-close-btn" onclick="document.getElementById(\'wip-script-modal\').remove()">✕</button>' +
            '</div>' +
            '<div class="intune-modal-body">' +
              '<p style="font-size:12px;color:var(--text-muted);">' +
                'This script configures Windows Information Protection boundaries for policy: <strong>' + esc(data.name) + '</strong>.' +
              '</p>' +
              '<pre style="background:#0f172a;padding:12px;border-radius:6px;font-size:12px;font-family:monospace;max-height:360px;overflow-y:auto;color:#38bdf8;">' +
                esc(script) +
              '</pre>' +
            '</div>' +
            '<div class="intune-modal-footer" style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">' +
              '<button class="intune-btn intune-btn-secondary" onclick="navigator.clipboard.writeText(document.querySelector(\'#wip-script-modal pre\').innerText);alert(\'Script copied to clipboard!\');">📋 Copy Script</button>' +
              '<button class="intune-btn intune-btn-primary" onclick="document.getElementById(\'wip-script-modal\').remove()">Close</button>' +
            '</div>' +
          '</div>' +
        '</div>';

      document.body.insertAdjacentHTML('beforeend', modalHtml);
    } catch (err) {
      alert('Failed to fetch script: ' + err.message);
    }
  }

  async function deletePolicy(id) {
    if (!confirm('Are you sure you want to delete this WIP policy?')) return;
    try {
      await window.FleetAPI.deleteWipPolicy(id);
      loadData();
    } catch (err) {
      alert('Failed to delete policy: ' + err.message);
    }
  }

  function switchTab(tab) {
    currentTab = tab;
    loadData();
  }

  // Export module interface
  window.WipTable = {
    init: loadData,
    switchTab,
    openCreateModal,
    applyPreset,
    submitCreatePolicy,
    viewScript,
    deletePolicy
  };
})();
