/**
 * LocalPilot Fleet — Device Firmware Configuration Interface (DFCI) & UEFI Security Blade
 * dashboard/js/components/dfciTable.js
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

  function getComplianceBadge(status) {
    const s = String(status || 'UNKNOWN').toUpperCase();
    if (s === 'COMPLIANT') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ COMPLIANT</span>';
    } else if (s === 'NON_COMPLIANT') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">❌ NON-COMPLIANT</span>';
    }
    return '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">⏳ UNKNOWN</span>';
  }

  function getScoreBadge(score) {
    const sc = Number(score) || 0;
    let bg = 'rgba(239,68,68,0.15)';
    let text = '#EF4444';
    if (sc >= 85) {
      bg = 'rgba(16,185,129,0.15)';
      text = '#10B981';
    } else if (sc >= 60) {
      bg = 'rgba(245,158,11,0.15)';
      text = '#F59E0B';
    }
    return '<span class="badge" style="background:' + bg + ';color:' + text + ';font-weight:700;font-size:12px;">' + sc + '/100</span>';
  }

  function getBoolBadge(val, trueLabel = 'Allowed', falseLabel = 'Blocked', inverted = false) {
    const isGood = inverted ? !val : !!val;
    const bg = isGood ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)';
    const text = isGood ? '#10B981' : '#EF4444';
    const label = val ? trueLabel : falseLabel;
    return '<span class="badge" style="background:' + bg + ';color:' + text + ';font-weight:600;font-size:11px;">' + label + '</span>';
  }

  function getEventBadge(eventType) {
    const type = String(eventType || 'FIRMWARE_AUDIT').toUpperCase();
    if (type.includes('VIOLATION') || type.includes('TAMPER') || type.includes('ALERT')) {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🚨 ' + esc(type) + '</span>';
    }
    return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;font-weight:600;">🛡️ ' + esc(type) + '</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-dfci');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Device Firmware &amp; UEFI Security Posture…</span>' +
      '</div>';

    try {
      const [stats, policiesData, inventoryData, auditData, groupsData] = await Promise.all([
        window.FleetAPI.getDfciStats().catch(() => ({})),
        window.FleetAPI.getDfciPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getDfciInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getDfciAuditLog().catch(() => ({ logs: [] })),
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
          '<h3>⚠️ Error loading DFCI Blade</h3>' +
          '<p>' + esc(err.message) + '</p>' +
          '<button class="intune-btn intune-btn-secondary" onclick="window.DfciTable.init()">Retry</button>' +
        '</div>';
    }
  }

  function renderView(container, stats, policies, inventory, logs, groups) {
    const totalAudited = stats.total_audited_devices || 0;
    const totalFleet = stats.total_devices_in_fleet || 0;
    const avgScore = Number(stats.avg_hardware_score) || 0.0;
    const secureBootPct = Number(stats.secure_boot_pct) || 0.0;
    const tpmReadyPct = Number(stats.tpm_ready_pct) || 0.0;

    container.innerHTML = 
      '<div style="padding:24px;display:flex;flex-direction:column;gap:20px;">' +
        '<!-- Header -->' +
        '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">' +
          '<div>' +
            '<h2 style="margin:0;font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px;">' +
              '<span>🛡️ Device Firmware Configuration Interface (DFCI) &amp; UEFI Security</span>' +
            '</h2>' +
            '<p style="margin:4px 0 0 0;color:var(--text-muted);font-size:13px;">' +
              'Hardware root-of-trust, zero-touch UEFI configuration, peripheral lockdowns, Secure Boot, and TPM 2.0 state enforcement.' +
            '</p>' +
          '</div>' +
          '<div style="display:flex;gap:10px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="window.DfciTable.init()">' +
              '🔄 Refresh' +
            '</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="window.DfciTable.openCreateModal()">' +
              '+ Create DFCI Policy' +
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
              '<span>🛡️ Hardware Root-of-Trust</span>' +
            '</div>' +
          '</div>' +

          '<!-- KPI 2: Avg Hardware Readiness -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Zero-Trust Hardware Score</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:' + (avgScore >= 80 ? '#10B981' : '#F59E0B') + ';">' +
              avgScore.toFixed(1) + '<span style="font-size:14px;color:var(--text-muted);font-weight:400;"> / 100</span>' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              'Fleet UEFI &amp; Virtualization Baseline' +
            '</div>' +
          '</div>' +

          '<!-- KPI 3: Secure Boot % -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Secure Boot Enabled</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:' + (secureBootPct === 100 ? '#10B981' : (secureBootPct >= 80 ? '#60A5FA' : '#EF4444')) + ';">' +
              secureBootPct.toFixed(1) + '%' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              (stats.secure_boot_enabled_count || 0) + ' / ' + totalAudited + ' active nodes' +
            '</div>' +
          '</div>' +

          '<!-- KPI 4: TPM 2.0 % -->' +
          '<div class="intune-card" style="padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">TPM 2.0 Root-of-Trust</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:' + (tpmReadyPct === 100 ? '#10B981' : (tpmReadyPct >= 80 ? '#60A5FA' : '#EF4444')) + ';">' +
              tpmReadyPct.toFixed(1) + '%' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">' +
              (stats.tpm_ready_count || 0) + ' cryptographically ready' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<!-- Tabs Navigation -->' +
        '<div style="display:flex;border-bottom:1px solid var(--border-color);gap:8px;">' +
          '<button class="intune-tab-btn ' + (currentTab === 'policies' ? 'active' : '') + '" onclick="window.DfciTable.switchTab(\'policies\')">' +
            '🛡️ Hardware Policies (' + policies.length + ')' +
          '</button>' +
          '<button class="intune-tab-btn ' + (currentTab === 'inventory' ? 'active' : '') + '" onclick="window.DfciTable.switchTab(\'inventory\')">' +
            '💻 Workstation Posture &amp; Readiness (' + inventory.length + ')' +
          '</button>' +
          '<button class="intune-tab-btn ' + (currentTab === 'audit' ? 'active' : '') + '" onclick="window.DfciTable.switchTab(\'audit\')">' +
            '📜 Firmware Audit Ledger (' + logs.length + ')' +
          '</button>' +
        '</div>' +

        '<!-- Tab Content -->' +
        '<div id="dfci-tab-content">' +
          (currentTab === 'policies' ? renderPoliciesTab(policies, groups) :
           currentTab === 'inventory' ? renderInventoryTab(inventory) :
           renderAuditTab(logs)) +
        '</div>' +
      '</div>';
  }

  function renderPoliciesTab(policies, groups) {
    if (policies.length === 0) {
      return '<div class="intune-card" style="padding:32px;text-align:center;color:var(--text-muted);">' +
        'No DFCI policies defined. Click "+ Create DFCI Policy" to configure your first firmware baseline.' +
      '</div>';
    }

    let rows = policies.map(p => {
      const groupName = p.target_group_name ? esc(p.target_group_name) : '<span style="color:var(--text-muted);">All Devices</span>';
      return '<tr>' +
        '<td>' +
          '<div style="font-weight:600;color:var(--text-primary);">' + esc(p.name) + '</div>' +
          '<div style="font-size:12px;color:var(--text-muted);">' + esc(p.description || '') + '</div>' +
        '</td>' +
        '<td>' + groupName + '</td>' +
        '<td>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;">' +
            getBoolBadge(p.cameras_enabled, '📷 Cam', '🚫 Cam') +
            getBoolBadge(p.microphones_enabled, '🎤 Mic', '🚫 Mic') +
            getBoolBadge(p.radios_enabled, '📶 Radio', '🚫 Radio') +
          '</div>' +
        '</td>' +
        '<td>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;">' +
            getBoolBadge(p.external_media_boot_enabled, 'USB Boot', '🚫 USB Boot', true) +
            getBoolBadge(p.network_adapter_boot_enabled, 'PXE Boot', '🚫 PXE Boot', true) +
          '</div>' +
        '</td>' +
        '<td>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;">' +
            getBoolBadge(p.require_secure_boot, 'Secure Boot', 'No SB') +
            getBoolBadge(p.require_tpm2, 'TPM 2.0', 'No TPM') +
            getBoolBadge(p.require_kernel_dma, 'DMA', 'No DMA') +
          '</div>' +
        '</td>' +
        '<td>' +
          (p.enabled ? '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">ACTIVE</span>' :
                       '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">DISABLED</span>') +
        '</td>' +
        '<td>' +
          '<div style="display:flex;gap:6px;">' +
            '<button class="intune-btn intune-btn-secondary" style="padding:4px 8px;font-size:12px;" onclick="window.DfciTable.viewScript(\'' + p.id + '\')">📜 Script</button>' +
            '<button class="intune-btn intune-btn-secondary" style="padding:4px 8px;font-size:12px;" onclick="window.DfciTable.openEditModal(\'' + p.id + '\')">✏️ Edit</button>' +
            '<button class="intune-btn intune-btn-danger" style="padding:4px 8px;font-size:12px;" onclick="window.DfciTable.deletePolicy(\'' + p.id + '\')">🗑️</button>' +
          '</div>' +
        '</td>' +
      '</tr>';
    }).join('');

    return '<div class="intune-card" style="overflow-x:auto;">' +
      '<table class="intune-table">' +
        '<thead>' +
          '<tr>' +
            '<th>Policy Name</th>' +
            '<th>Target Scope</th>' +
            '<th>Peripherals</th>' +
            '<th>Boot Isolation</th>' +
            '<th>Hardware Root-of-Trust</th>' +
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
        'No workstation firmware posture reports received yet. Ensure host agent runs with DFCI audit enabled.' +
      '</div>';
    }

    let rows = inventory.map(d => {
      const name = d.friendly_name || d.hostname || d.device_id;
      return '<tr>' +
        '<td>' +
          '<div style="font-weight:600;color:var(--text-primary);">' + esc(name) + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);font-family:monospace;">' + esc(d.device_id) + '</div>' +
        '</td>' +
        '<td>' + getScoreBadge(d.hardware_readiness_score) + '</td>' +
        '<td>' +
          '<div style="font-weight:500;">' + esc(d.bios_vendor || 'OEM') + ' ' + esc(d.bios_version || '') + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);">UEFI: ' + esc(d.uefi_version || '2.7+') + '</div>' +
        '</td>' +
        '<td>' +
          (d.secure_boot_enabled ? '<span style="color:#10B981;font-weight:600;">🔒 Enabled</span>' : '<span style="color:#EF4444;font-weight:600;">⚠️ Disabled</span>') +
        '</td>' +
        '<td>' +
          (d.tpm_present ? ('<span style="color:#10B981;font-weight:600;">v' + esc(d.tpm_version || '2.0') + '</span> ' + (d.tpm_ready ? '✅ Ready' : '⚠️ Not Ready')) : '<span style="color:#EF4444;font-weight:600;">❌ Absent</span>') +
        '</td>' +
        '<td>' +
          '<div style="font-size:11px;">' +
            'DMA: ' + (d.kernel_dma_protection ? '✅' : '❌') + ' | ' +
            'VBS: ' + esc(d.vbs_status || 'UNKNOWN') + ' | ' +
            'HVCI: ' + esc(d.hvci_status || 'UNKNOWN') +
          '</div>' +
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
            '<th>Readiness Score</th>' +
            '<th>Firmware / BIOS</th>' +
            '<th>Secure Boot</th>' +
            '<th>TPM 2.0</th>' +
            '<th>Hardware Isolation</th>' +
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
        'No firmware audit events recorded yet. Hardware configuration changes will be logged here.' +
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
        '<td><code>' + esc(l.setting_name) + '</code></td>' +
        '<td>' +
          '<span style="color:#EF4444;text-decoration:line-through;font-size:11px;">' + esc(l.old_value || 'None') + '</span> ' +
          '→ ' +
          '<span style="color:#10B981;font-weight:600;font-size:11px;">' + esc(l.new_value || 'None') + '</span>' +
        '</td>' +
        '<td style="font-size:12px;max-width:280px;white-space:normal;">' + esc(l.details || '') + '</td>' +
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
            '<th>Setting</th>' +
            '<th>Transition</th>' +
            '<th>Details</th>' +
            '<th>Timestamp</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table>' +
    '</div>';
  }

  // Modal handlers
  async function openCreateModal() {
    let groups = [];
    try {
      const g = await window.FleetAPI.getDynamicGroups();
      groups = Array.isArray(g) ? g : (g.groups || []);
    } catch {}

    const groupOptions = '<option value="">All Devices (Fleet Default)</option>' +
      groups.map(grp => '<option value="' + grp.id + '">' + esc(grp.name) + '</option>').join('');

    const modalHtml = 
      '<div class="intune-modal-backdrop" id="dfci-modal">' +
        '<div class="intune-modal" style="max-width:640px;max-height:90vh;overflow-y:auto;">' +
          '<div class="intune-modal-header">' +
            '<h3>Create DFCI &amp; UEFI Security Policy</h3>' +
            '<button class="intune-close-btn" onclick="document.getElementById(\'dfci-modal\').remove()">✕</button>' +
          '</div>' +
          '<div class="intune-modal-body" style="display:flex;flex-direction:column;gap:16px;">' +
            '<!-- Presets -->' +
            '<div style="background:var(--card-bg, #1e293b);padding:12px;border-radius:6px;border:1px solid var(--border-color);">' +
              '<div style="font-size:12px;font-weight:600;margin-bottom:8px;color:var(--text-muted);">⚡ QUICK PRESETS</div>' +
              '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DfciTable.applyPreset(\'zerotrust\')">🛡️ Zero-Trust Baseline</button>' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DfciTable.applyPreset(\'kiosk\')">🔒 Kiosk Hardware Isolation</button>' +
                '<button type="button" class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DfciTable.applyPreset(\'dev\')">💻 Developer Flexible</button>' +
              '</div>' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>' +
              '<input type="text" id="dfci-name" class="intune-input" placeholder="e.g., Enterprise Zero-Trust Hardware Baseline" style="width:100%;" required>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>' +
              '<input type="text" id="dfci-desc" class="intune-input" placeholder="Optional notes regarding firmware controls" style="width:100%;">' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>' +
              '<select id="dfci-target-group" class="intune-input" style="width:100%;">' + groupOptions + '</select>' +
            '</div>' +

            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
              '<div style="background:rgba(0,0,0,0.15);padding:10px;border-radius:6px;">' +
                '<div style="font-weight:600;font-size:12px;margin-bottom:8px;">📷 Peripheral Lockouts</div>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:6px;"><input type="checkbox" id="dfci-cameras" checked> Allow Built-in Cameras</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:6px;"><input type="checkbox" id="dfci-microphones" checked> Allow Microphones</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-radios" checked> Allow Wi-Fi / Bluetooth Radios</label>' +
              '</div>' +
              '<div style="background:rgba(0,0,0,0.15);padding:10px;border-radius:6px;">' +
                '<div style="font-weight:600;font-size:12px;margin-bottom:8px;">🔌 Boot Protection</div>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:6px;"><input type="checkbox" id="dfci-ext-boot"> Allow External USB Boot</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:6px;"><input type="checkbox" id="dfci-net-boot"> Allow Network PXE Boot</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-prevent-bios" checked> Prevent Local BIOS Changes</label>' +
              '</div>' +
            '</div>' +

            '<div style="background:rgba(0,0,0,0.15);padding:10px;border-radius:6px;">' +
              '<div style="font-weight:600;font-size:12px;margin-bottom:8px;">🛡️ Hardware Root-of-Trust &amp; VBS</div>' +
              '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-req-sb" checked> Require Secure Boot</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-req-tpm" checked> Require TPM 2.0</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-req-dma" checked> Require Kernel DMA</label>' +
                '<label style="display:flex;align-items:center;gap:8px;font-size:13px;"><input type="checkbox" id="dfci-req-vbs" checked> Require VBS / HVCI</label>' +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="intune-modal-footer" style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="document.getElementById(\'dfci-modal\').remove()">Cancel</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="window.DfciTable.submitCreatePolicy()">Create Policy</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  function applyPreset(type) {
    const nameEl = document.getElementById('dfci-name');
    const descEl = document.getElementById('dfci-desc');
    const camEl = document.getElementById('dfci-cameras');
    const micEl = document.getElementById('dfci-microphones');
    const radEl = document.getElementById('dfci-radios');
    const extEl = document.getElementById('dfci-ext-boot');
    const netEl = document.getElementById('dfci-net-boot');
    const biosEl = document.getElementById('dfci-prevent-bios');
    const sbEl = document.getElementById('dfci-req-sb');
    const tpmEl = document.getElementById('dfci-req-tpm');
    const dmaEl = document.getElementById('dfci-req-dma');
    const vbsEl = document.getElementById('dfci-req-vbs');

    if (type === 'zerotrust') {
      if (nameEl) nameEl.value = 'Zero-Trust High Security Baseline';
      if (descEl) descEl.value = 'Blocks external media boot, locks down BIOS password, enforces Secure Boot & TPM 2.0.';
      if (camEl) camEl.checked = true;
      if (micEl) micEl.checked = true;
      if (radEl) radEl.checked = true;
      if (extEl) extEl.checked = false;
      if (netEl) netEl.checked = false;
      if (biosEl) biosEl.checked = true;
      if (sbEl) sbEl.checked = true;
      if (tpmEl) tpmEl.checked = true;
      if (dmaEl) dmaEl.checked = true;
      if (vbsEl) vbsEl.checked = true;
    } else if (type === 'kiosk') {
      if (nameEl) nameEl.value = 'Public Kiosk & Exam Hardware Lockdown';
      if (descEl) descEl.value = 'Disables cameras, microphones, radios, and external boot to prevent data exfiltration.';
      if (camEl) camEl.checked = false;
      if (micEl) micEl.checked = false;
      if (radEl) radEl.checked = false;
      if (extEl) extEl.checked = false;
      if (netEl) netEl.checked = false;
      if (biosEl) biosEl.checked = true;
      if (sbEl) sbEl.checked = true;
      if (tpmEl) tpmEl.checked = true;
      if (dmaEl) dmaEl.checked = true;
      if (vbsEl) vbsEl.checked = true;
    } else if (type === 'dev') {
      if (nameEl) nameEl.value = 'Developer Workstation Baseline';
      if (descEl) descEl.value = 'Allows USB boot and peripherals while retaining Secure Boot and TPM 2.0 integrity.';
      if (camEl) camEl.checked = true;
      if (micEl) micEl.checked = true;
      if (radEl) radEl.checked = true;
      if (extEl) extEl.checked = true;
      if (netEl) netEl.checked = false;
      if (biosEl) biosEl.checked = false;
      if (sbEl) sbEl.checked = true;
      if (tpmEl) tpmEl.checked = true;
      if (dmaEl) dmaEl.checked = false;
      if (vbsEl) vbsEl.checked = false;
    }
  }

  async function submitCreatePolicy() {
    const name = document.getElementById('dfci-name')?.value?.trim();
    if (!name) {
      alert('Policy name is required.');
      return;
    }

    const payload = {
      name: name,
      description: document.getElementById('dfci-desc')?.value?.trim() || '',
      target_group_id: document.getElementById('dfci-target-group')?.value || null,
      cameras_enabled: document.getElementById('dfci-cameras')?.checked ? 1 : 0,
      microphones_enabled: document.getElementById('dfci-microphones')?.checked ? 1 : 0,
      radios_enabled: document.getElementById('dfci-radios')?.checked ? 1 : 0,
      external_media_boot_enabled: document.getElementById('dfci-ext-boot')?.checked ? 1 : 0,
      network_adapter_boot_enabled: document.getElementById('dfci-net-boot')?.checked ? 1 : 0,
      prevent_user_bios_changes: document.getElementById('dfci-prevent-bios')?.checked ? 1 : 0,
      require_secure_boot: document.getElementById('dfci-req-sb')?.checked ? 1 : 0,
      require_tpm2: document.getElementById('dfci-req-tpm')?.checked ? 1 : 0,
      require_kernel_dma: document.getElementById('dfci-req-dma')?.checked ? 1 : 0,
      require_vbs: document.getElementById('dfci-req-vbs')?.checked ? 1 : 0,
      enabled: 1
    };

    try {
      await window.FleetAPI.createDfciPolicy(payload);
      document.getElementById('dfci-modal')?.remove();
      loadData();
    } catch (err) {
      alert('Failed to create DFCI policy: ' + err.message);
    }
  }

  async function viewScript(id) {
    try {
      const data = await window.FleetAPI.getDfciPolicy(id);
      const script = data.powershell_script || '# No script generated';

      const modalHtml = 
        '<div class="intune-modal-backdrop" id="dfci-script-modal">' +
          '<div class="intune-modal" style="max-width:720px;max-height:90vh;overflow-y:auto;">' +
            '<div class="intune-modal-header">' +
              '<h3>📜 Generated PowerShell DFCI Configuration Script</h3>' +
              '<button class="intune-close-btn" onclick="document.getElementById(\'dfci-script-modal\').remove()">✕</button>' +
            '</div>' +
            '<div class="intune-modal-body">' +
              '<p style="font-size:12px;color:var(--text-muted);">' +
                'This script is compiled on-the-fly and dispatched automatically to nodes assigned to policy: <strong>' + esc(data.name) + '</strong>.' +
              '</p>' +
              '<pre style="background:#0f172a;padding:12px;border-radius:6px;font-size:12px;font-family:monospace;max-height:360px;overflow-y:auto;color:#38bdf8;">' +
                esc(script) +
              '</pre>' +
            '</div>' +
            '<div class="intune-modal-footer" style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">' +
              '<button class="intune-btn intune-btn-secondary" onclick="navigator.clipboard.writeText(document.querySelector(\'#dfci-script-modal pre\').innerText);alert(\'Script copied to clipboard!\');">📋 Copy Script</button>' +
              '<button class="intune-btn intune-btn-primary" onclick="document.getElementById(\'dfci-script-modal\').remove()">Close</button>' +
            '</div>' +
          '</div>' +
        '</div>';

      document.body.insertAdjacentHTML('beforeend', modalHtml);
    } catch (err) {
      alert('Failed to fetch script: ' + err.message);
    }
  }

  async function deletePolicy(id) {
    if (!confirm('Are you sure you want to delete this DFCI policy?')) return;
    try {
      await window.FleetAPI.deleteDfciPolicy(id);
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
  window.DfciTable = {
    init: loadData,
    switchTab,
    openCreateModal,
    applyPreset,
    submitCreatePolicy,
    viewScript,
    deletePolicy
  };
})();
