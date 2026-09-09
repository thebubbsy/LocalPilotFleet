/**
 * LocalPilot Fleet — Windows Driver & Firmware Update Profiles (WUfB) Blade
 * dashboard/js/components/driverUpdatesTable.js
 */

(function () {
  'use strict';

  let currentTab = 'policies'; // 'policies' | 'catalog' | 'inventory'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getApprovalBadge(status) {
    const s = String(status || 'PENDING_REVIEW').toUpperCase();
    if (s === 'APPROVED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ APPROVED</span>';
    } else if (s === 'DECLINED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛑 DECLINED</span>';
    } else if (s === 'SUSPENDED') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⏸️ SUSPENDED</span>';
    }
    return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;font-weight:700;">⏳ PENDING REVIEW</span>';
  }

  function getClassBadge(cls) {
    const c = String(cls || 'OTHER').toUpperCase();
    let icon = '🔌';
    if (c === 'DISPLAY') icon = '🖥️';
    else if (c === 'NET') icon = '📶';
    else if (c === 'MEDIA') icon = '🔊';
    else if (c === 'FIRMWARE') icon = '⚡';
    else if (c === 'BLUETOOTH') icon = '🦷';
    else if (c === 'STORAGE') icon = '💾';
    else if (c === 'SYSTEM') icon = '⚙️';

    return '<span class="badge" style="background:rgba(148,163,184,0.12);color:var(--text-main);font-size:0.75rem;">' + icon + ' ' + esc(c) + '</span>';
  }

  function getMethodBadge(method) {
    const m = String(method || 'MANUAL').toUpperCase();
    if (m === 'AUTOMATIC') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">⚡ AUTOMATIC</span>';
    }
    return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">✋ MANUAL APPROVAL</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-drivers');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Windows Driver & Firmware Update Profiles (WUfB)…</span>' +
      '</div>';

    try {
      const [stats, policiesData, catalogData, inventoryData, groupsData] = await Promise.all([
        window.FleetAPI.getDriverStats().catch(() => ({})),
        window.FleetAPI.getDriverPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getDriverCatalog().catch(() => ({ catalog: [] })),
        window.FleetAPI.getDriverInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getDynamicGroups ? window.FleetAPI.getDynamicGroups().catch(() => []) : Promise.resolve([])
      ]);

      const policies = policiesData.policies || [];
      const catalog = catalogData.catalog || [];
      const inventory = inventoryData.inventory || [];
      const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      renderView(container, stats, policies, catalog, inventory, groups);
    } catch (err) {
      container.innerHTML = 
        '<div class="error-banner" style="margin:24px;padding:16px;background:rgba(239,68,68,0.1);border-left:4px solid #EF4444;color:#EF4444;">' +
          '<strong>Error loading Driver update governance:</strong> ' + esc(err.message) +
        '</div>';
    }
  }

  function renderView(container, stats, policies, catalog, inventory, groups) {
    let html = '';

    // Header & Actions
    html += 
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">' +
        '<div>' +
          '<h2 style="margin:0 0 4px 0;font-size:1.4rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>⚙️</span> Windows Driver &amp; Firmware Update Profiles (WUfB)' +
          '</h2>' +
          '<p style="margin:0;color:var(--text-muted);font-size:0.85rem;">' +
            'Intune-grade OEM driver lifecycle management, automatic/manual approval rings, UEFI firmware governance, and driver rollback.' +
          '</p>' +
        '</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="intune-btn" id="btn-refresh-drivers" style="display:flex;align-items:center;gap:6px;">' +
            '<span>🔄</span> Refresh' +
          '</button>' +
          '<button class="intune-btn primary" id="btn-create-driver-policy" style="display:flex;align-items:center;gap:6px;">' +
            '<span>➕</span> Create Profile' +
          '</button>' +
        '</div>' +
      '</div>';

    // 4 KPI Cards
    html += 
      '<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px;">' +
        // Card 1: Active Profiles
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Driver Profiles' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main, #F8FAFC);margin-bottom:4px;">' +
            (stats.active_policies || 0) + ' <span style="font-size:0.9rem;font-weight:400;color:var(--text-muted);">/ ' + (stats.total_policies || 0) + ' active</span>' +
          '</div>' +
          '<div style="font-size:0.75rem;color:#10B981;">' +
            '● Windows Update for Business Rings' +
          '</div>' +
        '</div>' +

        // Card 2: Discovered OEM Drivers
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Catalog Drivers' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:#60A5FA;margin-bottom:4px;">' +
            (stats.total_catalog_drivers || 0) +
          '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' +
            (stats.approved_drivers_count || 0) + ' Approved | ' + (stats.pending_review_drivers_count || 0) + ' Pending' +
          '</div>' +
        '</div>' +

        // Card 3: Pending Review
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Pending Review' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:' + ((stats.pending_review_drivers_count || 0) > 0 ? '#F59E0B' : '#10B981') + ';margin-bottom:4px;">' +
            (stats.pending_review_drivers_count || 0) +
          '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' +
            'Requires administrator sign-off' +
          '</div>' +
        '</div>' +

        // Card 4: Workstation Compliance %
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Driver Compliance' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:#10B981;margin-bottom:4px;">' +
            (stats.fleet_driver_compliance_pct || 100) + '%' +
          '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' +
            (stats.up_to_date_devices_count || 0) + ' of ' + (stats.total_audited_devices || 0) + ' workstations aligned' +
          '</div>' +
        '</div>' +
      '</div>';

    // Sub-Navigation Tabs
    html += 
      '<div style="display:flex;border-bottom:1px solid var(--border-color, #334155);margin-bottom:16px;gap:8px;">' +
        '<button class="driver-tab-btn ' + (currentTab === 'policies' ? 'active' : '') + '" data-tab="policies" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'policies' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'policies' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '⚙️ Driver Update Profiles (' + policies.length + ')' +
        '</button>' +
        '<button class="driver-tab-btn ' + (currentTab === 'catalog' ? 'active' : '') + '" data-tab="catalog" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'catalog' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'catalog' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '📦 Recommended Driver Catalog (' + catalog.length + ')' +
        '</button>' +
        '<button class="driver-tab-btn ' + (currentTab === 'inventory' ? 'active' : '') + '" data-tab="inventory" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'inventory' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'inventory' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '💻 Workstation Driver Posture (' + inventory.length + ')' +
        '</button>' +
      '</div>';

    // Content Panels
    if (currentTab === 'policies') {
      html += renderPoliciesTab(policies);
    } else if (currentTab === 'catalog') {
      html += renderCatalogTab(catalog);
    } else {
      html += renderInventoryTab(inventory);
    }

    container.innerHTML = html;
    attachEvents(container, policies, catalog, inventory, groups);
  }

  function renderPoliciesTab(policies) {
    let html = 
      '<div class="intune-table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;text-align:left;">' +
          '<thead style="background:rgba(0,0,0,0.2);border-bottom:1px solid var(--border-color, #334155);">' +
            '<tr>' +
              '<th style="padding:10px 14px;">Profile Name</th>' +
              '<th style="padding:10px 14px;">Approval Method</th>' +
              '<th style="padding:10px 14px;">Delay (Days)</th>' +
              '<th style="padding:10px 14px;">Optional Drivers</th>' +
              '<th style="padding:10px 14px;">Target Group</th>' +
              '<th style="padding:10px 14px;">Status</th>' +
              '<th style="padding:10px 14px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    if (policies.length === 0) {
      html += '<tr><td colspan="7" style="padding:24px;text-align:center;color:var(--text-muted);">No driver update profiles created yet.</td></tr>';
    } else {
      for (const p of policies) {
        html += 
          '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
            '<td style="padding:10px 14px;">' +
              '<div style="font-weight:600;color:var(--text-main);">' + esc(p.name) + '</div>' +
              '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(p.description || p.id) + '</div>' +
            '</td>' +
            '<td style="padding:10px 14px;">' + getMethodBadge(p.approval_method) + '</td>' +
            '<td style="padding:10px 14px;font-family:monospace;">' + (p.automatic_approval_delay_days || 0) + ' d</td>' +
            '<td style="padding:10px 14px;">' + (p.allow_optional_drivers ? '✅ Allowed' : '❌ Excluded') + '</td>' +
            '<td style="padding:10px 14px;"><span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;">' + esc(p.target_group_name || p.target_group_id) + '</span></td>' +
            '<td style="padding:10px 14px;">' + (p.enabled ? '<span style="color:#10B981;font-weight:600;">Active</span>' : '<span style="color:#EF4444;font-weight:600;">Disabled</span>') + '</td>' +
            '<td style="padding:10px 14px;text-align:right;white-space:nowrap;">' +
              '<button class="intune-btn-sm btn-view-script" data-id="' + esc(p.id) + '" style="margin-right:6px;" title="Inspect PowerShell Script">📜 Script</button>' +
              '<button class="intune-btn-sm btn-delete-policy" data-id="' + esc(p.id) + '" style="color:#EF4444;" title="Delete Profile">🗑️</button>' +
            '</td>' +
          '</tr>';
      }
    }

    html += '</tbody></table></div>';
    return html;
  }

  function renderCatalogTab(catalog) {
    let html = 
      '<div class="intune-table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;text-align:left;">' +
          '<thead style="background:rgba(0,0,0,0.2);border-bottom:1px solid var(--border-color, #334155);">' +
            '<tr>' +
              '<th style="padding:10px 14px;">Driver / Firmware Name</th>' +
              '<th style="padding:10px 14px;">Class</th>' +
              '<th style="padding:10px 14px;">Provider</th>' +
              '<th style="padding:10px 14px;">Latest Version</th>' +
              '<th style="padding:10px 14px;">Release Date</th>' +
              '<th style="padding:10px 14px;">Approval Status</th>' +
              '<th style="padding:10px 14px;">Applicable Devices</th>' +
              '<th style="padding:10px 14px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    if (catalog.length === 0) {
      html += '<tr><td colspan="8" style="padding:24px;text-align:center;color:var(--text-muted);">No OEM drivers discovered in catalog.</td></tr>';
    } else {
      for (const d of catalog) {
        html += 
          '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
            '<td style="padding:10px 14px;">' +
              '<div style="font-weight:600;color:var(--text-main);">' + esc(d.driver_name) + '</div>' +
              '<div style="font-size:0.75rem;color:var(--text-muted);font-family:monospace;">' + esc(d.hardware_id || d.id) + '</div>' +
            '</td>' +
            '<td style="padding:10px 14px;">' + getClassBadge(d.driver_class) + '</td>' +
            '<td style="padding:10px 14px;">' + esc(d.driver_provider) + '</td>' +
            '<td style="padding:10px 14px;font-family:monospace;font-weight:600;">' + esc(d.driver_version) + '</td>' +
            '<td style="padding:10px 14px;color:var(--text-muted);">' + esc(d.driver_date || 'N/A') + '</td>' +
            '<td style="padding:10px 14px;">' + getApprovalBadge(d.approval_status) + '</td>' +
            '<td style="padding:10px 14px;">' +
              '<span style="font-weight:600;">' + (d.installed_devices_count || 0) + '</span> / ' + (d.applicable_devices_count || 0) + ' installed' +
            '</td>' +
            '<td style="padding:10px 14px;text-align:right;white-space:nowrap;">' +
              '<button class="intune-btn-sm btn-manage-approval" data-id="' + esc(d.id) + '" data-name="' + esc(d.driver_name) + '" data-status="' + esc(d.approval_status) + '">✍️ Manage Approval</button>' +
            '</td>' +
          '</tr>';
      }
    }

    html += '</tbody></table></div>';
    return html;
  }

  function renderInventoryTab(inventory) {
    let html = 
      '<div class="intune-table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;text-align:left;">' +
          '<thead style="background:rgba(0,0,0,0.2);border-bottom:1px solid var(--border-color, #334155);">' +
            '<tr>' +
              '<th style="padding:10px 14px;">Workstation</th>' +
              '<th style="padding:10px 14px;">OS &amp; User</th>' +
              '<th style="padding:10px 14px;">Total Drivers</th>' +
              '<th style="padding:10px 14px;">Pending Updates</th>' +
              '<th style="padding:10px 14px;">Posture State</th>' +
              '<th style="padding:10px 14px;">Last Scanned</th>' +
              '<th style="padding:10px 14px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    if (inventory.length === 0) {
      html += '<tr><td colspan="7" style="padding:24px;text-align:center;color:var(--text-muted);">No workstation driver telemetry received yet. Run agent heartbeat to harvest.</td></tr>';
    } else {
      for (const row of inventory) {
        const needsUpdate = row.needs_update_count > 0;
        html += 
          '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
            '<td style="padding:10px 14px;">' +
              '<div style="font-weight:600;color:var(--text-main);">' + esc(row.friendly_name || row.hostname) + '</div>' +
              '<div style="font-size:0.75rem;color:var(--text-muted);font-family:monospace;">' + esc(row.device_id) + '</div>' +
            '</td>' +
            '<td style="padding:10px 14px;">' +
              '<div>' + esc(row.os_name || 'Windows 11') + '</div>' +
              '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(row.primary_user || 'SYSTEM') + '</div>' +
            '</td>' +
            '<td style="padding:10px 14px;font-family:monospace;font-weight:600;">' + (row.total_drivers || 0) + '</td>' +
            '<td style="padding:10px 14px;">' +
              (needsUpdate ? '<span style="color:#F59E0B;font-weight:700;">⚠️ ' + row.needs_update_count + ' updates available</span>' : '<span style="color:#10B981;">✅ 0 updates</span>') +
            '</td>' +
            '<td style="padding:10px 14px;">' +
              (needsUpdate ? '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">UPDATE RECOMMENDED</span>' : '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">FULLY UPDATED</span>') +
            '</td>' +
            '<td style="padding:10px 14px;color:var(--text-muted);font-size:0.8rem;">' + esc(row.last_scanned_at || 'Recently') + '</td>' +
            '<td style="padding:10px 14px;text-align:right;white-space:nowrap;">' +
              '<button class="intune-btn-sm btn-inspect-device-drivers" data-device-id="' + esc(row.device_id) + '" data-hostname="' + esc(row.hostname) + '">🔍 View Drivers</button>' +
            '</td>' +
          '</tr>';
      }
    }

    html += '</tbody></table></div>';
    return html;
  }

  function attachEvents(container, policies, catalog, inventory, groups) {
    // Refresh Button
    const refreshBtn = document.getElementById('btn-refresh-drivers');
    if (refreshBtn) refreshBtn.onclick = () => loadData();

    // Tab Switchers
    container.querySelectorAll('.driver-tab-btn').forEach(btn => {
      btn.onclick = (e) => {
        currentTab = e.currentTarget.getAttribute('data-tab');
        loadData();
      };
    });

    // Create Policy Button
    const createBtn = document.getElementById('btn-create-driver-policy');
    if (createBtn) {
      createBtn.onclick = () => openCreatePolicyModal(groups);
    }

    // View Script Buttons
    container.querySelectorAll('.btn-view-script').forEach(btn => {
      btn.onclick = async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        try {
          const res = await window.FleetAPI.getDriverPolicy(id);
          openScriptModal(res.policy, res.script);
        } catch (err) {
          alert('Failed to fetch policy script: ' + err.message);
        }
      };
    });

    // Delete Policy Buttons
    container.querySelectorAll('.btn-delete-policy').forEach(btn => {
      btn.onclick = async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        if (!confirm('Are you sure you want to delete driver profile ' + id + '?')) return;
        try {
          await window.FleetAPI.deleteDriverPolicy(id);
          loadData();
        } catch (err) {
          alert('Failed to delete driver policy: ' + err.message);
        }
      };
    });

    // Manage Approval Buttons
    container.querySelectorAll('.btn-manage-approval').forEach(btn => {
      btn.onclick = (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const name = e.currentTarget.getAttribute('data-name');
        const status = e.currentTarget.getAttribute('data-status');
        openApprovalModal(id, name, status);
      };
    });

    // Inspect Device Drivers Buttons
    container.querySelectorAll('.btn-inspect-device-drivers').forEach(btn => {
      btn.onclick = async (e) => {
        const deviceId = e.currentTarget.getAttribute('data-device-id');
        const hostname = e.currentTarget.getAttribute('data-hostname');
        try {
          const res = await window.FleetAPI.getDeviceDrivers(deviceId);
          openDeviceDriversModal(hostname, res.drivers || []);
        } catch (err) {
          alert('Failed to load device drivers: ' + err.message);
        }
      };
    });
  }

  function openCreatePolicyModal(groups) {
    let groupOptions = '<option value="grp-all">All Devices (grp-all)</option>';
    for (const g of groups) {
      if (g.id !== 'grp-all') {
        groupOptions += '<option value="' + esc(g.id) + '">' + esc(g.name) + ' (' + esc(g.id) + ')</option>';
      }
    }

    const modalHtml = 
      '<div id="modal-driver-policy" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:10px;padding:24px;width:540px;max-width:90vw;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<h3 style="margin:0 0 16px 0;font-size:1.2rem;display:flex;align-items:center;gap:8px;">' +
            '<span>⚙️</span> New Driver Update Profile' +
          '</h3>' +
          '<div style="display:flex;flex-direction:column;gap:12px;">' +
            '<div>' +
              '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">PROFILE NAME</label>' +
              '<input id="inp-drv-name" type="text" class="intune-input" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;" placeholder="e.g. Critical Workstation Drivers" />' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">DESCRIPTION</label>' +
              '<input id="inp-drv-desc" type="text" class="intune-input" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;" placeholder="Purpose of this driver governance ring" />' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">APPROVAL METHOD</label>' +
                '<select id="sel-drv-method" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;">' +
                  '<option value="AUTOMATIC">Automatic Approval</option>' +
                  '<option value="MANUAL">Manual Administrator Review</option>' +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">DEFERRAL BUFFER (DAYS)</label>' +
                '<input id="inp-drv-delay" type="number" value="7" min="0" max="30" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;" />' +
              '</div>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">TARGET DYNAMIC GROUP</label>' +
              '<select id="sel-drv-group" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;">' +
                groupOptions +
              '</select>' +
            '</div>' +
            '<div style="display:flex;gap:16px;margin-top:4px;">' +
              '<label style="display:flex;align-items:center;gap:8px;font-size:0.85rem;cursor:pointer;">' +
                '<input id="chk-drv-optional" type="checkbox" checked /> Allow Optional OEM Drivers' +
              '</label>' +
              '<label style="display:flex;align-items:center;gap:8px;font-size:0.85rem;cursor:pointer;">' +
                '<input id="chk-drv-enabled" type="checkbox" checked /> Enable Policy' +
              '</label>' +
            '</div>' +
          '</div>' +
          '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px;">' +
            '<button class="intune-btn" id="btn-cancel-drv-modal">Cancel</button>' +
            '<button class="intune-btn primary" id="btn-save-drv-modal">Create Profile</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.getElementById('btn-cancel-drv-modal').onclick = () => {
      document.getElementById('modal-driver-policy').remove();
    };

    document.getElementById('btn-save-drv-modal').onclick = async () => {
      const name = document.getElementById('inp-drv-name').value.trim();
      if (!name) {
        alert('Please enter a policy name');
        return;
      }
      const desc = document.getElementById('inp-drv-desc').value.trim();
      const method = document.getElementById('sel-drv-method').value;
      const delay = parseInt(document.getElementById('inp-drv-delay').value, 10) || 0;
      const groupId = document.getElementById('sel-drv-group').value;
      const allowOpt = document.getElementById('chk-drv-optional').checked ? 1 : 0;
      const enabled = document.getElementById('chk-drv-enabled').checked ? 1 : 0;

      try {
        await window.FleetAPI.createDriverPolicy({
          name,
          description: desc,
          approval_method: method,
          automatic_approval_delay_days: delay,
          target_group_id: groupId,
          allow_optional_drivers: allowOpt,
          enabled
        });
        document.getElementById('modal-driver-policy').remove();
        loadData();
      } catch (err) {
        alert('Failed to create driver profile: ' + err.message);
      }
    };
  }

  function openApprovalModal(id, name, currentStatus) {
    const modalHtml = 
      '<div id="modal-driver-approval" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:10px;padding:24px;width:480px;max-width:90vw;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<h3 style="margin:0 0 12px 0;font-size:1.2rem;display:flex;align-items:center;gap:8px;">' +
            '<span>✍️</span> Manage Driver Approval' +
          '</h3>' +
          '<div style="font-weight:600;color:var(--text-main);margin-bottom:12px;">' + esc(name) + '</div>' +
          '<div style="display:flex;flex-direction:column;gap:12px;">' +
            '<div>' +
              '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">APPROVAL DECISION</label>' +
              '<select id="sel-drv-approval" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;">' +
                '<option value="APPROVED" ' + (currentStatus === 'APPROVED' ? 'selected' : '') + '>Approve for Fleet Rollout</option>' +
                '<option value="PENDING_REVIEW" ' + (currentStatus === 'PENDING_REVIEW' ? 'selected' : '') + '>Leave in Pending Review</option>' +
                '<option value="SUSPENDED" ' + (currentStatus === 'SUSPENDED' ? 'selected' : '') + '>Suspend (Temporarily Halt Installation)</option>' +
                '<option value="DECLINED" ' + (currentStatus === 'DECLINED' ? 'selected' : '') + '>Decline (Prohibit Driver Package)</option>' +
              '</select>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:0.75rem;font-weight:600;margin-bottom:4px;color:var(--text-muted);">REVIEWER SIGN-OFF</label>' +
              '<input id="inp-drv-reviewer" type="text" value="LocalPilot Administrator" style="width:100%;box-sizing:border-box;padding:8px 10px;background:rgba(0,0,0,0.2);border:1px solid var(--border-color, #334155);color:var(--text-main);border-radius:6px;" />' +
            '</div>' +
          '</div>' +
          '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px;">' +
            '<button class="intune-btn" id="btn-cancel-appr-modal">Cancel</button>' +
            '<button class="intune-btn primary" id="btn-save-appr-modal">Commit Decision</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.getElementById('btn-cancel-appr-modal').onclick = () => {
      document.getElementById('modal-driver-approval').remove();
    };

    document.getElementById('btn-save-appr-modal').onclick = async () => {
      const status = document.getElementById('sel-drv-approval').value;
      const reviewer = document.getElementById('inp-drv-reviewer').value.trim() || 'Fleet Admin';

      try {
        await window.FleetAPI.setDriverApprovalStatus(id, {
          status,
          approved_by: reviewer
        });
        document.getElementById('modal-driver-approval').remove();
        loadData();
      } catch (err) {
        alert('Failed to update driver approval: ' + err.message);
      }
    };
  }

  function openScriptModal(policy, script) {
    const modalHtml = 
      '<div id="modal-drv-script" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:10px;padding:24px;width:680px;max-width:92vw;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
            '<h3 style="margin:0;font-size:1.1rem;display:flex;align-items:center;gap:8px;">' +
              '<span>📜</span> PowerShell Driver Policy Script — ' + esc(policy.name) +
            '</h3>' +
            '<button class="intune-btn-sm" id="btn-close-drv-script" style="font-size:1rem;cursor:pointer;">✕</button>' +
          '</div>' +
          '<pre style="background:#0F172A;border:1px solid #334155;border-radius:6px;padding:14px;color:#38BDF8;font-family:monospace;font-size:0.8rem;max-height:360px;overflow-y:auto;white-space:pre-wrap;">' +
            esc(script) +
          '</pre>' +
          '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;">' +
            '<button class="intune-btn" id="btn-copy-drv-script">📋 Copy Script</button>' +
            '<button class="intune-btn primary" id="btn-ok-drv-script">Done</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    const closeModal = () => document.getElementById('modal-drv-script').remove();
    document.getElementById('btn-close-drv-script').onclick = closeModal;
    document.getElementById('btn-ok-drv-script').onclick = closeModal;
    document.getElementById('btn-copy-drv-script').onclick = () => {
      navigator.clipboard.writeText(script).then(() => {
        alert('PowerShell driver script copied to clipboard!');
      });
    };
  }

  function openDeviceDriversModal(hostname, drivers) {
    let rowsHtml = '';
    if (drivers.length === 0) {
      rowsHtml = '<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--text-muted);">No drivers registered for this workstation.</td></tr>';
    } else {
      for (const d of drivers) {
        rowsHtml += 
          '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
            '<td style="padding:8px 10px;font-weight:600;">' + esc(d.driver_name) + '</td>' +
            '<td style="padding:8px 10px;">' + getClassBadge(d.driver_class) + '</td>' +
            '<td style="padding:8px 10px;font-family:monospace;">' + esc(d.current_version) + '</td>' +
            '<td style="padding:8px 10px;">' + getApprovalBadge(d.approval_status) + '</td>' +
            '<td style="padding:8px 10px;">' +
              (d.install_status === 'INSTALLED' ? '<span style="color:#10B981;font-weight:600;">INSTALLED</span>' : '<span style="color:#F59E0B;font-weight:700;">' + esc(d.install_status) + '</span>') +
            '</td>' +
          '</tr>';
      }
    }

    const modalHtml = 
      '<div id="modal-dev-drivers" style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:10px;padding:24px;width:720px;max-width:92vw;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
            '<h3 style="margin:0;font-size:1.1rem;display:flex;align-items:center;gap:8px;">' +
              '<span>💻</span> Installed Drivers — ' + esc(hostname) +
            '</h3>' +
            '<button class="intune-btn-sm" id="btn-close-dev-drivers" style="font-size:1rem;cursor:pointer;">✕</button>' +
          '</div>' +
          '<div style="max-height:380px;overflow-y:auto;border:1px solid var(--border-color, #334155);border-radius:6px;">' +
            '<table style="width:100%;border-collapse:collapse;font-size:0.8rem;text-align:left;">' +
              '<thead style="background:rgba(0,0,0,0.2);position:sticky;top:0;">' +
                '<tr>' +
                  '<th style="padding:8px 10px;">Driver</th>' +
                  '<th style="padding:8px 10px;">Class</th>' +
                  '<th style="padding:8px 10px;">Installed Version</th>' +
                  '<th style="padding:8px 10px;">Fleet Approval</th>' +
                  '<th style="padding:8px 10px;">State</th>' +
                '</tr>' +
              '</thead>' +
              '<tbody>' + rowsHtml + '</tbody>' +
            '</table>' +
          '</div>' +
          '<div style="display:flex;justify-content:flex-end;margin-top:16px;">' +
            '<button class="intune-btn primary" id="btn-ok-dev-drivers">Close</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    const closeModal = () => document.getElementById('modal-dev-drivers').remove();
    document.getElementById('btn-close-dev-drivers').onclick = closeModal;
    document.getElementById('btn-ok-dev-drivers').onclick = closeModal;
  }

  window.DriverUpdatesTable = {
    init: loadData,
    render: loadData,
    refresh: loadData
  };
})();
