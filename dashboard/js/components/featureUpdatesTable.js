/**
 * LocalPilot Fleet — Microsoft Intune Feature Update Profiles & Expedited Quality Updates Blade
 * dashboard/js/components/featureUpdatesTable.js
 */

(function () {
  'use strict';

  let currentTab = 'policies'; // 'policies' | 'expedited' | 'inventory'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getStatusBadge(status) {
    const s = String(status || 'UP_TO_DATE').toUpperCase();
    if (s === 'UP_TO_DATE' || s === 'COMPLETED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ ' + esc(s) + '</span>';
    } else if (s === 'OFFERING' || s === 'INSTALLING' || s === 'ACTIVE') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;font-weight:700;">🔄 ' + esc(s) + '</span>';
    } else if (s === 'PENDING_REBOOT') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⚠️ PENDING REBOOT</span>';
    } else if (s === 'SAFEGUARD_HOLD') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛑 SAFEGUARD HOLD</span>';
    } else if (s === 'PAUSED' || s === 'CANCELLED') {
      return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9CA3AF;font-weight:700;">⏸️ ' + esc(s) + '</span>';
    }
    return '<span class="badge">' + esc(s) + '</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-featureupdates');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Feature Updates &amp; Expedited Hotfix Campaigns…</span>' +
      '</div>';

    try {
      const [statsRes, policiesRes, expeditedRes, inventoryRes, groupsRes] = await Promise.all([
        window.FleetAPI.getFeatureUpdateStats().catch(() => ({})),
        window.FleetAPI.getFeaturePolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getExpeditedUpdates().catch(() => ({ expedited: [] })),
        window.FleetAPI.getFeatureInventoryOverview().catch(() => ({ inventory: [] })),
        window.FleetAPI.getGroups ? window.FleetAPI.getGroups().catch(() => []) : Promise.resolve([])
      ]);

      const stats = statsRes.stats || statsRes || {};
      const policies = policiesRes.policies || [];
      const expedited = expeditedRes.expedited || expeditedRes.expedited_updates || [];
      const inventory = inventoryRes.inventory || [];
      const groups = Array.isArray(groupsRes) ? groupsRes : (groupsRes.groups || []);

      renderView(container, stats, policies, expedited, inventory, groups);
    } catch (err) {
      container.innerHTML = 
        '<div class="error-banner" style="margin:24px;padding:16px;background:rgba(239,68,68,0.1);border-left:4px solid #EF4444;color:#EF4444;">' +
          '<strong>Error loading Feature Updates:</strong> ' + esc(err.message) +
        '</div>';
    }
  }

  function renderView(container, stats, policies, expedited, inventory, groups) {
    let html = '';

    // Header
    html += 
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">' +
        '<div>' +
          '<h2 style="margin:0 0 4px 0;font-size:1.4rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>🚀</span> Feature Update Profiles &amp; Expedited Quality Updates' +
          '</h2>' +
          '<p style="margin:0;color:var(--text-muted);font-size:0.85rem;">' +
            'Microsoft Intune Windows Update for Business (WUfB) target OS version locking, safeguard hold compliance, and emergency out-of-band zero-day expedited hotfixes.' +
          '</p>' +
        '</div>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
          '<button class="intune-btn" id="btn-refresh-featureupdates" style="display:flex;align-items:center;gap:6px;">' +
            '<span>🔄</span> Refresh' +
          '</button>' +
          '<button class="intune-btn primary" id="btn-create-feature-policy" style="display:flex;align-items:center;gap:6px;">' +
            '<span>+</span> New Feature Profile' +
          '</button>' +
          '<button class="intune-btn" id="btn-create-expedited" style="display:flex;align-items:center;gap:6px;background:#EF4444;color:#fff;border-color:#DC2626;">' +
            '<span>⚡</span> Expedite Hotfix' +
          '</button>' +
        '</div>' +
      '</div>';

    // 4 KPI Cards
    html += 
      '<div class="kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:16px;margin-bottom:24px;">' +
        '<div class="kpi-card" style="background:var(--card-bg, #1e293b);padding:16px;border-radius:8px;border:1px solid var(--border-color, #334155);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Target Version Policies</div>' +
          '<div style="font-size:1.8rem;font-weight:700;margin:6px 0;color:#3B82F6;">' + (stats.totalFeaturePolicies || policies.length || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' + (stats.activeFeaturePolicies || 0) + ' actively enforced</div>' +
        '</div>' +
        '<div class="kpi-card" style="background:var(--card-bg, #1e293b);padding:16px;border-radius:8px;border:1px solid var(--border-color, #334155);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Expedited Hotfixes</div>' +
          '<div style="font-size:1.8rem;font-weight:700;margin:6px 0;color:#EF4444;">' + (stats.totalExpeditedUpdates || expedited.length || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' + (stats.activeExpeditedUpdates || 0) + ' emergency campaigns</div>' +
        '</div>' +
        '<div class="kpi-card" style="background:var(--card-bg, #1e293b);padding:16px;border-radius:8px;border:1px solid var(--border-color, #334155);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Safeguard Holds</div>' +
          '<div style="font-size:1.8rem;font-weight:700;margin:6px 0;color:#F59E0B;">' + (stats.safeguardHoldDevices || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">Workstations held for telemetry safety</div>' +
        '</div>' +
        '<div class="kpi-card" style="background:var(--card-bg, #1e293b);padding:16px;border-radius:8px;border:1px solid var(--border-color, #334155);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">Target Posture</div>' +
          '<div style="font-size:1.8rem;font-weight:700;margin:6px 0;color:#10B981;">' + (stats.upToDateDevices || 0) + ' / ' + (stats.totalMonitoredDevices || inventory.length || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' + (stats.offeringDevices || 0) + ' offering / installing</div>' +
        '</div>' +
      '</div>';

    // Sub-tab Bar
    html += 
      '<div class="subtab-bar" style="display:flex;gap:4px;border-bottom:1px solid var(--border-color, #334155);margin-bottom:20px;">' +
        '<button class="subtab-btn' + (currentTab === 'policies' ? ' active' : '') + '" data-tab="policies" style="padding:10px 18px;border:none;background:none;color:' + (currentTab === 'policies' ? 'var(--primary, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'policies' ? 'var(--primary, #3B82F6)' : 'transparent') + ';cursor:pointer;font-weight:600;font-size:0.9rem;">' +
          '🚀 Feature Profiles (' + policies.length + ')' +
        '</button>' +
        '<button class="subtab-btn' + (currentTab === 'expedited' ? ' active' : '') + '" data-tab="expedited" style="padding:10px 18px;border:none;background:none;color:' + (currentTab === 'expedited' ? 'var(--primary, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'expedited' ? 'var(--primary, #3B82F6)' : 'transparent') + ';cursor:pointer;font-weight:600;font-size:0.9rem;">' +
          '⚡ Expedited Hotfixes (' + expedited.length + ')' +
        '</button>' +
        '<button class="subtab-btn' + (currentTab === 'inventory' ? ' active' : '') + '" data-tab="inventory" style="padding:10px 18px;border:none;background:none;color:' + (currentTab === 'inventory' ? 'var(--primary, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'inventory' ? 'var(--primary, #3B82F6)' : 'transparent') + ';cursor:pointer;font-weight:600;font-size:0.9rem;">' +
          '💻 Workstation Posture (' + inventory.length + ')' +
        '</button>' +
      '</div>';

    // Sub-tab content
    if (currentTab === 'policies') {
      html += renderPoliciesTab(policies);
    } else if (currentTab === 'expedited') {
      html += renderExpeditedTab(expedited);
    } else {
      html += renderInventoryTab(inventory);
    }

    container.innerHTML = html;
    attachEvents(container, policies, expedited, inventory, groups);
  }

  function renderPoliciesTab(policies) {
    if (!policies || policies.length === 0) {
      return '<div class="empty-state" style="padding:48px 24px;text-align:center;color:var(--text-muted);">' +
        '<div style="font-size:36px;margin-bottom:12px;">🚀</div>' +
        '<div style="font-weight:600;font-size:1.1rem;margin-bottom:6px;">No Feature Update Profiles Defined</div>' +
        '<p style="max-width:480px;margin:0 auto 16px auto;font-size:0.85rem;">Create a profile to pin Windows 11 / 10 target release versions and enforce safeguard hold telemetry.</p>' +
      '</div>';
    }

    let html = 
      '<div class="table-responsive" style="overflow-x:auto;">' +
        '<table class="data-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color, #334155);text-align:left;color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Profile Name</th>' +
              '<th style="padding:12px 16px;">Target OS Version</th>' +
              '<th style="padding:12px 16px;">Rollout Type</th>' +
              '<th style="padding:12px 16px;">Safeguard Holds</th>' +
              '<th style="padding:12px 16px;">Target Scope</th>' +
              '<th style="padding:12px 16px;">Assigned Nodes</th>' +
              '<th style="padding:12px 16px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const p of policies) {
      html += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 16px;font-weight:600;">' +
            '<div>' + esc(p.name) + '</div>' +
            (p.description ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">' + esc(p.description) + '</div>' : '') +
          '</td>' +
          '<td style="padding:12px 16px;">' +
            '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;font-weight:700;">' + esc(p.target_os_version) + '</span>' +
          '</td>' +
          '<td style="padding:12px 16px;">' + esc(p.rollout_type || 'IMMEDIATELY') + '</td>' +
          '<td style="padding:12px 16px;">' +
            (p.safeguard_holds_enabled 
              ? '<span style="color:#10B981;font-weight:600;">🛡️ Enforced</span>' 
              : '<span style="color:#EF4444;font-weight:600;">⚠️ Bypassed</span>') +
          '</td>' +
          '<td style="padding:12px 16px;">' + (p.target_group_name ? '👥 ' + esc(p.target_group_name) : '🌐 All Workstations') + '</td>' +
          '<td style="padding:12px 16px;">' + (p.assigned_device_count || 0) + ' device(s)</td>' +
          '<td style="padding:12px 16px;text-align:right;">' +
            '<button class="intune-btn small btn-inspect-policy" data-id="' + esc(p.id) + '" style="margin-right:6px;">Registry Script</button>' +
            '<button class="intune-btn small danger btn-delete-policy" data-id="' + esc(p.id) + '">Delete</button>' +
          '</td>' +
        '</tr>';
    }

    html += '</tbody></table></div>';
    return html;
  }

  function renderExpeditedTab(expedited) {
    if (!expedited || expedited.length === 0) {
      return '<div class="empty-state" style="padding:48px 24px;text-align:center;color:var(--text-muted);">' +
        '<div style="font-size:36px;margin-bottom:12px;">⚡</div>' +
        '<div style="font-weight:600;font-size:1.1rem;margin-bottom:6px;">No Active Expedited Hotfixes</div>' +
        '<p style="max-width:480px;margin:0 auto 16px auto;font-size:0.85rem;">Launch an emergency out-of-band quality update campaign to force download and install critical security patches bypassing deferrals.</p>' +
      '</div>';
    }

    let html = 
      '<div class="table-responsive" style="overflow-x:auto;">' +
        '<table class="data-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color, #334155);text-align:left;color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Hotfix Campaign</th>' +
              '<th style="padding:12px 16px;">Target KB</th>' +
              '<th style="padding:12px 16px;">CVE Reference</th>' +
              '<th style="padding:12px 16px;">Status</th>' +
              '<th style="padding:12px 16px;">Reboot Deadline</th>' +
              '<th style="padding:12px 16px;">Progress</th>' +
              '<th style="padding:12px 16px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const e of expedited) {
      html += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 16px;font-weight:600;">' +
            '<div>' + esc(e.name) + '</div>' +
            (e.description ? '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">' + esc(e.description) + '</div>' : '') +
          '</td>' +
          '<td style="padding:12px 16px;"><span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">' + esc(e.target_kb_number) + '</span></td>' +
          '<td style="padding:12px 16px;">' + (e.cve_reference ? '<span style="color:#F59E0B;font-weight:600;">' + esc(e.cve_reference) + '</span>' : '—') + '</td>' +
          '<td style="padding:12px 16px;">' + getStatusBadge(e.status) + '</td>' +
          '<td style="padding:12px 16px;">' + (e.days_until_forced_reboot !== undefined ? e.days_until_forced_reboot + ' day(s)' : '1 day') + '</td>' +
          '<td style="padding:12px 16px;">' + (e.completed_device_count || 0) + ' / ' + (e.targeted_device_count || 0) + ' completed</td>' +
          '<td style="padding:12px 16px;text-align:right;">' +
            '<button class="intune-btn small btn-inspect-expedited" data-id="' + esc(e.id) + '" style="margin-right:6px;">USO Script</button>' +
            '<button class="intune-btn small danger btn-delete-expedited" data-id="' + esc(e.id) + '">Delete</button>' +
          '</td>' +
        '</tr>';
    }

    html += '</tbody></table></div>';
    return html;
  }

  function renderInventoryTab(inventory) {
    if (!inventory || inventory.length === 0) {
      return '<div class="empty-state" style="padding:48px 24px;text-align:center;color:var(--text-muted);">' +
        '<div style="font-size:36px;margin-bottom:12px;">💻</div>' +
        '<div style="font-weight:600;font-size:1.1rem;margin-bottom:6px;">No Workstation Telemetry Reported</div>' +
        '<p style="max-width:480px;margin:0 auto 16px auto;font-size:0.85rem;">As local agent daemons heartbeat and audit Windows Update for Business registries, their OS version lock status and safeguard holds will appear here.</p>' +
      '</div>';
    }

    let html = 
      '<div class="table-responsive" style="overflow-x:auto;">' +
        '<table class="data-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color, #334155);text-align:left;color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Workstation</th>' +
              '<th style="padding:12px 16px;">Current OS &amp; Build</th>' +
              '<th style="padding:12px 16px;">Pinned Target</th>' +
              '<th style="padding:12px 16px;">Feature Status</th>' +
              '<th style="padding:12px 16px;">Expedited Status</th>' +
              '<th style="padding:12px 16px;">Safeguard Holds</th>' +
              '<th style="padding:12px 16px;text-align:right;">Last Audit</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const inv of inventory) {
      html += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 16px;font-weight:600;">' +
            '<div>' + esc(inv.device_hostname || 'Unknown Host') + '</div>' +
            (inv.device_friendly_name ? '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(inv.device_friendly_name) + '</div>' : '') +
          '</td>' +
          '<td style="padding:12px 16px;">' +
            '<div>' + esc(inv.current_os_version) + '</div>' +
            '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(inv.current_os_build) + '</div>' +
          '</td>' +
          '<td style="padding:12px 16px;"><span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;">' + esc(inv.target_os_version || 'Default') + '</span></td>' +
          '<td style="padding:12px 16px;">' + getStatusBadge(inv.feature_update_status) + '</td>' +
          '<td style="padding:12px 16px;">' +
            (inv.target_kb_number 
              ? '<div><span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;">' + esc(inv.target_kb_number) + '</span> ' + getStatusBadge(inv.expedited_install_status) + '</div>'
              : '<span style="color:var(--text-muted);">None</span>') +
          '</td>' +
          '<td style="padding:12px 16px;">' +
            (inv.safeguard_hold_reasons 
              ? '<span style="color:#EF4444;font-weight:600;">⚠️ ' + esc(inv.safeguard_hold_reasons) + '</span>' 
              : '<span style="color:#10B981;">🛡️ None</span>') +
          '</td>' +
          '<td style="padding:12px 16px;text-align:right;color:var(--text-muted);font-size:0.75rem;">' +
            (inv.last_scanned_at ? new Date(inv.last_scanned_at).toLocaleString() : 'Recently') +
          '</td>' +
        '</tr>';
    }

    html += '</tbody></table></div>';
    return html;
  }

  function attachEvents(container, policies, expedited, inventory, groups) {
    // Refresh
    const btnRefresh = container.querySelector('#btn-refresh-featureupdates');
    if (btnRefresh) {
      btnRefresh.onclick = () => loadData();
    }

    // Subtab Switching
    container.querySelectorAll('.subtab-btn').forEach(btn => {
      btn.onclick = () => {
        currentTab = btn.getAttribute('data-tab');
        loadData();
      };
    });

    // Create Policy Modal
    const btnCreatePolicy = container.querySelector('#btn-create-feature-policy');
    if (btnCreatePolicy) {
      btnCreatePolicy.onclick = () => openCreatePolicyModal(groups);
    }

    // Create Expedited Modal
    const btnCreateExpedited = container.querySelector('#btn-create-expedited');
    if (btnCreateExpedited) {
      btnCreateExpedited.onclick = () => openCreateExpeditedModal(groups);
    }

    // Inspect Policy Registry Script
    container.querySelectorAll('.btn-inspect-policy').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        const policy = await window.FleetAPI.getFeaturePolicy(id);
        if (policy) openScriptModal('Feature Update Version Lock Script', policy.registry_script || '');
      };
    });

    // Delete Policy
    container.querySelectorAll('.btn-delete-policy').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Delete this feature update profile?')) {
          await window.FleetAPI.deleteFeaturePolicy(id);
          loadData();
        }
      };
    });

    // Inspect Expedited USO Script
    container.querySelectorAll('.btn-inspect-expedited').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        const exp = await window.FleetAPI.getExpeditedUpdate(id);
        if (exp) openScriptModal('Expedited Quality Update Enforcement Script', exp.expedite_script || '');
      };
    });

    // Delete Expedited Campaign
    container.querySelectorAll('.btn-delete-expedited').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Delete this expedited quality update campaign?')) {
          await window.FleetAPI.deleteExpeditedUpdate(id);
          loadData();
        }
      };
    });
  }

  function openScriptModal(title, script) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.7)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';

    overlay.innerHTML = 
      '<div class="modal-card" style="background:var(--card-bg, #1e293b);border-radius:8px;width:90%;max-width:680px;border:1px solid var(--border-color, #334155);overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border-color, #334155);display:flex;justify-content:space-between;align-items:center;">' +
          '<h3 style="margin:0;font-size:1.1rem;font-weight:600;">' + esc(title) + '</h3>' +
          '<button class="btn-close-modal" style="background:none;border:none;color:var(--text-muted);font-size:1.2rem;cursor:pointer;">✕</button>' +
        '</div>' +
        '<div style="padding:20px;">' +
          '<pre style="background:#0f172a;padding:16px;border-radius:6px;overflow-x:auto;font-family:monospace;font-size:0.85rem;color:#38bdf8;max-height:400px;">' +
            esc(script) +
          '</pre>' +
        '</div>' +
        '<div style="padding:12px 20px;background:rgba(0,0,0,0.2);display:flex;justify-content:flex-end;gap:8px;">' +
          '<button class="intune-btn primary btn-copy-script">📋 Copy Script</button>' +
          '<button class="intune-btn btn-close-modal">Close</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    overlay.querySelectorAll('.btn-close-modal').forEach(b => {
      b.onclick = () => overlay.remove();
    });

    const btnCopy = overlay.querySelector('.btn-copy-script');
    if (btnCopy) {
      btnCopy.onclick = () => {
        navigator.clipboard.writeText(script);
        btnCopy.textContent = '✅ Copied!';
        setTimeout(() => { btnCopy.textContent = '📋 Copy Script'; }, 2000);
      };
    }
  }

  function openCreatePolicyModal(groups) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.7)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';

    let groupOptions = '<option value="">All Workstations (Global Fleet)</option>';
    for (const g of groups) {
      groupOptions += '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>';
    }

    overlay.innerHTML = 
      '<div class="modal-card" style="background:var(--card-bg, #1e293b);border-radius:8px;width:90%;max-width:560px;border:1px solid var(--border-color, #334155);overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border-color, #334155);display:flex;justify-content:space-between;align-items:center;">' +
          '<h3 style="margin:0;font-size:1.1rem;font-weight:600;">Create Feature Update Profile</h3>' +
          '<button class="btn-close-modal" style="background:none;border:none;color:var(--text-muted);font-size:1.2rem;cursor:pointer;">✕</button>' +
        '</div>' +
        '<div style="padding:20px;display:flex;flex-direction:column;gap:14px;">' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Profile Name *</label>' +
            '<input type="text" id="pol-name" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="e.g. Production Windows 11 23H2 Target Version">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Description</label>' +
            '<input type="text" id="pol-desc" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="Lock devices to 23H2 build until validation complete">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Target OS Version *</label>' +
            '<select id="pol-target-ver" class="intune-input" style="width:100%;box-sizing:border-box;">' +
              '<option value="Windows 11, version 23H2">Windows 11, version 23H2 (Current Enterprise LTS)</option>' +
              '<option value="Windows 11, version 24H2">Windows 11, version 24H2 (Annual Feature Release)</option>' +
              '<option value="Windows 10, version 22H2">Windows 10, version 22H2 (Legacy Enterprise Pin)</option>' +
            '</select>' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Rollout Cadence</label>' +
            '<select id="pol-rollout" class="intune-input" style="width:100%;box-sizing:border-box;">' +
              '<option value="IMMEDIATELY">Immediately Available via WUfB</option>' +
              '<option value="SCHEDULED">Scheduled Gradually</option>' +
            '</select>' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Target Scope</label>' +
            '<select id="pol-group" class="intune-input" style="width:100%;box-sizing:border-box;">' +
              groupOptions +
            '</select>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:8px;margin-top:4px;">' +
            '<input type="checkbox" id="pol-safeguards" checked style="accent-color:#10B981;">' +
            '<label for="pol-safeguards" style="font-size:0.85rem;">Enforce Microsoft Safeguard Holds (Block updates on incompatible hardware/drivers)</label>' +
          '</div>' +
        '</div>' +
        '<div style="padding:12px 20px;background:rgba(0,0,0,0.2);display:flex;justify-content:flex-end;gap:8px;">' +
          '<button class="intune-btn btn-close-modal">Cancel</button>' +
          '<button class="intune-btn primary" id="btn-submit-policy">Save Profile</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    overlay.querySelectorAll('.btn-close-modal').forEach(b => {
      b.onclick = () => overlay.remove();
    });

    const btnSubmit = overlay.querySelector('#btn-submit-policy');
    if (btnSubmit) {
      btnSubmit.onclick = async () => {
        const name = overlay.querySelector('#pol-name').value.trim();
        const description = overlay.querySelector('#pol-desc').value.trim();
        const target_os_version = overlay.querySelector('#pol-target-ver').value;
        const rollout_type = overlay.querySelector('#pol-rollout').value;
        const target_group_id = overlay.querySelector('#pol-group').value || null;
        const safeguard_holds_enabled = overlay.querySelector('#pol-safeguards').checked ? 1 : 0;

        if (!name) {
          alert('Profile name is required');
          return;
        }

        try {
          await window.FleetAPI.createFeaturePolicy({
            name,
            description,
            target_os_version,
            rollout_type,
            target_group_id,
            safeguard_holds_enabled,
            enabled: 1
          });
          overlay.remove();
          loadData();
        } catch (err) {
          alert('Error saving policy: ' + err.message);
        }
      };
    }
  }

  function openCreateExpeditedModal(groups) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.right = '0';
    overlay.style.bottom = '0';
    overlay.style.background = 'rgba(0,0,0,0.7)';
    overlay.style.display = 'flex';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.zIndex = '9999';

    let groupOptions = '<option value="">All Workstations (Global Fleet)</option>';
    for (const g of groups) {
      groupOptions += '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>';
    }

    overlay.innerHTML = 
      '<div class="modal-card" style="background:var(--card-bg, #1e293b);border-radius:8px;width:90%;max-width:560px;border:1px solid var(--border-color, #334155);overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border-color, #334155);display:flex;justify-content:space-between;align-items:center;">' +
          '<h3 style="margin:0;font-size:1.1rem;font-weight:600;color:#EF4444;">⚡ Expedite Quality Security Update</h3>' +
          '<button class="btn-close-modal" style="background:none;border:none;color:var(--text-muted);font-size:1.2rem;cursor:pointer;">✕</button>' +
        '</div>' +
        '<div style="padding:20px;display:flex;flex-direction:column;gap:14px;">' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Campaign Name *</label>' +
            '<input type="text" id="exp-name" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="e.g. Emergency Out-of-Band RPC Zero-Day Hotfix">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Target KB Number *</label>' +
            '<input type="text" id="exp-kb" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="e.g. KB5044284">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">CVE Reference (Optional)</label>' +
            '<input type="text" id="exp-cve" class="intune-input" style="width:100%;box-sizing:border-box;" placeholder="e.g. CVE-2024-43573">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Days Until Forced Reboot</label>' +
            '<input type="number" id="exp-deadline" class="intune-input" style="width:100%;box-sizing:border-box;" value="1" min="0" max="14">' +
          '</div>' +
          '<div>' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Target Scope</label>' +
            '<select id="exp-group" class="intune-input" style="width:100%;box-sizing:border-box;">' +
              groupOptions +
            '</select>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:8px;margin-top:4px;">' +
            '<input type="checkbox" id="exp-override" checked style="accent-color:#EF4444;">' +
            '<label for="exp-override" style="font-size:0.85rem;">Override Active Hours to immediately trigger USO install</label>' +
          '</div>' +
        '</div>' +
        '<div style="padding:12px 20px;background:rgba(0,0,0,0.2);display:flex;justify-content:flex-end;gap:8px;">' +
          '<button class="intune-btn btn-close-modal">Cancel</button>' +
          '<button class="intune-btn primary" id="btn-submit-expedited" style="background:#EF4444;border-color:#DC2626;">Dispatch Expedited Hotfix</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    overlay.querySelectorAll('.btn-close-modal').forEach(b => {
      b.onclick = () => overlay.remove();
    });

    const btnSubmit = overlay.querySelector('#btn-submit-expedited');
    if (btnSubmit) {
      btnSubmit.onclick = async () => {
        const name = overlay.querySelector('#exp-name').value.trim();
        const target_kb_number = overlay.querySelector('#exp-kb').value.trim();
        const cve_reference = overlay.querySelector('#exp-cve').value.trim();
        const days_until_forced_reboot = parseInt(overlay.querySelector('#exp-deadline').value || '1', 10);
        const target_group_id = overlay.querySelector('#exp-group').value || null;
        const override_active_hours = overlay.querySelector('#exp-override').checked ? 1 : 0;

        if (!name || !target_kb_number) {
          alert('Campaign name and KB number are required');
          return;
        }

        try {
          await window.FleetAPI.createExpeditedUpdate({
            name,
            target_kb_number,
            cve_reference,
            days_until_forced_reboot,
            target_group_id,
            override_active_hours,
            status: 'ACTIVE'
          });
          overlay.remove();
          loadData();
        } catch (err) {
          alert('Error creating expedited update: ' + err.message);
        }
      };
    }
  }

  window.FeatureUpdatesTable = {
    init: loadData,
    render: loadData,
    refresh: loadData
  };

})();
