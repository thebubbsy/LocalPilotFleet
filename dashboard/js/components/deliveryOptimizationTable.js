/**
 * LocalPilot Fleet — Delivery Optimization & Peer-to-Peer Cache Governance Blade
 * dashboard/js/components/deliveryOptimizationTable.js
 */

(function () {
  'use strict';

  let currentTab = 'policies'; // 'policies' | 'inventory' | 'content-log'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function getModeBadge(mode) {
    const map = {
      LAN_PEER:       { bg: 'rgba(16,185,129,0.15)', text: '#10B981', label: '🏢 LAN Peering (Mode 1)' },
      GROUP_PEER:     { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '👥 Group Peering (Mode 2)' },
      INTERNET_PEER:  { bg: 'rgba(139,92,246,0.15)', text: '#A78BFA', label: '🌐 Internet Peering (Mode 3)' },
      HTTP_ONLY:      { bg: 'rgba(245,158,11,0.15)', text: '#F59E0B', label: '☁️ HTTP Only (Mode 0)' },
      BYPASS:         { bg: 'rgba(239,68,68,0.15)', text: '#EF4444', label: '⚡ Bypass (Mode 100)' },
      SIMPLE:         { bg: 'rgba(100,116,139,0.15)', text: '#94A3B8', label: '🔄 Simple (Mode 99)' }
    };
    const c = map[mode] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: mode || 'Unknown' };
    return '<span class="badge" style="background:' + c.bg + ';color:' + c.text + ';font-weight:600;">' + c.label + '</span>';
  }

  function getEfficiencyBadge(pct) {
    const p = Number(pct) || 0;
    let bg = 'rgba(239,68,68,0.15)';
    let text = '#EF4444';
    if (p >= 50) {
      bg = 'rgba(16,185,129,0.15)';
      text = '#10B981';
    } else if (p >= 20) {
      bg = 'rgba(245,158,11,0.15)';
      text = '#F59E0B';
    }
    return '<span class="badge" style="background:' + bg + ';color:' + text + ';font-weight:700;">' + p.toFixed(1) + '% P2P</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-delivery-optimization');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Delivery Optimization &amp; Peer-to-Peer Posture…</span>' +
      '</div>';

    try {
      const [stats, policiesData, inventoryData, contentData, groupsData] = await Promise.all([
        window.FleetAPI.getDOStats().catch(() => ({})),
        window.FleetAPI.getDOPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getDOInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getDOContentLog().catch(() => ({ logs: [] })),
        window.FleetAPI.getDynamicGroups().catch(() => [])
      ]);

      const policies = policiesData.policies || [];
      const inventory = inventoryData.inventory || [];
      const logs = contentData.logs || [];
      const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      renderView(container, stats, policies, inventory, logs, groups);
    } catch (err) {
      container.innerHTML = 
        '<div style="padding:24px;color:#EF4444;">' +
          '<h3>⚠️ Error loading Delivery Optimization</h3>' +
          '<p>' + esc(err.message) + '</p>' +
          '<button class="intune-btn intune-btn-secondary" onclick="window.DeliveryOptimizationTable.init()">Retry</button>' +
        '</div>';
    }
  }

  function renderView(container, stats, policies, inventory, logs, groups) {
    const totalAudited = stats.total_audited_devices || 0;
    const totalFleet = stats.total_devices_in_fleet || 0;
    const efficiencyPct = Number(stats.fleet_p2p_efficiency_pct) || 0.0;
    const p2pGb = stats.total_p2p_downloaded_gb || 0.0;
    const activePeers = stats.active_peering_devices || 0;

    container.innerHTML = 
      '<div style="padding:24px;display:flex;flex-direction:column;gap:20px;">' +
        '<!-- Header -->' +
        '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">' +
          '<div>' +
            '<h2 style="margin:0;font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px;">' +
              '<span>🚀 Delivery Optimization &amp; Peer-to-Peer Cache Governance</span>' +
            '</h2>' +
            '<p style="margin:4px 0 0 0;color:var(--text-muted);font-size:13px;">' +
              'Enterprise Windows Delivery Optimization (DO) peer-to-peer distribution, cache sizing, upload throttling, and WAN bandwidth offload.' +
            '</p>' +
          '</div>' +
          '<div style="display:flex;gap:10px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="window.DeliveryOptimizationTable.init()">' +
              '🔄 Refresh' +
            '</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="window.DeliveryOptimizationTable.openCreateModal()">' +
              '+ Create DO Policy' +
            '</button>' +
          '</div>' +
        '</div>' +

        '<!-- KPI Cards Row -->' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;">' +
          '<div class="kpi-card" style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Audited Workstations</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:var(--text-main);">' +
              totalAudited + ' <span style="font-size:14px;color:var(--text-muted);font-weight:normal;">/ ' + totalFleet + ' devices</span>' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Workstations with active DO telemetry</div>' +
          '</div>' +

          '<div class="kpi-card" style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">P2P WAN Offload Efficiency</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:#10B981;">' +
              efficiencyPct.toFixed(1) + '%' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Portion of updates served locally by peers</div>' +
          '</div>' +

          '<div class="kpi-card" style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Local Cache Data Saved</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:#60A5FA;">' +
              p2pGb.toFixed(2) + ' GB' +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">WAN bandwidth eliminated by local peering</div>' +
          '</div>' +

          '<div class="kpi-card" style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;padding:16px;">' +
            '<div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Active Swarm Peering Nodes</div>' +
            '<div style="font-size:24px;font-weight:700;margin-top:6px;color:#A78BFA;">' +
              activePeers +
            '</div>' +
            '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Devices actively peering with other nodes</div>' +
          '</div>' +
        '</div>' +

        '<!-- Navigation Tabs -->' +
        '<div style="border-bottom:1px solid var(--border-color);display:flex;gap:24px;">' +
          '<button class="tab-link ' + (currentTab === 'policies' ? 'active' : '') + '" ' +
                  'style="background:none;border:none;padding:8px 0;font-size:14px;font-weight:600;cursor:pointer;border-bottom:' + (currentTab === 'policies' ? '2px solid var(--primary)' : '2px solid transparent') + ';color:' + (currentTab === 'policies' ? 'var(--primary)' : 'var(--text-muted)') + ';" ' +
                  'onclick="window.DeliveryOptimizationTable.switchTab(\'policies\')">' +
            '📋 Delivery Optimization Policies (' + policies.length + ')' +
          '</button>' +
          '<button class="tab-link ' + (currentTab === 'inventory' ? 'active' : '') + '" ' +
                  'style="background:none;border:none;padding:8px 0;font-size:14px;font-weight:600;cursor:pointer;border-bottom:' + (currentTab === 'inventory' ? '2px solid var(--primary)' : '2px solid transparent') + ';color:' + (currentTab === 'inventory' ? 'var(--primary)' : 'var(--text-muted)') + ';" ' +
                  'onclick="window.DeliveryOptimizationTable.switchTab(\'inventory\')">' +
            '💻 Workstations Peering Posture (' + inventory.length + ')' +
          '</button>' +
          '<button class="tab-link ' + (currentTab === 'content-log' ? 'active' : '') + '" ' +
                  'style="background:none;border:none;padding:8px 0;font-size:14px;font-weight:600;cursor:pointer;border-bottom:' + (currentTab === 'content-log' ? '2px solid var(--primary)' : '2px solid transparent') + ';color:' + (currentTab === 'content-log' ? 'var(--primary)' : 'var(--text-muted)') + ';" ' +
                  'onclick="window.DeliveryOptimizationTable.switchTab(\'content-log\')">' +
            '📦 Content Delivery Log (' + logs.length + ')' +
          '</button>' +
        '</div>' +

        '<!-- Tab Content Views -->' +
        '<div id="do-tab-body">' +
          (currentTab === 'policies' ? renderPoliciesTab(policies) : '') +
          (currentTab === 'inventory' ? renderInventoryTab(inventory) : '') +
          (currentTab === 'content-log' ? renderContentLogTab(logs) : '') +
        '</div>' +
      '</div>';
  }

  function renderPoliciesTab(policies) {
    if (policies.length === 0) {
      return (
        '<div style="text-align:center;padding:48px;background:var(--bg-surface);border:1px dashed var(--border-color);border-radius:8px;">' +
          '<p style="color:var(--text-muted);margin-bottom:16px;">No Delivery Optimization policies configured yet.</p>' +
          '<button class="intune-btn intune-btn-primary" onclick="window.DeliveryOptimizationTable.openCreateModal()">' +
            'Create First DO Policy' +
          '</button>' +
        '</div>'
      );
    }

    return (
      '<div style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Policy Name</th>' +
              '<th style="padding:12px 16px;">Download Mode</th>' +
              '<th style="padding:12px 16px;">Target Group</th>' +
              '<th style="padding:12px 16px;">Max Cache</th>' +
              '<th style="padding:12px 16px;">Upload Cap</th>' +
              '<th style="padding:12px 16px;">Retention</th>' +
              '<th style="padding:12px 16px;">Assigned</th>' +
              '<th style="padding:12px 16px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' +
            policies.map(p => 
              '<tr style="border-bottom:1px solid var(--border-color);">' +
                '<td style="padding:12px 16px;">' +
                  '<div style="font-weight:600;color:var(--text-main);">' + esc(p.name) + '</div>' +
                  '<div style="font-size:11px;color:var(--text-muted);">' + esc(p.description || 'No description') + '</div>' +
                '</td>' +
                '<td style="padding:12px 16px;">' +
                  getModeBadge(p.download_mode) +
                  (p.group_id_guid ? '<div style="font-size:10px;color:var(--text-muted);margin-top:3px;font-family:monospace;">GUID: ' + esc(p.group_id_guid.substring(0, 18)) + '…</div>' : '') +
                '</td>' +
                '<td style="padding:12px 16px;">' +
                  '<span class="badge" style="background:rgba(59,130,246,0.1);color:#60A5FA;">' +
                    esc(p.target_group_name || p.target_group_id) +
                  '</span>' +
                '</td>' +
                '<td style="padding:12px 16px;">' + p.max_cache_size_pct + '% disk</td>' +
                '<td style="padding:12px 16px;">' + (p.monthly_upload_cap_gb > 0 ? p.monthly_upload_cap_gb + ' GB/mo' : 'Unlimited') + '</td>' +
                '<td style="padding:12px 16px;">' + p.cache_retention_days + ' days</td>' +
                '<td style="padding:12px 16px;">' +
                  '<span class="badge" style="background:rgba(100,116,139,0.15);color:var(--text-main);">' +
                    (p.assigned_devices_count || 0) + ' devices' +
                  '</span>' +
                '</td>' +
                '<td style="padding:12px 16px;text-align:right;">' +
                  '<button class="intune-btn intune-btn-secondary" style="font-size:11px;padding:4px 8px;margin-right:4px;" ' +
                          'onclick="window.DeliveryOptimizationTable.openScriptModal(\'' + esc(p.id) + '\')">' +
                    '📜 PowerShell' +
                  '</button>' +
                  '<button class="intune-btn intune-btn-secondary" style="font-size:11px;padding:4px 8px;margin-right:4px;" ' +
                          'onclick="window.DeliveryOptimizationTable.openEditModal(\'' + esc(p.id) + '\')">' +
                    '✏️ Edit' +
                  '</button>' +
                  '<button class="intune-btn intune-btn-danger" style="font-size:11px;padding:4px 8px;" ' +
                          'onclick="window.DeliveryOptimizationTable.deletePolicy(\'' + esc(p.id) + '\')">' +
                    '🗑️ Delete' +
                  '</button>' +
                '</td>' +
              '</tr>'
            ).join('') +
          '</tbody>' +
        '</table>' +
      '</div>'
    );
  }

  function renderInventoryTab(inventory) {
    if (inventory.length === 0) {
      return (
        '<div style="text-align:center;padding:48px;background:var(--bg-surface);border:1px dashed var(--border-color);border-radius:8px;">' +
          '<p style="color:var(--text-muted);">No workstation Delivery Optimization posture audited yet.</p>' +
        '</div>'
      );
    }

    return (
      '<div style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Workstation</th>' +
              '<th style="padding:12px 16px;">Active Mode</th>' +
              '<th style="padding:12px 16px;">P2P Efficiency</th>' +
              '<th style="padding:12px 16px;">Downloaded (Peers)</th>' +
              '<th style="padding:12px 16px;">Downloaded (CDN)</th>' +
              '<th style="padding:12px 16px;">Active Peers</th>' +
              '<th style="padding:12px 16px;">Local Cache</th>' +
              '<th style="padding:12px 16px;">Last Audit</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' +
            inventory.map(d => 
              '<tr style="border-bottom:1px solid var(--border-color);">' +
                '<td style="padding:12px 16px;">' +
                  '<div style="font-weight:600;color:var(--text-main);">' + esc(d.hostname || d.device_id) + '</div>' +
                  '<div style="font-size:11px;color:var(--text-muted);font-family:monospace;">' + esc(d.device_id.substring(0, 16)) + '…</div>' +
                '</td>' +
                '<td style="padding:12px 16px;">' + getModeBadge(d.download_mode_active) + '</td>' +
                '<td style="padding:12px 16px;">' + getEfficiencyBadge(d.p2p_efficiency_pct) + '</td>' +
                '<td style="padding:12px 16px;color:#10B981;font-weight:600;">' + formatBytes(d.bytes_downloaded_p2p) + '</td>' +
                '<td style="padding:12px 16px;color:var(--text-muted);">' + formatBytes(d.bytes_downloaded_http) + '</td>' +
                '<td style="padding:12px 16px;">' +
                  '<span class="badge" style="background:rgba(139,92,246,0.15);color:#A78BFA;font-weight:600;">' +
                    '👥 ' + (d.active_peers_count || 0) + ' peers' +
                  '</span>' +
                '</td>' +
                '<td style="padding:12px 16px;">' + formatBytes(d.cache_size_bytes) + ' (' + (d.cache_file_count || 0) + ' files)</td>' +
                '<td style="padding:12px 16px;color:var(--text-muted);font-size:11px;">' +
                  (d.last_audit_at ? new Date(d.last_audit_at).toLocaleTimeString() : 'Never') +
                '</td>' +
              '</tr>'
            ).join('') +
          '</tbody>' +
        '</table>' +
      '</div>'
    );
  }

  function renderContentLogTab(logs) {
    if (logs.length === 0) {
      return (
        '<div style="text-align:center;padding:48px;background:var(--bg-surface);border:1px dashed var(--border-color);border-radius:8px;">' +
          '<p style="color:var(--text-muted);">No package delivery transfer events recorded yet.</p>' +
        '</div>'
      );
    }

    return (
      '<div style="background:var(--bg-surface);border:1px solid var(--border-color);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">' +
          '<thead>' +
            '<tr style="border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<th style="padding:12px 16px;">Timestamp</th>' +
              '<th style="padding:12px 16px;">Workstation</th>' +
              '<th style="padding:12px 16px;">Content Type</th>' +
              '<th style="padding:12px 16px;">File Size</th>' +
              '<th style="padding:12px 16px;">From Peers</th>' +
              '<th style="padding:12px 16px;">From CDN / HTTP</th>' +
              '<th style="padding:12px 16px;">Peer IP</th>' +
              '<th style="padding:12px 16px;">Duration</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' +
            logs.map(l => {
              const total = (l.bytes_from_peers || 0) + (l.bytes_from_http || 0);
              const p2pPct = total > 0 ? ((l.bytes_from_peers / total) * 100).toFixed(0) : 0;
              return (
                '<tr style="border-bottom:1px solid var(--border-color);">' +
                  '<td style="padding:12px 16px;color:var(--text-muted);font-size:11px;">' +
                    (l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : 'N/A') +
                  '</td>' +
                  '<td style="padding:12px 16px;font-weight:600;">' + esc(l.hostname || l.device_id) + '</td>' +
                  '<td style="padding:12px 16px;">' +
                    '<span class="badge" style="background:rgba(59,130,246,0.1);color:#60A5FA;">' +
                      esc(l.content_type || 'MSI_PAYLOAD') +
                    '</span>' +
                  '</td>' +
                  '<td style="padding:12px 16px;font-weight:600;">' + formatBytes(l.file_size_bytes) + '</td>' +
                  '<td style="padding:12px 16px;color:#10B981;font-weight:600;">' +
                    formatBytes(l.bytes_from_peers) + ' (' + p2pPct + '%)' +
                  '</td>' +
                  '<td style="padding:12px 16px;color:var(--text-muted);">' + formatBytes(l.bytes_from_http) + '</td>' +
                  '<td style="padding:12px 16px;font-family:monospace;font-size:11px;">' + esc(l.peer_source_ip || 'None') + '</td>' +
                  '<td style="padding:12px 16px;color:var(--text-muted);">' + (l.duration_ms ? (l.duration_ms / 1000).toFixed(1) + 's' : 'N/A') + '</td>' +
                '</tr>'
              );
            }).join('') +
          '</tbody>' +
        '</table>' +
      '</div>'
    );
  }

  function switchTab(tab) {
    currentTab = tab;
    loadData();
  }

  async function openCreateModal(preset = 'lan') {
    const groupsData = await window.FleetAPI.getDynamicGroups().catch(() => []);
    const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

    let defaultName = 'Corporate LAN Peering Policy';
    let defaultDesc = 'Peer-to-peer cache sharing over local subnet';
    let defaultMode = 'LAN_PEER';
    let defaultCachePct = 30;
    let defaultRetention = 14;
    let defaultGuid = '';
    let defaultUploadCap = 0;
    let defaultUploadLimit = 0;

    if (preset === 'branch') {
      defaultName = 'Branch Office Bandwidth Saver';
      defaultDesc = 'Restricted domain group peering with bandwidth cap';
      defaultMode = 'GROUP_PEER';
      defaultCachePct = 40;
      defaultRetention = 21;
      defaultGuid = '9a369888-9d7e-46f3-9999-7ef827dc7f93';
      defaultUploadLimit = 5120;
      defaultUploadCap = 25;
    } else if (preset === 'direct') {
      defaultName = 'Direct CDN / HTTP Bypass';
      defaultDesc = 'Bypass P2P and download directly from Microsoft CDN';
      defaultMode = 'HTTP_ONLY';
      defaultCachePct = 0;
      defaultRetention = 1;
      defaultGuid = '';
      defaultUploadCap = 0;
      defaultUploadLimit = 0;
    }

    const modal = document.createElement('div');
    modal.className = 'intune-modal-backdrop';
    modal.innerHTML = 
      '<div class="intune-modal" style="max-width:640px;padding:24px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
          '<h3 style="margin:0;font-size:18px;">🚀 Create Delivery Optimization Policy</h3>' +
          '<button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest(\.intune-modal-backdrop\).remove()">✕</button>' +
        '</div>' +

        '<div style="margin-bottom:16px;">' +
          '<label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px;">POLICY PRESETS</label>' +
          '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
            '<button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DeliveryOptimizationTable.openCreateModal(\'lan\')">' +
              '🏢 Corporate LAN Peering' +
            '</button>' +
            '<button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DeliveryOptimizationTable.openCreateModal(\'branch\')">' +
              '👥 Branch Office Bandwidth Saver' +
            '</button>' +
            '<button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.DeliveryOptimizationTable.openCreateModal(\'direct\')">' +
              '☁️ Direct CDN Bypass' +
            '</button>' +
          '</div>' +
        '</div>' +

        '<form id="create-do-policy-form" style="display:flex;flex-direction:column;gap:14px;">' +
          '<div>' +
            '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>' +
            '<input type="text" name="name" class="intune-input" style="width:100%;" required value="' + esc(defaultName) + '" />' +
          '</div>' +

          '<div>' +
            '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>' +
            '<input type="text" name="description" class="intune-input" style="width:100%;" value="' + esc(defaultDesc) + '" />' +
          '</div>' +

          '<div>' +
            '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>' +
            '<select name="target_group_id" class="intune-input" style="width:100%;">' +
              '<option value="grp-all">All Workstations (grp-all)</option>' +
              groups.map(g => '<option value="' + g.id + '">' + esc(g.name) + '</option>').join('') +
            '</select>' +
          '</div>' +

          '<div>' +
            '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Download Mode</label>' +
            '<select name="download_mode" class="intune-input" style="width:100%;" onchange="' +
              'const guidDiv = this.form.querySelector(\'#guid-container\');' +
              'if (this.value === \'GROUP_PEER\') { guidDiv.style.display = \'block\'; } else { guidDiv.style.display = \'none\'; }' +
            '">' +
              '<option value="LAN_PEER" ' + (defaultMode === 'LAN_PEER' ? 'selected' : '') + '>🏢 LAN Peering (Mode 1) - Subnet Peers Only</option>' +
              '<option value="GROUP_PEER" ' + (defaultMode === 'GROUP_PEER' ? 'selected' : '') + '>👥 Group Peering (Mode 2) - Domain / Site GUID Peers</option>' +
              '<option value="INTERNET_PEER" ' + (defaultMode === 'INTERNET_PEER' ? 'selected' : '') + '>🌐 Internet Peering (Mode 3) - Public Peer Swarm</option>' +
              '<option value="HTTP_ONLY" ' + (defaultMode === 'HTTP_ONLY' ? 'selected' : '') + '>☁️ HTTP Only (Mode 0) - Direct CDN Only</option>' +
              '<option value="BYPASS" ' + (defaultMode === 'BYPASS' ? 'selected' : '') + '>⚡ Bypass (Mode 100) - BITS Fallback</option>' +
            '</select>' +
          '</div>' +

          '<div id="guid-container" style="display:' + (defaultMode === 'GROUP_PEER' ? 'block' : 'none') + ';">' +
            '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Group ID GUID (for Mode 2)</label>' +
            '<input type="text" name="group_id_guid" class="intune-input" style="width:100%;" value="' + esc(defaultGuid) + '" placeholder="e.g. 9a369888-9d7e-46f3-9999-7ef827dc7f93" />' +
          '</div>' +

          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Max Cache Size (% of Disk)</label>' +
              '<input type="number" name="max_cache_size_pct" class="intune-input" style="width:100%;" min="0" max="100" value="' + defaultCachePct + '" />' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Cache Retention (Days)</label>' +
              '<input type="number" name="cache_retention_days" class="intune-input" style="width:100%;" min="1" max="90" value="' + defaultRetention + '" />' +
            '</div>' +
          '</div>' +

          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Max Upload Limit (KB/s)</label>' +
              '<input type="number" name="max_upload_bandwidth_kbps" class="intune-input" style="width:100%;" min="0" value="' + defaultUploadLimit + '" placeholder="0 for unlimited" />' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Monthly Upload Cap (GB)</label>' +
              '<input type="number" name="monthly_upload_cap_gb" class="intune-input" style="width:100%;" min="0" value="' + defaultUploadCap + '" placeholder="0 for unlimited" />' +
            '</div>' +
          '</div>' +

          '<div style="display:flex;justify-content:flex-end;gap:10px;margin-top:8px;">' +
            '<button type="button" class="intune-btn intune-btn-secondary" onclick="this.closest(\.intune-modal-backdrop\).remove()">Cancel</button>' +
            '<button type="submit" class="intune-btn intune-btn-primary">Create Policy</button>' +
          '</div>' +
        '</form>' +
      '</div>';

    document.body.appendChild(modal);

    const form = modal.querySelector('#create-do-policy-form');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const payload = {
        name: fd.get('name'),
        description: fd.get('description'),
        target_group_id: fd.get('target_group_id') || 'grp-all',
        download_mode: fd.get('download_mode'),
        group_id_guid: fd.get('group_id_guid') || '',
        max_cache_size_pct: Number(fd.get('max_cache_size_pct')) || 20,
        cache_retention_days: Number(fd.get('cache_retention_days')) || 7,
        max_upload_bandwidth_kbps: Number(fd.get('max_upload_bandwidth_kbps')) || 0,
        monthly_upload_cap_gb: Number(fd.get('monthly_upload_cap_gb')) || 0,
        enabled: 1
      };

      try {
        await window.FleetAPI.createDOPolicy(payload);
        modal.remove();
        loadData();
      } catch (err) {
        alert('Error creating policy: ' + err.message);
      }
    });
  }

  async function openEditModal(id) {
    try {
      const policy = await window.FleetAPI.getDOPolicy(id);
      const groupsData = await window.FleetAPI.getDynamicGroups().catch(() => []);
      const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      const modal = document.createElement('div');
      modal.className = 'intune-modal-backdrop';
      modal.innerHTML = 
        '<div class="intune-modal" style="max-width:640px;padding:24px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<h3 style="margin:0;font-size:18px;">✏️ Edit Delivery Optimization Policy</h3>' +
            '<button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest(\.intune-modal-backdrop\).remove()">✕</button>' +
          '</div>' +

          '<form id="edit-do-policy-form" style="display:flex;flex-direction:column;gap:14px;">' +
            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>' +
              '<input type="text" name="name" class="intune-input" style="width:100%;" required value="' + esc(policy.name) + '" />' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>' +
              '<input type="text" name="description" class="intune-input" style="width:100%;" value="' + esc(policy.description || '') + '" />' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>' +
              '<select name="target_group_id" class="intune-input" style="width:100%;">' +
                '<option value="grp-all" ' + (policy.target_group_id === 'grp-all' ? 'selected' : '') + '>All Workstations (grp-all)</option>' +
                groups.map(g => '<option value="' + g.id + '" ' + (policy.target_group_id === g.id ? 'selected' : '') + '>' + esc(g.name) + '</option>').join('') +
              '</select>' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Download Mode</label>' +
              '<select name="download_mode" class="intune-input" style="width:100%;">' +
                '<option value="LAN_PEER" ' + (policy.download_mode === 'LAN_PEER' ? 'selected' : '') + '>🏢 LAN Peering (Mode 1)</option>' +
                '<option value="GROUP_PEER" ' + (policy.download_mode === 'GROUP_PEER' ? 'selected' : '') + '>👥 Group Peering (Mode 2)</option>' +
                '<option value="INTERNET_PEER" ' + (policy.download_mode === 'INTERNET_PEER' ? 'selected' : '') + '>🌐 Internet Peering (Mode 3)</option>' +
                '<option value="HTTP_ONLY" ' + (policy.download_mode === 'HTTP_ONLY' ? 'selected' : '') + '>☁️ HTTP Only (Mode 0)</option>' +
                '<option value="BYPASS" ' + (policy.download_mode === 'BYPASS' ? 'selected' : '') + '>⚡ Bypass (Mode 100)</option>' +
              '</select>' +
            '</div>' +

            '<div>' +
              '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Group ID GUID</label>' +
              '<input type="text" name="group_id_guid" class="intune-input" style="width:100%;" value="' + esc(policy.group_id_guid || '') + '" />' +
            '</div>' +

            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Max Cache Size (%)</label>' +
                '<input type="number" name="max_cache_size_pct" class="intune-input" style="width:100%;" min="0" max="100" value="' + (policy.max_cache_size_pct || 20) + '" />' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Cache Retention (Days)</label>' +
                '<input type="number" name="cache_retention_days" class="intune-input" style="width:100%;" min="1" max="90" value="' + (policy.cache_retention_days || 7) + '" />' +
              '</div>' +
            '</div>' +

            '<div style="display:flex;justify-content:flex-end;gap:10px;margin-top:8px;">' +
              '<button type="button" class="intune-btn intune-btn-secondary" onclick="this.closest(\.intune-modal-backdrop\).remove()">Cancel</button>' +
              '<button type="submit" class="intune-btn intune-btn-primary">Save Changes</button>' +
            '</div>' +
          '</form>' +
        '</div>';

      document.body.appendChild(modal);

      const form = modal.querySelector('#edit-do-policy-form');
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        const payload = {
          name: fd.get('name'),
          description: fd.get('description'),
          target_group_id: fd.get('target_group_id'),
          download_mode: fd.get('download_mode'),
          group_id_guid: fd.get('group_id_guid') || '',
          max_cache_size_pct: Number(fd.get('max_cache_size_pct')) || 20,
          cache_retention_days: Number(fd.get('cache_retention_days')) || 7
        };

        try {
          await window.FleetAPI.updateDOPolicy(id, payload);
          modal.remove();
          loadData();
        } catch (err) {
          alert('Error updating policy: ' + err.message);
        }
      });
    } catch (err) {
      alert('Error fetching policy details: ' + err.message);
    }
  }

  async function openScriptModal(id) {
    try {
      const policy = await window.FleetAPI.getDOPolicy(id);
      const script = policy.powershell_script || '# No script available';

      const modal = document.createElement('div');
      modal.className = 'intune-modal-backdrop';
      modal.innerHTML = 
        '<div class="intune-modal" style="max-width:720px;padding:24px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<h3 style="margin:0;font-size:18px;">📜 PowerShell Registry Policy Script</h3>' +
            '<button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest(\.intune-modal-backdrop\).remove()">✕</button>' +
          '</div>' +
          '<p style="font-size:12px;color:var(--text-muted);margin:0 0 12px 0;">' +
            'This PowerShell script applies native Delivery Optimization policies to <code>HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization</code>.' +
          '</p>' +
          '<pre style="background:var(--bg-subtle);border:1px solid var(--border-color);border-radius:6px;padding:14px;font-family:monospace;font-size:12px;max-height:360px;overflow-y:auto;white-space:pre-wrap;margin:0 0 16px 0;">' + esc(script) + '</pre>' +
          '<div style="display:flex;justify-content:flex-end;gap:10px;">' +
            '<button class="intune-btn intune-btn-secondary" onclick="navigator.clipboard.writeText(' + JSON.stringify(script) + '); alert(\'PowerShell script copied to clipboard!\');">' +
              '📋 Copy Script' +
            '</button>' +
            '<button class="intune-btn intune-btn-primary" onclick="this.closest(\.intune-modal-backdrop\).remove()">' +
              'Close' +
            '</button>' +
          '</div>' +
        '</div>';
      document.body.appendChild(modal);
    } catch (err) {
      alert('Error loading script: ' + err.message);
    }
  }

  async function deletePolicy(id) {
    if (!confirm('Are you sure you want to delete this Delivery Optimization policy?')) return;
    try {
      await window.FleetAPI.deleteDOPolicy(id);
      loadData();
    } catch (err) {
      alert('Error deleting policy: ' + err.message);
    }
  }

  window.DeliveryOptimizationTable = {
    init: loadData,
    refresh: loadData,
    switchTab,
    openCreateModal,
    openEditModal,
    openScriptModal,
    deletePolicy
  };
})();
