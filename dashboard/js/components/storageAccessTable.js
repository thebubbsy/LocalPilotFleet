/**
 * LocalPilot Fleet — Removable Storage Access Control & USB Peripheral Governance Blade
 * dashboard/js/components/storageAccessTable.js
 */

(function () {
  'use strict';

  let currentTab = 'policies'; // 'policies' | 'inventory' | 'events'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getAccessBadge(mode) {
    const map = {
      DENY_ALL:          { bg: 'rgba(239,68,68,0.15)', text: '#EF4444', label: '🚫 Block All Disks' },
      DENY_UNENCRYPTED:  { bg: 'rgba(245,158,11,0.15)', text: '#F59E0B', label: '🔐 BitLocker To Go Only' },
      READ_ONLY:         { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '📖 Read-Only Access' },
      ALLOW_ALL:         { bg: 'rgba(16,185,129,0.15)', text: '#10B981', label: '✅ Permissive' }
    };
    const c = map[mode] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: mode };
    return `<span class="badge" style="background:${c.bg};color:${c.text};font-weight:600;">${c.label}</span>`;
  }

  function getComplianceBadge(status) {
    if (status === 'COMPLIANT') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">✅ Compliant</span>';
    }
    if (status === 'UNENCRYPTED_USB_DETECTED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:600;">⚠️ Unencrypted USB</span>';
    }
    if (status === 'WRITE_DENIED_ENFORCED') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;font-weight:600;">🔒 Write Blocked</span>';
    }
    return '<span class="badge" style="background:rgba(100,116,139,0.15);color:#94A3B8;font-weight:500;">Unknown</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-storage');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Removable Storage &amp; USB Peripheral Governance Posture…</span>
      </div>
    `;

    try {
      const [stats, policiesData, inventoryData, eventsData, groupsData] = await Promise.all([
        window.FleetAPI.getStorageStats().catch(() => ({})),
        window.FleetAPI.getStoragePolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getStorageInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getStorageEvents().catch(() => ({ events: [] })),
        window.FleetAPI.getGroups().catch(() => ({ groups: [] }))
      ]);

      renderBlade(container, {
        stats,
        policies: policiesData.policies || [],
        inventory: inventoryData.inventory || [],
        events: eventsData.events || [],
        groups: groupsData.groups || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:var(--accent-red);">
          <h3>Error loading Removable Storage Governance</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.StorageAccessTable.init()">Retry</button>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const { stats, policies, inventory, events, groups } = data;

    container.innerHTML = `
      <div style="padding:20px;max-width:1400px;margin:0 auto;">
        <!-- Header Ribbon -->
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
          <div>
            <h2 style="margin:0;font-size:20px;font-weight:600;display:flex;align-items:center;gap:8px;">
              <span>💾</span> Removable Storage Access Control &amp; USB Governance
            </h2>
            <p style="margin:4px 0 0;font-size:13px;color:var(--text-muted);">
              Enforce BitLocker To Go on USB drives, prevent unencrypted data exfiltration, lock down WPD phones, and monitor peripheral insertions across the Windows fleet.
            </p>
          </div>
          <div style="display:flex;gap:10px;">
            <button class="intune-btn intune-btn-secondary" onclick="window.StorageAccessTable.init()">
              🔄 Refresh
            </button>
            <button class="intune-btn intune-btn-primary" onclick="window.StorageAccessTable.openCreateModal()">
              + New Storage Policy
            </button>
          </div>
        </div>

        <!-- 4 KPI Cards -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px;">
          <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Storage Policies</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:var(--accent-blue);">${stats.total_policies || 0}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${stats.enabled_policies || 0} active policies</div>
          </div>
          <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Audited Workstations</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:var(--accent-green);">${stats.total_audited_devices || 0}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${stats.compliant_devices || 0} compliant</div>
          </div>
          <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Unencrypted USB Alerts</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:${(stats.unencrypted_usb_alerts || 0) > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">
              ${stats.unencrypted_usb_alerts || 0}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Drives at risk of data leakage</div>
          </div>
          <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Write Block Enforced</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:var(--accent-purple);">${stats.write_denied_devices || 0}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Workstations in Read-Only mode</div>
          </div>
        </div>

        <!-- Navigation Tabs -->
        <div style="display:flex;border-bottom:1px solid var(--border-color);margin-bottom:20px;gap:8px;">
          <button class="tab-button ${currentTab === 'policies' ? 'active' : ''}" 
                  style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${currentTab === 'policies' ? 'var(--accent-blue)' : 'transparent'};color:${currentTab === 'policies' ? 'var(--text-primary)' : 'var(--text-muted)'};font-weight:600;cursor:pointer;"
                  onclick="window.StorageAccessTable.switchTab('policies')">
            🛡️ Storage Policies (${policies.length})
          </button>
          <button class="tab-button ${currentTab === 'inventory' ? 'active' : ''}" 
                  style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${currentTab === 'inventory' ? 'var(--accent-blue)' : 'transparent'};color:${currentTab === 'inventory' ? 'var(--text-primary)' : 'var(--text-muted)'};font-weight:600;cursor:pointer;"
                  onclick="window.StorageAccessTable.switchTab('inventory')">
            💻 Workstation Posture (${inventory.length})
          </button>
          <button class="tab-button ${currentTab === 'events' ? 'active' : ''}" 
                  style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${currentTab === 'events' ? 'var(--accent-blue)' : 'transparent'};color:${currentTab === 'events' ? 'var(--text-primary)' : 'var(--text-muted)'};font-weight:600;cursor:pointer;"
                  onclick="window.StorageAccessTable.switchTab('events')">
            📋 Peripheral Event Ledger (${events.length})
          </button>
        </div>

        <!-- Tab Content -->
        <div id="storage-tab-content">
          ${currentTab === 'policies' ? renderPoliciesTab(policies) : 
            currentTab === 'inventory' ? renderInventoryTab(inventory) : 
            renderEventsTab(events)}
        </div>
      </div>
    `;

    window._storageAccessData = data;
  }

  function renderPoliciesTab(policies) {
    if (!policies || policies.length === 0) {
      return `
        <div style="padding:40px;text-align:center;color:var(--text-muted);border:1px dashed var(--border-color);border-radius:8px;">
          <div style="font-size:32px;margin-bottom:8px;">💾</div>
          <div style="font-weight:600;font-size:16px;">No Removable Storage Policies Defined</div>
          <p style="font-size:13px;margin:8px 0 16px;">Create a policy to require BitLocker To Go or enforce read-only access on USB drives.</p>
          <button class="intune-btn intune-btn-primary" onclick="window.StorageAccessTable.openCreateModal()">
            + Create First Policy
          </button>
        </div>
      `;
    }

    return `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="background:var(--bg-subtle);border-bottom:1px solid var(--border-color);color:var(--text-muted);">
              <th style="padding:12px 16px;">Policy Name</th>
              <th style="padding:12px 16px;">Target Group</th>
              <th style="padding:12px 16px;">Disk Access</th>
              <th style="padding:12px 16px;">BitLocker To Go</th>
              <th style="padding:12px 16px;">Peripheral Blocks</th>
              <th style="padding:12px 16px;">Status</th>
              <th style="padding:12px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${policies.map(p => `
              <tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-primary);">${esc(p.name)}</div>
                  <div style="font-size:12px;color:var(--text-muted);">${esc(p.description || 'No description')}</div>
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;">${esc(p.target_group_name || p.target_group_id || 'All Devices')}</span>
                </td>
                <td style="padding:12px 16px;">
                  ${getAccessBadge(p.removable_disk_access)}
                </td>
                <td style="padding:12px 16px;">
                  ${p.require_bitlocker_to_go ? '<span style="color:var(--accent-green);font-weight:600;">🔒 Required</span>' : '<span style="color:var(--text-muted);">Optional</span>'}
                </td>
                <td style="padding:12px 16px;">
                  <div style="display:flex;gap:6px;flex-wrap:wrap;">
                    ${p.block_wpd_devices ? '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;">No MTP/Phones</span>' : ''}
                    ${p.block_bluetooth ? '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;">No Bluetooth</span>' : ''}
                    ${!p.block_wpd_devices && !p.block_bluetooth ? '<span style="color:var(--text-muted);font-size:12px;">Standard Peripherals</span>' : ''}
                  </div>
                </td>
                <td style="padding:12px 16px;">
                  ${p.enabled ? '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;">Enabled</span>' : '<span class="badge" style="background:rgba(100,116,139,0.15);color:#94A3B8;">Disabled</span>'}
                </td>
                <td style="padding:12px 16px;text-align:right;">
                  <div style="display:flex;gap:6px;justify-content:flex-end;">
                    <button class="intune-btn intune-btn-secondary" style="padding:4px 8px;font-size:12px;" onclick="window.StorageAccessTable.viewScript('${p.id}')">
                      📜 Script
                    </button>
                    <button class="intune-btn intune-btn-secondary" style="padding:4px 8px;font-size:12px;" onclick="window.StorageAccessTable.openEditModal('${p.id}')">
                      ✏️ Edit
                    </button>
                    <button class="intune-btn intune-btn-danger" style="padding:4px 8px;font-size:12px;" onclick="window.StorageAccessTable.deletePolicy('${p.id}')">
                      🗑️
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderInventoryTab(inventory) {
    if (!inventory || inventory.length === 0) {
      return `
        <div style="padding:40px;text-align:center;color:var(--text-muted);border:1px dashed var(--border-color);border-radius:8px;">
          <div style="font-size:32px;margin-bottom:8px;">💻</div>
          <div style="font-weight:600;font-size:16px;">No Workstations Audited</div>
          <p style="font-size:13px;margin:8px 0 0;">Agent nodes automatically audit connected USB drives and peripheral state during heartbeats.</p>
        </div>
      `;
    }

    return `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="background:var(--bg-subtle);border-bottom:1px solid var(--border-color);color:var(--text-muted);">
              <th style="padding:12px 16px;">Device Name</th>
              <th style="padding:12px 16px;">Assigned Policy</th>
              <th style="padding:12px 16px;">Connected Drives</th>
              <th style="padding:12px 16px;">Write Mode</th>
              <th style="padding:12px 16px;">Compliance</th>
              <th style="padding:12px 16px;">Last Audit</th>
            </tr>
          </thead>
          <tbody>
            ${inventory.map(item => {
              let drives = [];
              try { drives = typeof item.connected_removable_drives_json === 'string' ? JSON.parse(item.connected_removable_drives_json) : (item.connected_removable_drives_json || []); } catch(e){}
              
              return `
                <tr style="border-bottom:1px solid var(--border-color);">
                  <td style="padding:12px 16px;">
                    <div style="font-weight:600;color:var(--text-primary);">${esc(item.hostname || item.device_id)}</div>
                    <div style="font-size:12px;color:var(--text-muted);">${esc(item.device_id)}</div>
                  </td>
                  <td style="padding:12px 16px;">
                    <div style="font-weight:500;">${esc(item.policy_name || 'No Policy Assigned')}</div>
                  </td>
                  <td style="padding:12px 16px;">
                    ${drives.length === 0 ? '<span style="color:var(--text-muted);">None Connected</span>' : 
                      drives.map(d => `
                        <div style="margin-bottom:2px;">
                          <span style="font-weight:600;">${esc(d.drive_letter || 'USB')}:</span> 
                          <span>${esc(d.friendly_name || d.volume_name || 'Removable')}</span>
                          ${d.is_encrypted ? '<span style="color:var(--accent-green);margin-left:4px;">🔒 Encrypted</span>' : '<span style="color:var(--accent-red);margin-left:4px;">⚠️ Unencrypted</span>'}
                        </div>
                      `).join('')
                    }
                  </td>
                  <td style="padding:12px 16px;">
                    ${item.write_access_denied ? '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:600;">Read-Only Enforced</span>' : '<span style="color:var(--text-muted);">Read/Write</span>'}
                  </td>
                  <td style="padding:12px 16px;">
                    ${getComplianceBadge(item.compliance_status)}
                  </td>
                  <td style="padding:12px 16px;color:var(--text-muted);">
                    ${item.last_audit_at ? new Date(item.last_audit_at).toLocaleString() : 'Pending'}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderEventsTab(events) {
    if (!events || events.length === 0) {
      return `
        <div style="padding:40px;text-align:center;color:var(--text-muted);border:1px dashed var(--border-color);border-radius:8px;">
          <div style="font-size:32px;margin-bottom:8px;">📋</div>
          <div style="font-weight:600;font-size:16px;">No Storage Events Recorded</div>
          <p style="font-size:13px;margin:8px 0 0;">USB drive insertions, BitLocker verifications, and blocked writes will appear in this ledger.</p>
        </div>
      `;
    }

    return `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="background:var(--bg-subtle);border-bottom:1px solid var(--border-color);color:var(--text-muted);">
              <th style="padding:12px 16px;">Timestamp</th>
              <th style="padding:12px 16px;">Device</th>
              <th style="padding:12px 16px;">Event Type</th>
              <th style="padding:12px 16px;">Volume / Drive</th>
              <th style="padding:12px 16px;">Hardware ID</th>
              <th style="padding:12px 16px;">Encryption</th>
              <th style="padding:12px 16px;">Action Taken</th>
            </tr>
          </thead>
          <tbody>
            ${events.map(e => `
              <tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:12px 16px;color:var(--text-muted);font-size:12px;">
                  ${new Date(e.timestamp).toLocaleString()}
                </td>
                <td style="padding:12px 16px;font-weight:500;">
                  ${esc(e.hostname || e.device_id)}
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;">${esc(e.event_type)}</span>
                </td>
                <td style="padding:12px 16px;">
                  <span style="font-weight:600;">${esc(e.drive_letter || '-')}:</span> ${esc(e.volume_name || 'Removable')}
                </td>
                <td style="padding:12px 16px;font-family:monospace;font-size:11px;color:var(--text-muted);">
                  ${esc(e.hardware_id || '-')}
                </td>
                <td style="padding:12px 16px;">
                  ${e.is_encrypted === 1 ? '<span style="color:var(--accent-green);font-weight:600;">🔒 BitLocker</span>' : 
                    e.is_encrypted === 0 ? '<span style="color:var(--accent-red);font-weight:600;">⚠️ Plaintext</span>' : '-'}
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:rgba(100,116,139,0.15);color:#94A3B8;">${esc(e.action_taken || 'LOGGED')}</span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function switchTab(tab) {
    currentTab = tab;
    if (window._storageAccessData) {
      renderBlade(document.getElementById('view-storage'), window._storageAccessData);
    } else {
      loadData();
    }
  }

  function openCreateModal(preset = null) {
    const groups = window._storageAccessData?.groups || [];
    
    let defaultName = '';
    let defaultDesc = '';
    let defaultDiskAccess = 'DENY_UNENCRYPTED';
    let defaultBde = 1;
    let defaultWpd = 0;
    let defaultBt = 0;
    let defaultAudit = 0;

    if (preset === 'bitlocker') {
      defaultName = 'Corporate BitLocker To Go Enforcement';
      defaultDesc = 'Deny write access to unencrypted USB drives until encrypted with BitLocker';
      defaultDiskAccess = 'DENY_UNENCRYPTED';
      defaultBde = 1;
    } else if (preset === 'airgap') {
      defaultName = 'High-Security USB Peripheral Lockdown';
      defaultDesc = 'Complete block of all removable media, WPD smart devices, and Bluetooth transfers';
      defaultDiskAccess = 'DENY_ALL';
      defaultBde = 1;
      defaultWpd = 1;
      defaultBt = 1;
    } else if (preset === 'audit') {
      defaultName = 'Permissive USB Audit & Inventory';
      defaultDesc = 'Allow full USB read/write access while logging all peripheral insertions';
      defaultDiskAccess = 'ALLOW_ALL';
      defaultAudit = 1;
    }

    const modal = document.createElement('div');
    modal.className = 'intune-modal-backdrop';
    modal.innerHTML = `
      <div class="intune-modal" style="max-width:640px;padding:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:18px;">🛡️ Create Removable Storage Policy</h3>
          <button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest('.intune-modal-backdrop').remove()">✕</button>
        </div>

        <div style="margin-bottom:16px;">
          <label style="font-size:12px;font-weight:600;color:var(--text-muted);display:block;margin-bottom:6px;">QUICK TEMPLATES</label>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.StorageAccessTable.openCreateModal('bitlocker')">
              🔐 BitLocker To Go
            </button>
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.StorageAccessTable.openCreateModal('airgap')">
              🚫 Air-Gap Lockdown
            </button>
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.StorageAccessTable.openCreateModal('audit')">
              👁️ Permissive Audit
            </button>
          </div>
        </div>

        <form id="create-storage-policy-form" style="display:flex;flex-direction:column;gap:14px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>
            <input type="text" name="name" class="intune-input" style="width:100%;" required value="${esc(defaultName)}" placeholder="e.g. Finance USB Encryption Rule" />
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>
            <input type="text" name="description" class="intune-input" style="width:100%;" value="${esc(defaultDesc)}" placeholder="Purpose of this policy" />
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>
            <select name="target_group_id" class="intune-input" style="width:100%;">
              <option value="">All Workstations (grp-all)</option>
              ${groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('')}
            </select>
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Removable Disk Access Mode</label>
            <select name="removable_disk_access" class="intune-input" style="width:100%;">
              <option value="DENY_UNENCRYPTED" ${defaultDiskAccess === 'DENY_UNENCRYPTED' ? 'selected' : ''}>Deny Write to Unencrypted Disks (BitLocker To Go Required)</option>
              <option value="DENY_ALL" ${defaultDiskAccess === 'DENY_ALL' ? 'selected' : ''}>Deny All Removable Disk Access (Complete Block)</option>
              <option value="READ_ONLY" ${defaultDiskAccess === 'READ_ONLY' ? 'selected' : ''}>Enforce Read-Only on All Disks</option>
              <option value="ALLOW_ALL" ${defaultDiskAccess === 'ALLOW_ALL' ? 'selected' : ''}>Allow All Removable Disks</option>
            </select>
          </div>

          <div style="display:flex;gap:16px;flex-wrap:wrap;background:var(--bg-subtle);padding:12px;border-radius:6px;">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" name="require_bitlocker_to_go" value="1" ${defaultBde ? 'checked' : ''} />
              <span>Require BitLocker To Go</span>
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" name="block_wpd_devices" value="1" ${defaultWpd ? 'checked' : ''} />
              <span>Block WPD (Phones / MTP)</span>
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" name="block_bluetooth" value="1" ${defaultBt ? 'checked' : ''} />
              <span>Block Bluetooth Transfers</span>
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" name="audit_only" value="1" ${defaultAudit ? 'checked' : ''} />
              <span>Audit Only (Don't Block)</span>
            </label>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:8px;">
            <button type="button" class="intune-btn intune-btn-secondary" onclick="this.closest('.intune-modal-backdrop').remove()">Cancel</button>
            <button type="submit" class="intune-btn intune-btn-primary">Create Policy</button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);

    const form = modal.querySelector('#create-storage-policy-form');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const payload = {
        name: fd.get('name'),
        description: fd.get('description'),
        target_group_id: fd.get('target_group_id') || 'grp-all',
        removable_disk_access: fd.get('removable_disk_access'),
        require_bitlocker_to_go: fd.get('require_bitlocker_to_go') ? 1 : 0,
        block_wpd_devices: fd.get('block_wpd_devices') ? 1 : 0,
        block_bluetooth: fd.get('block_bluetooth') ? 1 : 0,
        audit_only: fd.get('audit_only') ? 1 : 0,
        enabled: 1
      };

      try {
        await window.FleetAPI.createStoragePolicy(payload);
        modal.remove();
        loadData();
      } catch (err) {
        alert('Failed to create storage policy: ' + err.message);
      }
    });
  }

  async function viewScript(id) {
    try {
      const res = await window.FleetAPI.getStoragePolicy(id);
      const policy = res.policy;
      const script = res.powershell_script || '# No script generated';

      const modal = document.createElement('div');
      modal.className = 'intune-modal-backdrop';
      modal.innerHTML = `
        <div class="intune-modal" style="max-width:760px;padding:24px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h3 style="margin:0;font-size:18px;">📜 Generated PowerShell Policy Script</h3>
            <button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest('.intune-modal-backdrop').remove()">✕</button>
          </div>
          <p style="font-size:13px;color:var(--text-muted);margin:0 0 12px;">
            This PowerShell payload is executed natively on agent nodes to configure local Windows Registry policy keys (<code style="color:var(--accent-blue);">HKLM:\SOFTWARE\Policies\Microsoft\FVE</code>).
          </p>
          <pre style="background:var(--bg-subtle);border:1px solid var(--border-color);padding:14px;border-radius:6px;font-family:monospace;font-size:12px;overflow-x:auto;max-height:400px;color:var(--text-primary);">${esc(script)}</pre>
          <div style="display:flex;justify-content:flex-end;margin-top:16px;">
            <button class="intune-btn intune-btn-secondary" onclick="this.closest('.intune-modal-backdrop').remove()">Close</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    } catch (err) {
      alert('Error fetching policy script: ' + err.message);
    }
  }

  async function deletePolicy(id) {
    if (!confirm('Are you sure you want to delete this Removable Storage policy?')) return;
    try {
      await window.FleetAPI.deleteStoragePolicy(id);
      loadData();
    } catch (err) {
      alert('Failed to delete policy: ' + err.message);
    }
  }

  async function openEditModal(id) {
    try {
      const res = await window.FleetAPI.getStoragePolicy(id);
      const p = res.policy;
      const groups = window._storageAccessData?.groups || [];

      const modal = document.createElement('div');
      modal.className = 'intune-modal-backdrop';
      modal.innerHTML = `
        <div class="intune-modal" style="max-width:640px;padding:24px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <h3 style="margin:0;font-size:18px;">✏️ Edit Removable Storage Policy</h3>
            <button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;" onclick="this.closest('.intune-modal-backdrop').remove()">✕</button>
          </div>

          <form id="edit-storage-policy-form" style="display:flex;flex-direction:column;gap:14px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Policy Name *</label>
              <input type="text" name="name" class="intune-input" style="width:100%;" required value="${esc(p.name)}" />
            </div>

            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Description</label>
              <input type="text" name="description" class="intune-input" style="width:100%;" value="${esc(p.description || '')}" />
            </div>

            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Target Device Group</label>
              <select name="target_group_id" class="intune-input" style="width:100%;">
                <option value="grp-all" ${p.target_group_id === 'grp-all' ? 'selected' : ''}>All Workstations (grp-all)</option>
                ${groups.map(g => `<option value="${g.id}" ${p.target_group_id === g.id ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}
              </select>
            </div>

            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;">Removable Disk Access Mode</label>
              <select name="removable_disk_access" class="intune-input" style="width:100%;">
                <option value="DENY_UNENCRYPTED" ${p.removable_disk_access === 'DENY_UNENCRYPTED' ? 'selected' : ''}>Deny Write to Unencrypted Disks (BitLocker To Go)</option>
                <option value="DENY_ALL" ${p.removable_disk_access === 'DENY_ALL' ? 'selected' : ''}>Deny All Removable Disks</option>
                <option value="READ_ONLY" ${p.removable_disk_access === 'READ_ONLY' ? 'selected' : ''}>Enforce Read-Only</option>
                <option value="ALLOW_ALL" ${p.removable_disk_access === 'ALLOW_ALL' ? 'selected' : ''}>Allow All</option>
              </select>
            </div>

            <div style="display:flex;gap:16px;flex-wrap:wrap;background:var(--bg-subtle);padding:12px;border-radius:6px;">
              <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
                <input type="checkbox" name="require_bitlocker_to_go" value="1" ${p.require_bitlocker_to_go ? 'checked' : ''} />
                <span>Require BitLocker To Go</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
                <input type="checkbox" name="block_wpd_devices" value="1" ${p.block_wpd_devices ? 'checked' : ''} />
                <span>Block WPD</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
                <input type="checkbox" name="block_bluetooth" value="1" ${p.block_bluetooth ? 'checked' : ''} />
                <span>Block Bluetooth</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
                <input type="checkbox" name="audit_only" value="1" ${p.audit_only ? 'checked' : ''} />
                <span>Audit Only</span>
              </label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
                <input type="checkbox" name="enabled" value="1" ${p.enabled ? 'checked' : ''} />
                <span>Policy Enabled</span>
              </label>
            </div>

            <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:8px;">
              <button type="button" class="intune-btn intune-btn-secondary" onclick="this.closest('.intune-modal-backdrop').remove()">Cancel</button>
              <button type="submit" class="intune-btn intune-btn-primary">Save Changes</button>
            </div>
          </form>
        </div>
      `;

      document.body.appendChild(modal);

      const form = modal.querySelector('#edit-storage-policy-form');
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(form);
        const payload = {
          name: fd.get('name'),
          description: fd.get('description'),
          target_group_id: fd.get('target_group_id'),
          removable_disk_access: fd.get('removable_disk_access'),
          require_bitlocker_to_go: fd.get('require_bitlocker_to_go') ? 1 : 0,
          block_wpd_devices: fd.get('block_wpd_devices') ? 1 : 0,
          block_bluetooth: fd.get('block_bluetooth') ? 1 : 0,
          audit_only: fd.get('audit_only') ? 1 : 0,
          enabled: fd.get('enabled') ? 1 : 0
        };

        try {
          await window.FleetAPI.updateStoragePolicy(id, payload);
          modal.remove();
          loadData();
        } catch (err) {
          alert('Failed to update policy: ' + err.message);
        }
      });
    } catch (err) {
      alert('Error fetching policy details: ' + err.message);
    }
  }

  window.StorageAccessTable = {
    init: loadData,
    switchTab,
    openCreateModal,
    openEditModal,
    viewScript,
    deletePolicy
  };
})();
