/**
 * LocalPilot Fleet — Windows Autopilot & Hardware Provisioning UI Blade
 * dashboard/js/components/autopilotTable.js
 *
 * Implements Microsoft Intune Windows Autopilot capability:
 * - Executive KPI summary cards (Total Registered, Profile Assigned, Enrolled, ESP Policies)
 * - 4 sub-tabs: Autopilot Devices, Deployment Profiles, Enrollment Status Page (ESP), CSV Bulk Import & Export
 * - Hardware Hash inspector with 1-click clipboard copy
 * - RFC 4180 standard Microsoft Intune CSV bulk importer & exporter
 * - Deployment Profile Creator Wizard with enterprise presets
 * - Profile assignment modal and provisioning timeline viewer
 */

(function() {
  let _activeSubTab = 'devices';
  let _devicesCache = [];
  let _profilesCache = [];
  let _espCache = [];
  let _searchQuery = '';
  let _statusFilter = '';
  let _parsedCsvEntries = [];

  function init() {
    renderLayout();
    loadAllData();
  }

  function renderLayout() {
    const container = document.getElementById('tab-autopilot');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <div>
          <div style="font-size:20px;font-weight:600;color:var(--text-bright);display:flex;align-items:center;gap:8px;">
            <span>🚀</span> Windows Autopilot &amp; Hardware Provisioning
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">
            Zero-touch OOBE device provisioning, hardware hash harvesting, Microsoft Intune CSV bulk import/export &amp; ESP orchestration
          </div>
        </div>
        <div style="display:flex;gap:8px;">
          <button class="intune-btn" id="btn-ap-refresh" style="display:flex;align-items:center;gap:6px;">
            <span>🔄</span> Refresh
          </button>
          <button class="intune-btn" id="btn-ap-export-csv" style="display:flex;align-items:center;gap:6px;">
            <span>📥</span> Export Intune CSV
          </button>
          <button class="intune-btn" id="btn-ap-register-device" style="display:flex;align-items:center;gap:6px;">
            <span>➕</span> Register Device
          </button>
          <button class="intune-btn primary" id="btn-ap-create-profile" style="display:flex;align-items:center;gap:6px;">
            <span>➕</span> Create Profile
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="ap-kpis" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;padding:20px 24px;background:var(--bg-main);">
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Registered Devices</div>
          <div id="kpi-ap-total" style="font-size:28px;font-weight:700;color:var(--text-bright);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-ap-unassigned-sub">0 pending profile assignment</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Profile Coverage</div>
          <div id="kpi-ap-assigned" style="font-size:28px;font-weight:700;color:var(--accent-blue, #3b82f6);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-ap-profiles-sub">Across 0 deployment profiles</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">Provisioned / Enrolled</div>
          <div id="kpi-ap-enrolled" style="font-size:28px;font-weight:700;color:var(--accent-green, #10b981);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-ap-provisioning-sub">0 currently provisioning</div>
        </div>
        <div class="kpi-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.5px;">ESP Policies Active</div>
          <div id="kpi-ap-esp" style="font-size:28px;font-weight:700;color:var(--text-bright);margin-top:6px;">—</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="kpi-ap-esp-sub">Default 60 min block timeout</div>
        </div>
      </div>

      <!-- Navigation Sub-Tabs -->
      <div class="blade-subtabs" style="display:flex;gap:24px;padding:0 24px;border-bottom:1px solid var(--border-color);background:var(--bg-card);">
        <button class="subtab-btn active" data-subtab="devices" style="padding:12px 0;background:none;border:none;border-bottom:2px solid var(--accent-blue, #3b82f6);color:var(--text-bright);font-weight:600;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px;">
          <span>💻</span> Autopilot Devices
        </button>
        <button class="subtab-btn" data-subtab="profiles" style="padding:12px 0;background:none;border:none;border-bottom:2px solid transparent;color:var(--text-muted);font-weight:500;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px;">
          <span>📜</span> Deployment Profiles
        </button>
        <button class="subtab-btn" data-subtab="esp" style="padding:12px 0;background:none;border:none;border-bottom:2px solid transparent;color:var(--text-muted);font-weight:500;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px;">
          <span>⏳</span> Enrollment Status Page (ESP)
        </button>
        <button class="subtab-btn" data-subtab="csv" style="padding:12px 0;background:none;border:none;border-bottom:2px solid transparent;color:var(--text-muted);font-weight:500;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px;">
          <span>📥</span> CSV Bulk Import &amp; Export
        </button>
      </div>

      <!-- Content Area -->
      <div id="ap-tab-content" style="padding:20px 24px;background:var(--bg-main);">
        <!-- Injected dynamically -->
      </div>
    `;

    bindHeaderEvents();
  }

  function bindHeaderEvents() {
    document.getElementById('btn-ap-refresh')?.addEventListener('click', loadAllData);
    document.getElementById('btn-ap-export-csv')?.addEventListener('click', handleExportCsv);
    document.getElementById('btn-ap-register-device')?.addEventListener('click', showRegisterDeviceModal);
    document.getElementById('btn-ap-create-profile')?.addEventListener('click', showCreateProfileModal);

    const subtabButtons = document.querySelectorAll('.blade-subtabs .subtab-btn');
    subtabButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetTab = btn.getAttribute('data-subtab');
        subtabButtons.forEach(b => {
          b.classList.remove('active');
          b.style.borderBottomColor = 'transparent';
          b.style.color = 'var(--text-muted)';
          b.style.fontWeight = '500';
        });
        btn.classList.add('active');
        btn.style.borderBottomColor = 'var(--accent-blue, #3b82f6)';
        btn.style.color = 'var(--text-bright)';
        btn.style.fontWeight = '600';
        _activeSubTab = targetTab;
        renderActiveSubTab();
      });
    });
  }

  async function loadAllData() {
    try {
      const [statsRes, devRes, profRes, espRes] = await Promise.all([
        window.FleetAPI.getAutopilotStats(),
        window.FleetAPI.getAutopilotDevices({ search: _searchQuery, status: _statusFilter }),
        window.FleetAPI.getAutopilotProfiles(),
        window.FleetAPI.getEspPolicies()
      ]);

      updateKpis(statsRes);
      _devicesCache = devRes.devices || [];
      _profilesCache = profRes.profiles || [];
      _espCache = espRes.esp_policies || [];

      renderActiveSubTab();
    } catch (err) {
      console.error('[Autopilot Blade Error]:', err);
      const content = document.getElementById('ap-tab-content');
      if (content) {
        content.innerHTML = `
          <div style="background:rgba(239, 68, 68, 0.1);border:1px solid var(--accent-red, #ef4444);color:var(--text-bright);padding:16px;border-radius:8px;">
            ⚠️ Failed to load Windows Autopilot data: ${escapeHtml(err.message)}
          </div>
        `;
      }
    }
  }

  function updateKpis(stats) {
    if (!stats) return;

    const elTotal = document.getElementById('kpi-ap-total');
    const elAssigned = document.getElementById('kpi-ap-assigned');
    const elEnrolled = document.getElementById('kpi-ap-enrolled');
    const elEsp = document.getElementById('kpi-ap-esp');

    if (elTotal) elTotal.textContent = stats.total_devices ?? 0;
    if (elAssigned) {
      const pct = stats.total_devices > 0 ? Math.round(((stats.assigned_devices + stats.enrolled_devices) / stats.total_devices) * 100) : 0;
      elAssigned.textContent = `${pct}%`;
    }
    if (elEnrolled) elEnrolled.textContent = stats.enrolled_devices ?? 0;
    if (elEsp) elEsp.textContent = stats.total_esp_policies ?? 0;

    const subUnassigned = document.getElementById('kpi-ap-unassigned-sub');
    if (subUnassigned) subUnassigned.textContent = `${stats.unassigned_devices || 0} pending profile assignment`;

    const subProfiles = document.getElementById('kpi-ap-profiles-sub');
    if (subProfiles) subProfiles.textContent = `Across ${stats.total_profiles || 0} deployment profile(s)`;

    const subProv = document.getElementById('kpi-ap-provisioning-sub');
    if (subProv) subProv.textContent = `${stats.provisioning_devices || 0} currently provisioning`;
  }

  function renderActiveSubTab() {
    const container = document.getElementById('ap-tab-content');
    if (!container) return;

    if (_activeSubTab === 'devices') {
      renderDevicesSubTab(container);
    } else if (_activeSubTab === 'profiles') {
      renderProfilesSubTab(container);
    } else if (_activeSubTab === 'esp') {
      renderEspSubTab(container);
    } else if (_activeSubTab === 'csv') {
      renderCsvSubTab(container);
    }
  }

  /* ── 1. Autopilot Devices Sub-Tab ──────────────────────────────────── */
  function renderDevicesSubTab(container) {
    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px;flex-wrap:wrap;">
        <div style="display:flex;gap:12px;align-items:center;flex:1;min-width:300px;">
          <input type="text" id="ap-search-input" placeholder="Search by serial number, model, group tag, user..."
            value="${escapeHtml(_searchQuery)}"
            style="flex:1;max-width:400px;padding:8px 12px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          <select id="ap-status-filter" style="padding:8px 12px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
            <option value="" ${_statusFilter === '' ? 'selected' : ''}>All Statuses</option>
            <option value="UNASSIGNED" ${_statusFilter === 'UNASSIGNED' ? 'selected' : ''}>Unassigned</option>
            <option value="ASSIGNED" ${_statusFilter === 'ASSIGNED' ? 'selected' : ''}>Assigned</option>
            <option value="PROVISIONING" ${_statusFilter === 'PROVISIONING' ? 'selected' : ''}>Provisioning</option>
            <option value="ENROLLED" ${_statusFilter === 'ENROLLED' ? 'selected' : ''}>Enrolled</option>
            <option value="FAILED" ${_statusFilter === 'FAILED' ? 'selected' : ''}>Failed</option>
          </select>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          Showing <strong>${_devicesCache.length}</strong> registered hardware devices
        </div>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="background:rgba(255,255,255,0.03);border-bottom:1px solid var(--border-color);color:var(--text-muted);font-weight:600;">
              <th style="padding:12px 16px;">Device Serial &amp; Model</th>
              <th style="padding:12px 16px;">Hardware Hash</th>
              <th style="padding:12px 16px;">Group Tag</th>
              <th style="padding:12px 16px;">Assigned User</th>
              <th style="padding:12px 16px;">Deployment Profile</th>
              <th style="padding:12px 16px;">Status</th>
              <th style="padding:12px 16px;">Live Node Binding</th>
              <th style="padding:12px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${_devicesCache.length === 0 ? `
              <tr>
                <td colspan="8" style="padding:36px;text-align:center;color:var(--text-muted);">
                  No registered Autopilot devices found. Import a Microsoft Intune CSV or click "Register Device".
                </td>
              </tr>
            ` : _devicesCache.map(dev => renderDeviceRow(dev)).join('')}
          </tbody>
        </table>
      </div>
    `;

    // Filter events
    document.getElementById('ap-search-input')?.addEventListener('input', debounce((e) => {
      _searchQuery = e.target.value.trim();
      loadAllData();
    }, 300));

    document.getElementById('ap-status-filter')?.addEventListener('change', (e) => {
      _statusFilter = e.target.value;
      loadAllData();
    });

    // Row action events
    container.querySelectorAll('.btn-assign-profile').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const currentProfId = btn.getAttribute('data-profile-id');
        showAssignProfileModal(id, currentProfId);
      });
    });

    container.querySelectorAll('.btn-delete-device').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const sn = btn.getAttribute('data-sn');
        if (confirm(`Are you sure you want to remove device '${sn}' from Windows Autopilot registry?`)) {
          try {
            await window.FleetAPI.deleteAutopilotDevice(id);
            loadAllData();
          } catch (err) {
            alert(`Failed to delete device: ${err.message}`);
          }
        }
      });
    });

    container.querySelectorAll('.btn-copy-hash').forEach(btn => {
      btn.addEventListener('click', () => {
        const hash = btn.getAttribute('data-hash');
        navigator.clipboard.writeText(hash).then(() => {
          btn.textContent = '✔️ Copied';
          setTimeout(() => { btn.textContent = '📋'; }, 1500);
        });
      });
    });
  }

  function renderDeviceRow(dev) {
    const statusBadges = {
      'ENROLLED': '<span style="background:rgba(16, 185, 129, 0.15);color:#10b981;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;">✔️ Enrolled</span>',
      'PROVISIONING': '<span style="background:rgba(59, 130, 246, 0.15);color:#3b82f6;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;">⚡ Provisioning</span>',
      'ASSIGNED': '<span style="background:rgba(139, 92, 246, 0.15);color:#8b5cf6;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;">📋 Assigned</span>',
      'UNASSIGNED': '<span style="background:rgba(156, 163, 175, 0.15);color:#9ca3af;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;">⚪ Unassigned</span>',
      'FAILED': '<span style="background:rgba(239, 68, 68, 0.15);color:#ef4444;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;">❌ Failed</span>'
    };

    const statusHtml = statusBadges[dev.deployment_status] || dev.deployment_status;
    const shortHash = dev.hardware_hash ? `${dev.hardware_hash.slice(0, 16)}...` : '—';

    const liveNodeHtml = dev.device_id ? `
      <div>
        <div style="font-weight:600;color:var(--text-bright);display:flex;align-items:center;gap:6px;">
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${dev.live_status === 'online' ? '#10b981' : '#6b7280'};"></span>
          ${escapeHtml(dev.live_hostname || dev.device_id)}
        </div>
        <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(dev.live_ip || 'LAN')} • ${escapeHtml(dev.live_os || 'Windows 11')}</div>
      </div>
    ` : `<span style="color:var(--text-muted);font-size:12px;">Not yet enrolled</span>`;

    return `
      <tr style="border-bottom:1px solid var(--border-color);">
        <td style="padding:12px 16px;">
          <div style="font-weight:600;color:var(--text-bright);">${escapeHtml(dev.serial_number)}</div>
          <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(dev.manufacturer || 'OEM')} ${escapeHtml(dev.model || 'PC')}</div>
        </td>
        <td style="padding:12px 16px;font-family:monospace;font-size:11px;">
          <div style="display:flex;align-items:center;gap:6px;">
            <span title="${escapeHtml(dev.hardware_hash)}">${escapeHtml(shortHash)}</span>
            <button class="btn-copy-hash intune-btn" data-hash="${escapeHtml(dev.hardware_hash)}" style="padding:2px 6px;font-size:11px;" title="Copy Full Hardware Hash">📋</button>
          </div>
        </td>
        <td style="padding:12px 16px;">
          ${dev.group_tag ? `<span style="background:rgba(59, 130, 246, 0.1);color:#60a5fa;border:1px solid rgba(59, 130, 246, 0.2);padding:2px 6px;border-radius:4px;font-size:11px;">${escapeHtml(dev.group_tag)}</span>` : '<span style="color:var(--text-muted);">—</span>'}
        </td>
        <td style="padding:12px 16px;color:var(--text-bright);">
          ${dev.assigned_user ? escapeHtml(dev.assigned_user) : '<span style="color:var(--text-muted);">—</span>'}
        </td>
        <td style="padding:12px 16px;">
          ${dev.profile_name ? `
            <div style="font-weight:500;color:var(--text-bright);">${escapeHtml(dev.profile_name)}</div>
            <div style="font-size:10px;color:var(--text-muted);">${escapeHtml(dev.profile_deployment_mode || 'USER_DRIVEN')}</div>
          ` : '<span style="color:var(--accent-orange, #f59e0b);font-size:11px;">⚠️ No Profile</span>'}
        </td>
        <td style="padding:12px 16px;">
          ${statusHtml}
        </td>
        <td style="padding:12px 16px;">
          ${liveNodeHtml}
        </td>
        <td style="padding:12px 16px;text-align:right;">
          <button class="btn-assign-profile intune-btn" data-id="${dev.id}" data-profile-id="${dev.profile_id || ''}" style="padding:4px 8px;font-size:11px;margin-right:4px;">
            Profile
          </button>
          <button class="btn-delete-device intune-btn" data-id="${dev.id}" data-sn="${dev.serial_number}" style="padding:4px 8px;font-size:11px;color:#ef4444;">
            🗑️
          </button>
        </td>
      </tr>
    `;
  }

  /* ── 2. Deployment Profiles Sub-Tab ─────────────────────────────────── */
  function renderProfilesSubTab(container) {
    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <div style="font-size:15px;font-weight:600;color:var(--text-bright);">Out-of-Box Experience (OOBE) Deployment Profiles</div>
          <div style="font-size:12px;color:var(--text-muted);">Profiles define user experience, privilege model, automated computer naming, and privacy screen bypass during Windows Setup.</div>
        </div>
        <button class="intune-btn primary" id="btn-ap-create-profile-sub" style="display:flex;align-items:center;gap:6px;">
          <span>➕</span> New Deployment Profile
        </button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(360px, 1fr));gap:16px;">
        ${_profilesCache.map(prof => renderProfileCard(prof)).join('')}
      </div>
    `;

    document.getElementById('btn-ap-create-profile-sub')?.addEventListener('click', showCreateProfileModal);

    container.querySelectorAll('.btn-delete-profile').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const name = btn.getAttribute('data-name');
        if (confirm(`Delete Autopilot profile '${name}'? Any assigned devices will revert to unassigned.`)) {
          try {
            await window.FleetAPI.deleteAutopilotProfile(id);
            loadAllData();
          } catch (err) {
            alert(`Failed to delete profile: ${err.message}`);
          }
        }
      });
    });
  }

  function renderProfileCard(prof) {
    return `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:20px;display:flex;flex-direction:column;justify-content:space-between;">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div style="font-size:16px;font-weight:600;color:var(--text-bright);">
              ${escapeHtml(prof.name)}
              ${prof.is_default ? '<span style="background:rgba(16, 185, 129, 0.15);color:#10b981;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px;font-weight:600;">DEFAULT</span>' : ''}
            </div>
            <button class="btn-delete-profile intune-btn" data-id="${prof.id}" data-name="${escapeHtml(prof.name)}" style="padding:2px 6px;font-size:11px;color:#ef4444;" title="Delete Profile">🗑️</button>
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:6px;line-height:1.4;">${escapeHtml(prof.description || 'No description provided')}</div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px;font-size:12px;">
            <div style="background:rgba(255,255,255,0.02);padding:8px;border-radius:6px;border:1px solid var(--border-color);">
              <div style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Deployment Mode</div>
              <div style="font-weight:600;color:var(--text-bright);margin-top:2px;">${escapeHtml(prof.deployment_mode)}</div>
            </div>
            <div style="background:rgba(255,255,255,0.02);padding:8px;border-radius:6px;border:1px solid var(--border-color);">
              <div style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">User Account Type</div>
              <div style="font-weight:600;color:var(--text-bright);margin-top:2px;">${escapeHtml(prof.account_type)}</div>
            </div>
            <div style="background:rgba(255,255,255,0.02);padding:8px;border-radius:6px;border:1px solid var(--border-color);">
              <div style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Join Type</div>
              <div style="font-weight:600;color:var(--text-bright);margin-top:2px;">${escapeHtml(prof.join_type)}</div>
            </div>
            <div style="background:rgba(255,255,255,0.02);padding:8px;border-radius:6px;border:1px solid var(--border-color);">
              <div style="color:var(--text-muted);font-size:10px;text-transform:uppercase;">Naming Template</div>
              <div style="font-weight:600;color:var(--text-bright);margin-top:2px;"><code>${escapeHtml(prof.device_name_template || 'None')}</code></div>
            </div>
          </div>

          <div style="margin-top:16px;font-size:11px;color:var(--text-muted);">
            <div style="margin-bottom:4px;">🛡️ <strong>OOBE Settings:</strong></div>
            <div>${prof.skip_eula ? '✔️ Skip EULA' : '❌ Show EULA'} • ${prof.skip_privacy_settings ? '✔️ Skip Privacy Screens' : '❌ Show Privacy'} • ${prof.skip_user_licensing ? '✔️ Skip OEM Registration' : '❌ Show OEM Reg'}</div>
          </div>
        </div>

        <div style="margin-top:20px;padding-top:12px;border-top:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;font-size:12px;">
          <div style="color:var(--text-muted);">Assigned Devices: <strong style="color:var(--text-bright);">${prof.assigned_device_count || 0}</strong></div>
          <div style="color:var(--accent-blue, #3b82f6);">${escapeHtml(prof.target_group_name || 'All Devices')}</div>
        </div>
      </div>
    `;
  }

  /* ── 3. Enrollment Status Page (ESP) Sub-Tab ───────────────────────── */
  function renderEspSubTab(container) {
    container.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:24px;margin-bottom:24px;">
        <div style="font-size:16px;font-weight:600;color:var(--text-bright);margin-bottom:8px;">Enrollment Status Page (ESP) Phase Orchestration</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:20px;line-height:1.5;">
          The Enrollment Status Page tracks and blocks device access during initial setup until security baseline policies, certificates, and required line-of-business applications have successfully installed.
        </div>

        <!-- ESP 3-Phase Interactive Progression Visualizer -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;">
          <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
              <span style="font-size:18px;">🛡️</span>
              <div style="font-weight:600;color:var(--text-bright);">Phase 1: Device Preparation</div>
            </div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-muted);line-height:1.6;">
              <li>Hardware Attestation &amp; TPM 2.0 validation</li>
              <li>Mutual TLS node token issuance</li>
              <li>LocalPilot Fleet Master Authority trust binding</li>
            </ul>
          </div>

          <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
              <span style="font-size:18px;">⚙️</span>
              <div style="font-weight:600;color:var(--text-bright);">Phase 2: Device Setup</div>
            </div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-muted);line-height:1.6;">
              <li>Enterprise Security Baselines &amp; Defender RTP</li>
              <li>Silent BitLocker Drive Encryption &amp; Key Escrow</li>
              <li>Blocking Win32 &amp; Winget core applications</li>
            </ul>
          </div>

          <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);border-radius:8px;padding:16px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
              <span style="font-size:18px;">👤</span>
              <div style="font-weight:600;color:var(--text-bright);">Phase 3: Account Setup</div>
            </div>
            <ul style="margin:0;padding-left:18px;font-size:12px;color:var(--text-muted);line-height:1.6;">
              <li>Standard user profile preparation</li>
              <li>Local Administrator Password Solution (LAPS) rotation</li>
              <li>Endpoint Privilege Management (EPM) rule deployment</li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Active ESP Policies Table -->
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="font-size:15px;font-weight:600;color:var(--text-bright);">Active ESP Policies</div>
        <button class="intune-btn primary" id="btn-create-esp" style="display:flex;align-items:center;gap:6px;">
          <span>➕</span> Create ESP Policy
        </button>
      </div>

      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="background:rgba(255,255,255,0.03);border-bottom:1px solid var(--border-color);color:var(--text-muted);font-weight:600;">
              <th style="padding:12px 16px;">Policy Name</th>
              <th style="padding:12px 16px;">Progress Display</th>
              <th style="padding:12px 16px;">Block Device Until Finished</th>
              <th style="padding:12px 16px;">Allow User Reset</th>
              <th style="padding:12px 16px;">Timeout</th>
              <th style="padding:12px 16px;">Target Group</th>
              <th style="padding:12px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${_espCache.map(esp => `
              <tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-bright);">
                    ${escapeHtml(esp.name)}
                    ${esp.is_default ? '<span style="background:rgba(16, 185, 129, 0.15);color:#10b981;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:6px;">DEFAULT</span>' : ''}
                  </div>
                  <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(esp.description || 'Standard provisioning flow')}</div>
                </td>
                <td style="padding:12px 16px;">${esp.show_progress ? '✔️ Enabled' : '❌ Disabled'}</td>
                <td style="padding:12px 16px;">${esp.block_until_completed ? '<span style="color:#ef4444;font-weight:600;">🔒 Blocked</span>' : '⚪ Permissive'}</td>
                <td style="padding:12px 16px;">${esp.allow_user_reset_on_failure ? '✔️ Allowed' : '❌ Disabled'}</td>
                <td style="padding:12px 16px;font-weight:600;color:var(--text-bright);">${esp.timeout_minutes} min</td>
                <td style="padding:12px 16px;color:var(--accent-blue, #3b82f6);">${escapeHtml(esp.target_group_name || 'All Devices')}</td>
                <td style="padding:12px 16px;text-align:right;">
                  ${!esp.is_default ? `<button class="btn-delete-esp intune-btn" data-id="${esp.id}" style="padding:4px 8px;font-size:11px;color:#ef4444;">🗑️</button>` : '<span style="color:var(--text-muted);font-size:11px;">Default</span>'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    document.getElementById('btn-create-esp')?.addEventListener('click', showCreateEspModal);

    container.querySelectorAll('.btn-delete-esp').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Delete this ESP policy?')) {
          try {
            await window.FleetAPI.deleteEspPolicy(id);
            loadAllData();
          } catch (err) {
            alert(`Failed to delete ESP policy: ${err.message}`);
          }
        }
      });
    });
  }

  /* ── 4. CSV Bulk Import & Export Sub-Tab ────────────────────────────── */
  function renderCsvSubTab(container) {
    container.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:24px;">
        <div style="font-size:16px;font-weight:600;color:var(--text-bright);margin-bottom:8px;">Microsoft Intune Standard CSV Bulk Import</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:16px;line-height:1.5;">
          Paste or load official Microsoft Intune CSV files generated by <code>Get-WindowsAutopilotInfo.ps1</code> or OEM vendors.
          Standard header expected: <code>Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User</code>.
        </div>

        <div style="display:flex;gap:12px;margin-bottom:16px;">
          <textarea id="ap-csv-textarea" rows="8" placeholder="Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
DELL-SN-102938,00330-80000-00000-AAOEM,T1BSR1VJRDAwMDFBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjEyMzQ1Njc4OTAqKipXRUJfSEFTSA==,Engineering,developer@localpilot.fleet"
            style="flex:1;padding:12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-family:monospace;font-size:12px;resize:vertical;"></textarea>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div style="display:flex;gap:12px;align-items:center;">
            <button class="intune-btn primary" id="btn-parse-and-import-csv" style="display:flex;align-items:center;gap:6px;">
              <span>⚡</span> Parse &amp; Import Devices
            </button>
            <button class="intune-btn" id="btn-clear-csv">Clear</button>
          </div>
          <div style="font-size:12px;color:var(--text-muted);" id="csv-import-result"></div>
        </div>
      </div>
    `;

    document.getElementById('btn-clear-csv')?.addEventListener('click', () => {
      const ta = document.getElementById('ap-csv-textarea');
      if (ta) ta.value = '';
      const res = document.getElementById('csv-import-result');
      if (res) res.textContent = '';
    });

    document.getElementById('btn-parse-and-import-csv')?.addEventListener('click', async () => {
      const ta = document.getElementById('ap-csv-textarea');
      const resDiv = document.getElementById('csv-import-result');
      if (!ta || !ta.value.trim()) {
        alert('Please paste or enter CSV content first');
        return;
      }

      try {
        if (resDiv) resDiv.textContent = 'Importing devices...';
        const result = await window.FleetAPI.importAutopilotCsv(ta.value.trim());
        if (resDiv) {
          resDiv.innerHTML = `<span style="color:#10b981;font-weight:600;">✔️ Success: ${result.imported_count} imported, ${result.updated_count} updated.</span>`;
        }
        loadAllData();
      } catch (err) {
        if (resDiv) {
          resDiv.innerHTML = `<span style="color:#ef4444;font-weight:600;">❌ Import error: ${escapeHtml(err.message)}</span>`;
        }
      }
    });
  }

  function handleExportCsv() {
    const url = window.FleetAPI.getAutopilotExportCsvUrl();
    window.open(url, '_blank');
  }

  /* ── Modals ────────────────────────────────────────────────────────── */

  function showRegisterDeviceModal() {
    const modalId = 'modal-ap-register';
    removeExistingModal(modalId);

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'intune-modal-backdrop';
    modal.style = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;backdrop-filter:blur(2px);';

    modal.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:550px;max-width:90%;overflow:hidden;box-shadow:0 12px 36px rgba(0,0,0,0.5);">
        <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:600;font-size:16px;color:var(--text-bright);">➕ Register Hardware Device</div>
          <button class="intune-btn btn-close-modal" style="padding:4px 8px;">✕</button>
        </div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px;max-height:75vh;overflow-y:auto;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Device Serial Number *</label>
            <input type="text" id="reg-dev-serial" placeholder="e.g. DELL-XPS-9530-XYZ" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Hardware Hash *</label>
            <textarea id="reg-dev-hash" rows="3" placeholder="4K Base64 hardware hash string" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-family:monospace;font-size:11px;"></textarea>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Model</label>
              <input type="text" id="reg-dev-model" placeholder="e.g. ThinkPad X1 Carbon" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Manufacturer</label>
              <input type="text" id="reg-dev-mfg" placeholder="e.g. Lenovo" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Group Tag</label>
              <input type="text" id="reg-dev-tag" placeholder="e.g. Engineering" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Assigned User</label>
              <input type="text" id="reg-dev-user" placeholder="e.g. user@localpilot.fleet" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
            </div>
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Initial Deployment Profile</label>
            <select id="reg-dev-profile" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
              <option value="">Default Profile (Automatic)</option>
              ${_profilesCache.map(p => `<option value="${p.id}">${escapeHtml(p.name)} (${p.deployment_mode})</option>`).join('')}
            </select>
          </div>
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--border-color);display:flex;justify-content:flex-end;gap:8px;background:rgba(255,255,255,0.02);">
          <button class="intune-btn btn-close-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-register-device">Register Device</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelectorAll('.btn-close-modal').forEach(b => b.addEventListener('click', () => modal.remove()));

    document.getElementById('btn-submit-register-device')?.addEventListener('click', async () => {
      const serial = document.getElementById('reg-dev-serial')?.value.trim();
      const hash = document.getElementById('reg-dev-hash')?.value.trim();
      const model = document.getElementById('reg-dev-model')?.value.trim();
      const mfg = document.getElementById('reg-dev-mfg')?.value.trim();
      const tag = document.getElementById('reg-dev-tag')?.value.trim();
      const user = document.getElementById('reg-dev-user')?.value.trim();
      const profId = document.getElementById('reg-dev-profile')?.value || undefined;

      if (!serial || !hash) {
        alert('Serial Number and Hardware Hash are required.');
        return;
      }

      try {
        await window.FleetAPI.registerAutopilotDevice({
          serial_number: serial,
          hardware_hash: hash,
          model: model || 'Custom PC',
          manufacturer: mfg || 'OEM',
          group_tag: tag,
          assigned_user: user,
          profile_id: profId
        });
        modal.remove();
        loadAllData();
      } catch (err) {
        alert(`Failed to register device: ${err.message}`);
      }
    });
  }

  function showAssignProfileModal(deviceId, currentProfId) {
    const modalId = 'modal-ap-assign-prof';
    removeExistingModal(modalId);

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'intune-modal-backdrop';
    modal.style = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;backdrop-filter:blur(2px);';

    modal.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:440px;max-width:90%;overflow:hidden;box-shadow:0 12px 36px rgba(0,0,0,0.5);">
        <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:600;font-size:16px;color:var(--text-bright);">Assign Autopilot Profile</div>
          <button class="intune-btn btn-close-modal" style="padding:4px 8px;">✕</button>
        </div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:6px;color:var(--text-muted);">Choose Deployment Profile</label>
            <select id="select-ap-assign-prof" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
              <option value="">-- Remove Profile (Unassign) --</option>
              ${_profilesCache.map(p => `
                <option value="${p.id}" ${p.id === currentProfId ? 'selected' : ''}>
                  ${escapeHtml(p.name)} (${p.deployment_mode})
                </option>
              `).join('')}
            </select>
          </div>
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--border-color);display:flex;justify-content:flex-end;gap:8px;background:rgba(255,255,255,0.02);">
          <button class="intune-btn btn-close-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-assign-prof">Assign Profile</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelectorAll('.btn-close-modal').forEach(b => b.addEventListener('click', () => modal.remove()));

    document.getElementById('btn-submit-assign-prof')?.addEventListener('click', async () => {
      const selectedProf = document.getElementById('select-ap-assign-prof')?.value || null;
      try {
        await window.FleetAPI.assignAutopilotProfile(deviceId, selectedProf);
        modal.remove();
        loadAllData();
      } catch (err) {
        alert(`Failed to assign profile: ${err.message}`);
      }
    });
  }

  function showCreateProfileModal() {
    const modalId = 'modal-ap-create-prof';
    removeExistingModal(modalId);

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'intune-modal-backdrop';
    modal.style = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;backdrop-filter:blur(2px);';

    modal.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:580px;max-width:90%;overflow:hidden;box-shadow:0 12px 36px rgba(0,0,0,0.5);">
        <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:600;font-size:16px;color:var(--text-bright);">➕ Create Autopilot Deployment Profile</div>
          <button class="intune-btn btn-close-modal" style="padding:4px 8px;">✕</button>
        </div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px;max-height:75vh;overflow-y:auto;">
          <!-- Presets -->
          <div style="background:rgba(59, 130, 246, 0.05);border:1px solid rgba(59, 130, 246, 0.2);padding:12px;border-radius:6px;">
            <div style="font-size:11px;font-weight:600;color:var(--accent-blue, #3b82f6);text-transform:uppercase;margin-bottom:6px;">Quick Presets</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button type="button" class="intune-btn btn-preset" data-preset="enterprise" style="font-size:11px;">🏢 Enterprise Standard</button>
              <button type="button" class="intune-btn btn-preset" data-preset="kiosk" style="font-size:11px;">🧪 Lab / Self-Deploying</button>
              <button type="button" class="intune-btn btn-preset" data-preset="developer" style="font-size:11px;">🛠️ Developer Workstation</button>
            </div>
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Profile Name *</label>
            <input type="text" id="prof-name" placeholder="e.g. Standard Corporate Workstation" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Description</label>
            <input type="text" id="prof-desc" placeholder="Summary of profile purpose and target fleet" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Deployment Mode</label>
              <select id="prof-mode" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
                <option value="USER_DRIVEN">User-Driven (OOBE Interactive)</option>
                <option value="SELF_DEPLOYING">Self-Deploying (Zero Touch Kiosk)</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">User Account Type</label>
              <select id="prof-account" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
                <option value="STANDARD">Standard User (Recommended)</option>
                <option value="ADMINISTRATOR">Administrator</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Computer Name Template</label>
              <input type="text" id="prof-template" value="FLEET-%RAND:4%" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Target Dynamic Group</label>
              <select id="prof-target-group" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;">
                <option value="grp-all">All Devices (grp-all)</option>
                <option value="grp-workstations">High-Performance Workstations</option>
                <option value="grp-family-laptops">Family Laptops</option>
              </select>
            </div>
          </div>

          <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border-color);border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <label style="font-size:12px;font-weight:600;color:var(--text-muted);">OOBE Experience Skips</label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="prof-skip-eula" checked /> Skip End User License Agreement (EULA)
            </label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="prof-skip-privacy" checked /> Skip Privacy &amp; Diagnostic Data Prompts
            </label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="prof-skip-licensing" checked /> Skip OEM Registration &amp; Account Links
            </label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;margin-top:4px;">
              <input type="checkbox" id="prof-is-default" /> Make this the Default Fleet Profile
            </label>
          </div>
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--border-color);display:flex;justify-content:flex-end;gap:8px;background:rgba(255,255,255,0.02);">
          <button class="intune-btn btn-close-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-create-prof">Create Profile</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelectorAll('.btn-close-modal').forEach(b => b.addEventListener('click', () => modal.remove()));

    // Presets
    modal.querySelectorAll('.btn-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        const type = btn.getAttribute('data-preset');
        if (type === 'enterprise') {
          document.getElementById('prof-name').value = 'Enterprise Workstation Baseline';
          document.getElementById('prof-desc').value = 'Standard user-driven enterprise provisioning';
          document.getElementById('prof-mode').value = 'USER_DRIVEN';
          document.getElementById('prof-account').value = 'STANDARD';
          document.getElementById('prof-template').value = 'FLEET-WK-%RAND:4%';
        } else if (type === 'kiosk') {
          document.getElementById('prof-name').value = 'Zero-Touch Homelab Kiosk';
          document.getElementById('prof-desc').value = 'Self-deploying automated setup for homelab test rigs';
          document.getElementById('prof-mode').value = 'SELF_DEPLOYING';
          document.getElementById('prof-account').value = 'ADMINISTRATOR';
          document.getElementById('prof-template').value = 'FLEET-LAB-%RAND:4%';
        } else if (type === 'developer') {
          document.getElementById('prof-name').value = 'Developer High-Performance Profile';
          document.getElementById('prof-desc').value = 'User-driven workstation profile with administrative rights';
          document.getElementById('prof-mode').value = 'USER_DRIVEN';
          document.getElementById('prof-account').value = 'ADMINISTRATOR';
          document.getElementById('prof-template').value = 'FLEET-DEV-%RAND:4%';
        }
      });
    });

    document.getElementById('btn-submit-create-prof')?.addEventListener('click', async () => {
      const name = document.getElementById('prof-name')?.value.trim();
      const desc = document.getElementById('prof-desc')?.value.trim();
      const mode = document.getElementById('prof-mode')?.value;
      const account = document.getElementById('prof-account')?.value;
      const template = document.getElementById('prof-template')?.value.trim();
      const targetGroup = document.getElementById('prof-target-group')?.value;
      const skipEula = document.getElementById('prof-skip-eula')?.checked;
      const skipPrivacy = document.getElementById('prof-skip-privacy')?.checked;
      const skipLic = document.getElementById('prof-skip-licensing')?.checked;
      const isDefault = document.getElementById('prof-is-default')?.checked;

      if (!name) {
        alert('Profile name is required');
        return;
      }

      try {
        await window.FleetAPI.createAutopilotProfile({
          name,
          description: desc,
          deployment_mode: mode,
          account_type: account,
          device_name_template: template,
          target_group_id: targetGroup,
          skip_eula: skipEula,
          skip_privacy_settings: skipPrivacy,
          skip_user_licensing: skipLic,
          is_default: isDefault
        });
        modal.remove();
        loadAllData();
      } catch (err) {
        alert(`Failed to create profile: ${err.message}`);
      }
    });
  }

  function showCreateEspModal() {
    const modalId = 'modal-ap-create-esp';
    removeExistingModal(modalId);

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'intune-modal-backdrop';
    modal.style = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;backdrop-filter:blur(2px);';

    modal.innerHTML = `
      <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;width:500px;max-width:90%;overflow:hidden;box-shadow:0 12px 36px rgba(0,0,0,0.5);">
        <div style="padding:16px 20px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
          <div style="font-weight:600;font-size:16px;color:var(--text-bright);">➕ Create ESP Policy</div>
          <button class="intune-btn btn-close-modal" style="padding:4px 8px;">✕</button>
        </div>
        <div style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Policy Name *</label>
            <input type="text" id="esp-name" placeholder="e.g. Lab Bench Fast ESP" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px;color:var(--text-muted);">Timeout (Minutes)</label>
            <input type="number" id="esp-timeout" value="60" min="10" max="1440" style="width:100%;padding:8px 12px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:6px;color:var(--text-bright);font-size:13px;" />
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="esp-show-progress" checked /> Show Setup Progress &amp; Phases to User
            </label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="esp-block" checked /> Block Device Use Until All Required Apps and Baselines Install
            </label>
            <label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;">
              <input type="checkbox" id="esp-allow-reset" checked /> Allow Users to Reset Device if Installation Encountered Error
            </label>
          </div>
        </div>
        <div style="padding:14px 20px;border-top:1px solid var(--border-color);display:flex;justify-content:flex-end;gap:8px;background:rgba(255,255,255,0.02);">
          <button class="intune-btn btn-close-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-create-esp">Create ESP Policy</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelectorAll('.btn-close-modal').forEach(b => b.addEventListener('click', () => modal.remove()));

    document.getElementById('btn-submit-create-esp')?.addEventListener('click', async () => {
      const name = document.getElementById('esp-name')?.value.trim();
      const timeout = parseInt(document.getElementById('esp-timeout')?.value, 10);
      const showProg = document.getElementById('esp-show-progress')?.checked;
      const block = document.getElementById('esp-block')?.checked;
      const allowReset = document.getElementById('esp-allow-reset')?.checked;

      if (!name) {
        alert('Policy name is required');
        return;
      }

      try {
        await window.FleetAPI.createEspPolicy({
          name,
          timeout_minutes: timeout,
          show_progress: showProg,
          block_until_completed: block,
          allow_user_reset_on_failure: allowReset
        });
        modal.remove();
        loadAllData();
      } catch (err) {
        alert(`Failed to create ESP policy: ${err.message}`);
      }
    });
  }

  function removeExistingModal(id) {
    const existing = document.getElementById(id);
    if (existing) existing.remove();
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  window.AutopilotTable = {
    init,
    refresh: loadAllData
  };
})();
