/**
 * LocalPilot Fleet — Kiosk Mode & Multi-App Assigned Access Blade
 * dashboard/js/components/kioskTable.js
 */

(function () {
  'use strict';

  let currentTab = 'profiles'; // 'profiles' | 'inventory'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getModeBadge(mode) {
    const map = {
      DIGITAL_SIGNAGE: { bg: 'rgba(236,72,153,0.15)', text: '#F472B6', label: '📺 Digital Signage' },
      SINGLE_APP:      { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '🖥️ Single-App Kiosk' },
      MULTI_APP:       { bg: 'rgba(16,185,129,0.15)', text: '#10B981', label: '🛒 Multi-App Assigned Access' },
      SHELL_LAUNCHER:  { bg: 'rgba(168,85,247,0.15)', text: '#C084FC', label: '⚡ Windows Shell Launcher' }
    };
    const c = map[mode] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: mode };
    return `<span class="badge" style="background:${c.bg};color:${c.text};font-weight:600;">${c.label}</span>`;
  }

  function getAppBadge(type, path) {
    let label = 'Edge Kiosk';
    if (type === 'UWP_AUMID') label = 'Store App (AUMID)';
    else if (type === 'WIN32_EXE') label = 'Win32 Application';
    else if (type === 'MULTI_APP_XML') label = 'Multi-App Catalog';
    return `<span style="font-size:12px;color:var(--text-muted);">${label}</span>`;
  }

  function getLockdownBadge(status, active) {
    if (active) {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">🔒 Kiosk Active</span>';
    }
    if (status === 'KIOSK_CONFIGURED') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;font-weight:600;">⚙️ Configured</span>';
    }
    return '<span class="badge" style="background:rgba(100,116,139,0.15);color:#94A3B8;font-weight:500;">💻 Standard Shell</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-kiosk');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Kiosk Mode &amp; Assigned Access Posture…</span>
      </div>
    `;

    try {
      const [stats, profilesData, inventoryData] = await Promise.all([
        window.FleetAPI.getKioskStats().catch(() => ({})),
        window.FleetAPI.getKioskProfiles().catch(() => ({ profiles: [] })),
        window.FleetAPI.getKioskInventory().catch(() => ({ inventory: [] }))
      ]);

      renderBlade(container, {
        stats,
        profiles: profilesData.profiles || [],
        inventory: inventoryData.inventory || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:var(--accent-red);">
          <h3>Error loading Kiosk profiles</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.KioskTable.init()">Retry</button>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const { stats, profiles, inventory } = data;

    container.innerHTML = `
      <div style="padding:20px;max-width:1400px;margin:0 auto;">
        <!-- Header Ribbon -->
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
          <div>
            <h2 style="margin:0;font-size:20px;font-weight:600;display:flex;align-items:center;gap:8px;">
              <span>🖥️</span> Kiosk Mode &amp; Multi-App Assigned Access
            </h2>
            <p style="margin:4px 0 0;font-size:13px;color:var(--text-muted);">
              Lockdown Windows 10/11 devices into dedicated single-purpose kiosks, Edge digital signage, or restricted multi-app terminals.
            </p>
          </div>
          <div style="display:flex;gap:10px;">
            <button class="intune-btn intune-btn-secondary" onclick="window.KioskTable.init()">
              🔄 Refresh
            </button>
            <button class="intune-btn intune-btn-primary" onclick="window.KioskTable.showCreateModal()">
              ➕ Create Kiosk Profile
            </button>
          </div>
        </div>

        <!-- 4 KPI Cards -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px;">
          <div class="kpi-card" style="padding:16px;background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Active Profiles</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:var(--text-primary);">${stats.active_profiles ?? 0} <span style="font-size:14px;font-weight:normal;color:var(--text-muted);">/ ${stats.total_profiles ?? 0} total</span></div>
            <div style="font-size:11px;color:var(--accent-blue, #3b82f6);margin-top:4px;">Governing fleet lockouts</div>
          </div>

          <div class="kpi-card" style="padding:16px;background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Digital Signage &amp; Edge</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:#F472B6;">${stats.single_app_count ?? 0}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Full-screen browser &amp; single app</div>
          </div>

          <div class="kpi-card" style="padding:16px;background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Multi-App &amp; Shell Launcher</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:#10B981;">${stats.multi_app_count ?? 0}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Restricted catalog &amp; custom shells</div>
          </div>

          <div class="kpi-card" style="padding:16px;background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
            <div style="font-size:12px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Audited Workstations</div>
            <div style="font-size:28px;font-weight:700;margin-top:4px;color:#60A5FA;">${stats.total_audited_workstations ?? 0}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${stats.kiosk_active_count ?? 0} active | ${stats.standard_shell_count ?? 0} explorer.exe</div>
          </div>
        </div>

        <!-- Sub-Tabs Navigation -->
        <div style="display:flex;border-bottom:1px solid var(--border-color, #334155);margin-bottom:20px;">
          <button id="tab-btn-kiosk-profiles" class="subtab-btn ${currentTab === 'profiles' ? 'active' : ''}" style="padding:10px 20px;border:none;background:none;font-weight:600;font-size:14px;cursor:pointer;color:${currentTab === 'profiles' ? 'var(--accent-blue, #3b82f6)' : 'var(--text-muted)'};border-bottom:2px solid ${currentTab === 'profiles' ? 'var(--accent-blue, #3b82f6)' : 'transparent'};">
            🖥️ Kiosk Profiles (${profiles.length})
          </button>
          <button id="tab-btn-kiosk-inventory" class="subtab-btn ${currentTab === 'inventory' ? 'active' : ''}" style="padding:10px 20px;border:none;background:none;font-weight:600;font-size:14px;cursor:pointer;color:${currentTab === 'inventory' ? 'var(--accent-blue, #3b82f6)' : 'var(--text-muted)'};border-bottom:2px solid ${currentTab === 'inventory' ? 'var(--accent-blue, #3b82f6)' : 'transparent'};">
            📊 Workstation Kiosk Posture (${inventory.length})
          </button>
        </div>

        <!-- Tab Content Area -->
        <div id="kiosk-subtab-content">
          ${currentTab === 'profiles' ? renderProfilesTable(profiles) : renderInventoryTable(inventory)}
        </div>
      </div>
    `;

    document.getElementById('tab-btn-kiosk-profiles').onclick = () => {
      currentTab = 'profiles';
      renderBlade(container, data);
    };
    document.getElementById('tab-btn-kiosk-inventory').onclick = () => {
      currentTab = 'inventory';
      renderBlade(container, data);
    };
  }

  function renderProfilesTable(profiles) {
    if (!profiles || profiles.length === 0) {
      return `
        <div style="padding:40px;text-align:center;color:var(--text-muted);background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
          <div style="font-size:36px;margin-bottom:12px;">🖥️</div>
          <div style="font-size:16px;font-weight:600;">No Kiosk Profiles configured yet</div>
          <p style="font-size:13px;margin:8px 0 16px;">Create a profile to lockdown Windows devices into digital signage or dedicated kiosks.</p>
          <button class="intune-btn intune-btn-primary" onclick="window.KioskTable.showCreateModal()">➕ Create Kiosk Profile</button>
        </div>
      `;
    }

    return `
      <div style="background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border-color, #334155);text-align:left;color:var(--text-muted);">
              <th style="padding:12px 16px;">Profile Name</th>
              <th style="padding:12px 16px;">Kiosk Mode</th>
              <th style="padding:12px 16px;">Application &amp; Target</th>
              <th style="padding:12px 16px;">Logon User</th>
              <th style="padding:12px 16px;">Assigned Group</th>
              <th style="padding:12px 16px;">Assigned Devices</th>
              <th style="padding:12px 16px;">Status</th>
              <th style="padding:12px 16px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${profiles.map(p => `
              <tr style="border-bottom:1px solid var(--border-color, #334155);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-primary);">${esc(p.name)}</div>
                  <div style="font-size:11px;color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(p.description)}</div>
                </td>
                <td style="padding:12px 16px;">${getModeBadge(p.kiosk_mode)}</td>
                <td style="padding:12px 16px;">
                  <div>${esc(p.edge_kiosk_url || p.app_path_or_aumid || 'Assigned Access App')}</div>
                  <div>${getAppBadge(p.app_type, p.app_path_or_aumid)}</div>
                </td>
                <td style="padding:12px 16px;">
                  <span style="font-family:monospace;font-size:12px;">${esc(p.user_account)}</span>
                  <div style="font-size:10px;color:var(--text-muted);">${esc(p.logon_type)}</div>
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:rgba(59,130,246,0.1);color:#60A5FA;">${esc(p.target_group_name || p.target_group_id)}</span>
                </td>
                <td style="padding:12px 16px;">
                  <span style="font-weight:600;">${p.assigned_devices_count}</span> <span style="font-size:11px;color:var(--text-muted);">workstations</span>
                </td>
                <td style="padding:12px 16px;">
                  <span class="badge" style="background:${p.enabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'};color:${p.enabled ? '#10B981' : '#EF4444'};">
                    ${p.enabled ? '● Enabled' : '○ Disabled'}
                  </span>
                </td>
                <td style="padding:12px 16px;text-align:right;">
                  <button class="action-btn" title="View XML" onclick="window.KioskTable.showXmlModal('${esc(p.id)}')">📄 XML</button>
                  <button class="action-btn" title="View Shell Script" onclick="window.KioskTable.showScriptModal('${esc(p.id)}')">📜 Script</button>
                  <button class="action-btn danger" title="Delete Profile" onclick="window.KioskTable.deleteProfile('${esc(p.id)}', '${esc(p.name)}')">🗑️</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderInventoryTable(inventory) {
    if (!inventory || inventory.length === 0) {
      return `
        <div style="padding:40px;text-align:center;color:var(--text-muted);background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);">
          <div style="font-size:36px;margin-bottom:12px;">📊</div>
          <div style="font-size:16px;font-weight:600;">No Workstation Kiosk Posture reports yet</div>
          <p style="font-size:13px;margin:8px 0;">Workstation agents report Assigned Access capability and shell status during periodic audits.</p>
        </div>
      `;
    }

    return `
      <div style="background:var(--card-bg, #1e293b);border-radius:8px;border:1px solid var(--border-color, #334155);overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border-color, #334155);text-align:left;color:var(--text-muted);">
              <th style="padding:12px 16px;">Workstation</th>
              <th style="padding:12px 16px;">Lockdown Status</th>
              <th style="padding:12px 16px;">Current Shell</th>
              <th style="padding:12px 16px;">Active Kiosk User</th>
              <th style="padding:12px 16px;">Assigned Profile</th>
              <th style="padding:12px 16px;">Capabilities</th>
              <th style="padding:12px 16px;">Last Audited</th>
            </tr>
          </thead>
          <tbody>
            ${inventory.map(row => `
              <tr style="border-bottom:1px solid var(--border-color, #334155);">
                <td style="padding:12px 16px;">
                  <div style="font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                    <span>💻</span>
                    <a href="#" onclick="window.FleetApp && window.FleetApp.showDeviceDetails('${esc(row.device_id)}');return false;" style="color:var(--accent-blue, #3b82f6);text-decoration:none;">
                      ${esc(row.hostname)}
                    </a>
                  </div>
                  <div style="font-size:11px;color:var(--text-muted);">${esc(row.device_ip)}</div>
                </td>
                <td style="padding:12px 16px;">
                  ${getLockdownBadge(row.lockdown_status, row.kiosk_active)}
                </td>
                <td style="padding:12px 16px;font-family:monospace;font-size:12px;">
                  ${esc(row.current_shell || 'explorer.exe')}
                </td>
                <td style="padding:12px 16px;">
                  ${row.active_kiosk_user ? `<span style="font-family:monospace;">${esc(row.active_kiosk_user)}</span>` : '<span style="color:var(--text-muted);">None</span>'}
                </td>
                <td style="padding:12px 16px;">
                  ${row.profile_name ? `<span style="font-weight:500;">${esc(row.profile_name)}</span>` : '<span style="color:var(--text-muted);">Standard Policy</span>'}
                </td>
                <td style="padding:12px 16px;">
                  <div style="font-size:11px;">
                    <span style="color:${row.assigned_access_supported ? '#10B981' : '#94A3B8'};">AssignedAccess: ${row.assigned_access_supported ? '✓' : '✗'}</span> | 
                    <span style="color:${row.shell_launcher_supported ? '#10B981' : '#94A3B8'};">ShellLauncher: ${row.shell_launcher_supported ? '✓' : '✗'}</span>
                  </div>
                </td>
                <td style="padding:12px 16px;color:var(--text-muted);font-size:11px;">
                  ${esc(row.last_scanned_at || 'Recently')}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  /* ── Presets & Create Modal ─────────────────────────────────────── */

  const PRESETS = {
    signage: {
      name: '4K Corporate Digital Signage Display',
      description: 'Single-app full-screen Microsoft Edge digital signage display with auto-logon and keyboard lockdown',
      kiosk_mode: 'DIGITAL_SIGNAGE',
      logon_type: 'AUTO_LOGON',
      user_account: 'KioskUser0',
      app_type: 'EDGE_BROWSER',
      edge_kiosk_type: 'DIGITAL_SIGNAGE',
      edge_kiosk_url: 'https://signage.localpilot.internal',
      edge_idle_timeout_min: 0,
      disable_taskbar: true,
      disable_cad_keys: true
    },
    interactive: {
      name: 'Front-Desk Customer Self-Service Kiosk',
      description: 'Public interactive kiosk running Edge InPrivate with 5-minute inactivity session reset',
      kiosk_mode: 'SINGLE_APP',
      logon_type: 'AUTO_LOGON',
      user_account: 'KioskVisitor',
      app_type: 'EDGE_BROWSER',
      edge_kiosk_type: 'PUBLIC_BROWSING',
      edge_kiosk_url: 'https://visitor.localpilot.internal',
      edge_idle_timeout_min: 5,
      disable_taskbar: true,
      disable_cad_keys: true
    },
    pos: {
      name: 'Retail Point-of-Sale & Multi-App Terminal',
      description: 'Multi-app assigned access lockdown environment providing Edge POS and Windows Calculator',
      kiosk_mode: 'MULTI_APP',
      logon_type: 'LOCAL_USER',
      user_account: 'PosOperator',
      app_type: 'MULTI_APP_XML',
      edge_kiosk_url: 'https://pos.localpilot.internal',
      edge_idle_timeout_min: 15,
      disable_taskbar: false,
      disable_cad_keys: true,
      allowed_apps: [
        { name: 'POS Web Application', aumid: 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe!App' },
        { name: 'Calculator', aumid: 'Microsoft.WindowsCalculator_8wekyb3d8bbwe!App' }
      ]
    }
  };

  function showCreateModal() {
    let modal = document.getElementById('modal-kiosk-create');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'modal-kiosk-create';
      modal.className = 'intune-modal-backdrop';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="intune-modal-card" style="max-width:640px;width:95%;background:var(--card-bg, #1e293b);padding:24px;border-radius:8px;border:1px solid var(--border-color, #334155);box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:18px;">➕ Create Kiosk &amp; Assigned Access Profile</h3>
          <button style="border:none;background:none;font-size:20px;color:var(--text-muted);cursor:pointer;" onclick="window.KioskTable.closeModal('modal-kiosk-create')">✕</button>
        </div>

        <!-- Quick Presets -->
        <div style="margin-bottom:16px;background:rgba(255,255,255,0.02);padding:12px;border-radius:6px;border:1px solid var(--border-color, #334155);">
          <div style="font-size:12px;font-weight:600;margin-bottom:8px;color:var(--text-muted);">Quick-Apply Enterprise Presets:</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.KioskTable.applyPreset('signage')">📺 4K Digital Signage</button>
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.KioskTable.applyPreset('interactive')">🏢 Public Interactive Kiosk</button>
            <button class="intune-btn intune-btn-secondary" style="font-size:12px;" onclick="window.KioskTable.applyPreset('pos')">🛒 Retail POS Terminal</button>
          </div>
        </div>

        <form id="form-kiosk-create" onsubmit="window.KioskTable.submitCreate(event)">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
            <div style="grid-column:1/-1;">
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Profile Name *</label>
              <input type="text" id="kiosk-name" class="intune-input" required placeholder="e.g. 4K Lobby Display Kiosk" style="width:100%;box-sizing:border-box;">
            </div>
            <div style="grid-column:1/-1;">
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Description</label>
              <input type="text" id="kiosk-desc" class="intune-input" placeholder="Deployment notes and purpose" style="width:100%;box-sizing:border-box;">
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Kiosk Mode</label>
              <select id="kiosk-mode" class="intune-input" style="width:100%;">
                <option value="DIGITAL_SIGNAGE">📺 Digital Signage (Edge Fullscreen)</option>
                <option value="SINGLE_APP">🖥️ Single-App (Interactive Kiosk)</option>
                <option value="MULTI_APP">🛒 Multi-App Assigned Access</option>
                <option value="SHELL_LAUNCHER">⚡ Windows Shell Launcher</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Logon Account Type</label>
              <select id="kiosk-logon" class="intune-input" style="width:100%;">
                <option value="AUTO_LOGON">Auto-Logon (KioskUser0)</option>
                <option value="LOCAL_USER">Local User Account</option>
                <option value="AZURE_AD_USER">Entra ID / Domain Account</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Target User Account</label>
              <input type="text" id="kiosk-user" class="intune-input" value="KioskUser0" style="width:100%;box-sizing:border-box;">
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Application Type</label>
              <select id="kiosk-app-type" class="intune-input" style="width:100%;">
                <option value="EDGE_BROWSER">Microsoft Edge Browser</option>
                <option value="UWP_AUMID">Store App (AUMID)</option>
                <option value="WIN32_EXE">Win32 Executable (.exe)</option>
                <option value="MULTI_APP_XML">Multi-App Allowed Catalog</option>
              </select>
            </div>
            <div style="grid-column:1/-1;">
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Edge Kiosk URL / App Path / AUMID</label>
              <input type="text" id="kiosk-url" class="intune-input" value="https://localpilot.internal" style="width:100%;box-sizing:border-box;">
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Edge Inactivity Reset (minutes)</label>
              <input type="number" id="kiosk-timeout" class="intune-input" value="5" min="0" max="1440" style="width:100%;box-sizing:border-box;">
            </div>
            <div>
              <label style="display:block;font-size:12px;margin-bottom:4px;color:var(--text-muted);">Target Dynamic Group</label>
              <select id="kiosk-group" class="intune-input" style="width:100%;">
                <option value="grp-all">All Devices (grp-all)</option>
              </select>
            </div>
          </div>

          <div style="display:flex;gap:16px;margin-bottom:16px;">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" id="kiosk-hide-taskbar" checked> Hide Windows Taskbar
            </label>
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;">
              <input type="checkbox" id="kiosk-disable-cad" checked> Block Ctrl+Alt+Del &amp; WinKey
            </label>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:10px;">
            <button type="button" class="intune-btn intune-btn-secondary" onclick="window.KioskTable.closeModal('modal-kiosk-create')">Cancel</button>
            <button type="submit" class="intune-btn intune-btn-primary">Create Profile</button>
          </div>
        </form>
      </div>
    `;

    modal.style.display = 'flex';

    // Populate dynamic groups in dropdown
    if (window.FleetAPI && window.FleetAPI.getGroups) {
      window.FleetAPI.getGroups().then(data => {
        const groups = data.groups || data || [];
        const sel = document.getElementById('kiosk-group');
        if (sel && Array.isArray(groups)) {
          groups.forEach(g => {
            if (g.id !== 'grp-all') {
              const opt = document.createElement('option');
              opt.value = g.id;
              opt.textContent = `${g.name} (${g.id})`;
              sel.appendChild(opt);
            }
          });
        }
      }).catch(() => {});
    }
  }

  function applyPreset(key) {
    const p = PRESETS[key];
    if (!p) return;
    document.getElementById('kiosk-name').value = p.name;
    document.getElementById('kiosk-desc').value = p.description;
    document.getElementById('kiosk-mode').value = p.kiosk_mode;
    document.getElementById('kiosk-logon').value = p.logon_type;
    document.getElementById('kiosk-user').value = p.user_account;
    document.getElementById('kiosk-app-type').value = p.app_type;
    document.getElementById('kiosk-url').value = p.edge_kiosk_url || p.app_path_or_aumid || '';
    document.getElementById('kiosk-timeout').value = p.edge_idle_timeout_min || 0;
    document.getElementById('kiosk-hide-taskbar').checked = p.disable_taskbar;
    document.getElementById('kiosk-disable-cad').checked = p.disable_cad_keys;
  }

  async function submitCreate(e) {
    e.preventDefault();
    const payload = {
      name: document.getElementById('kiosk-name').value.trim(),
      description: document.getElementById('kiosk-desc').value.trim(),
      kiosk_mode: document.getElementById('kiosk-mode').value,
      logon_type: document.getElementById('kiosk-logon').value,
      user_account: document.getElementById('kiosk-user').value.trim(),
      app_type: document.getElementById('kiosk-app-type').value,
      target_group_id: document.getElementById('kiosk-group').value,
      edge_kiosk_url: document.getElementById('kiosk-url').value.trim(),
      edge_idle_timeout_min: parseInt(document.getElementById('kiosk-timeout').value, 10) || 5,
      disable_taskbar: document.getElementById('kiosk-hide-taskbar').checked,
      disable_cad_keys: document.getElementById('kiosk-disable-cad').checked
    };

    try {
      await window.FleetAPI.createKioskProfile(payload);
      closeModal('modal-kiosk-create');
      loadData();
    } catch (err) {
      alert('Failed to create Kiosk profile: ' + err.message);
    }
  }

  /* ── XML & Script Viewer Modals ─────────────────────────────────── */

  async function showXmlModal(id) {
    try {
      const profile = await window.FleetAPI.getKioskProfile(id);
      let modal = document.getElementById('modal-kiosk-xml');
      if (!modal) {
        modal = document.createElement('div');
        modal.id = 'modal-kiosk-xml';
        modal.className = 'intune-modal-backdrop';
        document.body.appendChild(modal);
      }

      const xml = profile.generated_xml || '<!-- No XML available -->';

      modal.innerHTML = `
        <div class="intune-modal-card" style="max-width:750px;width:95%;background:var(--card-bg, #1e293b);padding:24px;border-radius:8px;border:1px solid var(--border-color, #334155);box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <h3 style="margin:0;font-size:18px;">📄 Windows Assigned Access XML — ${esc(profile.name)}</h3>
            <button style="border:none;background:none;font-size:20px;color:var(--text-muted);cursor:pointer;" onclick="window.KioskTable.closeModal('modal-kiosk-xml')">✕</button>
          </div>
          <p style="font-size:12px;color:var(--text-muted);margin:0 0 12px;">
            Native Microsoft AssignedAccessConfiguration XML v1/v2 schema for Intune MDM CSP &amp; WMI deployment.
          </p>
          <pre style="background:rgba(0,0,0,0.3);padding:16px;border-radius:6px;overflow:auto;max-height:360px;font-family:monospace;font-size:12px;color:#38BDF8;border:1px solid rgba(255,255,255,0.05);">${esc(xml)}</pre>
          <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">
            <button class="intune-btn intune-btn-secondary" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(xml)}'));alert('Copied XML to clipboard!');">📋 Copy XML</button>
            <button class="intune-btn intune-btn-primary" onclick="window.KioskTable.closeModal('modal-kiosk-xml')">Close</button>
          </div>
        </div>
      `;

      modal.style.display = 'flex';
    } catch (err) {
      alert('Failed to load profile XML: ' + err.message);
    }
  }

  async function showScriptModal(id) {
    try {
      const profile = await window.FleetAPI.getKioskProfile(id);
      let modal = document.getElementById('modal-kiosk-script');
      if (!modal) {
        modal = document.createElement('div');
        modal.id = 'modal-kiosk-script';
        modal.className = 'intune-modal-backdrop';
        document.body.appendChild(modal);
      }

      const script = profile.shell_launcher_script || '# No script available';

      modal.innerHTML = `
        <div class="intune-modal-card" style="max-width:750px;width:95%;background:var(--card-bg, #1e293b);padding:24px;border-radius:8px;border:1px solid var(--border-color, #334155);box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <h3 style="margin:0;font-size:18px;">📜 Shell Launcher Deployment Script — ${esc(profile.name)}</h3>
            <button style="border:none;background:none;font-size:20px;color:var(--text-muted);cursor:pointer;" onclick="window.KioskTable.closeModal('modal-kiosk-script')">✕</button>
          </div>
          <p style="font-size:12px;color:var(--text-muted);margin:0 0 12px;">
            PowerShell script configuring native Windows 10/11 Shell Launcher via WMI <code>WESL_UserSetting</code>.
          </p>
          <pre style="background:rgba(0,0,0,0.3);padding:16px;border-radius:6px;overflow:auto;max-height:360px;font-family:monospace;font-size:12px;color:#A78BFA;border:1px solid rgba(255,255,255,0.05);">${esc(script)}</pre>
          <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px;">
            <button class="intune-btn intune-btn-secondary" onclick="navigator.clipboard.writeText(decodeURIComponent('${encodeURIComponent(script)}'));alert('Copied PowerShell script to clipboard!');">📋 Copy Script</button>
            <button class="intune-btn intune-btn-primary" onclick="window.KioskTable.closeModal('modal-kiosk-script')">Close</button>
          </div>
        </div>
      `;

      modal.style.display = 'flex';
    } catch (err) {
      alert('Failed to load shell script: ' + err.message);
    }
  }

  async function deleteProfile(id, name) {
    if (!confirm(`Are you sure you want to delete kiosk profile "${name}"?`)) return;
    try {
      await window.FleetAPI.deleteKioskProfile(id);
      loadData();
    } catch (err) {
      alert('Failed to delete kiosk profile: ' + err.message);
    }
  }

  function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.style.display = 'none';
  }

  window.KioskTable = {
    init: loadData,
    showCreateModal,
    applyPreset,
    submitCreate,
    showXmlModal,
    showScriptModal,
    deleteProfile,
    closeModal
  };
})();
