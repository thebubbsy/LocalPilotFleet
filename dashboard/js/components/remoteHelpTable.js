/**
 * LocalPilot Fleet — Microsoft Intune Remote Help & Unattended Assistance Blade
 * dashboard/js/components/remoteHelpTable.js
 */

(function () {
  'use strict';

  let currentTab = 'sessions'; // 'sessions' | 'roles' | 'audit'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getStatusBadge(status) {
    const s = String(status || 'PENDING').toUpperCase();
    if (s === 'ACTIVE') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">🟢 ACTIVE</span>';
    } else if (s === 'PENDING') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⏳ PENDING PIN</span>';
    } else if (s === 'COMPLETED') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3B82F6;font-weight:700;">✅ COMPLETED</span>';
    } else if (s === 'EXPIRED') {
      return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9CA3AF;font-weight:700;">⌛ EXPIRED</span>';
    } else if (s === 'CANCELLED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛑 CANCELLED</span>';
    }
    return '<span class="badge">' + esc(s) + '</span>';
  }

  function getActionBadge(action) {
    const a = String(action || '').toUpperCase();
    if (a === 'SESSION_STARTED' || a === 'UNATTENDED_CONNECTED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">🟢 ' + esc(a) + '</span>';
    } else if (a === 'ELEVATION_TRIGGERED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">⚡ ELEVATION</span>';
    } else if (a === 'CONTROL_GRANTED') {
      return '<span class="badge" style="background:rgba(139,92,246,0.15);color:#8B5CF6;font-weight:700;">🎮 CONTROL</span>';
    } else if (a === 'SESSION_REQUESTED') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">🔑 PIN REQUESTED</span>';
    } else if (a === 'SESSION_TERMINATED') {
      return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9CA3AF;font-weight:700;">⏹️ CONCLUDED</span>';
    }
    return '<span class="badge">' + esc(a) + '</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-remotehelp');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Remote Help &amp; Unattended Assistance…</span>' +
      '</div>';

    try {
      const [stats, sessionsData, rolesData, auditData, devicesData] = await Promise.all([
        window.FleetAPI.getRemoteHelpStats().catch(() => ({})),
        window.FleetAPI.getRemoteHelpSessions().catch(() => ({ sessions: [] })),
        window.FleetAPI.getRemoteHelpRoles().catch(() => ({ roles: [] })),
        window.FleetAPI.getRemoteHelpAuditLog({ limit: 50 }).catch(() => ({ audit_log: [] })),
        window.FleetAPI.getDevices ? window.FleetAPI.getDevices().catch(() => []) : Promise.resolve([])
      ]);

      const sessions = sessionsData.sessions || [];
      const roles = rolesData.roles || [];
      const auditLog = auditData.audit_log || [];
      const devices = Array.isArray(devicesData) ? devicesData : (devicesData.devices || []);

      renderView(container, stats, sessions, roles, auditLog, devices);
    } catch (err) {
      container.innerHTML = 
        '<div class="error-banner" style="margin:24px;padding:16px;background:rgba(239,68,68,0.1);border-left:4px solid #EF4444;color:#EF4444;">' +
          '<strong>Error loading Remote Help:</strong> ' + esc(err.message) +
        '</div>';
    }
  }

  function renderView(container, stats, sessions, roles, auditLog, devices) {
    let html = '';

    // Header
    html += 
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">' +
        '<div>' +
          '<h2 style="margin:0 0 4px 0;font-size:1.4rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>🎧</span> Remote Help &amp; Unattended Assistance' +
          '</h2>' +
          '<p style="margin:0;color:var(--text-muted);font-size:0.85rem;">' +
            'Microsoft Intune-grade secure remote assistance, 6-digit one-time PIN pairing, UAC elevation governance, unattended maintenance, and RBAC.' +
          '</p>' +
        '</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="intune-btn" id="btn-refresh-remotehelp" style="display:flex;align-items:center;gap:6px;">' +
            '<span>🔄</span> Refresh' +
          '</button>' +
          '<button class="intune-btn primary" id="btn-start-rh-session" style="display:flex;align-items:center;gap:6px;">' +
            '<span>➕</span> Start Remote Help Session' +
          '</button>' +
        '</div>' +
      '</div>';

    // 4 KPI Cards
    html += 
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px;">' +
        // Card 1: Active Sessions
        '<div class="card" style="padding:16px;border-left:4px solid #10B981;background:var(--bg-card);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;margin-bottom:6px;">Active Sessions</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main);">' + (stats.activeSessions || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:#10B981;margin-top:4px;">Live screen sharing or unattended</div>' +
        '</div>' +
        // Card 2: Pending PIN Handshakes
        '<div class="card" style="padding:16px;border-left:4px solid #F59E0B;background:var(--bg-card);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;margin-bottom:6px;">Pending Handshakes</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main);">' + (stats.pendingSessions || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:#F59E0B;margin-top:4px;">Awaiting user PIN entry</div>' +
        '</div>' +
        // Card 3: Unattended Operations
        '<div class="card" style="padding:16px;border-left:4px solid #3B82F6;background:var(--bg-card);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;margin-bottom:6px;">Unattended Sessions</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main);">' + (stats.unattendedSessions || 0) + '</div>' +
          '<div style="font-size:0.75rem;color:#3B82F6;margin-top:4px;">Headless maintenance &amp; kiosks</div>' +
        '</div>' +
        // Card 4: RBAC Roles & Elevations
        '<div class="card" style="padding:16px;border-left:4px solid #8B5CF6;background:var(--bg-card);">' +
          '<div style="font-size:0.8rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;margin-bottom:6px;">Assistance Roles / Elevations</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main);">' + (stats.activeRoles || 0) + ' <span style="font-size:1rem;color:var(--text-muted);font-weight:normal;">/ ' + (stats.totalElevations || 0) + ' elev</span></div>' +
          '<div style="font-size:0.75rem;color:#8B5CF6;margin-top:4px;">UAC elevation governance active</div>' +
        '</div>' +
      '</div>';

    // Sub-Tabs Navigation
    html += 
      '<div style="display:flex;border-bottom:1px solid var(--border-color);margin-bottom:20px;gap:8px;">' +
        '<button class="tab-btn ' + (currentTab === 'sessions' ? 'active' : '') + '" data-subtab="sessions" style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ' + (currentTab === 'sessions' ? '#3B82F6' : 'transparent') + ';color:' + (currentTab === 'sessions' ? '#3B82F6' : 'var(--text-muted)') + ';font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;">' +
          '<span>📡</span> Remote Sessions (' + sessions.length + ')' +
        '</button>' +
        '<button class="tab-btn ' + (currentTab === 'roles' ? 'active' : '') + '" data-subtab="roles" style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ' + (currentTab === 'roles' ? '#3B82F6' : 'transparent') + ';color:' + (currentTab === 'roles' ? '#3B82F6' : 'var(--text-muted)') + ';font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;">' +
          '<span>🛡️</span> Assistance Roles (' + roles.length + ')' +
        '</button>' +
        '<button class="tab-btn ' + (currentTab === 'audit' ? 'active' : '') + '" data-subtab="audit" style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ' + (currentTab === 'audit' ? '#3B82F6' : 'transparent') + ';color:' + (currentTab === 'audit' ? '#3B82F6' : 'var(--text-muted)') + ';font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;">' +
          '<span>📋</span> Operations Audit Ledger (' + auditLog.length + ')' +
        '</button>' +
      '</div>';

    // TAB 1: SESSIONS
    if (currentTab === 'sessions') {
      html += 
        '<div class="card" style="background:var(--bg-card);padding:0;overflow:hidden;border:1px solid var(--border-color);border-radius:6px;">' +
          '<table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.85rem;">' +
            '<thead style="background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<tr>' +
                '<th style="padding:12px 16px;">Session PIN</th>' +
                '<th style="padding:12px 16px;">Target Workstation</th>' +
                '<th style="padding:12px 16px;">Operator</th>' +
                '<th style="padding:12px 16px;">Remote User</th>' +
                '<th style="padding:12px 16px;">Type / Mode</th>' +
                '<th style="padding:12px 16px;">Status</th>' +
                '<th style="padding:12px 16px;">Created / Expires</th>' +
                '<th style="padding:12px 16px;text-align:right;">Actions</th>' +
              '</tr>' +
            '</thead>' +
            '<tbody>';

      if (sessions.length === 0) {
        html += '<tr><td colspan="8" style="padding:32px;text-align:center;color:var(--text-muted);">No remote assistance sessions found. Click "+ Start Remote Help Session" to initiate support.</td></tr>';
      } else {
        sessions.forEach(s => {
          const pinFmt = s.session_code ? (s.session_code.slice(0, 3) + ' ' + s.session_code.slice(3)) : '—';
          const isUnattended = s.unattended_enabled === 1;

          html += 
            '<tr style="border-bottom:1px solid var(--border-color);">' +
              '<td style="padding:12px 16px;">' +
                '<span style="font-family:monospace;font-size:1rem;font-weight:700;background:rgba(59,130,246,0.12);color:#60A5FA;padding:3px 8px;border-radius:4px;letter-spacing:1px;">' + esc(pinFmt) + '</span>' +
              '</td>' +
              '<td style="padding:12px 16px;">' +
                '<div style="font-weight:600;color:var(--text-main);">' + esc(s.device_hostname || s.device_id) + '</div>' +
                '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(s.device_model || '') + ' ' + (s.device_ip ? '• ' + esc(s.device_ip) : '') + '</div>' +
              '</td>' +
              '<td style="padding:12px 16px;font-weight:500;">' + esc(s.helper_user) + '</td>' +
              '<td style="padding:12px 16px;color:var(--text-muted);">' + esc(s.sharer_user || (isUnattended ? 'Unattended (Daemon)' : 'Awaiting Connection')) + '</td>' +
              '<td style="padding:12px 16px;">' +
                '<div style="display:flex;align-items:center;gap:6px;">' +
                  '<span class="badge" style="background:rgba(148,163,184,0.12);font-size:0.75rem;">' + esc(s.session_type) + '</span>' +
                  (isUnattended ? '<span class="badge" style="background:rgba(139,92,246,0.15);color:#A78BFA;font-size:0.75rem;">🤖 UNATTENDED</span>' : '') +
                '</div>' +
              '</td>' +
              '<td style="padding:12px 16px;">' + getStatusBadge(s.status) + '</td>' +
              '<td style="padding:12px 16px;font-size:0.8rem;color:var(--text-muted);">' +
                '<div>' + (s.created_at ? new Date(s.created_at).toLocaleTimeString() : '—') + '</div>' +
                (s.status === 'PENDING' ? '<div style="font-size:0.75rem;color:#F59E0B;">Exp: ' + (s.expires_at ? new Date(s.expires_at).toLocaleTimeString() : '15m') + '</div>' : '') +
              '</td>' +
              '<td style="padding:12px 16px;text-align:right;">' +
                '<div style="display:flex;gap:6px;justify-content:flex-end;">' +
                  '<button class="intune-btn btn-view-rh-script" data-id="' + esc(s.id) + '" data-code="' + esc(s.session_code) + '" style="padding:4px 8px;font-size:0.75rem;" title="View PIN &amp; Launch Script">📋 Connect</button>' +
                  (s.status === 'ACTIVE' 
                    ? '<button class="intune-btn btn-elevate-rh" data-id="' + esc(s.id) + '" style="padding:4px 8px;font-size:0.75rem;background:rgba(239,68,68,0.15);color:#EF4444;" title="Request UAC Admin Elevation">⚡ Elevate</button>' +
                      '<button class="intune-btn btn-terminate-rh" data-id="' + esc(s.id) + '" style="padding:4px 8px;font-size:0.75rem;" title="End Session">🛑 End</button>'
                    : '') +
                  (s.status === 'PENDING' 
                    ? '<button class="intune-btn btn-accept-rh" data-id="' + esc(s.id) + '" style="padding:4px 8px;font-size:0.75rem;background:rgba(16,185,129,0.15);color:#10B981;" title="Simulate Remote User Accept">🔌 Accept</button>' +
                      '<button class="intune-btn btn-terminate-rh" data-id="' + esc(s.id) + '" style="padding:4px 8px;font-size:0.75rem;color:#EF4444;" title="Cancel Session">❌ Cancel</button>'
                    : '') +
                '</div>' +
              '</td>' +
            '</tr>';
        });
      }

      html += '</tbody></table></div>';
    }

    // TAB 2: ROLES
    if (currentTab === 'roles') {
      html += 
        '<div style="display:flex;justify-content:flex-end;margin-bottom:12px;">' +
          '<button class="intune-btn primary" id="btn-add-rh-role" style="font-size:0.85rem;display:flex;align-items:center;gap:6px;">' +
            '<span>➕</span> Add Assistance Role' +
          '</button>' +
        '</div>' +
        '<div class="card" style="background:var(--bg-card);padding:0;overflow:hidden;border:1px solid var(--border-color);border-radius:6px;">' +
          '<table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.85rem;">' +
            '<thead style="background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<tr>' +
                '<th style="padding:12px 16px;">Role Name</th>' +
                '<th style="padding:12px 16px;">Description</th>' +
                '<th style="padding:12px 16px;">Full Control</th>' +
                '<th style="padding:12px 16px;">UAC Elevation</th>' +
                '<th style="padding:12px 16px;">Unattended</th>' +
                '<th style="padding:12px 16px;">Target Scope</th>' +
                '<th style="padding:12px 16px;text-align:right;">Actions</th>' +
              '</tr>' +
            '</thead>' +
            '<tbody>';

      roles.forEach(r => {
        html += 
          '<tr style="border-bottom:1px solid var(--border-color);">' +
            '<td style="padding:12px 16px;font-weight:600;color:var(--text-main);">' + esc(r.name) + '</td>' +
            '<td style="padding:12px 16px;color:var(--text-muted);max-width:300px;">' + esc(r.description || '—') + '</td>' +
            '<td style="padding:12px 16px;">' + (r.can_request_full_control ? '✅ Yes' : '❌ View Only') + '</td>' +
            '<td style="padding:12px 16px;">' + (r.can_request_elevation ? '<span style="color:#EF4444;font-weight:700;">⚡ Allowed</span>' : '❌ Blocked') + '</td>' +
            '<td style="padding:12px 16px;">' + (r.can_unattended ? '<span style="color:#8B5CF6;font-weight:700;">🤖 Allowed</span>' : '❌ Attended Only') + '</td>' +
            '<td style="padding:12px 16px;color:var(--text-muted);">' + esc(r.target_group_name || 'All Fleet Devices') + '</td>' +
            '<td style="padding:12px 16px;text-align:right;">' +
              (r.id.startsWith('rh-role-') && ['rh-role-tier1', 'rh-role-tier2-admin', 'rh-role-unattended-ops'].includes(r.id)
                ? '<span style="font-size:0.75rem;color:var(--text-muted);font-style:italic;">Built-in Intune Role</span>'
                : '<button class="intune-btn btn-delete-rh-role" data-id="' + esc(r.id) + '" style="padding:4px 8px;font-size:0.75rem;color:#EF4444;">🗑️ Delete</button>') +
            '</td>' +
          '</tr>';
      });

      html += '</tbody></table></div>';
    }

    // TAB 3: AUDIT LEDGER
    if (currentTab === 'audit') {
      html += 
        '<div class="card" style="background:var(--bg-card);padding:0;overflow:hidden;border:1px solid var(--border-color);border-radius:6px;">' +
          '<table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.85rem;">' +
            '<thead style="background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border-color);color:var(--text-muted);">' +
              '<tr>' +
                '<th style="padding:12px 16px;">Timestamp</th>' +
                '<th style="padding:12px 16px;">Workstation</th>' +
                '<th style="padding:12px 16px;">Actor</th>' +
                '<th style="padding:12px 16px;">Action</th>' +
                '<th style="padding:12px 16px;">Details</th>' +
              '</tr>' +
            '</thead>' +
            '<tbody>';

      if (auditLog.length === 0) {
        html += '<tr><td colspan="5" style="padding:32px;text-align:center;color:var(--text-muted);">No audit events recorded yet.</td></tr>';
      } else {
        auditLog.forEach(l => {
          html += 
            '<tr style="border-bottom:1px solid var(--border-color);">' +
              '<td style="padding:12px 16px;white-space:nowrap;color:var(--text-muted);">' + (l.timestamp ? new Date(l.timestamp).toLocaleString() : '—') + '</td>' +
              '<td style="padding:12px 16px;font-weight:600;">' + esc(l.device_hostname || l.device_id) + '</td>' +
              '<td style="padding:12px 16px;font-weight:500;">' + esc(l.actor_user) + '</td>' +
              '<td style="padding:12px 16px;">' + getActionBadge(l.action) + '</td>' +
              '<td style="padding:12px 16px;color:var(--text-main);">' + esc(l.details || '—') + '</td>' +
            '</tr>';
        });
      }

      html += '</tbody></table></div>';
    }

    container.innerHTML = html;
    bindEvents(container, devices, roles);
  }

  function bindEvents(container, devices, roles) {
    // Subtab clicks
    container.querySelectorAll('[data-subtab]').forEach(btn => {
      btn.addEventListener('click', () => {
        currentTab = btn.getAttribute('data-subtab');
        loadData();
      });
    });

    // Refresh
    const refreshBtn = container.querySelector('#btn-refresh-remotehelp');
    if (refreshBtn) refreshBtn.addEventListener('click', loadData);

    // Start Session Button
    const startBtn = container.querySelector('#btn-start-rh-session');
    if (startBtn) {
      startBtn.addEventListener('click', () => {
        showStartSessionModal(devices, roles);
      });
    }

    // View Script / PIN
    container.querySelectorAll('.btn-view-rh-script').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        try {
          const session = await window.FleetAPI.getRemoteHelpSession(id);
          showSessionPinModal(session);
        } catch (err) {
          alert('Error fetching session: ' + err.message);
        }
      });
    });

    // Accept session (simulate user connection)
    container.querySelectorAll('.btn-accept-rh').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        try {
          await window.FleetAPI.connectRemoteHelpSession(id, { sharer_user: 'Interactive User' });
          loadData();
        } catch (err) {
          alert('Error connecting session: ' + err.message);
        }
      });
    });

    // Elevate UAC
    container.querySelectorAll('.btn-elevate-rh').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const reason = prompt('Enter justification for UAC Admin Elevation:', 'Troubleshooting software / installing diagnostics');
        if (!reason) return;
        try {
          await window.FleetAPI.triggerRemoteHelpElevation(id, { actor_user: 'LocalPilot Admin', details: reason });
          alert('UAC elevation request sent and logged in audit ledger.');
          loadData();
        } catch (err) {
          alert('Error elevating: ' + err.message);
        }
      });
    });

    // Terminate session
    container.querySelectorAll('.btn-terminate-rh').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm('Are you sure you want to conclude / cancel this remote assistance session?')) return;
        try {
          await window.FleetAPI.terminateRemoteHelpSession(id, { actor_user: 'LocalPilot Admin', reason: 'Closed by operator' });
          loadData();
        } catch (err) {
          alert('Error terminating: ' + err.message);
        }
      });
    });

    // Add Role
    const addRoleBtn = container.querySelector('#btn-add-rh-role');
    if (addRoleBtn) {
      addRoleBtn.addEventListener('click', () => {
        showAddRoleModal();
      });
    }

    // Delete custom role
    container.querySelectorAll('.btn-delete-rh-role').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm('Are you sure you want to delete this assistance role?')) return;
        try {
          await window.FleetAPI.deleteRemoteHelpRole(id);
          loadData();
        } catch (err) {
          alert('Error deleting role: ' + err.message);
        }
      });
    });
  }

  function showStartSessionModal(devices, roles) {
    let devOptions = devices.map(d => 
      '<option value="' + esc(d.id) + '">' + esc(d.hostname) + ' (' + esc(d.os_name || 'Windows') + ' - ' + esc(d.status) + ')</option>'
    ).join('');

    let roleOptions = '<option value="">Standard Attended (Default)</option>' + roles.map(r =>
      '<option value="' + esc(r.id) + '">' + esc(r.name) + '</option>'
    ).join('');

    const modalHtml = 
      '<div id="modal-start-rh" class="modal-backdrop" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div class="modal-card" style="background:var(--bg-main, #1E1E2D);border:1px solid var(--border-color);width:520px;border-radius:8px;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<h3 style="margin:0;font-size:1.2rem;display:flex;align-items:center;gap:8px;"><span>🎧</span> Start Remote Help Session</h3>' +
            '<button id="btn-close-rh-modal" style="background:none;border:none;font-size:1.2rem;color:var(--text-muted);cursor:pointer;">✖</button>' +
          '</div>' +
          '<form id="form-start-rh" style="display:flex;flex-direction:column;gap:14px;">' +
            '<div>' +
              '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Target Workstation *</label>' +
              '<select id="rh-target-device" required style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);">' +
                devOptions +
              '</select>' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Assistance Operator / Helper Name</label>' +
              '<input type="text" id="rh-helper-name" value="LocalPilot Administrator" style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);" />' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Initial Control Level</label>' +
                '<select id="rh-session-type" style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);">' +
                  '<option value="FULL_CONTROL">Full Control (Mouse & Keyboard)</option>' +
                  '<option value="VIEW_ONLY">View Only (Screen Sharing)</option>' +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">RBAC Role Profile</label>' +
                '<select id="rh-role-id" style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);">' +
                  roleOptions +
                '</select>' +
              '</div>' +
            '</div>' +
            '<div style="background:rgba(59,130,246,0.06);padding:12px;border-radius:6px;border:1px solid rgba(59,130,246,0.2);">' +
              '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.85rem;font-weight:600;">' +
                '<input type="checkbox" id="rh-unattended" />' +
                '<span>🤖 Enable Unattended Remote Assistance</span>' +
              '</label>' +
              '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:4px;padding-left:24px;">' +
                'Allows connection without requiring an interactive user to approve on screen (ideal for servers and kiosks).' +
              '</div>' +
            '</div>' +
            '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px;">' +
              '<button type="button" id="btn-cancel-rh-modal" class="intune-btn">Cancel</button>' +
              '<button type="submit" class="intune-btn primary">Generate 6-Digit PIN</button>' +
            '</div>' +
          '</form>' +
        '</div>' +
      '</div>';

    const div = document.createElement('div');
    div.innerHTML = modalHtml;
    document.body.appendChild(div);

    const close = () => div.remove();
    div.querySelector('#btn-close-rh-modal').onclick = close;
    div.querySelector('#btn-cancel-rh-modal').onclick = close;

    div.querySelector('#form-start-rh').onsubmit = async (e) => {
      e.preventDefault();
      const deviceId = div.querySelector('#rh-target-device').value;
      const helperUser = div.querySelector('#rh-helper-name').value;
      const sessionType = div.querySelector('#rh-session-type').value;
      const unattended = div.querySelector('#rh-unattended').checked ? 1 : 0;
      const roleId = div.querySelector('#rh-role-id').value || null;

      try {
        const session = await window.FleetAPI.createRemoteHelpSession({
          device_id: deviceId,
          helper_user: helperUser,
          session_type: sessionType,
          unattended_enabled: unattended,
          role_id: roleId
        });
        close();
        showSessionPinModal(session);
        loadData();
      } catch (err) {
        alert('Failed to generate remote help session: ' + err.message);
      }
    };
  }

  function showSessionPinModal(session) {
    if (!session) return;
    const pinFmt = session.session_code ? (session.session_code.slice(0, 3) + ' ' + session.session_code.slice(3)) : '—';

    const modalHtml = 
      '<div id="modal-pin-rh" class="modal-backdrop" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div class="modal-card" style="background:var(--bg-main, #1E1E2D);border:1px solid var(--border-color);width:580px;border-radius:8px;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<h3 style="margin:0;font-size:1.2rem;display:flex;align-items:center;gap:8px;"><span>🎧</span> Remote Help Session PIN</h3>' +
            '<button id="btn-close-pin-modal" style="background:none;border:none;font-size:1.2rem;color:var(--text-muted);cursor:pointer;">✖</button>' +
          '</div>' +
          '<div style="text-align:center;padding:16px 0 20px 0;background:rgba(16,185,129,0.06);border-radius:8px;margin-bottom:16px;border:1px dashed #10B981;">' +
            '<div style="font-size:0.8rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;margin-bottom:6px;">One-Time Security Passcode</div>' +
            '<div style="font-size:2.4rem;font-family:monospace;font-weight:800;color:#10B981;letter-spacing:6px;">' + esc(pinFmt) + '</div>' +
            '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:6px;">Give this 6-digit PIN to the remote user or enter on the target workstation</div>' +
          '</div>' +
          '<div style="margin-bottom:16px;">' +
            '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:6px;">PowerShell Launch Script (Click to Copy)</label>' +
            '<pre id="rh-launch-script-pre" style="background:#0F172A;color:#38BDF8;padding:12px;border-radius:6px;font-size:0.75rem;overflow-x:auto;max-height:160px;cursor:pointer;" title="Click to copy script">' + esc(session.launch_script || '') + '</pre>' +
          '</div>' +
          '<div style="display:flex;justify-content:space-between;align-items:center;">' +
            '<button id="btn-copy-pin-script" class="intune-btn" style="display:flex;align-items:center;gap:6px;">' +
              '<span>📋</span> Copy Script to Clipboard' +
            '</button>' +
            '<button id="btn-dismiss-pin-modal" class="intune-btn primary">Done</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    const div = document.createElement('div');
    div.innerHTML = modalHtml;
    document.body.appendChild(div);

    const close = () => div.remove();
    div.querySelector('#btn-close-pin-modal').onclick = close;
    div.querySelector('#btn-dismiss-pin-modal').onclick = close;

    const copyScript = () => {
      navigator.clipboard.writeText(session.launch_script || session.session_code);
      alert('PowerShell connector script copied to clipboard!');
    };
    div.querySelector('#btn-copy-pin-script').onclick = copyScript;
    div.querySelector('#rh-launch-script-pre').onclick = copyScript;
  }

  function showAddRoleModal() {
    const modalHtml = 
      '<div id="modal-role-rh" class="modal-backdrop" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:9999;">' +
        '<div class="modal-card" style="background:var(--bg-main, #1E1E2D);border:1px solid var(--border-color);width:480px;border-radius:8px;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<h3 style="margin:0;font-size:1.2rem;display:flex;align-items:center;gap:8px;"><span>🛡️</span> New Assistance Role</h3>' +
            '<button id="btn-close-role-modal" style="background:none;border:none;font-size:1.2rem;color:var(--text-muted);cursor:pointer;">✖</button>' +
          '</div>' +
          '<form id="form-add-role" style="display:flex;flex-direction:column;gap:12px;">' +
            '<div>' +
              '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Role Name *</label>' +
              '<input type="text" id="role-name" required placeholder="e.g. VIP Executive Support" style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);" />' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:0.8rem;color:var(--text-muted);margin-bottom:4px;">Description</label>' +
              '<textarea id="role-desc" rows="2" style="width:100%;padding:8px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:4px;color:var(--text-main);"></textarea>' +
            '</div>' +
            '<div style="display:flex;flex-direction:column;gap:8px;margin-top:6px;">' +
              '<label style="display:flex;align-items:center;gap:8px;font-size:0.85rem;cursor:pointer;">' +
                '<input type="checkbox" id="role-ctrl" checked />' +
                '<span>Allow Interactive Mouse &amp; Keyboard Control</span>' +
              '</label>' +
              '<label style="display:flex;align-items:center;gap:8px;font-size:0.85rem;cursor:pointer;">' +
                '<input type="checkbox" id="role-elev" />' +
                '<span>Allow UAC Admin Elevation Requests</span>' +
              '</label>' +
              '<label style="display:flex;align-items:center;gap:8px;font-size:0.85rem;cursor:pointer;">' +
                '<input type="checkbox" id="role-unatt" />' +
                '<span>Allow Unattended Remote Access</span>' +
              '</label>' +
            '</div>' +
            '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px;">' +
              '<button type="button" id="btn-cancel-role-modal" class="intune-btn">Cancel</button>' +
              '<button type="submit" class="intune-btn primary">Create Role</button>' +
            '</div>' +
          '</form>' +
        '</div>' +
      '</div>';

    const div = document.createElement('div');
    div.innerHTML = modalHtml;
    document.body.appendChild(div);

    const close = () => div.remove();
    div.querySelector('#btn-close-role-modal').onclick = close;
    div.querySelector('#btn-cancel-role-modal').onclick = close;

    div.querySelector('#form-add-role').onsubmit = async (e) => {
      e.preventDefault();
      const name = div.querySelector('#role-name').value;
      const description = div.querySelector('#role-desc').value;
      const canCtrl = div.querySelector('#role-ctrl').checked ? 1 : 0;
      const canElev = div.querySelector('#role-elev').checked ? 1 : 0;
      const canUnatt = div.querySelector('#role-unatt').checked ? 1 : 0;

      try {
        await window.FleetAPI.createRemoteHelpRole({
          name,
          description,
          can_request_full_control: canCtrl,
          can_request_elevation: canElev,
          can_unattended: canUnatt
        });
        close();
        loadData();
      } catch (err) {
        alert('Failed to create role: ' + err.message);
      }
    };
  }

  // Export
  window.renderRemoteHelpTable = function (targetEl) {
    if (!targetEl) return;
    targetEl.innerHTML = '<div id="view-remotehelp"></div>';
    loadData();
  };

  window.RemoteHelpTable = {
    init: loadData,
    render: loadData,
    refresh: loadData
  };
})();
